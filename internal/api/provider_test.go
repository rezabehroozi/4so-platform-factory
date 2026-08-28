package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestProviderLifecycleHTTPWorkflow(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "provider-http", DisplayName: "Provider HTTP"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "provider-project", DisplayName: "Provider Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := "provider-http-enrollment-token-abcdefghijklmnopqrstuvwxyz"
	agentToken := "provider-http-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "management", DisplayName: "Management", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, management, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agentToken), "uid-provider-http", "0.0.17")
	if err != nil {
		t.Fatal(err)
	}
	management, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, management.ID, credentialDigest(agentToken), management.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}})
	if err != nil {
		t.Fatal(err)
	}

	h := New("0.0.17", nil, nil, store).Handler()
	profileBody := fmt.Sprintf(`{"projectId":%q,"managementClusterId":%q,"name":"vsphere-standard","displayName":"vSphere Standard","clusterClassName":"vsphere-standard","workerClassName":"worker-standard","defaultKubernetesVersion":"v1.33.2","kubernetesSeries":["v1.32","v1.33"],"maxWorkerReplicas":20}`, project.ID, management.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/provider-profiles", profileBody, map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin", "Idempotency-Key": "provider-profile-http"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create profile %d: %s", w.Code, w.Body.String())
	}
	createdProfile := decodeBody[struct {
		ProviderProfile controlplane.ProviderProfile `json:"providerProfile"`
	}](t, w).ProviderProfile
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-profile-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("profile task %d: %s", w.Code, w.Body.String())
	}
	profileTask := decodeBody[controlplane.ProviderProfileTask](t, w)
	if profileTask.Namespace != providerNamespace || profileTask.ClusterClassName != "vsphere-standard" || profileTask.WorkerClassName != "worker-standard" {
		t.Fatalf("profile task=%#v", profileTask)
	}
	profileResult := fmt.Sprintf(`{"taskFenceToken":%d,"success":true,"observedDigest":%q,"observedVersion":"cluster.x-k8s.io/v1beta2"}`, profileTask.TaskFenceToken, "sha256:"+strings.Repeat("a", 64))
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+management.ID+"/provider-profile-tasks/"+createdProfile.ID+"/result", profileResult, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", profileTask.ProfileRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("profile result %d: %s", w.Code, w.Body.String())
	}
	readyProfile := decodeBody[controlplane.ProviderProfile](t, w)
	if readyProfile.State != controlplane.ProviderProfileReady {
		t.Fatalf("profile state=%s", readyProfile.State)
	}
	if len(readyProfile.DistributionIdentities) != 1 || readyProfile.DistributionIdentities[0] != "kubernetes" || readyProfile.ProvisioningMode != "cluster-api" || readyProfile.InfrastructureProvider != "unspecified" {
		t.Fatalf("provider target model=%#v", readyProfile)
	}

	clusterBody := fmt.Sprintf(`{"projectId":%q,"providerProfileId":%q,"name":"customer-a","displayName":"Customer A","kubernetesVersion":"v1.33.2","controlPlaneReplicas":3,"workerReplicas":3}`, project.ID, readyProfile.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/provider-clusters", clusterBody, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "provider-cluster-http"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create cluster %d: %s", w.Code, w.Body.String())
	}
	createdCluster := decodeBody[struct {
		ProviderCluster controlplane.ProviderCluster `json:"providerCluster"`
	}](t, w).ProviderCluster
	if createdCluster.Desired.DistributionIdentity != "kubernetes" || createdCluster.Desired.ProvisioningMode != "cluster-api" || createdCluster.Desired.InfrastructureProvider != "unspecified" {
		t.Fatalf("provider cluster target model=%#v", createdCluster.Desired)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/provider-clusters/"+createdCluster.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", createdCluster.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("approve cluster %d: %s", w.Code, w.Body.String())
	}
	approved := decodeBody[controlplane.ProviderCluster](t, w)
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("apply task %d: %s", w.Code, w.Body.String())
	}
	applyTask := decodeBody[controlplane.ProviderClusterTask](t, w)
	if applyTask.Action != "APPLY" || applyTask.Resource["apiVersion"] != "cluster.x-k8s.io/v1beta2" || applyTask.Resource["kind"] != "Cluster" {
		t.Fatalf("apply task=%#v", applyTask)
	}
	metadata := applyTask.Resource["metadata"].(map[string]any)
	if metadata["namespace"] != providerNamespace || metadata["name"] != approved.ResourceName {
		t.Fatalf("metadata=%#v", metadata)
	}
	applyResult := fmt.Sprintf(`{"taskFenceToken":%d,"action":"APPLY","success":true,"observedDigest":%q,"phase":"Provisioning"}`, applyTask.TaskFenceToken, applyTask.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/"+approved.ID+"/result", applyResult, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", applyTask.ClusterRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("apply result %d: %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	inspectTask := decodeBody[controlplane.ProviderClusterTask](t, w)
	if inspectTask.Action != "INSPECT" || len(inspectTask.Resource) != 0 {
		t.Fatalf("inspect task=%#v", inspectTask)
	}
	inspectResult := fmt.Sprintf(`{"taskFenceToken":%d,"action":"INSPECT","success":true,"ready":true,"observedDigest":%q,"phase":"Provisioned"}`, inspectTask.TaskFenceToken, inspectTask.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/"+approved.ID+"/result", inspectResult, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", inspectTask.ClusterRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("inspect result %d: %s", w.Code, w.Body.String())
	}
	active := decodeBody[controlplane.ProviderCluster](t, w)
	if active.State != controlplane.ProviderClusterActive || active.Applied.KubernetesVersion != "v1.33.2" {
		t.Fatalf("active=%#v", active)
	}
}
