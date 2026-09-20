package api

import (
	"context"
	"encoding/json"
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
	if applyTask.Action != "APPLY" || applyTask.PendingAction != "PROVISION" || applyTask.InfrastructureProvider != "unspecified" || applyTask.CredentialRef != "" || applyTask.Resource["apiVersion"] != "cluster.x-k8s.io/v1beta2" || applyTask.Resource["kind"] != "Cluster" {
		t.Fatalf("apply task envelope=%#v", applyTask)
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

	// Bind a separately enrolled target to this authoritative ProviderCluster and
	// request ADD through the target-node lifecycle API. The request must remain
	// independently approval-bound and idempotent even after the scale completes.
	targetEnrollment := "provider-target-http-enrollment-token-abcdefghijklmnopqrstuvwxyz"
	targetAgent := "provider-target-http-agent-token-abcdefghijklmnopqrstuvwxyz"
	targetImport, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "customer-a-target", DisplayName: "Customer A Target", TokenDigest: credentialDigest(targetEnrollment), ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	targetImport, err = store.ApproveClusterImport(ctx, targetImport.ID, targetImport.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, target, err := store.ClaimClusterImport(ctx, targetImport.ID, credentialDigest(targetEnrollment), credentialDigest(targetAgent), "uid-provider-target-http", "0.0.313")
	if err != nil {
		t.Fatal(err)
	}
	target, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, target.ID, credentialDigest(targetAgent), target.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "kubernetes", KubernetesVersion: "v1.33.2", Digest: "sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}

	bindBody := fmt.Sprintf(`{"providerClusterId":%q}`, active.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+target.ID+"/provider-binding", bindBody, map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", target.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("provider binding %d: %s", w.Code, w.Body.String())
	}
	bound := decodeBody[struct {
		Cluster   controlplane.ManagedCluster `json:"cluster"`
		Authority string                      `json:"authority"`
	}](t, w)
	if bound.Authority != controlplane.TargetNodeProviderBindingAuthority || bound.Cluster.ProviderClusterID != active.ID {
		t.Fatalf("binding=%#v", bound)
	}

	addHeaders := map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "target-add-http"}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+target.ID+"/node-lifecycle-actions", `{"action":"ADD"}`, addHeaders)
	if w.Code != http.StatusAccepted {
		t.Fatalf("ADD request %d: %s", w.Code, w.Body.String())
	}
	queued := decodeBody[struct {
		ProviderCluster  controlplane.ProviderCluster `json:"providerCluster"`
		IdempotentReplay bool                         `json:"idempotentReplay"`
	}](t, w)
	if queued.IdempotentReplay || queued.ProviderCluster.State != controlplane.ProviderClusterAwaitingApproval || queued.ProviderCluster.PendingAction != "SCALE" || queued.ProviderCluster.Desired.WorkerReplicas != 4 {
		t.Fatalf("queued ADD=%#v", queued)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+target.ID+"/node-lifecycle-actions", `{"action":"ADD"}`, addHeaders)
	if w.Code != http.StatusOK {
		t.Fatalf("ADD replay before approval %d: %s", w.Code, w.Body.String())
	}
	replayed := decodeBody[struct {
		ProviderCluster  controlplane.ProviderCluster `json:"providerCluster"`
		IdempotentReplay bool                         `json:"idempotentReplay"`
	}](t, w)
	if !replayed.IdempotentReplay || replayed.ProviderCluster.Desired.WorkerReplicas != 4 {
		t.Fatalf("pre-approval replay=%#v", replayed)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/provider-clusters/"+queued.ProviderCluster.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", queued.ProviderCluster.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("approve ADD scale %d: %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("ADD scale task %d: %s", w.Code, w.Body.String())
	}
	scaleTask := decodeBody[controlplane.ProviderClusterTask](t, w)
	scaleApply := fmt.Sprintf(`{"taskFenceToken":%d,"action":"APPLY","success":true,"observedDigest":%q,"phase":"Scaling"}`, scaleTask.TaskFenceToken, scaleTask.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/"+queued.ProviderCluster.ID+"/result", scaleApply, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", scaleTask.ClusterRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("ADD scale apply %d: %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("ADD inspect task %d: %s", w.Code, w.Body.String())
	}
	scaleInspect := decodeBody[controlplane.ProviderClusterTask](t, w)
	scaleInspectResult := fmt.Sprintf(`{"taskFenceToken":%d,"action":"INSPECT","success":true,"ready":true,"observedDigest":%q,"phase":"Provisioned"}`, scaleInspect.TaskFenceToken, scaleInspect.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/"+queued.ProviderCluster.ID+"/result", scaleInspectResult, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", scaleInspect.ClusterRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("ADD scale inspect %d: %s", w.Code, w.Body.String())
	}
	completedAdd := decodeBody[controlplane.ProviderCluster](t, w)
	if completedAdd.State != controlplane.ProviderClusterActive || completedAdd.Applied.WorkerReplicas != 4 {
		t.Fatalf("completed ADD=%#v", completedAdd)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+target.ID+"/node-lifecycle-actions", `{"action":"ADD"}`, addHeaders)
	if w.Code != http.StatusOK {
		t.Fatalf("completed ADD replay %d: %s", w.Code, w.Body.String())
	}
	completedReplay := decodeBody[struct {
		ProviderCluster  controlplane.ProviderCluster `json:"providerCluster"`
		IdempotentReplay bool                         `json:"idempotentReplay"`
		Next             string                       `json:"next"`
	}](t, w)
	if !completedReplay.IdempotentReplay || completedReplay.Next != "completed" || completedReplay.ProviderCluster.Desired.WorkerReplicas != 4 {
		t.Fatalf("completed replay created a second scale: %#v", completedReplay)
	}

	// Activate the management-plane exact Machine lifecycle capability, pin a Ready
	// worker identity on the target and execute REPLACE through the same HTTP/store
	// approval boundary. This proves REST does not advertise or queue destructive
	// provider mutations until management RBAC capability and a live window exist.
	management, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, management.ID, credentialDigest(agentToken), management.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC().Add(time.Second), Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, controlplane.TargetNodeProviderMachineLifecycleCapability}})
	if err != nil {
		t.Fatal(err)
	}
	target, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, target.ID, credentialDigest(targetAgent), target.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC().Add(time.Second), Distribution: "kubernetes", KubernetesVersion: "v1.33.2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}, Nodes: []controlplane.ClusterNode{{Name: "worker-1", UID: "uid-worker-1", Roles: []string{"worker"}, Ready: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertClusterMaintenanceProfile(ctx, controlplane.ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: target.ID, Environment: controlplane.ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 120}, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, controlplane.ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: target.ID, Name: "provider-replace", StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 120}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	replaceBody := fmt.Sprintf(`{"action":"REPLACE","nodeName":"worker-1","windowId":%q}`, window.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+target.ID+"/node-lifecycle-actions", replaceBody, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "target-replace-http"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("REPLACE request %d: %s", w.Code, w.Body.String())
	}
	replaceQueued := decodeBody[struct {
		ProviderCluster controlplane.ProviderCluster `json:"providerCluster"`
	}](t, w).ProviderCluster
	if replaceQueued.State != controlplane.ProviderClusterAwaitingApproval || replaceQueued.PendingAction != "TARGET_NODE_REPLACE" || replaceQueued.TargetNodeMutation.NodeUID != "uid-worker-1" || replaceQueued.TargetNodeMutation.WindowID != window.ID {
		t.Fatalf("replace queue=%#v", replaceQueued)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/provider-clusters/"+replaceQueued.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", replaceQueued.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("approve REPLACE %d: %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("REPLACE task %d: %s", w.Code, w.Body.String())
	}
	replaceTask := decodeBody[controlplane.ProviderClusterTask](t, w)
	if replaceTask.TargetNodeMutation.Authority != controlplane.TargetNodeProviderMachineLifecycleAuthority || replaceTask.TargetNodeMutation.NodeUID != "uid-worker-1" {
		t.Fatalf("replace task mutation=%#v", replaceTask.TargetNodeMutation)
	}

	completeMutation := func(task controlplane.ProviderClusterTask, suffix string) controlplane.ProviderCluster {
		evidence := task.TargetNodeMutation
		evidence.MachineName = "machine-" + suffix
		evidence.MachineUID = "machine-uid-" + suffix
		evidence.MachineResourceVersion = "51"
		evidence.MachineSetName = "md-0-" + suffix
		evidence.MachineDeploymentName = "md-0"
		evidence.EvidenceDigest = "sha256:" + strings.Repeat("e", 64)
		applyRaw, _ := json.Marshal(controlplane.ProviderClusterTaskResult{TaskFenceToken: task.TaskFenceToken, Action: "APPLY", Success: true, ObservedDigest: task.DesiredDigest, Phase: "Replacing", TargetNodeMutation: evidence})
		w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/"+task.ProviderClusterID+"/result", string(applyRaw), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", task.ClusterRevision)})
		if w.Code != http.StatusOK {
			t.Fatalf("%s APPLY report %d: %s", suffix, w.Code, w.Body.String())
		}
		w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
		if w.Code != http.StatusOK {
			t.Fatalf("%s INSPECT task %d: %s", suffix, w.Code, w.Body.String())
		}
		inspectTask := decodeBody[controlplane.ProviderClusterTask](t, w)
		inspectRaw, _ := json.Marshal(controlplane.ProviderClusterTaskResult{TaskFenceToken: inspectTask.TaskFenceToken, Action: "INSPECT", Success: true, Ready: true, ObservedDigest: inspectTask.DesiredDigest, Phase: "Provisioned", TargetNodeMutation: evidence})
		w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/"+inspectTask.ProviderClusterID+"/result", string(inspectRaw), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", inspectTask.ClusterRevision)})
		if w.Code != http.StatusOK {
			t.Fatalf("%s INSPECT report %d: %s", suffix, w.Code, w.Body.String())
		}
		return decodeBody[controlplane.ProviderCluster](t, w)
	}
	active = completeMutation(replaceTask, "replace")
	if active.State != controlplane.ProviderClusterActive {
		t.Fatalf("REPLACE did not return provider to ACTIVE: %#v", active)
	}

	queueReplacementAction := func(action controlplane.TargetNodeLifecycleAction, key string) controlplane.ProviderClusterTask {
		body := fmt.Sprintf(`{"action":%q,"nodeName":"worker-1","windowId":%q}`, action, window.ID)
		w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+target.ID+"/node-lifecycle-actions", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": key})
		if w.Code != http.StatusAccepted {
			t.Fatalf("%s request %d: %s", action, w.Code, w.Body.String())
		}
		queued := decodeBody[struct {
			ProviderCluster controlplane.ProviderCluster `json:"providerCluster"`
		}](t, w).ProviderCluster
		if queued.PendingAction != "TARGET_NODE_"+string(action) || queued.TargetNodeMutation.Action != action {
			t.Fatalf("%s queue=%#v", action, queued)
		}
		w = apiRequest(t, h, http.MethodPost, "/api/v1/provider-clusters/"+queued.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", queued.Revision)})
		if w.Code != http.StatusOK {
			t.Fatalf("approve %s %d: %s", action, w.Code, w.Body.String())
		}
		w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-cluster-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
		if w.Code != http.StatusOK {
			t.Fatalf("%s task %d: %s", action, w.Code, w.Body.String())
		}
		return decodeBody[controlplane.ProviderClusterTask](t, w)
	}

	certTask := queueReplacementAction(controlplane.TargetNodeActionCertificateRenewal, "target-cert-renewal-http")
	if certTask.TargetNodeMutation.Action != controlplane.TargetNodeActionCertificateRenewal {
		t.Fatalf("certificate task=%#v", certTask.TargetNodeMutation)
	}
	active = completeMutation(certTask, "certificate")

	target, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, target.ID, credentialDigest(targetAgent), target.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC().Add(5 * time.Second), Distribution: "kubernetes", KubernetesVersion: "v1.33.2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}, Nodes: []controlplane.ClusterNode{{Name: "worker-1", UID: "uid-worker-1", Roles: []string{"worker"}, Ready: false}}})
	if err != nil {
		t.Fatal(err)
	}
	remediationTask := queueReplacementAction(controlplane.TargetNodeActionRemediate, "target-remediate-http")
	if remediationTask.TargetNodeMutation.Action != controlplane.TargetNodeActionRemediate {
		t.Fatalf("remediation task=%#v", remediationTask.TargetNodeMutation)
	}
	active = completeMutation(remediationTask, "remediation")
	if active.State != controlplane.ProviderClusterActive {
		t.Fatalf("remediation did not return provider to ACTIVE: %#v", active)
	}
}

func TestVMwareProviderProfileHTTPCarriesSourceAuthorityWithoutRawSecret(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "vmware-http", DisplayName: "VMware HTTP"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "vmware-project", DisplayName: "VMware Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := "vmware-http-enrollment-token-abcdefghijklmnopqrstuvwxyz"
	agentToken := "vmware-http-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "management", DisplayName: "Management", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, management, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agentToken), "uid-vmware-http", "0.0.357")
	if err != nil {
		t.Fatal(err)
	}
	management, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, management.ID, credentialDigest(agentToken), management.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}})
	if err != nil {
		t.Fatal(err)
	}

	h := New("0.0.357", nil, nil, store).Handler()
	body := fmt.Sprintf(`{"projectId":%q,"managementClusterId":%q,"name":"vmware-prod","displayName":"VMware Production","clusterClassName":"vmware-prod","workerClassName":"workers","defaultKubernetesVersion":"v1.33.2","kubernetesSeries":["v1.33"],"architectures":["amd64"],"distributionProfiles":["kubernetes"],"maxWorkerReplicas":50,"infrastructureProvider":"vmware","infrastructureEndpoint":"https://vcenter.example.test","credentialRef":"external-secret://4so-provider-system/vcenter-prod"}`, project.ID, management.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/provider-profiles", body, map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin", "Idempotency-Key": "vmware-http"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create VMware profile %d: %s", w.Code, w.Body.String())
	}
	profile := decodeBody[struct {
		ProviderProfile controlplane.ProviderProfile `json:"providerProfile"`
	}](t, w).ProviderProfile
	if profile.InfrastructureProvider != "vmware" || profile.InfrastructureEndpoint != "https://vcenter.example.test" || profile.CredentialRef != "external-secret://4so-provider-system/vcenter-prod" {
		t.Fatalf("profile=%#v", profile)
	}

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+management.ID+"/provider-profile-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("task %d: %s", w.Code, w.Body.String())
	}
	task := decodeBody[controlplane.ProviderProfileTask](t, w)
	if task.InfrastructureProvider != "vmware" {
		t.Fatalf("task=%#v", task)
	}
	serialized, _ := json.Marshal(task)
	if strings.Contains(string(serialized), "vcenter-prod") || strings.Contains(string(serialized), "vcenter.example.test") {
		t.Fatalf("agent task leaked credential/endpoint: %s", serialized)
	}
}
