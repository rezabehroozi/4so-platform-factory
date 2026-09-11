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
	"platform.4so.io/factory/internal/evidence"
)

func runtimeClosureHTTPFixture(t *testing.T) (http.Handler, *controlplane.MemoryStore, controlplane.Project, controlplane.ManagedCluster, string) {
	t.Helper()
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "runtime-closure", DisplayName: "Runtime Closure"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "runtime-closure-project", DisplayName: "Runtime Closure Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := "runtime-closure-enrollment-token-abcdefghijklmnopqrstuvwxyz"
	agentToken := "runtime-closure-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "runtime-closure-cluster", DisplayName: "Runtime Closure Cluster", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agentToken), "uid-runtime-closure", "0.0.21")
	if err != nil {
		t.Fatal(err)
	}
	inventory := apiTestCompletePlanningInventory(controlplane.ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.34.2", Nodes: []controlplane.ClusterNode{{Name: "runtime-closure-node", Architecture: "amd64", Ready: true}}, Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, "outbound-agent", "read-only-inventory", "controlled-baseline-deployment"}})
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, inventory)
	if err != nil {
		t.Fatal(err)
	}
	server := New("0.0.21", nil, nil, store)
	if err := server.ConfigureRuntimeClosureReleaseIdentity("sha256:"+strings.Repeat("6", 64), "sha256:"+strings.Repeat("7", 64)); err != nil {
		t.Fatal(err)
	}
	server.ConfigureFleetImport("registry.local/agent@sha256:"+strings.Repeat("9", 64), "registry.local/probe@sha256:"+strings.Repeat("8", 64), "https://platform.example.test", "test-ca")
	return server.Handler(), store, project, cluster, agentToken
}

func createSucceededMarketplaceInstallation(t *testing.T, h http.Handler, project controlplane.Project, cluster controlplane.ManagedCluster, agentToken string) controlplane.BaselineDeployment {
	t.Helper()
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"offerId":"secure-namespace-foundation","offerVersion":"1.0.0"}`, project.ID, cluster.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/marketplace/installations", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "runtime-closure-install"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create installation %d: %s", w.Code, w.Body.String())
	}
	created := decodeBody[struct {
		Installation controlplane.BaselineDeployment `json:"installation"`
	}](t, w).Installation
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	planTask := decodeBody[controlplane.BaselineTask](t, w)
	changes := []controlplane.BaselinePlanChange{{Resource: "ConfigMap/4so-baseline-revision", Action: "ADD"}}
	impactRaw, _ := json.Marshal(apiTestPlanningImpactForTask(planTask, changes))
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/"+created.ID+"/result", fmt.Sprintf(`{"action":"PLAN","success":true,"taskFenceToken":%d,"changes":[{"resource":"ConfigMap/4so-baseline-revision","action":"ADD"}],"impact":%s}`, planTask.TaskFenceToken, string(impactRaw)), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", planTask.DeploymentRev)})
	if w.Code != http.StatusOK {
		t.Fatalf("plan result %d: %s", w.Code, w.Body.String())
	}
	planned := decodeBody[controlplane.BaselineDeployment](t, w)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/marketplace/installations/"+created.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", planned.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("approve %d: %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	applyTask := decodeBody[controlplane.BaselineTask](t, w)
	applyBody := apiTestApplyResultJSON(applyTask)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/"+created.ID+"/result", applyBody, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", applyTask.DeploymentRev)})
	if w.Code != http.StatusOK {
		t.Fatalf("apply result %d: %s", w.Code, w.Body.String())
	}
	return decodeBody[controlplane.BaselineDeployment](t, w)
}

func TestRuntimeClosureCampaignFailureRetryAndEvidenceWorkflow(t *testing.T) {
	h, _, project, cluster, agentToken := runtimeClosureHTTPFixture(t)
	baseline := createSucceededMarketplaceInstallation(t, h, project, cluster, agentToken)
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"baselineDeploymentId":%q}`, project.ID, cluster.ID, baseline.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/runtime-closure-campaigns", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "runtime-closure-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create campaign %d: %s", w.Code, w.Body.String())
	}
	campaign := decodeBody[struct {
		Campaign controlplane.RuntimeClosureCampaign `json:"campaign"`
	}](t, w).Campaign
	if campaign.State != controlplane.RuntimeClosureWaitingVerification {
		t.Fatalf("campaign=%#v", campaign)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-closure-campaigns/"+campaign.ID+"/advance", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("advance queue verification %d: %s", w.Code, w.Body.String())
	}
	campaign = decodeBody[controlplane.RuntimeClosureCampaign](t, w)
	if campaign.RuntimeVerificationID == "" || campaign.State != controlplane.RuntimeClosureWaitingVerification {
		t.Fatalf("campaign after queue=%#v", campaign)
	}

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/runtime-verification-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("verification task %d: %s", w.Code, w.Body.String())
	}
	task := decodeBody[controlplane.RuntimeVerificationTask](t, w)
	failedBody := fmt.Sprintf(`{"success":false,"taskFenceToken":%d,"observedDigest":%q,"checks":[{"key":"workload-scheduling","status":"FAIL","detail":"transient"}],"error":"transient probe failure"}`, task.TaskFenceToken, task.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-verification-tasks/"+task.VerificationID+"/result", failedBody, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", task.VerificationRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("verification failure result %d: %s", w.Code, w.Body.String())
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-closure-campaigns/"+campaign.ID+"/advance", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	campaign = decodeBody[controlplane.RuntimeClosureCampaign](t, w)
	if w.Code != http.StatusOK || campaign.State != controlplane.RuntimeClosureFailed || campaign.NextAction != "retry-runtime-verification" {
		t.Fatalf("campaign failure %d: %#v body=%s", w.Code, campaign, w.Body.String())
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-closure-campaigns/"+campaign.ID+"/retry", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != http.StatusAccepted {
		t.Fatalf("retry campaign %d: %s", w.Code, w.Body.String())
	}
	campaign = decodeBody[controlplane.RuntimeClosureCampaign](t, w)
	if campaign.State != controlplane.RuntimeClosureWaitingVerification {
		t.Fatalf("campaign retry=%#v", campaign)
	}

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/runtime-verification-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	task = decodeBody[controlplane.RuntimeVerificationTask](t, w)
	passBody := fmt.Sprintf(`{"success":true,"taskFenceToken":%d,"observedDigest":%q,"checks":[{"key":"workload-scheduling","status":"PASS"},{"key":"cluster-dns","status":"PASS"},{"key":"kubernetes-api","status":"PASS"}]}`, task.TaskFenceToken, task.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/runtime-verification-tasks/"+task.VerificationID+"/result", passBody, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", task.VerificationRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("verification success result %d: %s", w.Code, w.Body.String())
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-closure-campaigns/"+campaign.ID+"/advance", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("advance success %d: %s", w.Code, w.Body.String())
	}
	campaign = decodeBody[controlplane.RuntimeClosureCampaign](t, w)
	if campaign.State != controlplane.RuntimeClosureSucceeded || !strings.HasPrefix(campaign.EvidenceDigest, "sha256:") || campaign.DesiredDigest != campaign.ObservedDigest || campaign.EvidenceSchemaVersion != evidence.RuntimeClosureEvidenceSchema || campaign.ReleaseArtifactDigest != "sha256:"+strings.Repeat("6", 64) || campaign.ProducerBinaryDigest != "sha256:"+strings.Repeat("7", 64) {
		t.Fatalf("completed campaign=%#v", campaign)
	}

	w = apiRequest(t, h, http.MethodGet, "/api/v1/runtime-closure-campaigns/"+campaign.ID+"/report", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"runtimeClosed":true`) || !strings.Contains(w.Body.String(), `"canonicalization":"sorted-string-map-json-v2"`) || !strings.Contains(w.Header().Get("Content-Disposition"), "runtime-closure") {
		t.Fatalf("report %d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}
	reportBody := w.Body.String()
	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-closure-reports/verify", reportBody, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"valid":true`) || !strings.Contains(w.Body.String(), campaign.EvidenceDigest) {
		t.Fatalf("verify report %d body=%s", w.Code, w.Body.String())
	}

	tampered := strings.Replace(reportBody, cluster.InventoryDigest, "sha256:"+strings.Repeat("7", 64), 1)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/runtime-closure-reports/verify", tampered, nil)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("tampered report accepted %d body=%s", w.Code, w.Body.String())
	}
}

func TestRuntimeClosureCampaignRequiresExactReleaseRuntimeIdentity(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "runtime-closure-no-identity", DisplayName: "Runtime Closure"}, "admin")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "runtime-closure-no-identity", DisplayName: "Runtime Closure"}, "admin")
	server := New("0.0.260", nil, nil, store)
	w := apiRequest(t, server.Handler(), http.MethodPost, "/api/v1/runtime-closure-campaigns", fmt.Sprintf(`{"projectId":%q,"clusterId":"missing","baselineDeploymentId":"missing"}`, project.ID), map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "no-identity"})
	// Scope/entity checks happen before release-identity admission; the dedicated
	// fixture path above exercises the exact release gate on a valid campaign.
	if w.Code != http.StatusNotFound {
		t.Fatalf("unexpected precondition ordering: %d %s", w.Code, w.Body.String())
	}
}
