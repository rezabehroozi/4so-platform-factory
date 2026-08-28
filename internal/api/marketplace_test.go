package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/airuntime"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/marketplace"
)

func marketplaceHTTPFixture(t *testing.T) (*Server, *controlplane.MemoryStore, controlplane.Project, controlplane.ManagedCluster, string) {
	t.Helper()
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "marketplace-http", DisplayName: "Marketplace HTTP"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "marketplace-project", DisplayName: "Marketplace Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := "marketplace-http-enrollment-token-abcdefghijklmnopqrstuvwxyz"
	agentToken := "marketplace-http-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "marketplace-cluster", DisplayName: "Marketplace Cluster", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agentToken), "uid-marketplace-http", "0.0.18")
	if err != nil {
		t.Fatal(err)
	}
	inventory := apiTestCompletePlanningInventory(controlplane.ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.34.2", Nodes: []controlplane.ClusterNode{{Name: "marketplace-node", Architecture: "amd64", Ready: true}}, Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, "outbound-agent", "read-only-inventory", "controlled-baseline-deployment"}})
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, inventory)
	if err != nil {
		t.Fatal(err)
	}
	return New("0.0.18", nil, nil, store), store, project, cluster, agentToken
}

func TestMarketplaceInstallationRecommendationAndRollbackWorkflow(t *testing.T) {
	s, store, project, cluster, agentToken := marketplaceHTTPFixture(t)
	h := s.Handler()
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"offerId":"secure-namespace-foundation","offerVersion":"1.0.0"}`, project.ID, cluster.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/marketplace/installations", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "marketplace-install-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create installation %d: %s", w.Code, w.Body.String())
	}
	created := decodeBody[struct {
		Installation controlplane.BaselineDeployment `json:"installation"`
	}](t, w).Installation
	if created.SourceType != "marketplace" || created.PendingAction != "PLAN" {
		t.Fatalf("created=%#v", created)
	}

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	if w.Code != http.StatusOK {
		t.Fatalf("plan task %d: %s", w.Code, w.Body.String())
	}
	planTask := decodeBody[controlplane.BaselineTask](t, w)
	changes := []controlplane.BaselinePlanChange{{Resource: "ConfigMap/4so-baseline-revision", Action: "ADD", Desired: planTask.DesiredDigest}}
	impactRaw, _ := json.Marshal(apiTestPlanningImpactForTask(planTask, changes))
	planResult := fmt.Sprintf(`{"action":"PLAN","success":true,"taskFenceToken":%d,"observedDigest":"","changes":[{"resource":"ConfigMap/4so-baseline-revision","action":"ADD","desiredDigest":"%s"}],"impact":%s}`, planTask.TaskFenceToken, planTask.DesiredDigest, string(impactRaw))
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/"+created.ID+"/result", planResult, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", planTask.DeploymentRev)})
	if w.Code != http.StatusOK {
		t.Fatalf("plan result %d: %s", w.Code, w.Body.String())
	}
	planned := decodeBody[controlplane.BaselineDeployment](t, w)
	if planned.State != controlplane.BaselineDeploymentAwaitingApproval {
		t.Fatalf("planned=%#v", planned)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/marketplace/installations/"+created.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", planned.Revision)})
	if w.Code != http.StatusOK {
		t.Fatalf("approve %d: %s", w.Code, w.Body.String())
	}
	approved := decodeBody[struct {
		Installation controlplane.BaselineDeployment `json:"installation"`
	}](t, w).Installation

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	applyTask := decodeBody[controlplane.BaselineTask](t, w)
	applyResult := apiTestApplyResultJSON(applyTask)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/"+created.ID+"/result", applyResult, map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", applyTask.DeploymentRev)})
	if w.Code != http.StatusOK {
		t.Fatalf("apply result %d: %s", w.Code, w.Body.String())
	}
	active := decodeBody[controlplane.BaselineDeployment](t, w)
	if active.State != controlplane.BaselineDeploymentSucceeded || active.PendingAction != "" || approved.State != controlplane.BaselineDeploymentQueued {
		t.Fatalf("active=%#v approved=%#v", active, approved)
	}

	recommendationBody := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"objective":"Improve security without direct AI execution"}`, project.ID, cluster.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/marketplace/recommendations", recommendationBody, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "marketplace-recommend-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("recommendation %d: %s", w.Code, w.Body.String())
	}
	recommendation := decodeBody[struct {
		Recommendation   controlplane.MarketplaceRecommendation `json:"recommendation"`
		AdvisoryOnly     bool                                   `json:"advisoryOnly"`
		ExecutionAllowed bool                                   `json:"executionAllowed"`
	}](t, w)
	if !recommendation.AdvisoryOnly || recommendation.ExecutionAllowed || recommendation.Recommendation.Engine != "policy" || len(recommendation.Recommendation.Items) != 0 {
		t.Fatalf("recommendation=%#v", recommendation)
	}

	cp, err := store.CreateRecoveryCheckpoint(context.Background(), controlplane.RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "marketplace-uninstall-backup", EvidenceDigest: "sha256:" + strings.Repeat("c", 64), CompletedAt: time.Now().Add(-5 * time.Minute), ExpiresAt: time.Now().Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/marketplace/installations/"+created.ID+"/uninstall", fmt.Sprintf(`{"recoveryCheckpointId":%q}`, cp.ID), map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", active.Revision), "X-Confirm-Uninstall": "remove-marketplace-installation"})
	if w.Code != http.StatusOK {
		t.Fatalf("uninstall %d: %s", w.Code, w.Body.String())
	}
	uninstalling := decodeBody[struct {
		Installation controlplane.BaselineDeployment `json:"installation"`
	}](t, w).Installation
	if uninstalling.PendingAction != "ROLLBACK" {
		t.Fatalf("uninstalling=%#v", uninstalling)
	}
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/next", "", map[string]string{"Authorization": "Bearer " + agentToken})
	rollbackTask := decodeBody[controlplane.BaselineTask](t, w)
	if rollbackTask.Action != "ROLLBACK" {
		t.Fatalf("rollback task=%#v", rollbackTask)
	}
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/baseline-tasks/"+created.ID+"/result", fmt.Sprintf(`{"action":"ROLLBACK","success":true,"taskFenceToken":%d,"observedDigest":""}`, rollbackTask.TaskFenceToken), map[string]string{"Authorization": "Bearer " + agentToken, "If-Match": fmt.Sprintf("\"%d\"", rollbackTask.DeploymentRev)})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"ROLLED_BACK"`) {
		t.Fatalf("rollback result %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplaceRejectsClusterWithoutCapability(t *testing.T) {
	s, store, project, cluster, _ := marketplaceHTTPFixture(t)
	h := s.Handler()
	_, _, err := store.UpsertClusterInventory(context.Background(), cluster.ID, credentialDigest("wrong"), cluster.ExternalUID, controlplane.ClusterInventory{})
	if err == nil {
		t.Fatal("wrong token unexpectedly accepted")
	}
	// Create a second connected cluster without controlled-baseline-deployment.
	enrollment, agent := "no-cap-enrollment-token-abcdefghijklmnopqrstuvwxyz", "no-cap-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(context.Background(), controlplane.ClusterImport{ProjectID: project.ID, Name: "no-cap", DisplayName: "No Cap", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(context.Background(), imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, noCap, err := store.ClaimClusterImport(context.Background(), imp.ID, credentialDigest(enrollment), credentialDigest(agent), "uid-no-cap", "0.0.18")
	if err != nil {
		t.Fatal(err)
	}
	noCapInventory := controlplane.ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{"read-only-inventory", controlplane.TargetMutationRBACActiveCapability}}
	noCapInventory.Digest = controlplane.ClusterInventoryDigest(noCapInventory)
	_, _, err = store.UpsertClusterInventory(context.Background(), noCap.ID, credentialDigest(agent), noCap.ExternalUID, noCapInventory)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"offerId":"secure-namespace-foundation"}`, project.ID, noCap.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/marketplace/installations", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "no-cap"})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMarketplaceModelRecommendationPersistsAIRunAndReplaysBeforeProvider(t *testing.T) {
	s, store, project, cluster, _ := marketplaceHTTPFixture(t)
	calls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		input, _ := body["input"].(string)
		if strings.Contains(input, "super-secret") {
			t.Fatalf("secret reached provider: %s", input)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output_text":"{\"recommendations\":[{\"offerId\":\"secure-namespace-foundation\",\"offerVersion\":\"1.0.0\",\"score\":94,\"reason\":\"Matches the admitted security capability.\"}]}","usage":{"input_tokens":15,"output_tokens":9}}`))
	}))
	defer provider.Close()
	runtime, err := airuntime.New(airuntime.Config{Provider: airuntime.ProviderOpenAIResponses, Endpoint: provider.URL, Model: "market-model", MaxInputBytes: 8192, MaxOutputTokens: 600})
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureAIRuntime(runtime)
	s.ConfigureMarketplaceAdvisor(marketplace.NewRuntimeAdvisor(runtime))
	body := fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"objective":"password=super-secret improve security"}`, project.ID, cluster.ID)
	headers := map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "model-recommend-1"}
	w := apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/marketplace/recommendations", body, headers)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	if calls != 1 || !strings.Contains(w.Body.String(), `"engine":"model"`) {
		t.Fatalf("calls=%d body=%s", calls, w.Body.String())
	}
	runs, err := store.ListAIRuns(context.Background(), project.ID)
	if err != nil || len(runs) != 1 || runs[0].Purpose != "marketplace-recommendation" || runs[0].RedactionCount < 1 {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}

	w = apiRequest(t, s.Handler(), http.MethodPost, "/api/v1/marketplace/recommendations", body, headers)
	if w.Code != http.StatusOK || calls != 1 || !strings.Contains(w.Body.String(), `"idempotentReplay":true`) {
		t.Fatalf("replay=%d calls=%d body=%s", w.Code, calls, w.Body.String())
	}
}
