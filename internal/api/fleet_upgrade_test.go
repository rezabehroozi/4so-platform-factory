package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"platform.4so.io/factory/internal/baseline"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
	"testing"
	"time"
)

func seedAPICluster(t *testing.T, store *controlplane.MemoryStore, project controlplane.Project, name string, n int) (controlplane.ManagedCluster, string, controlplane.BaselineDeployment) {
	t.Helper()
	ctx := context.Background()
	enrollment := fmt.Sprintf("enrollment-token-%d-abcdefghijklmnopqrstuvwxyz", n)
	agentToken := fmt.Sprintf("agent-token-%d-abcdefghijklmnopqrstuvwxyz", n)
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: name, DisplayName: name, TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agentToken), "uid-"+name, "0.0.14")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, controlplane.ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}, KubernetesVersion: "1.31.0", Digest: fmt.Sprintf("sha256:%064x", 900+n)})
	if err != nil {
		t.Fatal(err)
	}
	desired, err := baseline.DesiredDigestVersion(project.ID, cluster.ID, baseline.SecureNamespaceID, baseline.SecureNamespaceVersion)
	if err != nil {
		t.Fatal(err)
	}
	dep, _, err := store.CreateBaselineDeployment(ctx, controlplane.BaselineDeployment{ProjectID: project.ID, ClusterID: cluster.ID, BaselineID: baseline.SecureNamespaceID, BaselineVersion: baseline.SecureNamespaceVersion, TargetNamespace: baseline.ManagedNamespace, Risk: "medium", DesiredDigest: desired, RequestDigest: fmt.Sprintf("sha256:%064x", 1000+n), IdempotencyKey: "seed-baseline-" + name}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	planClaim, err := store.NextBaselineTask(ctx, cluster.ID, credentialDigest(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	planned, err := store.ReportBaselineTask(ctx, cluster.ID, credentialDigest(agentToken), planClaim.Revision, controlplane.BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: true, Impact: apiTestPlanningImpact(cluster.InventoryDigest), Changes: []controlplane.BaselinePlanChange{{Resource: "ConfigMap/4so-baseline-revision", Action: "ADD", Desired: desired}}, TaskFenceToken: planClaim.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ApproveBaselineDeployment(ctx, dep.ID, planned.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.NextBaselineTask(ctx, cluster.ID, credentialDigest(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	applied, err := store.ReportBaselineTask(ctx, cluster.ID, credentialDigest(agentToken), claimed.Revision, controlplane.BaselineTaskResult{DeploymentID: dep.ID, Action: "APPLY", Success: true, ObservedDigest: desired, Evidence: apiTestCollectedBaselineEvidence(claimed.PlanImpact.Evidence, dep.ID), TaskFenceToken: claimed.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	return cluster, agentToken, applied
}

func apiRequest(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeBody[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %d body %q: %v", w.Code, w.Body.String(), err)
	}
	return v
}

func completeCampaignTarget(t *testing.T, h http.Handler, store *controlplane.MemoryStore, campaign *controlplane.UpgradeCampaign, cluster controlplane.ManagedCluster, rawToken string) {
	t.Helper()
	advance := func() {
		w := apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/advance", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
		if w.Code != http.StatusOK {
			t.Fatalf("advance %d: %s", w.Code, w.Body.String())
		}
		*campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	}
	advance() // create upgrade deployment
	var target *controlplane.UpgradeCampaignTarget
	for i := range campaign.Targets {
		if campaign.Targets[i].ClusterID == cluster.ID {
			target = &campaign.Targets[i]
			break
		}
	}
	if target == nil || target.UpgradeDeploymentID == "" {
		t.Fatalf("upgrade target not created: %#v", campaign.Targets)
	}
	dep, err := store.NextBaselineTask(context.Background(), cluster.ID, credentialDigest(rawToken))
	if err != nil || dep.State != controlplane.BaselineDeploymentPlanning {
		t.Fatalf("plan task: %#v %v", dep, err)
	}
	planned, err := store.ReportBaselineTask(context.Background(), cluster.ID, credentialDigest(rawToken), dep.Revision, controlplane.BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: true, ObservedDigest: target.PreviousDigest, Impact: apiTestPlanningImpact(cluster.InventoryDigest), Changes: []controlplane.BaselinePlanChange{{Resource: "ResourceQuota/4so-baseline-quota", Action: "UPDATE", Current: target.PreviousDigest, Desired: dep.DesiredDigest}}, TaskFenceToken: dep.TaskFenceToken})
	if err != nil || planned.State != controlplane.BaselineDeploymentAwaitingApproval {
		t.Fatalf("report plan: %#v %v", planned, err)
	}
	advance() // auto approve
	dep, err = store.NextBaselineTask(context.Background(), cluster.ID, credentialDigest(rawToken))
	if err != nil || dep.State != controlplane.BaselineDeploymentApplying {
		t.Fatalf("apply task: %#v %v", dep, err)
	}
	applied, err := store.ReportBaselineTask(context.Background(), cluster.ID, credentialDigest(rawToken), dep.Revision, controlplane.BaselineTaskResult{DeploymentID: dep.ID, Action: "APPLY", Success: true, ObservedDigest: dep.DesiredDigest, Evidence: apiTestCollectedBaselineEvidence(dep.PlanImpact.Evidence, dep.ID), TaskFenceToken: dep.TaskFenceToken})
	if err != nil || applied.State != controlplane.BaselineDeploymentSucceeded {
		t.Fatalf("report apply: %#v %v", applied, err)
	}
	advance() // create verification
	for i := range campaign.Targets {
		if campaign.Targets[i].ClusterID == cluster.ID {
			target = &campaign.Targets[i]
		}
	}
	if target.RuntimeVerificationID == "" {
		t.Fatalf("verification missing: %#v", *target)
	}
	verify, err := store.NextRuntimeVerificationTask(context.Background(), cluster.ID, credentialDigest(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	checks := []controlplane.RuntimeCheck{{Key: "baseline-digest-equality", Status: "PASS"}, {Key: "baseline-resources-present", Status: "PASS"}, {Key: "nodes-ready", Status: "PASS"}, {Key: "probe-job-created", Status: "PASS"}, {Key: "probe-job-completed", Status: "PASS"}, {Key: "cluster-dns", Status: "PASS"}, {Key: "kubernetes-api-service-tcp", Status: "PASS"}}
	verified, err := store.ReportRuntimeVerificationTask(context.Background(), cluster.ID, credentialDigest(rawToken), verify.Revision, controlplane.RuntimeVerificationResult{VerificationID: verify.ID, Success: true, ObservedDigest: verify.DesiredDigest, Checks: checks, TaskFenceToken: verify.TaskFenceToken})
	if err != nil || verified.State != controlplane.RuntimeVerificationSucceeded {
		t.Fatalf("verify: %#v %v", verified, err)
	}
	advance() // mark target succeeded / next wave
}

func TestFleetDriftAndCanaryUpgradeRoutes(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "acme", DisplayName: "Acme"}, "operator")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	c1, token1, b1 := seedAPICluster(t, store, project, "edge-a", 1)
	c2, token2, b2 := seedAPICluster(t, store, project, "edge-b", 2)
	s := New("0.0.14", nil, nil, store)
	s.ConfigureFleetImport("registry.test/platform-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "registry.test/platform-probe@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "https://platform.example.test", "")
	h := s.Handler()

	body := fmt.Sprintf(`{"projectId":%q,"name":"production","displayName":"Production","clusterIds":[%q,%q]}`, project.ID, c1.ID, c2.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/fleet-groups", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "fleet-web-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("group %d: %s", w.Code, w.Body.String())
	}
	var groupBody struct {
		FleetGroup controlplane.FleetGroup `json:"fleetGroup"`
	}
	groupBody = decodeBody[struct {
		FleetGroup controlplane.FleetGroup `json:"fleetGroup"`
	}](t, w)

	body = fmt.Sprintf(`{"projectId":%q,"fleetGroupId":%q}`, project.ID, groupBody.FleetGroup.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/drift-scans", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "drift-web-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("drift %d: %s", w.Code, w.Body.String())
	}
	var driftBody struct {
		DriftScan controlplane.DriftScan `json:"driftScan"`
	}
	driftBody = decodeBody[struct {
		DriftScan controlplane.DriftScan `json:"driftScan"`
	}](t, w)
	// Cluster 1 is in sync.
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+c1.ID+"/drift-tasks/next", "", map[string]string{"Authorization": "Bearer " + token1})
	if w.Code != 200 {
		t.Fatalf("drift task1 %d: %s", w.Code, w.Body.String())
	}
	task1 := decodeBody[controlplane.DriftTask](t, w)
	body = fmt.Sprintf(`{"clusterId":%q,"success":true,"observedDigest":%q,"changes":[{"resource":"ConfigMap/4so-baseline-revision","action":"NOOP","desiredDigest":%q}]}`, c1.ID, b1.DesiredDigest, b1.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+c1.ID+"/drift-tasks/"+driftBody.DriftScan.ID+"/result", body, map[string]string{"Authorization": "Bearer " + token1, "If-Match": fmt.Sprintf("\"%d\"", task1.ScanRevision)})
	if w.Code != 200 {
		t.Fatalf("drift result1 %d: %s", w.Code, w.Body.String())
	}
	// Cluster 2 is drifted.
	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+c2.ID+"/drift-tasks/next", "", map[string]string{"Authorization": "Bearer " + token2})
	task2 := decodeBody[controlplane.DriftTask](t, w)
	body = fmt.Sprintf(`{"clusterId":%q,"success":true,"observedDigest":"","changes":[{"resource":"ConfigMap/4so-baseline-revision","action":"ADD","desiredDigest":%q}]}`, c2.ID, b2.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+c2.ID+"/drift-tasks/"+driftBody.DriftScan.ID+"/result", body, map[string]string{"Authorization": "Bearer " + token2, "If-Match": fmt.Sprintf("\"%d\"", task2.ScanRevision)})
	if w.Code != 200 {
		t.Fatalf("drift result2 %d: %s", w.Code, w.Body.String())
	}
	drift := decodeBody[controlplane.DriftScan](t, w)
	if drift.State != controlplane.DriftScanDrifted {
		t.Fatalf("drift state %#v", drift)
	}
	var remediationFinding *controlplane.DriftFinding
	versionFindingSeen := false
	for _, target := range drift.Targets {
		if target.Comparison == nil || target.Comparison.ProductGeneratedDigest == "" {
			t.Fatalf("drift comparison missing for target %#v", target)
		}
		for i := range target.Findings {
			finding := &target.Findings[i]
			if finding.Category == "VERSION" && finding.Code == "KUBERNETES_EOL" && finding.Owner == "cluster-admin" {
				versionFindingSeen = true
			}
			if target.ClusterID == c2.ID && finding.Remediation.Mode == "OPERATION" && finding.Remediation.Eligible {
				copy := *finding
				remediationFinding = &copy
			}
		}
	}
	if !versionFindingSeen || remediationFinding == nil || remediationFinding.Fingerprint == "" || remediationFinding.FirstSeenAt.IsZero() || remediationFinding.LastSeenAt.IsZero() || remediationFinding.Occurrences != 1 {
		t.Fatalf("unified drift findings incomplete: version=%v remediation=%#v", versionFindingSeen, remediationFinding)
	}
	remediationPath := fmt.Sprintf("/api/v1/drift-scans/%s/targets/%s/findings/%s/remediate", drift.ID, c2.ID, remediationFinding.Fingerprint)
	w = apiRequest(t, h, http.MethodPost, remediationPath, "", map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "drift-remediation-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("remediation %d: %s", w.Code, w.Body.String())
	}
	remediation := decodeBody[struct {
		Operation        controlplane.Operation `json:"operation"`
		IdempotentReplay bool                   `json:"idempotentReplay"`
	}](t, w)
	if remediation.Operation.State != controlplane.OperationQueued || remediation.Operation.Class != controlplane.OperationClassMutating || remediation.IdempotentReplay || !strings.HasPrefix(remediation.Operation.TargetRef, "drift-finding:"+drift.ID+":") {
		t.Fatalf("remediation operation %#v", remediation)
	}
	w = apiRequest(t, h, http.MethodPost, remediationPath, "", map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "drift-remediation-1"})
	if w.Code != http.StatusOK {
		t.Fatalf("remediation replay %d: %s", w.Code, w.Body.String())
	}
	replayed := decodeBody[struct {
		Operation        controlplane.Operation `json:"operation"`
		IdempotentReplay bool                   `json:"idempotentReplay"`
	}](t, w)
	if !replayed.IdempotentReplay || replayed.Operation.ID != remediation.Operation.ID {
		t.Fatalf("remediation replay mismatch %#v", replayed)
	}

	now := time.Now().UTC()
	cp1, err := store.CreateRecoveryCheckpoint(ctx, controlplane.RecoveryCheckpoint{ProjectID: project.ID, ClusterID: c1.ID, Provider: "s3", Reference: "backup-a", EvidenceDigest: fmt.Sprintf("sha256:%064x", 2101), CompletedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	cp2, err := store.CreateRecoveryCheckpoint(ctx, controlplane.RecoveryCheckpoint{ProjectID: project.ID, ClusterID: c2.ID, Provider: "s3", Reference: "backup-b", EvidenceDigest: fmt.Sprintf("sha256:%064x", 2102), CompletedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	body = fmt.Sprintf(`{"projectId":%q,"fleetGroupId":%q,"baselineId":"secure-namespace-foundation","targetVersion":"1.1.0","canaryCount":1,"waveSize":1,"haltAfterFailures":1,"maintenanceWindowStart":%q,"maintenanceWindowEnd":%q,"recoveryCheckpointIds":[%q,%q]}`, project.ID, groupBody.FleetGroup.ID, now.Add(-time.Minute).Format(time.RFC3339), now.Add(2*time.Hour).Format(time.RFC3339), cp1.ID, cp2.ID)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "campaign-web-1"})
	if w.Code != 201 {
		t.Fatalf("campaign %d: %s", w.Code, w.Body.String())
	}
	var campaignBody struct {
		Campaign controlplane.UpgradeCampaign `json:"campaign"`
	}
	campaignBody = decodeBody[struct {
		Campaign controlplane.UpgradeCampaign `json:"campaign"`
	}](t, w)
	campaign := campaignBody.Campaign
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != 200 {
		t.Fatalf("approve campaign %d: %s", w.Code, w.Body.String())
	}
	campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	// Stable sorting makes c1/c2 wave assignment deterministic by ID, not by seed order.
	wave1 := campaign.Targets[0]
	wave2 := campaign.Targets[1]
	var firstCluster, secondCluster controlplane.ManagedCluster
	var firstToken, secondToken string
	if wave1.ClusterID == c1.ID {
		firstCluster, firstToken = c1, token1
		secondCluster, secondToken = c2, token2
	} else {
		firstCluster, firstToken = c2, token2
		secondCluster, secondToken = c1, token1
	}
	completeCampaignTarget(t, h, store, &campaign, firstCluster, firstToken)
	if campaign.CurrentWave != 2 || campaign.State != controlplane.UpgradeCampaignRunning {
		t.Fatalf("canary did not advance: %#v", campaign)
	}
	_ = wave2
	completeCampaignTarget(t, h, store, &campaign, secondCluster, secondToken)
	if campaign.State != controlplane.UpgradeCampaignSucceeded {
		t.Fatalf("campaign not succeeded: %#v", campaign)
	}
}

func TestUpgradeCampaignHaltsAndReappliesPreviousRevision(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "rollback-org", DisplayName: "Rollback Org"}, "operator")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "rollback", DisplayName: "Rollback"}, "operator")
	cluster, rawToken, previous := seedAPICluster(t, store, project, "rollback-edge", 9)
	s := New("0.0.14", nil, nil, store)
	s.ConfigureFleetImport("registry.test/platform-agent@sha256:"+strings.Repeat("a", 64), "registry.test/platform-probe@sha256:"+strings.Repeat("b", 64), "https://platform.example.test", "")
	h := s.Handler()
	group, _, err := store.CreateFleetGroup(ctx, controlplane.FleetGroup{ProjectID: project.ID, Name: "rollback-fleet", DisplayName: "Rollback Fleet", ClusterIDs: []string{cluster.ID}, IdempotencyKey: "rollback-fleet", RequestDigest: "sha256:" + strings.Repeat("c", 64)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cp, err := store.CreateRecoveryCheckpoint(ctx, controlplane.RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "rollback-backup", EvidenceDigest: "sha256:" + strings.Repeat("d", 64), CompletedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"projectId":%q,"fleetGroupId":%q,"baselineId":"secure-namespace-foundation","targetVersion":"1.1.0","canaryCount":1,"waveSize":1,"haltAfterFailures":1,"maintenanceWindowStart":%q,"maintenanceWindowEnd":%q,"recoveryCheckpointIds":[%q]}`, project.ID, group.ID, now.Add(-time.Minute).Format(time.RFC3339), now.Add(2*time.Hour).Format(time.RFC3339), cp.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "rollback-campaign"})
	var created struct {
		Campaign controlplane.UpgradeCampaign `json:"campaign"`
	}
	created = decodeBody[struct {
		Campaign controlplane.UpgradeCampaign `json:"campaign"`
	}](t, w)
	campaign := created.Campaign
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	advance := func() {
		w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/advance", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
		if w.Code != http.StatusOK {
			t.Fatalf("advance %d: %s", w.Code, w.Body.String())
		}
		campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	}
	advance()
	upgrade, err := store.NextBaselineTask(ctx, cluster.ID, credentialDigest(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	planned, err := store.ReportBaselineTask(ctx, cluster.ID, credentialDigest(rawToken), upgrade.Revision, controlplane.BaselineTaskResult{DeploymentID: upgrade.ID, Action: "PLAN", Success: true, ObservedDigest: previous.DesiredDigest, Impact: apiTestPlanningImpact(cluster.InventoryDigest), Changes: []controlplane.BaselinePlanChange{{Resource: "ResourceQuota/4so-baseline-quota", Action: "UPDATE", Current: previous.DesiredDigest, Desired: upgrade.DesiredDigest}}, TaskFenceToken: upgrade.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	_ = planned
	advance()
	upgrade, err = store.NextBaselineTask(ctx, cluster.ID, credentialDigest(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ReportBaselineTask(ctx, cluster.ID, credentialDigest(rawToken), upgrade.Revision, controlplane.BaselineTaskResult{DeploymentID: upgrade.ID, Action: "APPLY", Success: false, Error: "simulated rollout failure", TaskFenceToken: upgrade.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	advance()
	if campaign.State != controlplane.UpgradeCampaignHalted || campaign.Targets[0].State != controlplane.UpgradeTargetRollingBack || campaign.Targets[0].RollbackDeploymentID == "" {
		t.Fatalf("campaign did not halt and begin rollback: %#v", campaign)
	}
	rollback, err := store.NextBaselineTask(ctx, cluster.ID, credentialDigest(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	if rollback.BaselineVersion != baseline.SecureNamespaceVersion {
		t.Fatalf("rollback version=%s", rollback.BaselineVersion)
	}
	_, err = store.ReportBaselineTask(ctx, cluster.ID, credentialDigest(rawToken), rollback.Revision, controlplane.BaselineTaskResult{DeploymentID: rollback.ID, Action: "PLAN", Success: true, ObservedDigest: upgrade.DesiredDigest, Impact: apiTestPlanningImpact(cluster.InventoryDigest), Changes: []controlplane.BaselinePlanChange{{Resource: "ResourceQuota/4so-baseline-quota", Action: "UPDATE", Current: upgrade.DesiredDigest, Desired: rollback.DesiredDigest}}, TaskFenceToken: rollback.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	advance()
	rollback, err = store.NextBaselineTask(ctx, cluster.ID, credentialDigest(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ReportBaselineTask(ctx, cluster.ID, credentialDigest(rawToken), rollback.Revision, controlplane.BaselineTaskResult{DeploymentID: rollback.ID, Action: "APPLY", Success: true, ObservedDigest: rollback.DesiredDigest, Evidence: apiTestCollectedBaselineEvidence(rollback.PlanImpact.Evidence, rollback.ID), TaskFenceToken: rollback.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	advance()
	verification, err := store.NextRuntimeVerificationTask(ctx, cluster.ID, credentialDigest(rawToken))
	if err != nil {
		t.Fatal(err)
	}
	checks := []controlplane.RuntimeCheck{{Key: "baseline-digest-equality", Status: "PASS"}, {Key: "baseline-resources-present", Status: "PASS"}, {Key: "nodes-ready", Status: "PASS"}, {Key: "probe-job-created", Status: "PASS"}, {Key: "probe-job-completed", Status: "PASS"}, {Key: "cluster-dns", Status: "PASS"}, {Key: "kubernetes-api-service-tcp", Status: "PASS"}}
	_, err = store.ReportRuntimeVerificationTask(ctx, cluster.ID, credentialDigest(rawToken), verification.Revision, controlplane.RuntimeVerificationResult{VerificationID: verification.ID, Success: true, ObservedDigest: verification.DesiredDigest, Checks: checks, TaskFenceToken: verification.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	advance()
	if campaign.State != controlplane.UpgradeCampaignHalted || campaign.Targets[0].State != controlplane.UpgradeTargetRolledBack {
		t.Fatalf("rollback not completed: %#v", campaign)
	}
}

func TestUpgradeCampaignPauseResumeAndBoundedCancelAtSafePoints(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "control-org", DisplayName: "Control Org"}, "operator")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "control-project", DisplayName: "Control Project"}, "operator")
	c1, token1, _ := seedAPICluster(t, store, project, "control-a", 31)
	c2, token2, _ := seedAPICluster(t, store, project, "control-b", 32)
	c3, token3, _ := seedAPICluster(t, store, project, "control-c", 33)
	s := New("0.0.46", nil, nil, store)
	s.ConfigureFleetImport("registry.test/platform-agent@sha256:"+strings.Repeat("a", 64), "registry.test/platform-probe@sha256:"+strings.Repeat("b", 64), "https://platform.example.test", "")
	h := s.Handler()
	group, _, err := store.CreateFleetGroup(ctx, controlplane.FleetGroup{ProjectID: project.ID, Name: "control-fleet", DisplayName: "Control Fleet", ClusterIDs: []string{c1.ID, c2.ID, c3.ID}, IdempotencyKey: "control-fleet", RequestDigest: "sha256:" + strings.Repeat("e", 64)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	clusters := []controlplane.ManagedCluster{c1, c2, c3}
	tokens := map[string]string{c1.ID: token1, c2.ID: token2, c3.ID: token3}
	checkpoints := make([]string, 0, 3)
	for i, cluster := range clusters {
		cp, e := store.CreateRecoveryCheckpoint(ctx, controlplane.RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: fmt.Sprintf("control-backup-%d", i+1), EvidenceDigest: fmt.Sprintf("sha256:%064x", 9300+i), CompletedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "operator")
		if e != nil {
			t.Fatal(e)
		}
		checkpoints = append(checkpoints, cp.ID)
	}
	body := fmt.Sprintf(`{"projectId":%q,"fleetGroupId":%q,"baselineId":"secure-namespace-foundation","targetVersion":"1.1.0","canaryCount":1,"waveSize":1,"haltAfterFailures":1,"maintenanceWindowStart":%q,"maintenanceWindowEnd":%q,"recoveryCheckpointIds":[%q,%q,%q]}`, project.ID, group.ID, now.Add(-time.Minute).Format(time.RFC3339), now.Add(2*time.Hour).Format(time.RFC3339), checkpoints[0], checkpoints[1], checkpoints[2])
	w := apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "control-campaign"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create %d: %s", w.Code, w.Body.String())
	}
	created := decodeBody[struct {
		Campaign controlplane.UpgradeCampaign `json:"campaign"`
	}](t, w)
	campaign := created.Campaign
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/approve", `{}`, map[string]string{"X-Actor-ID": "approver", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != 200 {
		t.Fatalf("approve %d: %s", w.Code, w.Body.String())
	}
	campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	advance := func() {
		w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/advance", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
		if w.Code != 200 {
			t.Fatalf("advance %d: %s", w.Code, w.Body.String())
		}
		campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	}
	completeActive := func(clusterID string) {
		raw := tokens[clusterID]
		dep, e := store.NextBaselineTask(ctx, clusterID, credentialDigest(raw))
		if e != nil {
			t.Fatal(e)
		}
		managed, e := store.GetManagedCluster(ctx, clusterID)
		if e != nil {
			t.Fatal(e)
		}
		planned, e := store.ReportBaselineTask(ctx, clusterID, credentialDigest(raw), dep.Revision, controlplane.BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: true, Impact: apiTestPlanningImpact(managed.InventoryDigest), Changes: []controlplane.BaselinePlanChange{{Resource: "ResourceQuota/4so-baseline-quota", Action: "UPDATE", Desired: dep.DesiredDigest}}, TaskFenceToken: dep.TaskFenceToken})
		if e != nil {
			t.Fatal(e)
		}
		_ = planned
		advance()
		dep, e = store.NextBaselineTask(ctx, clusterID, credentialDigest(raw))
		if e != nil {
			t.Fatal(e)
		}
		_, e = store.ReportBaselineTask(ctx, clusterID, credentialDigest(raw), dep.Revision, controlplane.BaselineTaskResult{DeploymentID: dep.ID, Action: "APPLY", Success: true, ObservedDigest: dep.DesiredDigest, Evidence: apiTestCollectedBaselineEvidence(dep.PlanImpact.Evidence, dep.ID), TaskFenceToken: dep.TaskFenceToken})
		if e != nil {
			t.Fatal(e)
		}
		advance()
		verification, e := store.NextRuntimeVerificationTask(ctx, clusterID, credentialDigest(raw))
		if e != nil {
			t.Fatal(e)
		}
		checks := []controlplane.RuntimeCheck{{Key: "baseline-digest-equality", Status: "PASS"}, {Key: "baseline-resources-present", Status: "PASS"}, {Key: "nodes-ready", Status: "PASS"}, {Key: "probe-job-created", Status: "PASS"}, {Key: "probe-job-completed", Status: "PASS"}, {Key: "cluster-dns", Status: "PASS"}, {Key: "kubernetes-api-service-tcp", Status: "PASS"}}
		_, e = store.ReportRuntimeVerificationTask(ctx, clusterID, credentialDigest(raw), verification.Revision, controlplane.RuntimeVerificationResult{VerificationID: verification.ID, Success: true, ObservedDigest: verification.DesiredDigest, Checks: checks, TaskFenceToken: verification.TaskFenceToken})
		if e != nil {
			t.Fatal(e)
		}
		advance()
	}

	advance() // starts wave 1
	wave1 := campaign.Targets[0]
	if wave1.State != controlplane.UpgradeTargetPlanning {
		t.Fatalf("wave1 not active: %#v", wave1)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/pause", `{"reason":"change window check"}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != 200 {
		t.Fatalf("pause %d: %s", w.Code, w.Body.String())
	}
	campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	if campaign.State != controlplane.UpgradeCampaignPauseRequested {
		t.Fatalf("pause state=%s", campaign.State)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/pause", `{"reason":"duplicate pause must not overwrite"}`, map[string]string{"X-Actor-ID": "second-operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate pause should conflict, got %d: %s", w.Code, w.Body.String())
	}
	completeActive(wave1.ClusterID)
	if campaign.State != controlplane.UpgradeCampaignPaused || campaign.CurrentWave != 1 || campaign.PauseCount != 1 || campaign.StartedAt == nil {
		t.Fatalf("not safely paused: %#v", campaign)
	}
	startedAt := *campaign.StartedAt
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/resume", `{}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != 200 {
		t.Fatalf("resume %d: %s", w.Code, w.Body.String())
	}
	campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	if campaign.State != controlplane.UpgradeCampaignQueued || campaign.CurrentWave != 1 || campaign.StartedAt == nil || !campaign.StartedAt.Equal(startedAt) {
		t.Fatalf("resume reset progress: %#v", campaign)
	}
	advance() // closes completed wave 1 and selects wave 2
	if campaign.CurrentWave != 2 {
		t.Fatalf("resume did not preserve next wave: %#v", campaign)
	}
	advance() // starts wave 2
	wave2 := campaign.Targets[1]
	if wave2.State != controlplane.UpgradeTargetPlanning {
		t.Fatalf("wave2 not active: %#v", wave2)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/cancel", `{"reason":"operator bounded cancel"}`, map[string]string{"X-Actor-ID": "operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != 200 {
		t.Fatalf("cancel %d: %s", w.Code, w.Body.String())
	}
	campaign = decodeBody[controlplane.UpgradeCampaign](t, w)
	if campaign.State != controlplane.UpgradeCampaignCancelRequested {
		t.Fatalf("cancel state=%s", campaign.State)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/upgrade-campaigns/"+campaign.ID+"/cancel", `{"reason":"duplicate cancel must not overwrite"}`, map[string]string{"X-Actor-ID": "second-operator", "If-Match": fmt.Sprintf("\"%d\"", campaign.Revision)})
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate cancel should conflict, got %d: %s", w.Code, w.Body.String())
	}
	completeActive(wave2.ClusterID)
	if campaign.State != controlplane.UpgradeCampaignCancelled || campaign.CancelledAt == nil || campaign.FinishedAt == nil {
		t.Fatalf("campaign not cancelled at safe point: %#v", campaign)
	}
	if campaign.Targets[0].State != controlplane.UpgradeTargetSucceeded || campaign.Targets[1].State != controlplane.UpgradeTargetSucceeded || campaign.Targets[2].State != controlplane.UpgradeTargetPending {
		t.Fatalf("bounded cancel changed wrong targets: %#v", campaign.Targets)
	}
}

func TestDriftRemediationReplayRepairsOperationLeftInDraft(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "repair-org", DisplayName: "Repair Org"}, "operator")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	cluster, token, baselineDep := seedAPICluster(t, store, project, "repair-edge", 31)

	s := New("test", nil, nil, store)
	s.ConfigureFleetImport("registry.test/platform-agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "registry.test/platform-probe@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "https://platform.example.test", "")
	h := s.Handler()

	body := fmt.Sprintf(`{"projectId":%q,"clusterIds":[%q]}`, project.ID, cluster.ID)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/drift-scans", body, map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": "repair-drift-scan"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create drift scan %d: %s", w.Code, w.Body.String())
	}
	drift := decodeBody[struct {
		DriftScan controlplane.DriftScan `json:"driftScan"`
	}](t, w).DriftScan

	w = apiRequest(t, h, http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/drift-tasks/next", "", map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Fatalf("next drift task %d: %s", w.Code, w.Body.String())
	}
	task := decodeBody[controlplane.DriftTask](t, w)
	body = fmt.Sprintf(`{"clusterId":%q,"success":true,"observedDigest":"","changes":[{"resource":"ConfigMap/4so-baseline-revision","action":"ADD","desiredDigest":%q}]}`,
		cluster.ID, baselineDep.DesiredDigest)
	w = apiRequest(t, h, http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/drift-tasks/"+drift.ID+"/result", body, map[string]string{"Authorization": "Bearer " + token, "If-Match": fmt.Sprintf("\"%d\"", task.ScanRevision)})
	if w.Code != http.StatusOK {
		t.Fatalf("drift result %d: %s", w.Code, w.Body.String())
	}
	drift = decodeBody[controlplane.DriftScan](t, w)
	if len(drift.Targets) != 1 {
		t.Fatalf("unexpected targets %#v", drift.Targets)
	}
	var finding *controlplane.DriftFinding
	for i := range drift.Targets[0].Findings {
		candidate := &drift.Targets[0].Findings[i]
		if candidate.Remediation.Mode == "OPERATION" && candidate.Remediation.Eligible {
			finding = candidate
			break
		}
	}
	if finding == nil {
		t.Fatalf("expected executable remediation finding: %#v", drift.Targets[0].Findings)
	}

	key := "repair-drift-remediation"
	action := strings.ToLower(strings.ReplaceAll(finding.Remediation.Action, "_", "-"))
	precreated, replay, err := store.CreateOperation(ctx, controlplane.OperationRequest{
		ProjectID:       project.ID,
		Kind:            "drift.remediate." + action,
		TargetRef:       "drift-finding:" + drift.ID + ":" + cluster.ID + ":" + finding.Fingerprint,
		DesiredRevision: baselineDep.DesiredDigest,
		Risk:            driftRisk(finding.Severity),
		Class:           controlplane.OperationClassMutating,
	}, key, "operator", "lost-response-request")
	if err != nil || replay || precreated.State != controlplane.OperationDraft {
		t.Fatalf("precreate operation replay=%v err=%v op=%#v", replay, err, precreated)
	}

	path := fmt.Sprintf("/api/v1/drift-scans/%s/targets/%s/findings/%s/remediate", drift.ID, cluster.ID, finding.Fingerprint)
	w = apiRequest(t, h, http.MethodPost, path, "", map[string]string{"X-Actor-ID": "operator", "Idempotency-Key": key})
	if w.Code != http.StatusOK {
		t.Fatalf("remediation replay %d: %s", w.Code, w.Body.String())
	}
	got := decodeBody[struct {
		Operation        controlplane.Operation `json:"operation"`
		IdempotentReplay bool                   `json:"idempotentReplay"`
	}](t, w)
	if !got.IdempotentReplay || got.Operation.ID != precreated.ID || got.Operation.State != controlplane.OperationQueued {
		t.Fatalf("replay must repair the same durable operation through QUEUED: %#v", got)
	}
}

func TestConvergeOperationToQueuedToleratesConcurrentStaleRevision(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "queue-race-org", DisplayName: "Queue Race Org"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	op, replay, err := store.CreateOperation(ctx, controlplane.OperationRequest{
		ProjectID:       project.ID,
		Kind:            "drift.remediate.reapply-baseline",
		TargetRef:       "drift-finding:test:cluster:fingerprint",
		DesiredRevision: "sha256:" + strings.Repeat("a", 64),
		Risk:            "medium",
		Class:           controlplane.OperationClassMutating,
	}, "queue-race", "operator", "request")
	if err != nil || replay {
		t.Fatalf("create operation replay=%v err=%v", replay, err)
	}

	s := New("test", nil, nil, store)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		stale := op
		go func(actor string) {
			got, convergeErr := s.convergeOperationToQueued(ctx, stale, actor)
			if convergeErr == nil && got.State != controlplane.OperationQueued {
				convergeErr = fmt.Errorf("unexpected converged state %s", got.State)
			}
			results <- convergeErr
		}(fmt.Sprintf("operator-%d", i))
	}
	for i := 0; i < 2; i++ {
		if err = <-results; err != nil {
			t.Fatalf("concurrent convergence failed: %v", err)
		}
	}
	final, err := store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != controlplane.OperationQueued {
		t.Fatalf("final operation must be queued: %#v", final)
	}
}
