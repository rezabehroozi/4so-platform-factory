package controlplane

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func testDigest(n int) string { return fmt.Sprintf("sha256:%064x", n) }

func refreshClusterTaskInventoryAt(t *testing.T, store *MemoryStore, ctx context.Context, clusterID, agentTokenDigest string, observedAt time.Time) ManagedCluster {
	t.Helper()
	store.mu.RLock()
	inv, ok := store.clusterInventories[clusterID]
	cluster := store.managedClusters[clusterID]
	if ok {
		inv = cloneClusterInventory(inv)
	}
	store.mu.RUnlock()
	if !ok {
		t.Fatalf("cluster inventory %s not found", clusterID)
	}
	inv.ObservedAt = observedAt
	cluster, _, err := store.UpsertClusterInventory(ctx, clusterID, agentTokenDigest, cluster.ExternalUID, inv)
	if err != nil {
		t.Fatalf("refresh cluster task inventory: %v", err)
	}
	return cluster
}

func seedFleetCluster(t *testing.T, store *MemoryStore, project Project, name string, n int) (ManagedCluster, string, BaselineDeployment) {
	t.Helper()
	ctx := context.Background()
	now := nowUTC(store.now)
	importToken := testDigest(100 + n)
	agentToken := testDigest(200 + n)
	imp, err := store.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: name, DisplayName: name, TokenDigest: importToken, ExpiresAt: now.Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, importToken, agentToken, "uid-"+name, "0.0.14")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agentToken, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "1.31.0", Digest: testDigest(250 + n)})
	if err != nil {
		t.Fatal(err)
	}
	desired := testDigest(300 + n)
	dep, _, err := store.CreateBaselineDeployment(ctx, BaselineDeployment{ProjectID: project.ID, ClusterID: cluster.ID, BaselineID: "secure-namespace-foundation", BaselineVersion: "1.0.0", TargetNamespace: "4so-platform-baseline", Risk: "medium", DesiredDigest: desired, RequestDigest: testDigest(400 + n), IdempotencyKey: "baseline-" + name}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	planClaim, err := store.NextBaselineTask(ctx, cluster.ID, agentToken)
	if err != nil {
		t.Fatal(err)
	}
	planned, err := store.ReportBaselineTask(ctx, cluster.ID, agentToken, planClaim.Revision, BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: true, ObservedDigest: "", Impact: testPlanningImpact(cluster.InventoryDigest, dep.ID), Changes: []BaselinePlanChange{{Resource: "ConfigMap/4so-baseline-revision", Action: "ADD", Desired: desired}}, TaskFenceToken: planClaim.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.ApproveBaselineDeployment(ctx, dep.ID, planned.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.NextBaselineTask(ctx, cluster.ID, agentToken)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.State != BaselineDeploymentApplying || claimed.Revision <= approved.Revision {
		t.Fatalf("unexpected claimed deployment %#v", claimed)
	}
	applied, err := store.ReportBaselineTask(ctx, cluster.ID, agentToken, claimed.Revision, BaselineTaskResult{DeploymentID: dep.ID, Action: "APPLY", Success: true, ObservedDigest: desired, Evidence: testCollectedBaselineEvidence(planned.PlanImpact.Evidence), TaskFenceToken: claimed.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	return cluster, agentToken, applied
}

func TestFleetGroupDriftAndUpgradeAuthority(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "acme", DisplayName: "Acme"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	c1, token1, b1 := seedFleetCluster(t, store, project, "edge-a", 1)
	c2, token2, b2 := seedFleetCluster(t, store, project, "edge-b", 2)

	group, replay, err := store.CreateFleetGroup(ctx, FleetGroup{ProjectID: project.ID, Name: "production", DisplayName: "Production fleet", ClusterIDs: []string{c2.ID, c1.ID}, IdempotencyKey: "fleet-1", RequestDigest: testDigest(500)}, "operator")
	if err != nil || replay {
		t.Fatalf("group err=%v replay=%v", err, replay)
	}
	if len(group.ClusterIDs) != 2 || group.ClusterIDs[0] > group.ClusterIDs[1] {
		t.Fatalf("clusters not normalized: %#v", group.ClusterIDs)
	}

	scan, replay, err := store.CreateDriftScan(ctx, DriftScan{ProjectID: project.ID, FleetGroupID: group.ID, Targets: []DriftScanTarget{{ClusterID: c1.ID, BaselineDeploymentID: b1.ID, BaselineID: b1.BaselineID, BaselineVersion: b1.BaselineVersion, DesiredDigest: b1.DesiredDigest}, {ClusterID: c2.ID, BaselineDeploymentID: b2.ID, BaselineID: b2.BaselineID, BaselineVersion: b2.BaselineVersion, DesiredDigest: b2.DesiredDigest}}, IdempotencyKey: "drift-1", RequestDigest: testDigest(501)}, "operator")
	if err != nil || replay {
		t.Fatalf("scan err=%v replay=%v", err, replay)
	}
	claimed, target, err := store.NextDriftTask(ctx, c1.ID, token1)
	if err != nil || target.State != DriftTargetRunning {
		t.Fatalf("claim drift: %#v %v", target, err)
	}
	result, err := store.ReportDriftTask(ctx, c1.ID, token1, claimed.Revision, DriftTaskResult{ScanID: scan.ID, ClusterID: c1.ID, Success: true, ObservedDigest: b1.DesiredDigest, Changes: []BaselinePlanChange{{Resource: "ConfigMap/4so-baseline-revision", Action: "NOOP"}}})
	if err != nil || result.State != DriftScanRunning {
		t.Fatalf("first drift result: %#v %v", result, err)
	}
	claimed, _, err = store.NextDriftTask(ctx, c2.ID, token2)
	if err != nil {
		t.Fatal(err)
	}
	result, err = store.ReportDriftTask(ctx, c2.ID, token2, claimed.Revision, DriftTaskResult{ScanID: scan.ID, ClusterID: c2.ID, Success: true, ObservedDigest: "", Changes: []BaselinePlanChange{{Resource: "ConfigMap/4so-baseline-revision", Action: "ADD", Desired: b2.DesiredDigest}}})
	if err != nil || result.State != DriftScanDrifted {
		t.Fatalf("final drift result: %#v %v", result, err)
	}

	now := time.Now().UTC()
	cp1, err := store.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: c1.ID, Provider: "s3", Reference: "backup-edge-a", EvidenceDigest: testDigest(601), CompletedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	cp2, err := store.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: c2.ID, Provider: "s3", Reference: "backup-edge-b", EvidenceDigest: testDigest(602), CompletedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	campaign, replay, err := store.CreateUpgradeCampaign(ctx, UpgradeCampaign{ProjectID: project.ID, FleetGroupID: group.ID, BaselineID: "secure-namespace-foundation", TargetVersion: "1.1.0", CanaryCount: 1, WaveSize: 1, HaltAfterFailures: 1, Targets: []UpgradeCampaignTarget{{ClusterID: c1.ID, Wave: 1, State: UpgradeTargetPending, PreviousBaselineDeploymentID: b1.ID, PreviousVersion: b1.BaselineVersion, PreviousDigest: b1.DesiredDigest}, {ClusterID: c2.ID, Wave: 2, State: UpgradeTargetPending, PreviousBaselineDeploymentID: b2.ID, PreviousVersion: b2.BaselineVersion, PreviousDigest: b2.DesiredDigest}}, IdempotencyKey: "campaign-1", RequestDigest: testDigest(502), MaintenanceWindowStart: now.Add(-time.Minute), MaintenanceWindowEnd: now.Add(2 * time.Hour), RecoveryCheckpointIDs: []string{cp1.ID, cp2.ID}}, "operator")
	if err != nil || replay || campaign.State != UpgradeCampaignAwaitingApproval {
		t.Fatalf("campaign: %#v %v", campaign, err)
	}
	campaign, err = store.ApproveUpgradeCampaign(ctx, campaign.ID, campaign.Revision, "approver")
	if err != nil || campaign.State != UpgradeCampaignQueued {
		t.Fatalf("approve: %#v %v", campaign, err)
	}
	campaign.State = UpgradeCampaignRunning
	campaign.CurrentWave = 1
	campaign.Targets[0].State = UpgradeTargetPlanning
	campaign, err = store.UpdateUpgradeCampaign(ctx, campaign, campaign.Revision, "controller")
	if err != nil || campaign.Revision < 3 {
		t.Fatalf("update: %#v %v", campaign, err)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.FleetGroups) != 1 || len(snapshot.DriftScans) != 1 || len(snapshot.UpgradeCampaigns) != 1 {
		t.Fatalf("snapshot missing fleet data: %#v", snapshot)
	}
}
