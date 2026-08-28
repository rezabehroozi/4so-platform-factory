package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestBaselinePlanExpiresAndInventoryChangeForcesReplan(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return fmt.Sprintf("%s_%06d", prefix, seq) })
	org, err := store.CreateOrganization(ctx, Organization{Name: "plan-safety", DisplayName: "Plan Safety"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	cluster, agentToken, _ := seedFleetCluster(t, store, project, "plan-edge", 31)

	desired := testDigest(7101)
	dep, _, err := store.CreateBaselineDeployment(ctx, BaselineDeployment{ProjectID: project.ID, ClusterID: cluster.ID, BaselineID: "secure-namespace-foundation", BaselineVersion: "1.1.0", TargetNamespace: "4so-platform-baseline", Risk: "medium", DesiredDigest: desired, RequestDigest: testDigest(7102), IdempotencyKey: "plan-expiry"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	planClaim, err := store.NextBaselineTask(ctx, cluster.ID, agentToken)
	if err != nil {
		t.Fatal(err)
	}
	planned, err := store.ReportBaselineTask(ctx, cluster.ID, agentToken, planClaim.Revision, BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: true, ObservedDigest: testDigest(7100), Impact: testPlanningImpact(cluster.InventoryDigest, dep.ID), Changes: []BaselinePlanChange{{Resource: "ConfigMap/plan", Action: "UPDATE", Desired: desired}}, TaskFenceToken: planClaim.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	if planned.PlanExpiresAt == nil || planned.PlanContextDigest == "" || planned.PlanInventoryDigest == "" {
		t.Fatalf("plan safety context missing: %#v", planned)
	}

	now = now.Add(ExecutionPlanTTL + time.Second)
	if _, err = store.ApproveBaselineDeployment(ctx, dep.ID, planned.Revision, "approver"); !errors.Is(err, ErrPlanStale) {
		t.Fatalf("expected stale plan, got %v", err)
	}
	replanning, err := store.RevalidateBaselineDeployment(ctx, dep.ID, planned.Revision, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if replanning.State != BaselineDeploymentPlanning || replanning.PlanRevalidationCount != 1 || replanning.ApprovedAt != nil {
		t.Fatalf("unexpected revalidation: %#v", replanning)
	}

	cluster = refreshClusterTaskInventoryAt(t, store, ctx, cluster.ID, agentToken, now)
	replanClaim, err := store.NextBaselineTask(ctx, cluster.ID, agentToken)
	if err != nil {
		t.Fatal(err)
	}
	replanned, err := store.ReportBaselineTask(ctx, cluster.ID, agentToken, replanClaim.Revision, BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: true, ObservedDigest: testDigest(7100), Impact: testPlanningImpact(cluster.InventoryDigest, dep.ID), Changes: []BaselinePlanChange{{Resource: "ConfigMap/plan", Action: "UPDATE", Desired: desired}}, TaskFenceToken: replanClaim.TaskFenceToken})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.ApproveBaselineDeployment(ctx, dep.ID, replanned.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agentToken, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "1.31.1", Digest: testDigest(7199)})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := store.NextBaselineTask(ctx, cluster.ID, agentToken)
	if err != nil {
		t.Fatal(err)
	}
	if stale.ID != approved.ID || stale.State != BaselineDeploymentPlanning || stale.PendingAction != "PLAN" || stale.ApprovedAt != nil || stale.PlanRevalidationCount != 2 {
		t.Fatalf("inventory change did not force safe replan: %#v", stale)
	}
}

func TestUpgradeCampaignRequiresCheckpointFreshContextAndOpenWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return fmt.Sprintf("%s_%06d", prefix, seq) })
	org, _ := store.CreateOrganization(ctx, Organization{Name: "upgrade-safety", DisplayName: "Upgrade Safety"}, "operator")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	cluster, agentToken, previous := seedFleetCluster(t, store, project, "upgrade-edge", 41)
	group, _, err := store.CreateFleetGroup(ctx, FleetGroup{ProjectID: project.ID, Name: "prod-fleet", DisplayName: "Production fleet", ClusterIDs: []string{cluster.ID}, IdempotencyKey: "safe-fleet", RequestDigest: testDigest(7201)}, "operator")
	if err != nil {
		t.Fatal(err)
	}

	checkpoint, err := store.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "backup-20260807", EvidenceDigest: testDigest(7202), CompletedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(6 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	target := UpgradeCampaignTarget{ClusterID: cluster.ID, Wave: 1, State: UpgradeTargetPending, PreviousBaselineDeploymentID: previous.ID, PreviousVersion: previous.BaselineVersion, PreviousDigest: previous.DesiredDigest}
	campaign, _, err := store.CreateUpgradeCampaign(ctx, UpgradeCampaign{ProjectID: project.ID, FleetGroupID: group.ID, BaselineID: previous.BaselineID, TargetVersion: "1.1.0", CanaryCount: 1, WaveSize: 1, HaltAfterFailures: 1, Targets: []UpgradeCampaignTarget{target}, IdempotencyKey: "safe-upgrade", RequestDigest: testDigest(7203), MaintenanceWindowStart: now.Add(10 * time.Minute), MaintenanceWindowEnd: now.Add(2 * time.Hour), RecoveryCheckpointIDs: []string{checkpoint.ID}}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if campaign.PlanContextDigest == "" || campaign.PlanExpiresAt == nil || campaign.TargetInventoryDigests[cluster.ID] == "" {
		t.Fatalf("upgrade safety snapshot missing: %#v", campaign)
	}
	campaign, err = store.ApproveUpgradeCampaign(ctx, campaign.ID, campaign.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	queued := cloneUpgradeCampaign(campaign)
	queued.State = UpgradeCampaignRunning
	queued.CurrentWave = 1
	if _, err = store.UpdateUpgradeCampaign(ctx, queued, campaign.Revision, "operator"); !errors.Is(err, ErrMaintenanceWindow) {
		t.Fatalf("expected closed maintenance window, got %v", err)
	}

	now = now.Add(11 * time.Minute)
	running, err := store.UpdateUpgradeCampaign(ctx, queued, campaign.Revision, "operator")
	if err != nil || running.State != UpgradeCampaignRunning {
		t.Fatalf("windowed start failed: %#v %v", running, err)
	}

	// A checkpoint is tied to the exact inventory context. A later inventory change
	// makes the old evidence unusable for a new/revalidated campaign.
	_, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agentToken, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "1.31.1", Digest: testDigest(7299)})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.CreateUpgradeCampaign(ctx, UpgradeCampaign{ProjectID: project.ID, FleetGroupID: group.ID, BaselineID: previous.BaselineID, TargetVersion: "1.1.0", CanaryCount: 1, WaveSize: 1, HaltAfterFailures: 1, Targets: []UpgradeCampaignTarget{target}, IdempotencyKey: "stale-checkpoint", RequestDigest: testDigest(7204), MaintenanceWindowStart: now, MaintenanceWindowEnd: now.Add(time.Hour), RecoveryCheckpointIDs: []string{checkpoint.ID}}, "operator")
	if !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("expected stale checkpoint prerequisite failure, got %v", err)
	}
}
