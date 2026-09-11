package controlplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func seedMaintenanceCluster(t *testing.T, store *MemoryStore, now time.Time) (Project, ManagedCluster, string) {
	t.Helper()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "maint-org", DisplayName: "Maintenance Org"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	enrollment, agent := testDigest(12001), testDigest(12002)
	imp, err := store.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "maint-a", DisplayName: "Maintenance A", TokenDigest: enrollment, ExpiresAt: now.Add(time.Hour)}, "requester")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, enrollment, agent, "uid-maint-a", "0.0.67")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{
		ObservedAt:        now,
		Distribution:      "rke2",
		KubernetesVersion: "1.33.1",
		Digest:            testDigest(12003),
		Capabilities:      []string{TargetMutationRBACActiveCapability, ClusterMaintenanceFencedReportCapability},
		Nodes:             []ClusterNode{{Name: "worker-1", UID: "node-1", Roles: []string{"worker"}, Ready: true}, {Name: "worker-2", UID: "node-2", Roles: []string{"worker"}, Ready: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return project, cluster, agent
}

func createMaintenanceOperation(t *testing.T, store *MemoryStore, ctx context.Context, project Project, cluster ManagedCluster, digest string) Operation {
	t.Helper()
	op, replay, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "CLUSTER_MAINTENANCE", TargetRef: "cluster/" + cluster.ID, DesiredRevision: digest, Risk: "high", Class: OperationClassMutating}, "maintenance-op-"+digest, "requester", "req-maint")
	if err != nil || replay {
		t.Fatalf("create operation replay=%v err=%v", replay, err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationPlanning, "", "requester")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationAwaitingApproval, "", "requester")
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestClusterMaintenanceAuthorityInventoryBindingAndCompletion(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return prefix + "_test_" + string(rune('a'+seq)) })
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)

	profile, err := store.UpsertClusterMaintenanceProfile(ctx, ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 120}, 0, "operator")
	if err != nil || profile.Environment != ClusterEnvironmentProduction {
		t.Fatalf("profile=%+v err=%v", profile, err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "prod-maint", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 120}, "operator")
	if err != nil {
		t.Fatal(err)
	}

	op := createMaintenanceOperation(t, store, ctx, project, cluster, testDigest(12010))
	run, replay, err := store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: op.ID, NodeNames: []string{"worker-1"}, IdempotencyKey: "run-one", RequestDigest: testDigest(12010)}, "requester")
	if err != nil || replay || run.State != ClusterMaintenanceAwaitingApproval {
		t.Fatalf("run=%+v replay=%v err=%v", run, replay, err)
	}
	if _, err = store.ApproveClusterMaintenanceRun(ctx, run.ID, run.Revision, "requester"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("self approval err=%v", err)
	}
	run, err = store.ApproveClusterMaintenanceRun(ctx, run.ID, run.Revision, "approver")
	if err != nil || run.State != ClusterMaintenanceQueued {
		t.Fatalf("approve=%+v err=%v", run, err)
	}

	// Inventory drift after approval invalidates the exact maintenance request before claim.
	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now.Add(time.Minute), Distribution: "rke2", KubernetesVersion: "1.33.2", Digest: testDigest(12004), Capabilities: []string{TargetMutationRBACActiveCapability, ClusterMaintenanceFencedReportCapability}, Nodes: []ClusterNode{{Name: "worker-1", UID: "node-1", Roles: []string{"worker"}, Ready: true}, {Name: "worker-2", UID: "node-2", Roles: []string{"worker"}, Ready: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.NextClusterMaintenanceTask(ctx, cluster.ID, agent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected no claim after inventory drift, err=%v", err)
	}
	stale, err := store.GetClusterMaintenanceRun(ctx, run.ID)
	if err != nil || stale.State != ClusterMaintenanceFailed {
		t.Fatalf("stale=%+v err=%v", stale, err)
	}

	op2 := createMaintenanceOperation(t, store, ctx, project, cluster, testDigest(12011))
	run2, _, err := store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: op2.ID, NodeNames: []string{"worker-2"}, IdempotencyKey: "run-two", RequestDigest: testDigest(12011)}, "requester")
	if err != nil {
		t.Fatal(err)
	}
	run2, err = store.ApproveClusterMaintenanceRun(ctx, run2.ID, run2.Revision, "approver-two")
	if err != nil {
		t.Fatal(err)
	}
	claimedRun, claimedOp, err := store.NextClusterMaintenanceTask(ctx, cluster.ID, agent)
	if err != nil {
		t.Fatal(err)
	}
	if claimedRun.ID != run2.ID || claimedOp.FenceToken == 0 || claimedRun.InventoryDigest != cluster.InventoryDigest || claimedRun.DrainTimeoutSeconds != 120 {
		t.Fatalf("claimed run=%+v op=%+v", claimedRun, claimedOp)
	}
	completed, completedOp, err := store.ReportClusterMaintenanceTask(ctx, cluster.ID, claimedRun.ID, claimedRun.Revision, ClusterMaintenanceTaskResult{OperationFenceToken: claimedOp.FenceToken, Success: true, Results: []NodeMaintenanceResult{{NodeName: "worker-2", Cordoned: true, DrainAttempted: true, Drained: true, Uncordoned: true, EvictedPods: []string{"app/web-1"}}}})
	if err != nil || completed.State != ClusterMaintenanceSucceeded || completedOp.State != OperationSucceeded {
		t.Fatalf("completed=%+v op=%+v err=%v", completed, completedOp, err)
	}
	finalOp, err := store.GetOperation(ctx, op2.ID)
	if err != nil || finalOp.State != OperationSucceeded {
		t.Fatalf("operation=%+v err=%v", finalOp, err)
	}
}

func TestClusterMaintenanceLeaseFenceAndExpiredTaskNeedsOperator(t *testing.T) {
	now := time.Date(2026, 8, 10, 7, 0, 0, 0, time.UTC)
	clock := now
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return clock }, func(prefix string) string { seq++; return fmt.Sprintf("%s_lease_%d", prefix, seq) })
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)
	if _, err := store.UpsertClusterMaintenanceProfile(ctx, ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 3600}, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "long-maint", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(3 * time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 3600}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	op := createMaintenanceOperation(t, store, ctx, project, cluster, testDigest(12100))
	run, _, err := store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: op.ID, NodeNames: []string{"worker-1"}, IdempotencyKey: "long-run", RequestDigest: testDigest(12100)}, "requester")
	if err != nil {
		t.Fatal(err)
	}
	run, err = store.ApproveClusterMaintenanceRun(ctx, run.ID, run.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	claimedRun, claimedOp, err := store.NextClusterMaintenanceTask(ctx, cluster.ID, agent)
	if err != nil {
		t.Fatal(err)
	}
	if claimedOp.LeaseExpiresAt == nil || claimedOp.LeaseExpiresAt.Sub(now) < 62*time.Minute {
		t.Fatalf("maintenance lease does not cover declared drain timeout: %+v", claimedOp.LeaseExpiresAt)
	}
	good := ClusterMaintenanceTaskResult{OperationFenceToken: claimedOp.FenceToken, Success: true, Results: []NodeMaintenanceResult{{NodeName: "worker-1", Cordoned: true, DrainAttempted: true, Drained: true, Uncordoned: true}}}
	badFence := good
	badFence.OperationFenceToken++
	if _, _, err = store.ReportClusterMaintenanceTask(ctx, cluster.ID, claimedRun.ID, claimedRun.Revision, badFence); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale maintenance fence err=%v", err)
	}
	clock = claimedOp.LeaseExpiresAt.Add(time.Second)
	if _, _, err = store.ReportClusterMaintenanceTask(ctx, cluster.ID, claimedRun.ID, claimedRun.Revision, good); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("expired maintenance lease report err=%v", err)
	}
	refreshClusterTaskInventoryAt(t, store, ctx, cluster.ID, agent, clock)
	if _, _, err = store.NextClusterMaintenanceTask(ctx, cluster.ID, agent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired maintenance task should not be reissued automatically, err=%v", err)
	}
	staleRun, err := store.GetClusterMaintenanceRun(ctx, claimedRun.ID)
	if err != nil || staleRun.State != ClusterMaintenanceNeedsOperator {
		t.Fatalf("expired run=%+v err=%v", staleRun, err)
	}
	staleOp, err := store.GetOperation(ctx, claimedOp.ID)
	if err != nil || staleOp.State != OperationNeedsOperator || staleOp.LeaseOwner != "" || staleOp.LeaseExpiresAt != nil {
		t.Fatalf("expired operation=%+v err=%v", staleOp, err)
	}
}

func TestClusterMaintenanceWaitsForFencedAgentCapability(t *testing.T) {
	now := time.Date(2026, 8, 10, 8, 0, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return fmt.Sprintf("%s_cap_%d", prefix, seq) })
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)
	cluster, _, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now.Add(time.Second), Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "1.33.1", Digest: testDigest(12110), Nodes: []ClusterNode{{Name: "worker-1", UID: "node-1", Roles: []string{"worker"}, Ready: true}, {Name: "worker-2", UID: "node-2", Roles: []string{"worker"}, Ready: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertClusterMaintenanceProfile(ctx, ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 120}, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "rolling-agent", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 120}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	op := createMaintenanceOperation(t, store, ctx, project, cluster, testDigest(12111))
	run, _, err := store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: op.ID, NodeNames: []string{"worker-1"}, IdempotencyKey: "rolling-agent-run", RequestDigest: testDigest(12111)}, "requester")
	if err != nil {
		t.Fatal(err)
	}
	run, err = store.ApproveClusterMaintenanceRun(ctx, run.ID, run.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.NextClusterMaintenanceTask(ctx, cluster.ID, agent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("legacy agent must not receive fenced maintenance task, err=%v", err)
	}
	queued, err := store.GetClusterMaintenanceRun(ctx, run.ID)
	if err != nil || queued.State != ClusterMaintenanceQueued {
		t.Fatalf("legacy-agent run=%+v err=%v", queued, err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now.Add(2 * time.Second), Distribution: "rke2", KubernetesVersion: "1.33.2", Digest: testDigest(12112), Capabilities: []string{TargetMutationRBACActiveCapability, ClusterMaintenanceFencedReportCapability}, Nodes: []ClusterNode{{Name: "worker-1", UID: "node-1", Roles: []string{"worker"}, Ready: true}, {Name: "worker-2", UID: "node-2", Roles: []string{"worker"}, Ready: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.NextClusterMaintenanceTask(ctx, cluster.ID, agent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inventory-changing agent upgrade requires resubmission, err=%v", err)
	}
	failed, err := store.GetClusterMaintenanceRun(ctx, run.ID)
	if err != nil || failed.State != ClusterMaintenanceFailed {
		t.Fatalf("post-upgrade stale run=%+v err=%v", failed, err)
	}
}

func TestClusterMaintenancePersistsNodeIdentityAndRejectsSameDigestReplacement(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return fmt.Sprintf("%s_uid_%d", prefix, seq) })
	ctx := context.Background()
	project, cluster, _ := seedMaintenanceCluster(t, store, now)
	if _, err := store.UpsertClusterMaintenanceProfile(ctx, ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 120}, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "uid-fence", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 120}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	op := createMaintenanceOperation(t, store, ctx, project, cluster, testDigest(12150))
	run, _, err := store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: op.ID, NodeNames: []string{"worker-1"}, IdempotencyKey: "uid-fenced-run", RequestDigest: testDigest(12150)}, "requester")
	if err != nil {
		t.Fatal(err)
	}
	if got := run.NodeUIDs["worker-1"]; got != "node-1" {
		t.Fatalf("maintenance run did not persist approved node UID: %q", got)
	}
	// Simulate a same-digest inventory identity replacement. Digest equality alone must not authorize maintenance.
	store.mu.Lock()
	inv := store.clusterInventories[cluster.ID]
	inv.Nodes[0].UID = "replacement-node-uid"
	store.clusterInventories[cluster.ID] = inv
	store.mu.Unlock()
	if _, err = store.ApproveClusterMaintenanceRun(ctx, run.ID, run.Revision, "approver"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("same-digest node replacement must invalidate approval, err=%v", err)
	}
}

func TestClusterMaintenanceRejectsInventoryNodeWithoutUID(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 10, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return fmt.Sprintf("%s_nouid_%d", prefix, seq) })
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)
	cluster, _, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now.Add(time.Second), Distribution: "rke2", KubernetesVersion: "1.33.1", Digest: testDigest(12160), Capabilities: []string{TargetMutationRBACActiveCapability, ClusterMaintenanceFencedReportCapability}, Nodes: []ClusterNode{{Name: "worker-1", Ready: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertClusterMaintenanceProfile(ctx, ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 120}, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "uid-required", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 120}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	op := createMaintenanceOperation(t, store, ctx, project, cluster, testDigest(12161))
	if _, _, err = store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: op.ID, NodeNames: []string{"worker-1"}, IdempotencyKey: "uid-required-run", RequestDigest: testDigest(12161)}, "requester"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("maintenance run must reject node inventory without UID, err=%v", err)
	}
}

func TestClusterMaintenanceRunOrderingMatchesPostgresTieBreak(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	// All rows deliberately share the same CreatedAt. PostgreSQL orders this
	// collection by created_at,id; map iteration must not decide membership or
	// chronology in Memory/FileStore.
	for i := 31; i >= 0; i-- {
		id := fmt.Sprintf("cmr_order_%02d", i)
		store.clusterMaintenanceRuns[id] = ClusterMaintenanceRun{
			ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now},
			ClusterID:    "clu_order",
			State:        ClusterMaintenanceQueued,
		}
	}
	for attempt := 0; attempt < 8; attempt++ {
		got, err := store.ListClusterMaintenanceRuns(context.Background(), "clu_order")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 32 {
			t.Fatalf("maintenance runs=%d want=32", len(got))
		}
		for i := range got {
			want := fmt.Sprintf("cmr_order_%02d", i)
			if got[i].ID != want {
				t.Fatalf("attempt %d maintenance ordering[%d]=%q want %q for created_at,id parity", attempt, i, got[i].ID, want)
			}
		}
	}
}

func TestClusterMaintenanceClaimUsesCreatedAtIDTieBreak(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 30, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string {
		seq++
		return fmt.Sprintf("%s_claim_%04d", prefix, seq)
	})
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)
	if _, err := store.UpsertClusterMaintenanceProfile(ctx, ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 120}, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "deterministic-claim", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 120}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, 24)
	for i := 0; i < 24; i++ {
		digest := testDigest(14000 + i)
		op := createMaintenanceOperation(t, store, ctx, project, cluster, digest)
		run, _, err := store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: op.ID, NodeNames: []string{"worker-1"}, IdempotencyKey: fmt.Sprintf("claim-run-%02d", i), RequestDigest: digest}, "requester")
		if err != nil {
			t.Fatal(err)
		}
		run, err = store.ApproveClusterMaintenanceRun(ctx, run.ID, run.Revision, "approver")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, run.ID)
	}
	sort.Strings(ids)
	claimed, _, err := store.NextClusterMaintenanceTask(ctx, cluster.ID, agent)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != ids[0] {
		t.Fatalf("claimed maintenance run=%q want %q for PostgreSQL ORDER BY created_at,id parity", claimed.ID, ids[0])
	}
}

func TestClusterMaintenanceRunOrderingSurvivesFileStoreRestart(t *testing.T) {
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	store.MemoryStore.now = func() time.Time { return now }
	for i := 15; i >= 0; i-- {
		id := fmt.Sprintf("cmr_restart_%02d", i)
		store.clusterMaintenanceRuns[id] = ClusterMaintenanceRun{
			ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now},
			ClusterID:    "clu_restart",
			State:        ClusterMaintenanceQueued,
		}
	}
	if err := store.persist(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.ListClusterMaintenanceRuns(context.Background(), "clu_restart")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 16 {
		t.Fatalf("maintenance runs after restart=%d want=16", len(got))
	}
	for i := range got {
		want := fmt.Sprintf("cmr_restart_%02d", i)
		if got[i].ID != want {
			t.Fatalf("maintenance ordering after restart[%d]=%q want %q", i, got[i].ID, want)
		}
	}
}

func TestClusterMaintenanceOSPatchRequiresLiveExecutorAndEvidence(t *testing.T) {
	now := time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return fmt.Sprintf("%s_patch_%d", prefix, seq) })
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)
	if _, err := store.UpsertClusterMaintenanceProfile(ctx, ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 120}, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "patch", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(2 * time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 120}, "operator")
	if err != nil {
		t.Fatal(err)
	}

	blockedOp := createMaintenanceOperation(t, store, ctx, project, cluster, testDigest(12100))
	if _, _, err := store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: blockedOp.ID, Action: TargetNodeActionOSPatch, NodeNames: []string{"worker-1"}, IdempotencyKey: "patch-blocked", RequestDigest: testDigest(12100)}, "requester"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("OS patch without live executor capabilities should fail closed, got %v", err)
	}

	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now.Add(time.Minute), Distribution: "rke2", KubernetesVersion: "1.33.2+rke2r1", Digest: testDigest(12101), Capabilities: []string{TargetMutationRBACActiveCapability, ClusterMaintenanceFencedReportCapability, TargetNodeHostMaintenanceCapability, TargetNodeOSPatchCapability}, Nodes: []ClusterNode{{Name: "worker-1", UID: "node-1", Roles: []string{"worker"}, Ready: true}, {Name: "worker-2", UID: "node-2", Roles: []string{"worker"}, Ready: true}}})
	if err != nil {
		t.Fatal(err)
	}
	op := createMaintenanceOperation(t, store, ctx, project, cluster, testDigest(12102))
	run, replay, err := store.CreateClusterMaintenanceRun(ctx, ClusterMaintenanceRun{ProjectID: project.ID, ClusterID: cluster.ID, WindowID: window.ID, OperationID: op.ID, Action: TargetNodeActionOSPatch, NodeNames: []string{"worker-1"}, IdempotencyKey: "patch-admitted", RequestDigest: testDigest(12102)}, "requester")
	if err != nil || replay || run.Action != TargetNodeActionOSPatch || run.HostActionTimeoutSeconds != 3600 {
		t.Fatalf("run=%+v replay=%v err=%v", run, replay, err)
	}
	run, err = store.ApproveClusterMaintenanceRun(ctx, run.ID, run.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	claimed, claimedOp, err := store.NextClusterMaintenanceTask(ctx, cluster.ID, agent)
	if err != nil {
		t.Fatal(err)
	}
	bad := ClusterMaintenanceTaskResult{OperationFenceToken: claimedOp.FenceToken, Success: true, Results: []NodeMaintenanceResult{{NodeName: "worker-1", Cordoned: true, DrainAttempted: true, Drained: true, Uncordoned: true}}}
	if _, _, err := store.ReportClusterMaintenanceTask(ctx, cluster.ID, claimed.ID, claimed.Revision, bad); !errors.Is(err, ErrValidation) {
		t.Fatalf("missing host action evidence must be rejected, got %v", err)
	}
	good := bad
	good.Results[0].HostActionAttempted = true
	good.Results[0].HostActionSucceeded = true
	good.Results[0].HostActionAuthority = "TARGET_NODE_HOST_MAINTENANCE_EXECUTOR_V1"
	good.Results[0].HostActionEvidence = "Job/4so-os-patch-test@uid:sha256:" + strings.Repeat("a", 64)
	completed, completedOp, err := store.ReportClusterMaintenanceTask(ctx, cluster.ID, claimed.ID, claimed.Revision, good)
	if err != nil || completed.State != ClusterMaintenanceSucceeded || completedOp.State != OperationSucceeded {
		t.Fatalf("completed=%+v op=%+v err=%v", completed, completedOp, err)
	}
}
