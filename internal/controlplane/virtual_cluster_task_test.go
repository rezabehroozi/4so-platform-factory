package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"platform.4so.io/factory/internal/virtualcluster"
)

func claimedVirtualClusterFixture(t *testing.T) (*MemoryStore, ManagedCluster, string, VirtualCluster, VirtualClusterTask) {
	t.Helper()
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	workspace, binding := virtualClusterStoreFixture(t, store)
	cluster, err := store.GetManagedCluster(ctx, binding.ClusterID)
	if err != nil { t.Fatal(err) }
	agent := digestTenantTest("vcluster-agent")
	store.mu.Lock()
	imp := store.clusterImports[cluster.ImportID]
	imp.AgentTokenDigest = agent
	store.clusterImports[cluster.ImportID] = imp
	store.mu.Unlock()
	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{
		ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.34.2",
		Digest: digestTenantTest("vcluster-runtime-inventory"),
		Capabilities: []string{TargetMutationRBACActiveCapability},
	})
	if err != nil { t.Fatal(err) }
	created, _, err := store.CreateVirtualCluster(ctx, virtualClusterCreateRequest(workspace, binding), "owner")
	if err != nil { t.Fatal(err) }
	sourceDigest := "sha256:" + stringsRepeat("d", 64)
	task, err := store.NextVirtualClusterTask(ctx, cluster.ID, agent, sourceDigest)
	if err != nil { t.Fatal(err) }
	return store, cluster, agent, created, task
}

func stringsRepeat(value string, count int) string {
	out := ""
	for i := 0; i < count; i++ { out += value }
	return out
}

func TestVirtualClusterTaskClaimAndReadbackNeverReplayApply(t *testing.T) {
	ctx := context.Background()
	store, cluster, agent, created, task := claimedVirtualClusterFixture(t)
	if task.Action != "APPLY" || task.VirtualClusterID != created.ID || task.TaskFenceToken <= 0 || task.WorkspaceBindingRevision <= 0 {
		t.Fatalf("claim=%#v", task)
	}
	updated, err := store.ReportVirtualClusterTask(ctx, cluster.ID, agent, task.ClusterRevision, VirtualClusterTaskResult{
		VirtualClusterID: created.ID, TaskFenceToken: task.TaskFenceToken, Action: "APPLY",
		Success: true, Ready: false, ObservedDigest: created.DesiredDigest, Phase: "Pending",
	})
	if err != nil || updated.State != virtualcluster.StateProvisioning || updated.TaskAction != "INSPECT" {
		t.Fatalf("apply report=%#v err=%v", updated, err)
	}
	inspect, err := store.NextVirtualClusterTask(ctx, cluster.ID, agent, task.RuntimeSourceDigest)
	if err != nil || inspect.Action != "INSPECT" || inspect.TaskFenceToken != task.TaskFenceToken {
		t.Fatalf("read-only inspect must preserve the APPLY mutation fence: inspect=%#v apply=%#v err=%v", inspect, task, err)
	}
	active, err := store.ReportVirtualClusterTask(ctx, cluster.ID, agent, inspect.ClusterRevision, VirtualClusterTaskResult{
		VirtualClusterID: created.ID, TaskFenceToken: inspect.TaskFenceToken, Action: "INSPECT",
		Success: true, Ready: true, ObservedDigest: created.DesiredDigest, Phase: "Ready",
	})
	if err != nil || active.State != virtualcluster.StateActive || active.PendingAction != "" {
		t.Fatalf("active=%#v err=%v", active, err)
	}
}

func TestVirtualClusterExpiredApplyLeaseRequiresRecovery(t *testing.T) {
	ctx := context.Background()
	store, cluster, agent, created, task := claimedVirtualClusterFixture(t)
	store.mu.Lock()
	v := store.virtualClusters[created.ID]
	expired := time.Date(2026, 9, 21, 7, 59, 0, 0, time.UTC)
	v.TaskLeaseExpiresAt = &expired
	store.virtualClusters[v.ID] = v
	store.mu.Unlock()
	if _, err := store.NextVirtualClusterTask(ctx, cluster.ID, agent, task.RuntimeSourceDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired APPLY must not be replayed: %v", err)
	}
	got, err := store.GetVirtualCluster(ctx, created.ID)
	if err != nil || got.State != virtualcluster.StateRecoveryRequired || got.TaskLeaseExpiresAt != nil {
		t.Fatalf("recovery=%#v err=%v", got, err)
	}
}

func TestVirtualClusterTaskFenceAndSourceDigestAreImmutable(t *testing.T) {
	ctx := context.Background()
	store, cluster, agent, created, task := claimedVirtualClusterFixture(t)
	_, err := store.ReportVirtualClusterTask(ctx, cluster.ID, agent, task.ClusterRevision, VirtualClusterTaskResult{
		VirtualClusterID: created.ID, TaskFenceToken: task.TaskFenceToken - 1, Action: "APPLY",
		Success: true, Ready: false, ObservedDigest: created.DesiredDigest,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale fence admitted: %v", err)
	}
	// Finish APPLY safely into readback state, then a different runtime source
	// cannot claim the same operation.
	_, err = store.ReportVirtualClusterTask(ctx, cluster.ID, agent, task.ClusterRevision, VirtualClusterTaskResult{
		VirtualClusterID: created.ID, TaskFenceToken: task.TaskFenceToken, Action: "APPLY",
		Success: true, Ready: false, ObservedDigest: created.DesiredDigest,
	})
	if err != nil { t.Fatal(err) }
	other := "sha256:" + stringsRepeat("e", 64)
	if _, err = store.NextVirtualClusterTask(ctx, cluster.ID, agent, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("runtime source drift admitted: %v", err)
	}
}

func TestVirtualClusterUnknownOutcomeAndDigestMismatchFailClosed(t *testing.T) {
	ctx := context.Background()
	store, cluster, agent, created, task := claimedVirtualClusterFixture(t)
	got, err := store.ReportVirtualClusterTask(ctx, cluster.ID, agent, task.ClusterRevision, VirtualClusterTaskResult{
		VirtualClusterID: created.ID, TaskFenceToken: task.TaskFenceToken, Action: "APPLY",
		Success: false, RecoveryRequired: true, Error: "connection reset after submission",
	})
	if err != nil || got.State != virtualcluster.StateRecoveryRequired {
		t.Fatalf("unknown=%#v err=%v", got, err)
	}

	store, cluster, agent, created, task = claimedVirtualClusterFixture(t)
	got, err = store.ReportVirtualClusterTask(ctx, cluster.ID, agent, task.ClusterRevision, VirtualClusterTaskResult{
		VirtualClusterID: created.ID, TaskFenceToken: task.TaskFenceToken, Action: "APPLY",
		Success: true, Ready: true, ObservedDigest: "sha256:" + stringsRepeat("f", 64),
	})
	if err != nil || got.State != virtualcluster.StateRecoveryRequired {
		t.Fatalf("digest mismatch=%#v err=%v", got, err)
	}
}

func TestVirtualClusterBindingRevisionMustRemainCurrentBeforeFirstClaim(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	workspace, binding := virtualClusterStoreFixture(t, store)
	cluster, _ := store.GetManagedCluster(ctx, binding.ClusterID)
	agent := digestTenantTest("vcluster-agent-binding")
	store.mu.Lock()
	imp := store.clusterImports[cluster.ImportID]
	imp.AgentTokenDigest = agent
	store.clusterImports[cluster.ImportID] = imp
	store.mu.Unlock()
	cluster, _, err := upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{
		ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.34.2",
		Digest: digestTenantTest("vcluster-binding-inventory"),
		Capabilities: []string{TargetMutationRBACActiveCapability},
	})
	if err != nil { t.Fatal(err) }
	created, _, err := store.CreateVirtualCluster(ctx, virtualClusterCreateRequest(workspace, binding), "owner")
	if err != nil { t.Fatal(err) }
	if _, err = store.RevokeWorkspaceBinding(ctx, binding.ID, binding.Revision, "owner"); err != nil { t.Fatal(err) }
	source := "sha256:" + stringsRepeat("d", 64)
	if _, err = store.NextVirtualClusterTask(ctx, cluster.ID, agent, source); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked binding task claim=%v", err)
	}
	got, _ := store.GetVirtualCluster(ctx, created.ID)
	if got.State != virtualcluster.StateFailed {
		t.Fatalf("revoked binding state=%#v", got)
	}
}
