package controlplane

import (
	"errors"
	"testing"
	"time"
)

func TestClusterInventoryObservationEpochRejectsStaleFutureAndRollback(t *testing.T) {
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	store, ctx, cluster, agent := seedAdmissionCluster(t, &now)

	stale := ClusterInventory{
		ObservedAt:        now.Add(-(ClusterInventoryAuthorityFreshness + time.Second)),
		Distribution:      "rke2",
		KubernetesVersion: "v1.33.2+rke2r1",
	}
	if _, _, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, stale); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("stale target observation was accepted as fresh authority: %v", err)
	}

	future := stale
	future.ObservedAt = now.Add(ClusterInventoryObservationFutureSkew + time.Second)
	if _, _, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, future); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("far-future target observation was accepted as current authority: %v", err)
	}

	fresh := stale
	fresh.ObservedAt = now
	cluster, stored, err := store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if cluster.InventoryObservedAt == nil || !cluster.InventoryObservedAt.Equal(now) || !stored.ObservedAt.Equal(now) {
		t.Fatalf("accepted observation epoch was not persisted: cluster=%+v inventory=%+v", cluster.InventoryObservedAt, stored.ObservedAt)
	}

	rollback := fresh
	rollback.ObservedAt = now.Add(-time.Second)
	if _, _, err = store.UpsertClusterInventory(ctx, cluster.ID, agent, cluster.ExternalUID, rollback); !errors.Is(err, ErrConflict) {
		t.Fatalf("out-of-order target observation rolled authority backwards: %v", err)
	}
}

func TestClusterTaskClaimAdmissionRequiresFreshTargetObservation(t *testing.T) {
	now := time.Date(2026, 8, 28, 8, 30, 0, 0, time.UTC)
	staleObserved := now.Add(-(ClusterInventoryAuthorityFreshness + time.Second))
	digest := digestTenantTest("observation-epoch")
	cluster := ManagedCluster{
		ConnectionState:             "CONNECTED",
		Distribution:                "rke2",
		InventoryDigest:             digest,
		InventoryUpdatedAt:          &now,
		InventoryObservedAt:         &staleObserved,
		LastSeenAt:                  &now,
		Capabilities:                []string{TargetMutationRBACActiveCapability, TargetMutationRBACActivationIssuedCapability},
		MutationRBACBasisDigest:     digest,
		MutationRBACIssuedForDigest: digest,
	}
	if !ClusterTaskAdmitted(cluster) {
		t.Fatal("non-time-sensitive fenced task continuation unexpectedly lost structural admission")
	}
	if ClusterTaskClaimAdmittedAt(cluster, now) {
		t.Fatal("stale target observation was treated as fresh task-claim authority")
	}
	cluster.InventoryObservedAt = nil
	if ClusterTaskClaimAdmittedAt(cluster, now) {
		t.Fatal("legacy cluster without an observation epoch was admitted after v52 fail-closed boundary")
	}
}
