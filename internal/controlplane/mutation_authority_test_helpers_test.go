package controlplane

import (
	"context"
	"testing"
)

type mutationAuthorityTestStore interface {
	UpsertClusterInventory(context.Context, string, string, string, ClusterInventory) (ManagedCluster, ClusterInventory, error)
	AuthorizeClusterMutationRBACActivation(context.Context, string, string) (ManagedCluster, ClusterImport, error)
}

func upsertMutationReadyInventoryForTest(t *testing.T, store mutationAuthorityTestStore, ctx context.Context, clusterID, agentTokenDigest, externalUID string, inv ClusterInventory) (ManagedCluster, ClusterInventory, error) {
	t.Helper()
	pre := cloneClusterInventory(inv)
	pre.Capabilities = removeClusterCapability(pre.Capabilities, TargetMutationRBACActiveCapability)
	pre.Capabilities = dedupeSortedStrings(append(pre.Capabilities, TargetEnrollmentPrincipalIsolatedCapability))
	if _, _, err := store.UpsertClusterInventory(ctx, clusterID, agentTokenDigest, externalUID, pre); err != nil {
		return ManagedCluster{}, ClusterInventory{}, err
	}
	if _, _, err := store.AuthorizeClusterMutationRBACActivation(ctx, clusterID, "test-mutation-rbac-issuer"); err != nil {
		return ManagedCluster{}, ClusterInventory{}, err
	}
	inv.Capabilities = dedupeSortedStrings(append(inv.Capabilities, TargetEnrollmentPrincipalIsolatedCapability))
	return store.UpsertClusterInventory(ctx, clusterID, agentTokenDigest, externalUID, inv)
}
