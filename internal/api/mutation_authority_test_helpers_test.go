package api

import (
	"context"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

type mutationAuthorityAPITestStore interface {
	UpsertClusterInventory(context.Context, string, string, string, controlplane.ClusterInventory) (controlplane.ManagedCluster, controlplane.ClusterInventory, error)
	AuthorizeClusterMutationRBACActivation(context.Context, string, string) (controlplane.ManagedCluster, controlplane.ClusterImport, error)
}

func upsertMutationReadyInventoryForAPITest(t *testing.T, store mutationAuthorityAPITestStore, ctx context.Context, clusterID, agentTokenDigest, externalUID string, inv controlplane.ClusterInventory) (controlplane.ManagedCluster, controlplane.ClusterInventory, error) {
	t.Helper()
	pre := inv
	pre.Capabilities = append([]string(nil), inv.Capabilities...)
	filtered := make([]string, 0, len(pre.Capabilities)+1)
	for _, capability := range pre.Capabilities {
		if capability != controlplane.TargetMutationRBACActiveCapability {
			filtered = append(filtered, capability)
		}
	}
	pre.Capabilities = append(filtered, controlplane.TargetEnrollmentPrincipalIsolatedCapability)
	if _, _, err := store.UpsertClusterInventory(ctx, clusterID, agentTokenDigest, externalUID, pre); err != nil {
		return controlplane.ManagedCluster{}, controlplane.ClusterInventory{}, err
	}
	if _, _, err := store.AuthorizeClusterMutationRBACActivation(ctx, clusterID, "test-mutation-rbac-issuer"); err != nil {
		return controlplane.ManagedCluster{}, controlplane.ClusterInventory{}, err
	}
	inv.Capabilities = append(append([]string(nil), inv.Capabilities...), controlplane.TargetEnrollmentPrincipalIsolatedCapability)
	return store.UpsertClusterInventory(ctx, clusterID, agentTokenDigest, externalUID, inv)
}
