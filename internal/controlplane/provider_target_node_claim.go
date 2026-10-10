package controlplane

// ProviderClusterTargetNodeMutationRequiresClaimFence returns true only before
// a target-node mutation is claimed for execution. Once a provider mutation is
// ambiguous or has advanced to reconciliation, subsequent tasks are read-only
// authoritative inspections and must not be blocked by an expired maintenance
// window that governed the original side effect.
func ProviderClusterTargetNodeMutationRequiresClaimFence(v ProviderCluster) bool {
	return v.State == ProviderClusterQueued && IsTargetNodeProviderPendingAction(v.PendingAction)
}
