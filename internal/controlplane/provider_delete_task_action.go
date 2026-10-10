package controlplane

import "strings"

// ProviderClusterDeleteMutationRequired distinguishes the initial destructive
// DELETE from later read-only deletion inspection. TaskAttempt is cumulative
// across the ProviderCluster lifetime and therefore cannot identify whether a
// DELETE side effect has already been attempted. A durable Deleting phase means
// mutation was already issued; RecoveryInspectQueued also requires readback.
func ProviderClusterDeleteMutationRequired(v ProviderCluster) bool {
	if v.State != ProviderClusterDeleting {
		return false
	}
	switch strings.TrimSpace(v.Phase) {
	case "Deleting", "RecoveryInspectQueued":
		return false
	default:
		return true
	}
}
