package controlplane

import "testing"

func TestProviderDeleteMutationDecisionUsesDurablePhaseNotLifetimeAttempts(t *testing.T) {
	firstDelete := ProviderCluster{State: ProviderClusterDeleting, Phase: "Ready", TaskAttempt: 9}
	if !ProviderClusterDeleteMutationRequired(firstDelete) {
		t.Fatal("first destructive DELETE must execute even when lifetime taskAttempt is already greater than one")
	}
	for _, v := range []ProviderCluster{
		{State: ProviderClusterDeleting, Phase: "Deleting", TaskAttempt: 10},
		{State: ProviderClusterDeleting, Phase: "RecoveryInspectQueued", TaskAttempt: 10},
		{State: ProviderClusterActive, Phase: "Ready", TaskAttempt: 9},
	} {
		if ProviderClusterDeleteMutationRequired(v) {
			t.Fatalf("read-only/non-delete state must not execute DELETE again: %#v", v)
		}
	}
}
