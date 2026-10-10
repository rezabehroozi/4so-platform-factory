package controlplane

import "testing"

func TestProviderTargetNodeFenceOnlyGatesMutationClaim(t *testing.T) {
	cases := []struct {
		name      string
		state     ProviderClusterState
		wantFence bool
	}{
		{name: "queued mutation", state: ProviderClusterQueued, wantFence: true},
		{name: "applying mutation", state: ProviderClusterApplying, wantFence: false},
		{name: "reconciling readback", state: ProviderClusterReconciling, wantFence: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := ProviderCluster{State: tc.state, PendingAction: "TARGET_NODE_REPLACE"}
			got := ProviderClusterTargetNodeMutationRequiresClaimFence(v)
			if got != tc.wantFence {
				t.Fatalf("target-node claim fence state=%s got=%v want=%v", tc.state, got, tc.wantFence)
			}
		})
	}
}
