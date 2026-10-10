package accelerator

import "testing"

func TestPartitionOutcomeRejectsIncompleteOperationIdentity(t *testing.T) {
	op := PartitionOperation{
		Authority: PartitionLifecycleAuthority,
		FenceToken: 7,
		Action: PartitionCreate,
		ExpectedGeneration: 3,
		PlanDigest: digest64('a'),
	}
	readback := PartitionReadback{
		Observed: true,
		FenceToken: op.FenceToken,
		PlanDigest: op.PlanDigest,
		Generation: 4,
		State: PartitionStateReady,
		EvidenceDigest: digest64('b'),
	}
	got := ResolvePartitionOutcome(op, OutcomeUnknown, readback)
	if got.State != PartitionStateFailed || got.RecoveryRequired || got.EvidenceDigest != "" {
		t.Fatalf("incomplete fabricated operation identity must fail before readback resolution: %#v", got)
	}
}
