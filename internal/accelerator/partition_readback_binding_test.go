package accelerator

import "testing"

func TestAmbiguousPartitionOutcomeRequiresExactOperationReadbackBinding(t *testing.T) {
	plan := testPlacementPlan()
	op, err := NewPartitionOperation(plan, "op-1", "idem-1", 7, PartitionCreate, "gpu-a", "partition-1", 3)
	if err != nil {
		t.Fatal(err)
	}
	base := PartitionReadback{Observed: true, OperationID: op.OperationID, FenceToken: op.FenceToken, PlanDigest: op.PlanDigest, DeviceID: "gpu-a", PartitionID: "partition-1", Generation: 4, State: PartitionStateReady, EvidenceDigest: digest64('b')}

	wrongOperation := base
	wrongOperation.OperationID = "op-other"
	if got := ResolvePartitionOutcome(op, OutcomeUnknown, wrongOperation); got.State != PartitionStateRecoveryRequired || !got.RecoveryRequired {
		t.Fatalf("readback from a different operation must not resolve ambiguity: %#v", got)
	}

	wrongFence := base
	wrongFence.FenceToken++
	if got := ResolvePartitionOutcome(op, OutcomeUnknown, wrongFence); got.State != PartitionStateRecoveryRequired || !got.RecoveryRequired {
		t.Fatalf("readback from a different fence must not resolve ambiguity: %#v", got)
	}

	wrongPlan := base
	wrongPlan.PlanDigest = digest64('c')
	if got := ResolvePartitionOutcome(op, OutcomeUnknown, wrongPlan); got.State != PartitionStateRecoveryRequired || !got.RecoveryRequired {
		t.Fatalf("readback from a different placement plan must not resolve ambiguity: %#v", got)
	}

	if got := ResolvePartitionOutcome(op, OutcomeUnknown, base); got.State != PartitionStateReady || got.RecoveryRequired || got.EvidenceDigest == "" {
		t.Fatalf("exact operation-bound readback must resolve ambiguity: %#v", got)
	}
}
