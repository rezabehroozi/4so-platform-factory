package controlplane

import "testing"

func TestManagedResourceOutcomeRejectsIncompleteOperationIdentity(t *testing.T) {
	op := ManagedResourceOperation{
		Authority: ResourceProvisionOperationAuthority,
		FenceToken: 9,
		Action: ManagedResourceProvision,
		PlanDigest: testMRDigest('c'),
	}
	readback := ManagedResourceReadback{
		Observed: true,
		OperationID: op.OperationID,
		FenceToken: op.FenceToken,
		PlanDigest: op.PlanDigest,
		InstanceID: op.InstanceID,
		Revision: 1,
		State: ManagedResourceReady,
		ObservedDigest: testMRDigest('d'),
		EvidenceDigest: testMRDigest('e'),
	}
	got := ResolveManagedResourceOutcome(op, ManagedResourceOutcomeUnknown, readback)
	if got.State != ManagedResourceFailed || got.RecoveryRequired || got.EvidenceDigest != "" {
		t.Fatalf("incomplete fabricated managed resource operation must fail before readback resolution: %#v", got)
	}
}
