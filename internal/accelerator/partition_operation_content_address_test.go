package accelerator

import "testing"

func TestPartitionOperationRejectsTamperedOperationContentAddress(t *testing.T) {
	plan := testPlacementPlan()
	op, err := NewPartitionOperation(plan, "op-1", "idem-1", 7, PartitionCreate, "gpu-a", "partition-1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if op.OperationDigest == "" || !validPartitionOperation(op) {
		t.Fatalf("constructor must seal a valid partition operation: %#v", op)
	}

	cases := []struct {
		name string
		mutate func(*PartitionOperation)
	}{
		{"action", func(v *PartitionOperation) { v.Action = PartitionDrain }},
		{"device", func(v *PartitionOperation) { v.DeviceID = "gpu-b" }},
		{"project scope", func(v *PartitionOperation) { v.ProjectID = "project-b" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := op
			tc.mutate(&candidate)
			if validPartitionOperation(candidate) {
				t.Fatal("partition operation content changed after sealing must fail validation")
			}
			if got := ResolvePartitionOutcome(candidate, OutcomeUnknown, PartitionReadback{}); got.State != PartitionStateFailed || got.RecoveryRequired {
				t.Fatalf("tampered partition operation must fail before readback resolution: %#v", got)
			}
		})
	}
}
