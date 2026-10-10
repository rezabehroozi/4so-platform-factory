package controlplane

import "testing"

func TestManagedResourceOperationRejectsTamperedOperationContentAddress(t *testing.T) {
	plan := ManagedResourcePlan{
		Authority: ResourceRequestPlanAuthority,
		ProjectID: "project-a",
		TypeID: "type-1",
		TypeDigest: testMRDigest('a'),
		Name: "orders-db",
		InputDigest: testMRDigest('b'),
		Provisioner: "product-api",
		DeletePolicy: "delete",
	}
	plan.PlanDigest = managedResourcePlanDigest(plan)
	op, err := NewManagedResourceOperation(plan, "mri_1", 4, "op-1", "idem-1", 9, ManagedResourceProvision)
	if err != nil {
		t.Fatal(err)
	}
	if op.OperationDigest == "" || !validManagedResourceOperation(op) {
		t.Fatalf("constructor must seal a valid managed resource operation: %#v", op)
	}

	invalidPolicy := plan
	invalidPolicy.DeletePolicy = ""
	invalidPolicy.PlanDigest = managedResourcePlanDigest(invalidPolicy)
	if _, err := NewManagedResourceOperation(invalidPolicy, "mri_1", 4, "op-invalid", "idem-invalid", 10, ManagedResourceProvision); err == nil {
		t.Fatal("managed resource operation constructor must reject a plan whose delete policy cannot produce a valid operation")
	}

	cases := []struct {
		name string
		mutate func(*ManagedResourceOperation)
	}{
		{"action", func(v *ManagedResourceOperation) { v.Action = ManagedResourceDelete }},
		{"delete policy", func(v *ManagedResourceOperation) { v.DeletePolicy = "retain" }},
		{"project scope", func(v *ManagedResourceOperation) { v.ProjectID = "project-b" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := op
			tc.mutate(&candidate)
			if validManagedResourceOperation(candidate) {
				t.Fatal("operation content changed after sealing must fail validation")
			}
			if got := ResolveManagedResourceOutcome(candidate, ManagedResourceOutcomeUnknown, ManagedResourceReadback{}); got.State != ManagedResourceFailed || got.RecoveryRequired {
				t.Fatalf("tampered operation must fail before outcome resolution: %#v", got)
			}
		})
	}
}
