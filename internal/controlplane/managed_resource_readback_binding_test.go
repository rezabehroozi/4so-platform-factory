package controlplane

import (
	"encoding/json"
	"testing"
)

func TestManagedResourceAmbiguousOutcomeRequiresExactOperationBoundReadback(t *testing.T) {
	plan := ManagedResourcePlan{Authority: ResourceRequestPlanAuthority, ProjectID: "project-a", TypeID: "type-1", TypeDigest: testMRDigest('a'), Name: "orders-db", InputDigest: testMRDigest('b'), PlanDigest: testMRDigest('c')}
	op, err := NewManagedResourceOperation(plan, "mri_1", 4, "op-1", "idem-1", 9, ManagedResourceProvision)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(operationID string, fenceToken int64, planDigest string) ManagedResourceReadback {
		raw, err := json.Marshal(map[string]any{
			"observed": true,
			"operationId": operationID,
			"fenceToken": fenceToken,
			"planDigest": planDigest,
			"instanceId": "mri_1",
			"revision": 5,
			"state": ManagedResourceReady,
			"observedDigest": testMRDigest('d'),
			"evidenceDigest": testMRDigest('e'),
		})
		if err != nil {
			t.Fatal(err)
		}
		var readback ManagedResourceReadback
		if err := json.Unmarshal(raw, &readback); err != nil {
			t.Fatal(err)
		}
		return readback
	}

	for name, readback := range map[string]ManagedResourceReadback{
		"wrong operation": decode("op-other", op.FenceToken, op.PlanDigest),
		"wrong fence": decode(op.OperationID, op.FenceToken+1, op.PlanDigest),
		"wrong plan": decode(op.OperationID, op.FenceToken, testMRDigest('f')),
	} {
		got := ResolveManagedResourceOutcome(op, ManagedResourceOutcomeUnknown, readback)
		if got.State != ManagedResourceRecoveryRequired || !got.RecoveryRequired || got.EvidenceDigest != "" {
			t.Fatalf("%s readback must not resolve ambiguous managed resource mutation: %#v", name, got)
		}
	}

	exact := ResolveManagedResourceOutcome(op, ManagedResourceOutcomeUnknown, decode(op.OperationID, op.FenceToken, op.PlanDigest))
	if exact.State != ManagedResourceReady || exact.RecoveryRequired || exact.EvidenceDigest == "" {
		t.Fatalf("exact operation-bound readback must resolve ambiguous managed resource mutation: %#v", exact)
	}
}
