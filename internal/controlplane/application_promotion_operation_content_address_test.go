package controlplane

import (
	"strings"
	"testing"
)

func TestPromotionOperationRejectsTamperedOperationContentAddress(t *testing.T) {
	op := ApplicationPromotionOperation{
		Authority: PromotionOperationAuthority,
		OperationID: "op-1",
		ProjectID: "project-a",
		TargetBindingID: "dst",
		TargetBindingRevision: 7,
		DesiredReleaseID: "rel-new",
		DesiredReleaseDigest: promotionDigest('a'),
		ForgejoCommitSHA: strings.Repeat("a", 40),
		DesiredStateDigest: promotionDigest('b'),
		ReconciliationEngine: "argo-cd",
		PlanDigest: promotionDigest('c'),
		VerificationDigest: promotionDigest('d'),
		IdempotencyKey: "idem-1",
		FenceToken: 11,
		RequesterID: "user-requester",
	}
	op.OperationDigest = digestApplicationPromotionOperation(op)
	if got := ResolveApplicationPromotionOutcome(op, PromotionOutcomePending, PromotionReadback{}); got.State != PromotionRunning {
		t.Fatalf("sealed promotion operation must remain valid: %#v", got)
	}

	cases := []struct {
		name string
		mutate func(*ApplicationPromotionOperation)
	}{
		{"desired release", func(v *ApplicationPromotionOperation) { v.DesiredReleaseID = "rel-other" }},
		{"requester", func(v *ApplicationPromotionOperation) { v.RequesterID = "user-other" }},
		{"project scope", func(v *ApplicationPromotionOperation) { v.ProjectID = "project-b" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := op
			tc.mutate(&candidate)
			if got := ResolveApplicationPromotionOutcome(candidate, PromotionOutcomePending, PromotionReadback{}); got.State != PromotionFailed {
				t.Fatalf("promotion operation content changed after sealing must fail: %#v", got)
			}
		})
	}
}
