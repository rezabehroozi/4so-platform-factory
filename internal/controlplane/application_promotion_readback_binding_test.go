package controlplane

import (
	"strings"
	"testing"
)

func TestPromotionReadbackRequiresExactOperationFencePlanAndVerificationBinding(t *testing.T) {
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
	readback := PromotionReadback{
		Observed: true,
		OperationID: op.OperationID,
		FenceToken: op.FenceToken,
		PlanDigest: op.PlanDigest,
		VerificationDigest: op.VerificationDigest,
		EnvironmentBindingID: op.TargetBindingID,
		Revision: 8,
		ReleaseID: op.DesiredReleaseID,
		ReleaseDigest: op.DesiredReleaseDigest,
		BindingDigest: promotionDigest('e'),
		ReconciliationObserved: true,
		ForgejoCommitSHA: op.ForgejoCommitSHA,
		DesiredStateDigest: op.DesiredStateDigest,
		ReconciliationEngine: op.ReconciliationEngine,
		EvidenceDigest: promotionDigest('f'),
	}

	if got := ResolveApplicationPromotionOutcome(op, PromotionOutcomeUnknown, readback); got.State != PromotionSucceeded {
		t.Fatalf("exact operation-bound promotion readback must resolve ambiguity: %#v", got)
	}

	cases := []struct {
		name string
		mutate func(*PromotionReadback)
	}{
		{"foreign operation", func(r *PromotionReadback) { r.OperationID = "op-2" }},
		{"stale fence", func(r *PromotionReadback) { r.FenceToken-- }},
		{"foreign plan", func(r *PromotionReadback) { r.PlanDigest = promotionDigest('1') }},
		{"foreign verification", func(r *PromotionReadback) { r.VerificationDigest = promotionDigest('2') }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := readback
			tc.mutate(&candidate)
			got := ResolveApplicationPromotionOutcome(op, PromotionOutcomeUnknown, candidate)
			if got.State != PromotionRecoveryRequired || !got.RecoveryRequired || got.RetryAllowed {
				t.Fatalf("mismatched promotion readback must stay recovery-required: %#v", got)
			}
		})
	}

	invalid := op
	invalid.OperationID = ""
	if got := ResolveApplicationPromotionOutcome(invalid, PromotionOutcomeUnknown, readback); got.State != PromotionFailed {
		t.Fatalf("promotion outcome resolver must reject incomplete operation identity: %#v", got)
	}
}
