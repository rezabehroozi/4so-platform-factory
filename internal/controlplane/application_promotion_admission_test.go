package controlplane

import (
	"testing"
	"time"
)

func TestPromotionOperationRejectsIncompleteAuthorityPacket(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	plan := ApplicationPromotionPlan{
		Authority: ApplicationPromotionPlanAuthority,
		ForgejoCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DesiredStateDigest: promotionDigest('a'),
		ReconciliationEngine: "argo-cd",
	}
	plan.PlanDigest = digestPromotionPlan(plan)
	verification := PromotionVerification{
		Authority: PromotionVerificationAuthority,
		PlanDigest: plan.PlanDigest,
		Verified: true,
		RequesterID: "user-requester",
		VerifiedAt: now,
		ValidUntil: now.Add(PromotionVerificationTTL),
	}
	verification.VerificationDigest = digestPromotionVerification(verification)
	if _, err := NewApplicationPromotionOperation(plan, verification, "op-1", "idem-1", 11, "user-requester", now); err == nil {
		t.Fatal("self-consistent digest must not admit an incomplete promotion scope/release packet")
	}
}

func TestPromotionVerificationExpiresAtBoundary(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	plan := ApplicationPromotionPlan{
		Authority: ApplicationPromotionPlanAuthority,
		ProjectID: "project-a",
		TargetBindingID: "dst",
		TargetBindingRevision: 7,
		DesiredReleaseID: "rel-new",
		DesiredReleaseDigest: promotionDigest('a'),
		ForgejoCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DesiredStateDigest: promotionDigest('b'),
		ReconciliationEngine: "argo-cd",
	}
	plan.PlanDigest = digestPromotionPlan(plan)
	verification := PromotionVerification{
		Authority: PromotionVerificationAuthority,
		PlanDigest: plan.PlanDigest,
		Verified: true,
		RequesterID: "user-requester",
		VerifiedAt: now,
		ValidUntil: now.Add(PromotionVerificationTTL),
	}
	verification.VerificationDigest = digestPromotionVerification(verification)
	if _, err := NewApplicationPromotionOperation(plan, verification, "op-1", "idem-1", 11, "user-requester", verification.ValidUntil); err == nil {
		t.Fatal("promotion verification must be expired at the exact ValidUntil boundary")
	}
}
