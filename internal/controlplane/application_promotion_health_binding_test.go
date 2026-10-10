package controlplane

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPromotionVerificationRejectsHealthEvidenceFromStaleBindingRevision(t *testing.T) {
	now := time.Date(2026, 10, 10, 15, 30, 0, 0, time.UTC)
	policy := PromotionPolicy{Authority: PromotionPolicyAuthority, PolicyID: "policy-1", ProjectID: "project-a", Revision: 3, Stages: []PromotionStage{{Name: "stage"}, {Name: "prod", RequiresApproval: true, MinHealthyMinutes: 30}}}
	release := promotionRelease()
	source := promotionBinding("src", "stage", release.ID, release.Digest, 4)
	target := promotionBinding("dst", "prod", "old-release", promotionDigest('b'), 7)
	plan, err := BuildApplicationPromotionPlan(policy, release, source, target, PromotionDesiredState{ForgejoCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DesiredStateDigest: promotionDigest('c'), ReconciliationEngine: "argo-cd"})
	if err != nil {
		t.Fatal(err)
	}
	deployedAt := now.Add(-31 * time.Minute)
	evidence := promotionDeploymentEvidence(source, release, deployedAt)
	rawHealth, err := json.Marshal(map[string]any{
		"authority": PromotionHealthAuthority,
		"projectId": "project-a",
		"environmentBindingId": source.ID,
		"environmentBindingRevision": source.Revision - 1,
		"environmentBindingDigest": promotionDigest('9'),
		"complete": true,
		"healthy": true,
		"windowStartedAt": now.Add(-30 * time.Minute),
		"observedAt": now,
		"evidenceDigest": promotionDigest('d'),
	})
	if err != nil {
		t.Fatal(err)
	}
	var health PromotionHealthObservation
	if err := json.Unmarshal(rawHealth, &health); err != nil {
		t.Fatal(err)
	}
	approval := PromotionApprovalEvidence{Granted: true, PlanDigest: plan.PlanDigest, RequesterID: "user-requester", ApproverID: "user-approver", EvidenceDigest: promotionDigest('e')}
	if _, err := VerifyApplicationPromotion(plan, evidence, health, approval); err == nil {
		t.Fatal("health evidence from an older environment binding revision must not authorize promotion")
	}
}
