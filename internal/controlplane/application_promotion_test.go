package controlplane

import (
	"testing"
	"time"
)

func TestPromotionPlanRequiresAdjacentPolicyStageAndExactDesiredState(t *testing.T) {
	policy := PromotionPolicy{Authority: PromotionPolicyAuthority, PolicyID: "policy-1", ProjectID: "project-a", Revision: 3, Stages: []PromotionStage{{Name: "dev"}, {Name: "stage", MinHealthyMinutes: 15}, {Name: "prod", RequiresApproval: true, MinHealthyMinutes: 30}}}
	release := promotionRelease()
	source := promotionBinding("src", "stage", release.ID, release.Digest, 4)
	target := promotionBinding("dst", "prod", "old-release", promotionDigest('b'), 7)
	plan, err := BuildApplicationPromotionPlan(policy, release, source, target, PromotionDesiredState{ForgejoCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DesiredStateDigest: promotionDigest('c'), ReconciliationEngine: "argo-cd"})
	if err != nil { t.Fatal(err) }
	if plan.Authority != ApplicationPromotionPlanAuthority || plan.PlanDigest == "" || plan.SourceStage != "stage" || plan.TargetStage != "prod" || !plan.RequiresApproval || plan.MinHealthyMinutes != 30 { t.Fatalf("promotion plan drift: %#v", plan) }
	skipped := source; skipped.Environment = "dev"
	if _, err := BuildApplicationPromotionPlan(policy, release, skipped, target, PromotionDesiredState{ForgejoCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DesiredStateDigest: promotionDigest('c'), ReconciliationEngine: "argo-cd"}); err == nil { t.Fatal("promotion must not skip policy stages") }
	if _, err := BuildApplicationPromotionPlan(policy, release, source, target, PromotionDesiredState{ForgejoCommitSHA: "not-a-commit", DesiredStateDigest: promotionDigest('c'), ReconciliationEngine: "argo-cd"}); err == nil { t.Fatal("promotion desired state must bind exact Forgejo commit") }
}

func TestPromotionVerificationReusesExactDeploymentEvidenceAndHealthWindow(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	policy := PromotionPolicy{Authority: PromotionPolicyAuthority, PolicyID: "policy-1", ProjectID: "project-a", Revision: 3, Stages: []PromotionStage{{Name: "stage"}, {Name: "prod", RequiresApproval: true, MinHealthyMinutes: 30}}}
	release := promotionRelease()
	source := promotionBinding("src", "stage", release.ID, release.Digest, 4)
	target := promotionBinding("dst", "prod", "old-release", promotionDigest('b'), 7)
	plan, err := BuildApplicationPromotionPlan(policy, release, source, target, PromotionDesiredState{ForgejoCommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DesiredStateDigest: promotionDigest('c'), ReconciliationEngine: "argo-cd"})
	if err != nil { t.Fatal(err) }
	deployedAt := now.Add(-31*time.Minute)
	evidence := promotionDeploymentEvidence(source, release, deployedAt)
	health := PromotionHealthObservation{Authority: PromotionHealthAuthority, ProjectID: "project-a", EnvironmentBindingID: source.ID, Complete: true, Healthy: true, WindowStartedAt: now.Add(-30*time.Minute), ObservedAt: now, EvidenceDigest: promotionDigest('d')}
	approval := PromotionApprovalEvidence{Granted: true, RequesterID: "user-requester", ApproverID: "user-approver", EvidenceDigest: promotionDigest('e')}
	verification, err := VerifyApplicationPromotion(plan, evidence, health, approval)
	if err != nil { t.Fatal(err) }
	if verification.Authority != PromotionVerificationAuthority || !verification.Verified || verification.VerificationDigest == "" { t.Fatalf("promotion verification drift: %#v", verification) }
	staleHealth := health; staleHealth.WindowStartedAt = now.Add(-5*time.Minute)
	if _, err := VerifyApplicationPromotion(plan, evidence, staleHealth, approval); err == nil { t.Fatal("insufficient health window must block promotion") }
	preDeployHealth := health; preDeployHealth.WindowStartedAt = deployedAt.Add(-time.Minute)
	if _, err := VerifyApplicationPromotion(plan, evidence, preDeployHealth, approval); err == nil { t.Fatal("health window beginning before deployment evidence must be rejected") }
	selfApproval := approval; selfApproval.ApproverID = selfApproval.RequesterID
	if _, err := VerifyApplicationPromotion(plan, evidence, health, selfApproval); err == nil { t.Fatal("requester self-approval must be rejected") }
	evidence.Readback.ReadyReplicas = 0
	if _, err := VerifyApplicationPromotion(plan, evidence, health, approval); err == nil { t.Fatal("non-converged source deployment must block promotion") }
}

func TestPromotionUnknownOutcomeRequiresExactTargetReadbackWithoutReplay(t *testing.T) {
	plan := ApplicationPromotionPlan{Authority: ApplicationPromotionPlanAuthority, ProjectID: "project-a", TargetBindingID: "dst", TargetBindingRevision: 7, DesiredReleaseID: "rel-new", DesiredReleaseDigest: promotionDigest('a'), PlanDigest: promotionDigest('b')}
	verification := PromotionVerification{Authority: PromotionVerificationAuthority, PlanDigest: plan.PlanDigest, Verified: true, VerificationDigest: promotionDigest('c')}
	op, err := NewApplicationPromotionOperation(plan, verification, "op-1", "idem-1", 11, "user-requester")
	if err != nil { t.Fatal(err) }
	unknown := ResolveApplicationPromotionOutcome(op, PromotionOutcomeUnknown, PromotionReadback{})
	if unknown.State != PromotionRecoveryRequired || !unknown.RecoveryRequired || unknown.RetryAllowed { t.Fatalf("unknown promotion outcome must require recovery: %#v", unknown) }
	resolved := ResolveApplicationPromotionOutcome(op, PromotionOutcomeUnknown, PromotionReadback{Observed: true, EnvironmentBindingID: "dst", Revision: 8, ReleaseID: "rel-new", ReleaseDigest: promotionDigest('a'), BindingDigest: promotionDigest('d'), EvidenceDigest: promotionDigest('e')})
	if resolved.State != PromotionSucceeded || resolved.RecoveryRequired || resolved.EvidenceDigest == "" { t.Fatalf("exact promotion readback must resolve ambiguity: %#v", resolved) }
	stale := ResolveApplicationPromotionOutcome(op, PromotionOutcomeUnknown, PromotionReadback{Observed: true, EnvironmentBindingID: "dst", Revision: 7, ReleaseID: "rel-new", ReleaseDigest: promotionDigest('a'), BindingDigest: promotionDigest('d'), EvidenceDigest: promotionDigest('e')})
	if stale.State != PromotionRecoveryRequired { t.Fatalf("stale target readback must not resolve promotion: %#v", stale) }
}

func promotionRelease() ApplicationRelease {
	return ApplicationRelease{ResourceMeta: ResourceMeta{ID: "rel-new", Revision: 5}, ProjectID: "project-a", Name: "orders", Version: "2.0.0", WorkloadImageReference: "registry.internal/orders@"+promotionDigest('f'), SourceDigest: promotionDigest('1'), Digest: promotionDigest('a')}
}

func promotionBinding(id, environment, releaseID, releaseDigest string, revision int64) EnvironmentBinding {
	return EnvironmentBinding{ResourceMeta: ResourceMeta{ID: id, Revision: revision}, ProjectID: "project-a", ReleaseID: releaseID, ReleaseDigest: releaseDigest, WorkspaceID: "ws-1", WorkspaceBindingID: "wsb-1", WorkspaceBindingRevision: 2, ClusterID: "cluster-a", Namespace: "orders", Environment: environment, CapabilityResolutionDigest: promotionDigest('2'), Digest: promotionDigest('3')}
}

func promotionDeploymentEvidence(binding EnvironmentBinding, release ApplicationRelease, observedAt time.Time) ApplicationDeploymentEvidence {
	return ApplicationDeploymentEvidence{Authority: ApplicationDeploymentEvidenceAuthority, OperationID: "deploy-op", ProjectID: binding.ProjectID, ClusterID: binding.ClusterID, Namespace: binding.Namespace, EnvironmentBindingID: binding.ID, EnvironmentBindingRevision: binding.Revision, ReleaseDigest: release.Digest, InventoryDigest: promotionDigest('4'), RenderedDigest: promotionDigest('5'), ObservedAt: observedAt.Format(time.RFC3339Nano), RuntimeMutationObserved: true, PhysicalCertificationInferred: false, Readback: ApplicationDeploymentReadback{DeploymentName: "orders", DeploymentUID: "uid-1", Generation: 3, ObservedGeneration: 3, DesiredReplicas: 2, UpdatedReplicas: 2, ReadyReplicas: 2, AvailableReplicas: 2, WorkloadImage: release.WorkloadImageReference, PodTemplateAuthorityMatch: true, ReadinessProbeMatch: true, AutomountServiceAccountTokenDisabled: true, AuthorityLabelsMatch: true, AuthorityDigestsMatch: true}}
}

func promotionDigest(ch byte) string { buf:=make([]byte,64); for i:=range buf { buf[i]=ch }; return "sha256:"+string(buf) }
