package controlplane

import (
	"fmt"
	"strings"
	"time"
)

const (
	PromotionPolicyAuthority          = "APPLICATION_PROMOTION_POLICY_AUTHORITY_V1"
	ApplicationPromotionPlanAuthority = "APPLICATION_PROMOTION_PLAN_AUTHORITY_V1"
	PromotionHealthAuthority          = "APPLICATION_PROMOTION_HEALTH_AUTHORITY_V1"
	PromotionVerificationAuthority    = "APPLICATION_PROMOTION_VERIFICATION_AUTHORITY_V1"
	PromotionOperationAuthority       = "APPLICATION_PROMOTION_OPERATION_AUTHORITY_V1"
	PromotionVerificationTTL          = 10 * time.Minute
)

type PromotionStage struct {
	Name              string `json:"name"`
	RequiresApproval  bool   `json:"requiresApproval"`
	MinHealthyMinutes int    `json:"minHealthyMinutes"`
}

type PromotionPolicy struct {
	Authority string           `json:"authority"`
	PolicyID  string           `json:"policyId"`
	ProjectID string           `json:"projectId"`
	Revision  int64            `json:"revision"`
	Stages    []PromotionStage `json:"stages"`
}

type PromotionDesiredState struct {
	ForgejoCommitSHA      string `json:"forgejoCommitSHA"`
	DesiredStateDigest    string `json:"desiredStateDigest"`
	ReconciliationEngine string `json:"reconciliationEngine"`
}

type ApplicationPromotionPlan struct {
	Authority              string `json:"authority"`
	ProjectID              string `json:"projectId"`
	PolicyID               string `json:"policyId"`
	PolicyRevision         int64  `json:"policyRevision"`
	SourceStage            string `json:"sourceStage"`
	TargetStage            string `json:"targetStage"`
	SourceBindingID        string `json:"sourceBindingId"`
	SourceBindingRevision  int64  `json:"sourceBindingRevision"`
	SourceBindingDigest    string `json:"sourceBindingDigest"`
	SourceClusterID        string `json:"sourceClusterId"`
	SourceNamespace        string `json:"sourceNamespace"`
	TargetBindingID        string `json:"targetBindingId"`
	TargetBindingRevision  int64  `json:"targetBindingRevision"`
	TargetBindingDigest    string `json:"targetBindingDigest"`
	TargetClusterID        string `json:"targetClusterId"`
	TargetNamespace        string `json:"targetNamespace"`
	DesiredReleaseID       string `json:"desiredReleaseId"`
	DesiredReleaseDigest   string `json:"desiredReleaseDigest"`
	WorkloadImageReference string `json:"workloadImageReference"`
	ForgejoCommitSHA       string `json:"forgejoCommitSHA"`
	DesiredStateDigest     string `json:"desiredStateDigest"`
	ReconciliationEngine   string `json:"reconciliationEngine"`
	RequiresApproval       bool   `json:"requiresApproval"`
	MinHealthyMinutes      int    `json:"minHealthyMinutes"`
	PlanDigest             string `json:"planDigest"`
}

func BuildApplicationPromotionPlan(policy PromotionPolicy, release ApplicationRelease, source, target EnvironmentBinding, desired PromotionDesiredState) (ApplicationPromotionPlan, error) {
	stages, err := normalizePromotionPolicy(policy)
	if err != nil { return ApplicationPromotionPlan{}, err }
	if strings.TrimSpace(release.ID) == "" || release.Revision <= 0 || strings.TrimSpace(release.ProjectID) != strings.TrimSpace(policy.ProjectID) || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(release.Digest)) || !applicationWorkloadImagePattern.MatchString(strings.TrimSpace(release.WorkloadImageReference)) {
		return ApplicationPromotionPlan{}, fmt.Errorf("%w: desired application release authority is incomplete", ErrValidation)
	}
	if err := validatePromotionBinding(source, policy.ProjectID); err != nil { return ApplicationPromotionPlan{}, err }
	if err := validatePromotionBinding(target, policy.ProjectID); err != nil { return ApplicationPromotionPlan{}, err }
	if source.ID == target.ID { return ApplicationPromotionPlan{}, fmt.Errorf("%w: source and target promotion bindings must differ", ErrValidation) }
	if source.ReleaseID != release.ID || source.ReleaseDigest != release.Digest { return ApplicationPromotionPlan{}, fmt.Errorf("%w: source environment has not proven the desired release", ErrPrerequisite) }
	sourceIndex, targetIndex := -1, -1
	for i, stage := range stages {
		if stage.Name == strings.ToLower(strings.TrimSpace(source.Environment)) { sourceIndex = i }
		if stage.Name == strings.ToLower(strings.TrimSpace(target.Environment)) { targetIndex = i }
	}
	if sourceIndex < 0 || targetIndex < 0 || targetIndex != sourceIndex+1 { return ApplicationPromotionPlan{}, fmt.Errorf("%w: promotion must move to the immediately adjacent policy stage", ErrValidation) }
	desired.ForgejoCommitSHA = strings.ToLower(strings.TrimSpace(desired.ForgejoCommitSHA))
	desired.DesiredStateDigest = strings.ToLower(strings.TrimSpace(desired.DesiredStateDigest))
	desired.ReconciliationEngine = strings.ToLower(strings.TrimSpace(desired.ReconciliationEngine))
	if !isPromotionCommitSHA(desired.ForgejoCommitSHA) || !applicationPlatformDigestPattern.MatchString(desired.DesiredStateDigest) || desired.ReconciliationEngine != "argo-cd" {
		return ApplicationPromotionPlan{}, fmt.Errorf("%w: promotion desired state must bind exact Forgejo commit/digest and Argo CD reconciliation", ErrValidation)
	}
	targetStage := stages[targetIndex]
	plan := ApplicationPromotionPlan{
		Authority: ApplicationPromotionPlanAuthority, ProjectID: strings.TrimSpace(policy.ProjectID), PolicyID: strings.TrimSpace(policy.PolicyID), PolicyRevision: policy.Revision,
		SourceStage: stages[sourceIndex].Name, TargetStage: targetStage.Name,
		SourceBindingID: source.ID, SourceBindingRevision: source.Revision, SourceBindingDigest: source.Digest, SourceClusterID: source.ClusterID, SourceNamespace: source.Namespace,
		TargetBindingID: target.ID, TargetBindingRevision: target.Revision, TargetBindingDigest: target.Digest, TargetClusterID: target.ClusterID, TargetNamespace: target.Namespace,
		DesiredReleaseID: release.ID, DesiredReleaseDigest: release.Digest, WorkloadImageReference: release.WorkloadImageReference,
		ForgejoCommitSHA: desired.ForgejoCommitSHA, DesiredStateDigest: desired.DesiredStateDigest, ReconciliationEngine: desired.ReconciliationEngine,
		RequiresApproval: targetStage.RequiresApproval, MinHealthyMinutes: targetStage.MinHealthyMinutes,
	}
	plan.PlanDigest = digestPromotionPlan(plan)
	return plan, nil
}

func normalizePromotionPolicy(policy PromotionPolicy) ([]PromotionStage, error) {
	policy.Authority = strings.TrimSpace(policy.Authority); policy.PolicyID = strings.TrimSpace(policy.PolicyID); policy.ProjectID = strings.TrimSpace(policy.ProjectID)
	if policy.Authority != PromotionPolicyAuthority || policy.PolicyID == "" || policy.ProjectID == "" || policy.Revision <= 0 || len(policy.Stages) < 2 || len(policy.Stages) > 16 {
		return nil, fmt.Errorf("%w: promotion policy authority/scope/revision/stages are invalid", ErrValidation)
	}
	seen := map[string]bool{}; out := make([]PromotionStage, 0, len(policy.Stages))
	for _, stage := range policy.Stages {
		stage.Name = strings.ToLower(strings.TrimSpace(stage.Name))
		if !variableNamePattern.MatchString(stage.Name) || seen[stage.Name] || stage.MinHealthyMinutes < 0 || stage.MinHealthyMinutes > 10080 { return nil, fmt.Errorf("%w: promotion stage is invalid or duplicated", ErrValidation) }
		seen[stage.Name] = true; out = append(out, stage)
	}
	return out, nil
}

func validatePromotionBinding(binding EnvironmentBinding, projectID string) error {
	if strings.TrimSpace(binding.ID) == "" || binding.Revision <= 0 || strings.TrimSpace(binding.ProjectID) != strings.TrimSpace(projectID) || strings.TrimSpace(binding.Environment) == "" || strings.TrimSpace(binding.ClusterID) == "" || strings.TrimSpace(binding.Namespace) == "" || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(binding.Digest)) || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(binding.ReleaseDigest)) {
		return fmt.Errorf("%w: promotion environment binding authority is incomplete or cross-project", ErrValidation)
	}
	return nil
}

func isPromotionCommitSHA(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value)); if len(value) != 40 { return false }
	for _, r := range value { if !strings.ContainsRune("0123456789abcdef", r) { return false } }
	return true
}

type PromotionHealthObservation struct {
	Authority string `json:"authority"`; ProjectID string `json:"projectId"`; EnvironmentBindingID string `json:"environmentBindingId"`; EnvironmentBindingRevision int64 `json:"environmentBindingRevision"`; EnvironmentBindingDigest string `json:"environmentBindingDigest"`
	Complete bool `json:"complete"`; Healthy bool `json:"healthy"`; WindowStartedAt time.Time `json:"windowStartedAt"`; ObservedAt time.Time `json:"observedAt"`; EvidenceDigest string `json:"evidenceDigest"`
}

type PromotionApprovalEvidence struct { Granted bool `json:"granted"`; PlanDigest string `json:"planDigest,omitempty"`; RequesterID string `json:"requesterId"`; ApproverID string `json:"approverId"`; EvidenceDigest string `json:"evidenceDigest"` }

type PromotionVerification struct {
	Authority string `json:"authority"`; PlanDigest string `json:"planDigest"`; Verified bool `json:"verified"`; RequesterID string `json:"requesterId"`; ApproverID string `json:"approverId,omitempty"`
	DeploymentEvidenceDigest string `json:"deploymentEvidenceDigest"`; HealthEvidenceDigest string `json:"healthEvidenceDigest"`; ApprovalEvidenceDigest string `json:"approvalEvidenceDigest,omitempty"`
	VerifiedAt time.Time `json:"verifiedAt"`; ValidUntil time.Time `json:"validUntil"`; VerificationDigest string `json:"verificationDigest"`
}

func VerifyApplicationPromotion(plan ApplicationPromotionPlan, deployment ApplicationDeploymentEvidence, health PromotionHealthObservation, approval PromotionApprovalEvidence) (PromotionVerification, error) {
	if plan.Authority != ApplicationPromotionPlanAuthority || !applicationPlatformDigestPattern.MatchString(plan.PlanDigest) || digestPromotionPlan(plan) != plan.PlanDigest { return PromotionVerification{}, fmt.Errorf("%w: promotion plan authority/digest is invalid", ErrValidation) }
	if err := validatePromotionDeploymentEvidence(plan, deployment); err != nil { return PromotionVerification{}, err }
	deploymentObservedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(deployment.ObservedAt)); if err != nil { return PromotionVerification{}, fmt.Errorf("%w: deployment evidence observedAt is invalid", ErrValidation) }
	healthBindingDigest := strings.ToLower(strings.TrimSpace(health.EnvironmentBindingDigest))
	if health.Authority != PromotionHealthAuthority || strings.TrimSpace(health.ProjectID) != plan.ProjectID || strings.TrimSpace(health.EnvironmentBindingID) != plan.SourceBindingID || health.EnvironmentBindingRevision != plan.SourceBindingRevision || !applicationPlatformDigestPattern.MatchString(healthBindingDigest) || healthBindingDigest != strings.ToLower(strings.TrimSpace(plan.SourceBindingDigest)) || !health.Complete || !health.Healthy || health.WindowStartedAt.IsZero() || health.ObservedAt.IsZero() || health.ObservedAt.Before(health.WindowStartedAt) || health.WindowStartedAt.Before(deploymentObservedAt) || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(health.EvidenceDigest)) {
		return PromotionVerification{}, fmt.Errorf("%w: promotion health evidence is incomplete, unhealthy, stale or predates deployment evidence", ErrPrerequisite)
	}
	if health.ObservedAt.Sub(health.WindowStartedAt) < time.Duration(plan.MinHealthyMinutes)*time.Minute { return PromotionVerification{}, fmt.Errorf("%w: promotion health window is shorter than policy minimum", ErrPrerequisite) }
	approval.PlanDigest = strings.ToLower(strings.TrimSpace(approval.PlanDigest)); approval.RequesterID = strings.TrimSpace(approval.RequesterID); approval.ApproverID = strings.TrimSpace(approval.ApproverID); approval.EvidenceDigest = strings.ToLower(strings.TrimSpace(approval.EvidenceDigest))
	if approval.RequesterID == "" { return PromotionVerification{}, fmt.Errorf("%w: promotion requester identity is required", ErrValidation) }
	approvalDigest, approverID := "", ""
	if plan.RequiresApproval {
		if !approval.Granted || approval.PlanDigest != plan.PlanDigest || !applicationPlatformDigestPattern.MatchString(approval.PlanDigest) || approval.ApproverID == "" || approval.RequesterID == approval.ApproverID || !applicationPlatformDigestPattern.MatchString(approval.EvidenceDigest) { return PromotionVerification{}, fmt.Errorf("%w: independent promotion approval must bind the exact promotion plan", ErrPrerequisite) }
		approvalDigest, approverID = approval.EvidenceDigest, approval.ApproverID
	} else if approval.Granted || approval.PlanDigest != "" || approval.ApproverID != "" || approval.EvidenceDigest != "" { return PromotionVerification{}, fmt.Errorf("%w: approval evidence is not admitted when policy does not require approval", ErrValidation) }
	verification := PromotionVerification{Authority: PromotionVerificationAuthority, PlanDigest: plan.PlanDigest, Verified: true, RequesterID: approval.RequesterID, ApproverID: approverID, DeploymentEvidenceDigest: digestApplicationPlatformMaterial(deployment), HealthEvidenceDigest: health.EvidenceDigest, ApprovalEvidenceDigest: approvalDigest, VerifiedAt: health.ObservedAt.UTC(), ValidUntil: health.ObservedAt.UTC().Add(PromotionVerificationTTL)}
	verification.VerificationDigest = digestPromotionVerification(verification)
	return verification, nil
}

func digestPromotionPlan(plan ApplicationPromotionPlan) string { copy := plan; copy.PlanDigest = ""; return digestApplicationPlatformMaterial(copy) }
func digestPromotionVerification(v PromotionVerification) string { copy := v; copy.VerificationDigest = ""; return digestApplicationPlatformMaterial(copy) }

func validatePromotionDeploymentEvidence(plan ApplicationPromotionPlan, evidence ApplicationDeploymentEvidence) error {
	if evidence.Authority != ApplicationDeploymentEvidenceAuthority || strings.TrimSpace(evidence.ProjectID) != plan.ProjectID || strings.TrimSpace(evidence.ClusterID) != plan.SourceClusterID || strings.TrimSpace(evidence.Namespace) != plan.SourceNamespace || strings.TrimSpace(evidence.EnvironmentBindingID) != plan.SourceBindingID || evidence.EnvironmentBindingRevision != plan.SourceBindingRevision || strings.TrimSpace(evidence.ReleaseDigest) != plan.DesiredReleaseDigest || !evidence.RuntimeMutationObserved || evidence.PhysicalCertificationInferred || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(evidence.InventoryDigest)) || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(evidence.RenderedDigest)) { return fmt.Errorf("%w: exact source deployment evidence is missing or mismatched", ErrPrerequisite) }
	r := evidence.Readback
	if strings.TrimSpace(r.DeploymentName) == "" || strings.TrimSpace(r.DeploymentUID) == "" || r.Generation <= 0 || r.ObservedGeneration < r.Generation || r.DesiredReplicas <= 0 || r.UpdatedReplicas != r.DesiredReplicas || r.ReadyReplicas != r.DesiredReplicas || r.AvailableReplicas != r.DesiredReplicas || strings.TrimSpace(r.WorkloadImage) != plan.WorkloadImageReference || !r.PodTemplateAuthorityMatch || !r.ReadinessProbeMatch || !r.AutomountServiceAccountTokenDisabled || !r.AuthorityLabelsMatch || !r.AuthorityDigestsMatch { return fmt.Errorf("%w: source deployment has not converged to exact desired authority", ErrPrerequisite) }
	return nil
}

type PromotionOperationState string
const ( PromotionRequested PromotionOperationState = "REQUESTED"; PromotionRunning PromotionOperationState = "RUNNING"; PromotionSucceeded PromotionOperationState = "SUCCEEDED"; PromotionRecoveryRequired PromotionOperationState = "RECOVERY_REQUIRED"; PromotionFailed PromotionOperationState = "FAILED" )
type PromotionOutcome string
const ( PromotionOutcomeApplied PromotionOutcome = "APPLIED"; PromotionOutcomePending PromotionOutcome = "PENDING"; PromotionOutcomeUnknown PromotionOutcome = "UNKNOWN"; PromotionOutcomeFailed PromotionOutcome = "FAILED" )

type ApplicationPromotionOperation struct {
	Authority string `json:"authority"`; OperationID string `json:"operationId"`; ProjectID string `json:"projectId"`; TargetBindingID string `json:"targetBindingId"`; TargetBindingRevision int64 `json:"targetBindingRevision"`
	DesiredReleaseID string `json:"desiredReleaseId"`; DesiredReleaseDigest string `json:"desiredReleaseDigest"`; ForgejoCommitSHA string `json:"forgejoCommitSHA"`; DesiredStateDigest string `json:"desiredStateDigest"`; ReconciliationEngine string `json:"reconciliationEngine"`
	PlanDigest string `json:"planDigest"`; VerificationDigest string `json:"verificationDigest"`; IdempotencyKey string `json:"idempotencyKey"`; FenceToken int64 `json:"fenceToken"`; RequesterID string `json:"requesterId"`
}

type PromotionReadback struct {
	Observed bool `json:"observed"`; OperationID string `json:"operationId"`; FenceToken int64 `json:"fenceToken"`; PlanDigest string `json:"planDigest"`; VerificationDigest string `json:"verificationDigest"`; EnvironmentBindingID string `json:"environmentBindingId"`; Revision int64 `json:"revision"`; ReleaseID string `json:"releaseId"`; ReleaseDigest string `json:"releaseDigest"`; BindingDigest string `json:"bindingDigest"`
	ReconciliationObserved bool `json:"reconciliationObserved"`; ForgejoCommitSHA string `json:"forgejoCommitSHA"`; DesiredStateDigest string `json:"desiredStateDigest"`; ReconciliationEngine string `json:"reconciliationEngine"`; EvidenceDigest string `json:"evidenceDigest"`
}

type PromotionOperationResult struct { State PromotionOperationState `json:"state"`; RecoveryRequired bool `json:"recoveryRequired"`; RetryAllowed bool `json:"retryAllowed"`; EvidenceDigest string `json:"evidenceDigest,omitempty"`; Message string `json:"message,omitempty"` }

func promotionVerificationAdmissionComplete(plan ApplicationPromotionPlan, v PromotionVerification) bool {
	if !applicationPlatformDigestPattern.MatchString(strings.ToLower(strings.TrimSpace(v.DeploymentEvidenceDigest))) || !applicationPlatformDigestPattern.MatchString(strings.ToLower(strings.TrimSpace(v.HealthEvidenceDigest))) { return false }
	if plan.RequiresApproval {
		return strings.TrimSpace(v.ApproverID) != "" && strings.TrimSpace(v.ApproverID) != strings.TrimSpace(v.RequesterID) && applicationPlatformDigestPattern.MatchString(strings.ToLower(strings.TrimSpace(v.ApprovalEvidenceDigest)))
	}
	return strings.TrimSpace(v.ApproverID) == "" && strings.TrimSpace(v.ApprovalEvidenceDigest) == ""
}

func NewApplicationPromotionOperation(plan ApplicationPromotionPlan, verification PromotionVerification, operationID, idempotencyKey string, fenceToken int64, requesterID string, now time.Time) (ApplicationPromotionOperation, error) {
	operationID = strings.TrimSpace(operationID); idempotencyKey = strings.TrimSpace(idempotencyKey); requesterID = strings.TrimSpace(requesterID)
	projectID := strings.TrimSpace(plan.ProjectID); targetBindingID := strings.TrimSpace(plan.TargetBindingID); desiredReleaseID := strings.TrimSpace(plan.DesiredReleaseID); desiredReleaseDigest := strings.ToLower(strings.TrimSpace(plan.DesiredReleaseDigest))
	if now.IsZero() || plan.Authority != ApplicationPromotionPlanAuthority || projectID == "" || targetBindingID == "" || plan.TargetBindingRevision <= 0 || desiredReleaseID == "" || !applicationPlatformDigestPattern.MatchString(desiredReleaseDigest) || !applicationPlatformDigestPattern.MatchString(plan.PlanDigest) || digestPromotionPlan(plan) != plan.PlanDigest || !isPromotionCommitSHA(plan.ForgejoCommitSHA) || !applicationPlatformDigestPattern.MatchString(plan.DesiredStateDigest) || plan.ReconciliationEngine != "argo-cd" || verification.Authority != PromotionVerificationAuthority || !verification.Verified || verification.PlanDigest != plan.PlanDigest || !promotionVerificationAdmissionComplete(plan, verification) || !applicationPlatformDigestPattern.MatchString(verification.VerificationDigest) || digestPromotionVerification(verification) != verification.VerificationDigest || verification.RequesterID != requesterID || verification.VerifiedAt.IsZero() || verification.ValidUntil.IsZero() || !verification.ValidUntil.After(verification.VerifiedAt) || now.Before(verification.VerifiedAt) || !now.Before(verification.ValidUntil) || operationID == "" || idempotencyKey == "" || requesterID == "" || fenceToken <= 0 {
		return ApplicationPromotionOperation{}, fmt.Errorf("%w: promotion operation requires complete fresh exact verified plan/evidence, requester identity and fence", ErrValidation)
	}
	return ApplicationPromotionOperation{Authority: PromotionOperationAuthority, OperationID: operationID, ProjectID: projectID, TargetBindingID: targetBindingID, TargetBindingRevision: plan.TargetBindingRevision, DesiredReleaseID: desiredReleaseID, DesiredReleaseDigest: desiredReleaseDigest, ForgejoCommitSHA: strings.ToLower(strings.TrimSpace(plan.ForgejoCommitSHA)), DesiredStateDigest: strings.ToLower(strings.TrimSpace(plan.DesiredStateDigest)), ReconciliationEngine: strings.ToLower(strings.TrimSpace(plan.ReconciliationEngine)), PlanDigest: plan.PlanDigest, VerificationDigest: verification.VerificationDigest, IdempotencyKey: idempotencyKey, FenceToken: fenceToken, RequesterID: requesterID}, nil
}

func ResolveApplicationPromotionOutcome(op ApplicationPromotionOperation, outcome PromotionOutcome, readback PromotionReadback) PromotionOperationResult {
	if op.Authority != PromotionOperationAuthority || strings.TrimSpace(op.OperationID) == "" || strings.TrimSpace(op.ProjectID) == "" || strings.TrimSpace(op.TargetBindingID) == "" || op.TargetBindingRevision <= 0 || strings.TrimSpace(op.DesiredReleaseID) == "" || strings.TrimSpace(op.IdempotencyKey) == "" || strings.TrimSpace(op.RequesterID) == "" || op.FenceToken <= 0 || !applicationPlatformDigestPattern.MatchString(op.DesiredReleaseDigest) || !applicationPlatformDigestPattern.MatchString(op.PlanDigest) || !applicationPlatformDigestPattern.MatchString(op.VerificationDigest) || !isPromotionCommitSHA(op.ForgejoCommitSHA) || !applicationPlatformDigestPattern.MatchString(op.DesiredStateDigest) || op.ReconciliationEngine != "argo-cd" {
		return PromotionOperationResult{State: PromotionFailed, Message: "promotion operation authority is invalid"}
	}
	converged := readback.Observed && strings.TrimSpace(readback.OperationID) == op.OperationID && readback.FenceToken == op.FenceToken && strings.ToLower(strings.TrimSpace(readback.PlanDigest)) == op.PlanDigest && strings.ToLower(strings.TrimSpace(readback.VerificationDigest)) == op.VerificationDigest && strings.TrimSpace(readback.EnvironmentBindingID) == op.TargetBindingID && readback.Revision > op.TargetBindingRevision && strings.TrimSpace(readback.ReleaseID) == op.DesiredReleaseID && strings.ToLower(strings.TrimSpace(readback.ReleaseDigest)) == op.DesiredReleaseDigest && applicationPlatformDigestPattern.MatchString(strings.ToLower(strings.TrimSpace(readback.BindingDigest))) && readback.ReconciliationObserved && strings.ToLower(strings.TrimSpace(readback.ForgejoCommitSHA)) == op.ForgejoCommitSHA && strings.ToLower(strings.TrimSpace(readback.DesiredStateDigest)) == op.DesiredStateDigest && strings.ToLower(strings.TrimSpace(readback.ReconciliationEngine)) == op.ReconciliationEngine && applicationPlatformDigestPattern.MatchString(strings.ToLower(strings.TrimSpace(readback.EvidenceDigest)))
	switch outcome {
	case PromotionOutcomeUnknown:
		if converged { return PromotionOperationResult{State: PromotionSucceeded, EvidenceDigest: strings.ToLower(strings.TrimSpace(readback.EvidenceDigest)), Message: "ambiguous promotion resolved by exact target and GitOps readback"} }
		return PromotionOperationResult{State: PromotionRecoveryRequired, RecoveryRequired: true, RetryAllowed: false, Message: "promotion outcome is ambiguous; exact target and GitOps readback is required"}
	case PromotionOutcomeApplied:
		if converged { return PromotionOperationResult{State: PromotionSucceeded, EvidenceDigest: strings.ToLower(strings.TrimSpace(readback.EvidenceDigest))} }
		return PromotionOperationResult{State: PromotionRunning, Message: "promotion accepted; target/GitOps authority has not converged"}
	case PromotionOutcomePending: return PromotionOperationResult{State: PromotionRunning}
	case PromotionOutcomeFailed: return PromotionOperationResult{State: PromotionFailed, RetryAllowed: false, Message: "promotion failed"}
	default: return PromotionOperationResult{State: PromotionFailed, Message: "unsupported promotion outcome"}
	}
}
