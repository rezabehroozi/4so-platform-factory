package controlplane

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	PromotionPolicyAuthority          = "APPLICATION_PROMOTION_POLICY_AUTHORITY_V1"
	ApplicationPromotionPlanAuthority = "APPLICATION_PROMOTION_PLAN_AUTHORITY_V1"
	PromotionHealthAuthority          = "APPLICATION_PROMOTION_HEALTH_AUTHORITY_V1"
	PromotionVerificationAuthority    = "APPLICATION_PROMOTION_VERIFICATION_AUTHORITY_V1"
	PromotionOperationAuthority       = "APPLICATION_PROMOTION_OPERATION_AUTHORITY_V1"
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
	Authority                string `json:"authority"`
	ProjectID                string `json:"projectId"`
	PolicyID                 string `json:"policyId"`
	PolicyRevision           int64  `json:"policyRevision"`
	SourceStage              string `json:"sourceStage"`
	TargetStage              string `json:"targetStage"`
	SourceBindingID          string `json:"sourceBindingId"`
	SourceBindingRevision    int64  `json:"sourceBindingRevision"`
	SourceBindingDigest      string `json:"sourceBindingDigest"`
	TargetBindingID          string `json:"targetBindingId"`
	TargetBindingRevision    int64  `json:"targetBindingRevision"`
	TargetBindingDigest      string `json:"targetBindingDigest"`
	DesiredReleaseID         string `json:"desiredReleaseId"`
	DesiredReleaseDigest     string `json:"desiredReleaseDigest"`
	WorkloadImageReference   string `json:"workloadImageReference"`
	ForgejoCommitSHA         string `json:"forgejoCommitSHA"`
	DesiredStateDigest       string `json:"desiredStateDigest"`
	ReconciliationEngine     string `json:"reconciliationEngine"`
	RequiresApproval         bool   `json:"requiresApproval"`
	MinHealthyMinutes        int    `json:"minHealthyMinutes"`
	PlanDigest               string `json:"planDigest"`
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
	if source.ReleaseID != release.ID || source.ReleaseDigest != release.Digest {
		return ApplicationPromotionPlan{}, fmt.Errorf("%w: source environment has not proven the desired release", ErrPrerequisite)
	}
	sourceIndex, targetIndex := -1, -1
	for i, stage := range stages {
		if stage.Name == strings.ToLower(strings.TrimSpace(source.Environment)) { sourceIndex = i }
		if stage.Name == strings.ToLower(strings.TrimSpace(target.Environment)) { targetIndex = i }
	}
	if sourceIndex < 0 || targetIndex < 0 || targetIndex != sourceIndex+1 {
		return ApplicationPromotionPlan{}, fmt.Errorf("%w: promotion must move to the immediately adjacent policy stage", ErrValidation)
	}
	desired.ForgejoCommitSHA = strings.ToLower(strings.TrimSpace(desired.ForgejoCommitSHA))
	desired.DesiredStateDigest = strings.ToLower(strings.TrimSpace(desired.DesiredStateDigest))
	desired.ReconciliationEngine = strings.ToLower(strings.TrimSpace(desired.ReconciliationEngine))
	if !commitSHAPattern.MatchString(desired.ForgejoCommitSHA) || !applicationPlatformDigestPattern.MatchString(desired.DesiredStateDigest) || desired.ReconciliationEngine != "argo-cd" {
		return ApplicationPromotionPlan{}, fmt.Errorf("%w: promotion desired state must bind exact Forgejo commit/digest and Argo CD reconciliation", ErrValidation)
	}
	targetStage := stages[targetIndex]
	plan := ApplicationPromotionPlan{
		Authority: ApplicationPromotionPlanAuthority, ProjectID: policy.ProjectID, PolicyID: strings.TrimSpace(policy.PolicyID), PolicyRevision: policy.Revision,
		SourceStage: stages[sourceIndex].Name, TargetStage: targetStage.Name,
		SourceBindingID: source.ID, SourceBindingRevision: source.Revision, SourceBindingDigest: source.Digest,
		TargetBindingID: target.ID, TargetBindingRevision: target.Revision, TargetBindingDigest: target.Digest,
		DesiredReleaseID: release.ID, DesiredReleaseDigest: release.Digest, WorkloadImageReference: release.WorkloadImageReference,
		ForgejoCommitSHA: desired.ForgejoCommitSHA, DesiredStateDigest: desired.DesiredStateDigest, ReconciliationEngine: desired.ReconciliationEngine,
		RequiresApproval: targetStage.RequiresApproval, MinHealthyMinutes: targetStage.MinHealthyMinutes,
	}
	plan.PlanDigest = digestApplicationPlatformMaterial(plan)
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
		if !variableNamePattern.MatchString(stage.Name) || seen[stage.Name] || stage.MinHealthyMinutes < 0 || stage.MinHealthyMinutes > 10080 {
			return nil, fmt.Errorf("%w: promotion stage is invalid or duplicated", ErrValidation)
		}
		seen[stage.Name] = true; out = append(out, stage)
	}
	return out, nil
}

func validatePromotionBinding(binding EnvironmentBinding, projectID string) error {
	if strings.TrimSpace(binding.ID) == "" || binding.Revision <= 0 || strings.TrimSpace(binding.ProjectID) != strings.TrimSpace(projectID) || strings.TrimSpace(binding.Environment) == "" || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(binding.Digest)) || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(binding.ReleaseDigest)) {
		return fmt.Errorf("%w: promotion environment binding authority is incomplete or cross-project", ErrValidation)
	}
	return nil
}

type PromotionHealthObservation struct {
	Authority            string    `json:"authority"`
	ProjectID            string    `json:"projectId"`
	EnvironmentBindingID string    `json:"environmentBindingId"`
	Complete             bool      `json:"complete"`
	Healthy              bool      `json:"healthy"`
	WindowStartedAt      time.Time `json:"windowStartedAt"`
	ObservedAt           time.Time `json:"observedAt"`
	EvidenceDigest       string    `json:"evidenceDigest"`
}

type PromotionApprovalEvidence struct {
	Granted        bool   `json:"granted"`
	RequesterID    string `json:"requesterId"`
	ApproverID     string `json:"approverId"`
	EvidenceDigest string `json:"evidenceDigest"`
}

type PromotionVerification struct {
	Authority                string   `json:"authority"`
	PlanDigest               string   `json:"planDigest"`
	Verified                 bool     `json:"verified"`
	DeploymentEvidenceDigest string   `json:"deploymentEvidenceDigest"`
	HealthEvidenceDigest     string   `json:"healthEvidenceDigest"`
	ApprovalEvidenceDigest   string   `json:"approvalEvidenceDigest,omitempty"`
	VerificationDigest       string   `json:"verificationDigest"`
}

func VerifyApplicationPromotion(plan ApplicationPromotionPlan, deployment ApplicationDeploymentEvidence, health PromotionHealthObservation, approval PromotionApprovalEvidence) (PromotionVerification, error) {
	if plan.Authority != ApplicationPromotionPlanAuthority || !applicationPlatformDigestPattern.MatchString(plan.PlanDigest) || digestPromotionPlan(plan) != plan.PlanDigest {
		return PromotionVerification{}, fmt.Errorf("%w: promotion plan authority/digest is invalid", ErrValidation)
	}
	if err := validatePromotionDeploymentEvidence(plan, deployment); err != nil { return PromotionVerification{}, err }
	deploymentObservedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(deployment.ObservedAt))
	if err != nil { return PromotionVerification{}, fmt.Errorf("%w: deployment evidence observedAt is invalid", ErrValidation) }
	if health.Authority != PromotionHealthAuthority || health.ProjectID != plan.ProjectID || health.EnvironmentBindingID != plan.SourceBindingID || !health.Complete || !health.Healthy || health.WindowStartedAt.IsZero() || health.ObservedAt.IsZero() || health.ObservedAt.Before(health.WindowStartedAt) || health.WindowStartedAt.Before(deploymentObservedAt) || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(health.EvidenceDigest)) {
		return PromotionVerification{}, fmt.Errorf("%w: promotion health evidence is incomplete, unhealthy, stale or predates deployment evidence", ErrPrerequisite)
	}
	if health.ObservedAt.Sub(health.WindowStartedAt) < time.Duration(plan.MinHealthyMinutes)*time.Minute {
		return PromotionVerification{}, fmt.Errorf("%w: promotion health window is shorter than policy minimum", ErrPrerequisite)
	}
	approvalDigest := ""
	if plan.RequiresApproval {
		approval.RequesterID = strings.TrimSpace(approval.RequesterID); approval.ApproverID = strings.TrimSpace(approval.ApproverID); approval.EvidenceDigest = strings.ToLower(strings.TrimSpace(approval.EvidenceDigest))
		if !approval.Granted || approval.RequesterID == "" || approval.ApproverID == "" || approval.RequesterID == approval.ApproverID || !applicationPlatformDigestPattern.MatchString(approval.EvidenceDigest) {
			return PromotionVerification{}, fmt.Errorf("%w: independent promotion approval is required", ErrPrerequisite)
		}
		approvalDigest = approval.EvidenceDigest
	}
	deploymentDigest := digestApplicationPlatformMaterial(deployment)
	verification := PromotionVerification{Authority: PromotionVerificationAuthority, PlanDigest: plan.PlanDigest, Verified: true, DeploymentEvidenceDigest: deploymentDigest, HealthEvidenceDigest: health.EvidenceDigest, ApprovalEvidenceDigest: approvalDigest}
	verification.VerificationDigest = digestApplicationPlatformMaterial(verification)
	return verification, nil
}

func digestPromotionPlan(plan ApplicationPromotionPlan) string {
	copy := plan; copy.PlanDigest = ""; return digestApplicationPlatformMaterial(copy)
}

func validatePromotionDeploymentEvidence(plan ApplicationPromotionPlan, evidence ApplicationDeploymentEvidence) error {
	if evidence.Authority != ApplicationDeploymentEvidenceAuthority || evidence.ProjectID != plan.ProjectID || evidence.EnvironmentBindingID != plan.SourceBindingID || evidence.EnvironmentBindingRevision != plan.SourceBindingRevision || evidence.ReleaseDigest != plan.DesiredReleaseDigest || !evidence.RuntimeMutationObserved || evidence.PhysicalCertificationInferred || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(evidence.InventoryDigest)) || !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(evidence.RenderedDigest)) {
		return fmt.Errorf("%w: exact source deployment evidence is missing or mismatched", ErrPrerequisite)
	}
	r := evidence.Readback
	if strings.TrimSpace(r.DeploymentName) == "" || strings.TrimSpace(r.DeploymentUID) == "" || r.Generation <= 0 || r.ObservedGeneration < r.Generation || r.DesiredReplicas <= 0 || r.UpdatedReplicas != r.DesiredReplicas || r.ReadyReplicas != r.DesiredReplicas || r.AvailableReplicas != r.DesiredReplicas || strings.TrimSpace(r.WorkloadImage) != plan.WorkloadImageReference || !r.PodTemplateAuthorityMatch || !r.ReadinessProbeMatch || !r.AutomountServiceAccountTokenDisabled || !r.AuthorityLabelsMatch || !r.AuthorityDigestsMatch {
		return fmt.Errorf("%w: source deployment has not converged to exact desired authority", ErrPrerequisite)
	}
	return nil
}

type PromotionOperationState string
const ( PromotionRequested PromotionOperationState = "REQUESTED"; PromotionRunning PromotionOperationState = "RUNNING"; PromotionSucceeded PromotionOperationState = "SUCCEEDED"; PromotionRecoveryRequired PromotionOperationState = "RECOVERY_REQUIRED"; PromotionFailed PromotionOperationState = "FAILED" )
type PromotionOutcome string
const ( PromotionOutcomeApplied PromotionOutcome = "APPLIED"; PromotionOutcomePending PromotionOutcome = "PENDING"; PromotionOutcomeUnknown PromotionOutcome = "UNKNOWN"; PromotionOutcomeFailed PromotionOutcome = "FAILED" )

type ApplicationPromotionOperation struct {
	Authority             string `json:"authority"`
	OperationID           string `json:"operationId"`
	ProjectID             string `json:"projectId"`
	TargetBindingID       string `json:"targetBindingId"`
	TargetBindingRevision int64  `json:"targetBindingRevision"`
	DesiredReleaseID      string `json:"desiredReleaseId"`
	DesiredReleaseDigest  string `json:"desiredReleaseDigest"`
	PlanDigest            string `json:"planDigest"`
	VerificationDigest    string `json:"verificationDigest"`
	IdempotencyKey        string `json:"idempotencyKey"`
	FenceToken            int64  `json:"fenceToken"`
	RequesterID           string `json:"requesterId"`
}

type PromotionReadback struct {
	Observed             bool   `json:"observed"`
	EnvironmentBindingID string `json:"environmentBindingId"`
	Revision             int64  `json:"revision"`
	ReleaseID            string `json:"releaseId"`
	ReleaseDigest        string `json:"releaseDigest"`
	BindingDigest        string `json:"bindingDigest"`
	EvidenceDigest       string `json:"evidenceDigest"`
}

type PromotionOperationResult struct { State PromotionOperationState `json:"state"`; RecoveryRequired bool `json:"recoveryRequired"`; RetryAllowed bool `json:"retryAllowed"`; EvidenceDigest string `json:"evidenceDigest,omitempty"`; Message string `json:"message,omitempty"` }

func NewApplicationPromotionOperation(plan ApplicationPromotionPlan, verification PromotionVerification, operationID, idempotencyKey string, fenceToken int64, requesterID string) (ApplicationPromotionOperation, error) {
	operationID = strings.TrimSpace(operationID); idempotencyKey = strings.TrimSpace(idempotencyKey); requesterID = strings.TrimSpace(requesterID)
	if plan.Authority != ApplicationPromotionPlanAuthority || !applicationPlatformDigestPattern.MatchString(plan.PlanDigest) || verification.Authority != PromotionVerificationAuthority || !verification.Verified || verification.PlanDigest != plan.PlanDigest || !applicationPlatformDigestPattern.MatchString(verification.VerificationDigest) || operationID == "" || idempotencyKey == "" || requesterID == "" || fenceToken <= 0 {
		return ApplicationPromotionOperation{}, fmt.Errorf("%w: promotion operation requires verified plan, identity and fence", ErrValidation)
	}
	return ApplicationPromotionOperation{Authority: PromotionOperationAuthority, OperationID: operationID, ProjectID: plan.ProjectID, TargetBindingID: plan.TargetBindingID, TargetBindingRevision: plan.TargetBindingRevision, DesiredReleaseID: plan.DesiredReleaseID, DesiredReleaseDigest: plan.DesiredReleaseDigest, PlanDigest: plan.PlanDigest, VerificationDigest: verification.VerificationDigest, IdempotencyKey: idempotencyKey, FenceToken: fenceToken, RequesterID: requesterID}, nil
}

func ResolveApplicationPromotionOutcome(op ApplicationPromotionOperation, outcome PromotionOutcome, readback PromotionReadback) PromotionOperationResult {
	if op.Authority != PromotionOperationAuthority || op.FenceToken <= 0 || !applicationPlatformDigestPattern.MatchString(op.PlanDigest) || !applicationPlatformDigestPattern.MatchString(op.VerificationDigest) { return PromotionOperationResult{State: PromotionFailed, Message: "promotion operation authority is invalid"} }
	converged := readback.Observed && readback.EnvironmentBindingID == op.TargetBindingID && readback.Revision > op.TargetBindingRevision && readback.ReleaseID == op.DesiredReleaseID && readback.ReleaseDigest == op.DesiredReleaseDigest && applicationPlatformDigestPattern.MatchString(strings.TrimSpace(readback.BindingDigest)) && applicationPlatformDigestPattern.MatchString(strings.TrimSpace(readback.EvidenceDigest))
	switch outcome {
	case PromotionOutcomeUnknown:
		if converged { return PromotionOperationResult{State: PromotionSucceeded, EvidenceDigest: readback.EvidenceDigest, Message: "ambiguous promotion resolved by exact target readback"} }
		return PromotionOperationResult{State: PromotionRecoveryRequired, RecoveryRequired: true, RetryAllowed: false, Message: "promotion outcome is ambiguous; exact target readback is required"}
	case PromotionOutcomeApplied:
		if converged { return PromotionOperationResult{State: PromotionSucceeded, EvidenceDigest: readback.EvidenceDigest} }
		return PromotionOperationResult{State: PromotionRunning, Message: "promotion accepted; target authority has not converged"}
	case PromotionOutcomePending: return PromotionOperationResult{State: PromotionRunning}
	case PromotionOutcomeFailed: return PromotionOperationResult{State: PromotionFailed, RetryAllowed: false, Message: "promotion failed"}
	default: return PromotionOperationResult{State: PromotionFailed, Message: "unsupported promotion outcome"}
	}
}

func sortedPromotionStages(policy PromotionPolicy) []string {
	out:=make([]string,0,len(policy.Stages)); for _,stage:=range policy.Stages { out=append(out,strings.ToLower(strings.TrimSpace(stage.Name))) }; sort.Strings(out); return out
}
