package virtualcluster

import (
	"errors"
	"strings"
	"time"
)

const (
	IdlePolicyAuthority     = "VIRTUAL_CLUSTER_IDLE_POLICY_AUTHORITY_V1"
	SnapshotPolicyAuthority = "VIRTUAL_CLUSTER_SNAPSHOT_POLICY_AUTHORITY_V1"
	TTLPolicyAuthority      = "VIRTUAL_CLUSTER_TTL_AUTHORITY_V1"
	MaxIdleTelemetryAge     = 10 * time.Minute
)

type IdlePolicy struct {
	Authority                string
	ProjectID                string
	WorkspaceID              string
	VirtualClusterID         string
	Revision                 int64
	SleepAfterMinutes        int
	WakeOnAuthorizedActivity bool
}

type TelemetryWindow struct {
	VirtualClusterID string
	Complete         bool
	LastActivityAt   time.Time
	ObservedAt       time.Time
	EvidenceDigest   string
}

type AuthorizedActivity struct {
	ProjectID                   string
	WorkspaceID                 string
	VirtualClusterID            string
	ActorID                     string
	ObservedAt                  time.Time
	AuthorizationEvidenceDigest string
}

type AutomationDecision struct {
	Known                    bool
	Action                   Action
	MutationAllowed          bool
	RequiresDurableLifecycle bool
	PolicyRevision           int64
	Blocker                  string
	Reason                   string
}

func EvaluateIdle(policy IdlePolicy, state State, telemetry TelemetryWindow, now time.Time) AutomationDecision {
	decision := AutomationDecision{PolicyRevision: policy.Revision}
	if err := validateIdlePolicy(policy); err != nil {
		decision.Blocker = "POLICY_INVALID"
		decision.Reason = err.Error()
		return decision
	}
	if state != StateActive {
		decision.Known = true
		decision.Blocker = "STATE_NOT_ACTIVE"
		decision.Reason = "idle automation only evaluates ACTIVE virtual clusters"
		return decision
	}
	if telemetry.VirtualClusterID != policy.VirtualClusterID || !telemetry.Complete || telemetry.ObservedAt.IsZero() || telemetry.LastActivityAt.IsZero() || telemetry.LastActivityAt.After(telemetry.ObservedAt) || !validAutomationDigest(telemetry.EvidenceDigest) {
		decision.Blocker = "TELEMETRY_INCOMPLETE"
		decision.Reason = "complete evidence-backed activity telemetry is required"
		return decision
	}
	if now.IsZero() || telemetry.ObservedAt.After(now) {
		decision.Blocker = "TELEMETRY_TIME_INVALID"
		decision.Reason = "telemetry observation time is outside the evaluation window"
		return decision
	}
	if now.Sub(telemetry.ObservedAt) > MaxIdleTelemetryAge {
		decision.Blocker = "TELEMETRY_STALE"
		decision.Reason = "stale activity telemetry cannot authorize automated suspension"
		return decision
	}
	decision.Known = true
	if now.Sub(telemetry.LastActivityAt) < time.Duration(policy.SleepAfterMinutes)*time.Minute {
		decision.Reason = "idle threshold has not elapsed"
		return decision
	}
	decision.Action = ActionSuspend
	decision.MutationAllowed = true
	decision.RequiresDurableLifecycle = true
	decision.Reason = "idle threshold elapsed with complete fresh telemetry; suspend must use durable lifecycle authority"
	return decision
}

func EvaluateWake(policy IdlePolicy, state State, activity AuthorizedActivity) AutomationDecision {
	decision := AutomationDecision{PolicyRevision: policy.Revision}
	if err := validateIdlePolicy(policy); err != nil {
		decision.Blocker = "POLICY_INVALID"
		decision.Reason = err.Error()
		return decision
	}
	if !policy.WakeOnAuthorizedActivity {
		decision.Known = true
		decision.Blocker = "WAKE_POLICY_DISABLED"
		return decision
	}
	if state != StateSuspended {
		decision.Known = true
		decision.Blocker = "STATE_NOT_SUSPENDED"
		return decision
	}
	if strings.TrimSpace(activity.ProjectID) != policy.ProjectID || strings.TrimSpace(activity.WorkspaceID) != policy.WorkspaceID || strings.TrimSpace(activity.VirtualClusterID) != policy.VirtualClusterID || strings.TrimSpace(activity.ActorID) == "" || activity.ObservedAt.IsZero() || !validAutomationDigest(activity.AuthorizationEvidenceDigest) {
		decision.Blocker = "AUTHORIZED_ACTIVITY_REQUIRED"
		decision.Reason = "wake activity must match project/workspace/virtual-cluster authority and carry authorization evidence"
		return decision
	}
	decision.Known = true
	decision.Action = ActionResume
	decision.MutationAllowed = true
	decision.RequiresDurableLifecycle = true
	decision.Reason = "authorized activity may wake only through durable lifecycle resume"
	return decision
}

func validateIdlePolicy(policy IdlePolicy) error {
	if policy.Authority != IdlePolicyAuthority {
		return errors.New("idle policy authority is invalid")
	}
	if strings.TrimSpace(policy.ProjectID) == "" || strings.TrimSpace(policy.WorkspaceID) == "" || strings.TrimSpace(policy.VirtualClusterID) == "" || policy.Revision <= 0 || policy.SleepAfterMinutes <= 0 {
		return errors.New("idle policy scope/revision/threshold is incomplete")
	}
	return nil
}

type SnapshotPolicy struct {
	Authority        string
	ProjectID        string
	WorkspaceID      string
	VirtualClusterID string
	Retain           int
	BeforeAutoDelete bool
}

type SnapshotPlan struct {
	Authority              string
	ProjectID              string
	WorkspaceID            string
	VirtualClusterID       string
	VirtualClusterRevision int64
	SourceDesiredDigest    string
	SnapshotID             string
	Retain                 int
	BeforeAutoDelete       bool
}

type SnapshotReadback struct {
	Observed               bool
	SnapshotID             string
	VirtualClusterID       string
	VirtualClusterRevision int64
	SourceDesiredDigest    string
	RestoredObservedDigest string
	EvidenceDigest         string
}

type SnapshotRestoreResult struct {
	Verified         bool
	RecoveryRequired bool
	EvidenceDigest   string
	Reason           string
}

func BuildSnapshotPlan(policy SnapshotPolicy, virtualClusterRevision int64, sourceDesiredDigest, snapshotID string) (SnapshotPlan, error) {
	policy.ProjectID = strings.TrimSpace(policy.ProjectID)
	policy.WorkspaceID = strings.TrimSpace(policy.WorkspaceID)
	policy.VirtualClusterID = strings.TrimSpace(policy.VirtualClusterID)
	snapshotID = strings.TrimSpace(snapshotID)
	if policy.Authority != SnapshotPolicyAuthority || policy.ProjectID == "" || policy.WorkspaceID == "" || policy.VirtualClusterID == "" || policy.Retain <= 0 {
		return SnapshotPlan{}, errors.New("snapshot policy authority/scope/retention is invalid")
	}
	if virtualClusterRevision <= 0 || snapshotID == "" || !validAutomationDigest(sourceDesiredDigest) {
		return SnapshotPlan{}, errors.New("snapshot plan requires exact virtual-cluster revision/digest/identity")
	}
	return SnapshotPlan{Authority: SnapshotPolicyAuthority, ProjectID: policy.ProjectID, WorkspaceID: policy.WorkspaceID, VirtualClusterID: policy.VirtualClusterID, VirtualClusterRevision: virtualClusterRevision, SourceDesiredDigest: strings.TrimSpace(sourceDesiredDigest), SnapshotID: snapshotID, Retain: policy.Retain, BeforeAutoDelete: policy.BeforeAutoDelete}, nil
}

func ResolveSnapshotRestore(plan SnapshotPlan, readback SnapshotReadback) SnapshotRestoreResult {
	if plan.Authority != SnapshotPolicyAuthority || !readback.Observed || strings.TrimSpace(readback.SnapshotID) != plan.SnapshotID || strings.TrimSpace(readback.VirtualClusterID) != plan.VirtualClusterID || readback.VirtualClusterRevision != plan.VirtualClusterRevision || strings.TrimSpace(readback.SourceDesiredDigest) != plan.SourceDesiredDigest || !validAutomationDigest(readback.RestoredObservedDigest) || !validAutomationDigest(readback.EvidenceDigest) {
		return SnapshotRestoreResult{RecoveryRequired: true, Reason: "restore readback does not match the exact snapshot/virtual-cluster authority"}
	}
	return SnapshotRestoreResult{Verified: true, EvidenceDigest: strings.TrimSpace(readback.EvidenceDigest), Reason: "restore verified by exact observed readback evidence"}
}

type TTLPolicy struct {
	Authority        string
	ProjectID        string
	WorkspaceID      string
	VirtualClusterID string
	Revision         int64
	Enabled          bool
	DeleteAfter      time.Time
	RequireSnapshot  bool
	RequireApproval  bool
}

type TTLPrerequisites struct {
	SnapshotVerified bool
	ApprovalGranted  bool
	RecoveryPending  bool
}

func EvaluateTTL(policy TTLPolicy, state State, now time.Time, prerequisites TTLPrerequisites) AutomationDecision {
	decision := AutomationDecision{PolicyRevision: policy.Revision, Known: true}
	if policy.Authority != TTLPolicyAuthority || strings.TrimSpace(policy.ProjectID) == "" || strings.TrimSpace(policy.WorkspaceID) == "" || strings.TrimSpace(policy.VirtualClusterID) == "" || policy.Revision <= 0 || policy.DeleteAfter.IsZero() {
		decision.Known = false
		decision.Blocker = "POLICY_INVALID"
		decision.Reason = "TTL policy authority/scope/revision/deadline is invalid"
		return decision
	}
	if !policy.Enabled { decision.Blocker = "TTL_DISABLED"; return decision }
	if now.IsZero() || now.Before(policy.DeleteAfter) { decision.Blocker = "TTL_NOT_EXPIRED"; return decision }
	if prerequisites.RecoveryPending || state == StateRecoveryRequired {
		decision.Blocker = "RECOVERY_PENDING"
		decision.Reason = "recovery must be resolved before TTL deletion"
		return decision
	}
	if policy.RequireSnapshot && !prerequisites.SnapshotVerified {
		decision.Blocker = "SNAPSHOT_REQUIRED"
		decision.Reason = "verified snapshot evidence is required before TTL deletion"
		return decision
	}
	if policy.RequireApproval && !prerequisites.ApprovalGranted {
		decision.Blocker = "APPROVAL_REQUIRED"
		decision.Reason = "independent approval is required before TTL deletion"
		return decision
	}
	if state != StateActive && state != StateSuspended && state != StateFailed && state != StateRequested {
		decision.Blocker = "STATE_NOT_DELETABLE"
		decision.Reason = "current lifecycle state cannot enter durable delete"
		return decision
	}
	decision.Action = ActionDelete
	decision.MutationAllowed = true
	decision.RequiresDurableLifecycle = true
	decision.Reason = "TTL policy is eligible; deletion must use the existing durable lifecycle authority"
	return decision
}

func validAutomationDigest(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") { return false }
	for _, r := range value[len("sha256:"):] { if !strings.ContainsRune("0123456789abcdef", r) { return false } }
	return true
}
