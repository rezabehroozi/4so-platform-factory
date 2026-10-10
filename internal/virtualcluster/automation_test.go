package virtualcluster

import (
	"testing"
	"time"
)

func TestIdleAutomationFailsClosedOnIncompleteTelemetry(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	policy := IdlePolicy{Authority: IdlePolicyAuthority, ProjectID: "project-a", WorkspaceID: "workspace-a", VirtualClusterID: "vcl-a", Revision: 3, SleepAfterMinutes: 30, WakeOnAuthorizedActivity: true}
	decision := EvaluateIdle(policy, StateActive, TelemetryWindow{VirtualClusterID: "vcl-a", Complete: false, LastActivityAt: now.Add(-2 * time.Hour), ObservedAt: now, EvidenceDigest: digest64('a')}, now)
	if decision.Known || decision.Action != "" || decision.MutationAllowed {
		t.Fatalf("incomplete telemetry must remain UNKNOWN: %#v", decision)
	}
	complete := EvaluateIdle(policy, StateActive, TelemetryWindow{VirtualClusterID: "vcl-a", Complete: true, LastActivityAt: now.Add(-31 * time.Minute), ObservedAt: now, EvidenceDigest: digest64('b')}, now)
	if !complete.Known || complete.Action != ActionSuspend || !complete.MutationAllowed || complete.PolicyRevision != 3 {
		t.Fatalf("complete idle telemetry should request durable suspend: %#v", complete)
	}
}

func TestWakeRequiresMatchingAuthorizedActivityEvidence(t *testing.T) {
	policy := IdlePolicy{Authority: IdlePolicyAuthority, ProjectID: "project-a", WorkspaceID: "workspace-a", VirtualClusterID: "vcl-a", Revision: 4, SleepAfterMinutes: 30, WakeOnAuthorizedActivity: true}
	activity := AuthorizedActivity{ProjectID: "project-a", WorkspaceID: "workspace-a", VirtualClusterID: "vcl-a", ActorID: "user-a", ObservedAt: time.Now().UTC(), AuthorizationEvidenceDigest: digest64('c')}
	decision := EvaluateWake(policy, StateSuspended, activity)
	if decision.Action != ActionResume || !decision.MutationAllowed || !decision.RequiresDurableLifecycle {
		t.Fatalf("authorized activity must route through durable resume: %#v", decision)
	}
	activity.ProjectID = "project-b"
	if decision := EvaluateWake(policy, StateSuspended, activity); decision.MutationAllowed || decision.Action != "" {
		t.Fatalf("cross-project activity must not wake virtual cluster: %#v", decision)
	}
}

func TestSnapshotRestoreBindsVirtualClusterRevisionAndObservedEvidence(t *testing.T) {
	policy := SnapshotPolicy{Authority: SnapshotPolicyAuthority, ProjectID: "project-a", WorkspaceID: "workspace-a", VirtualClusterID: "vcl-a", Retain: 3, BeforeAutoDelete: true}
	plan, err := BuildSnapshotPlan(policy, 9, digest64('d'), "snap-1")
	if err != nil { t.Fatal(err) }
	if plan.Authority != SnapshotPolicyAuthority || plan.VirtualClusterRevision != 9 || plan.SnapshotID != "snap-1" || plan.SourceDesiredDigest != digest64('d') {
		t.Fatalf("unexpected snapshot plan: %#v", plan)
	}
	result := ResolveSnapshotRestore(plan, SnapshotReadback{Observed: true, SnapshotID: "snap-1", VirtualClusterID: "vcl-a", VirtualClusterRevision: 9, SourceDesiredDigest: digest64('d'), RestoredObservedDigest: digest64('e'), EvidenceDigest: digest64('f')})
	if !result.Verified || result.RecoveryRequired || result.EvidenceDigest == "" {
		t.Fatalf("matching restore readback must verify: %#v", result)
	}
	stale := ResolveSnapshotRestore(plan, SnapshotReadback{Observed: true, SnapshotID: "snap-1", VirtualClusterID: "vcl-a", VirtualClusterRevision: 8, SourceDesiredDigest: digest64('d'), RestoredObservedDigest: digest64('e'), EvidenceDigest: digest64('f')})
	if stale.Verified || !stale.RecoveryRequired {
		t.Fatalf("stale restore evidence must remain recovery-required: %#v", stale)
	}
}

func TestTTLAutoDeleteCannotBypassSnapshotApprovalOrRecoveryFences(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	policy := TTLPolicy{Authority: TTLPolicyAuthority, ProjectID: "project-a", WorkspaceID: "workspace-a", VirtualClusterID: "vcl-a", Revision: 2, Enabled: true, DeleteAfter: now.Add(-time.Minute), RequireSnapshot: true, RequireApproval: true}
	blocked := EvaluateTTL(policy, StateActive, now, TTLPrerequisites{SnapshotVerified: false, ApprovalGranted: true, RecoveryPending: false})
	if blocked.MutationAllowed || blocked.Action != "" || blocked.Blocker != "SNAPSHOT_REQUIRED" {
		t.Fatalf("TTL delete must require verified snapshot: %#v", blocked)
	}
	blocked = EvaluateTTL(policy, StateActive, now, TTLPrerequisites{SnapshotVerified: true, ApprovalGranted: false, RecoveryPending: false})
	if blocked.MutationAllowed || blocked.Blocker != "APPROVAL_REQUIRED" {
		t.Fatalf("TTL delete must require approval: %#v", blocked)
	}
	blocked = EvaluateTTL(policy, StateRecoveryRequired, now, TTLPrerequisites{SnapshotVerified: true, ApprovalGranted: true, RecoveryPending: true})
	if blocked.MutationAllowed || blocked.Blocker != "RECOVERY_PENDING" {
		t.Fatalf("TTL delete must not bypass recovery: %#v", blocked)
	}
	allowed := EvaluateTTL(policy, StateActive, now, TTLPrerequisites{SnapshotVerified: true, ApprovalGranted: true, RecoveryPending: false})
	if !allowed.MutationAllowed || allowed.Action != ActionDelete || !allowed.RequiresDurableLifecycle {
		t.Fatalf("eligible TTL delete must route through durable delete: %#v", allowed)
	}
}

func digest64(ch byte) string {
	buf := make([]byte, 64)
	for i := range buf { buf[i] = ch }
	return "sha256:" + string(buf)
}
