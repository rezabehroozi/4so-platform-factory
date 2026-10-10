package virtualcluster

import (
	"testing"
	"time"
)

func TestWakeActivityMustBelongToCurrentAuthorizationEpoch(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	policy := IdlePolicy{
		Authority: IdlePolicyAuthority,
		ProjectID: "project-a", WorkspaceID: "workspace-a", VirtualClusterID: "vcl-a",
		Revision: 4, SleepAfterMinutes: 30, WakeOnAuthorizedActivity: true,
	}
	activity := AuthorizedActivity{
		ProjectID: "project-a", WorkspaceID: "workspace-a", VirtualClusterID: "vcl-a", ActorID: "user-a",
		ObservedAt: now, AuthorizationEvidenceDigest: digest64('c'),
	}

	fresh := EvaluateWake(policy, StateSuspended, activity, now)
	if !fresh.Known || fresh.Action != ActionResume || !fresh.MutationAllowed || !fresh.RequiresDurableLifecycle {
		t.Fatalf("fresh authorized activity must route through durable resume: %#v", fresh)
	}

	activity.ObservedAt = now.Add(-MaxAuthorizedActivityAge - time.Nanosecond)
	stale := EvaluateWake(policy, StateSuspended, activity, now)
	if stale.Known || stale.Action != "" || stale.MutationAllowed || stale.Blocker != "AUTHORIZED_ACTIVITY_STALE" {
		t.Fatalf("stale authorization activity must fail closed: %#v", stale)
	}

	activity.ObservedAt = now.Add(time.Nanosecond)
	future := EvaluateWake(policy, StateSuspended, activity, now)
	if future.Known || future.Action != "" || future.MutationAllowed || future.Blocker != "AUTHORIZED_ACTIVITY_TIME_INVALID" {
		t.Fatalf("future authorization activity must fail closed: %#v", future)
	}
}
