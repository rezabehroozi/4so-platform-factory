package virtualcluster

import (
	"testing"
	"time"
)

func TestIdleAutomationTreatsStaleTelemetryAsUnknown(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	policy := IdlePolicy{Authority: IdlePolicyAuthority, ProjectID: "project-a", WorkspaceID: "workspace-a", VirtualClusterID: "vcl-a", Revision: 3, SleepAfterMinutes: 30, WakeOnAuthorizedActivity: true}
	decision := EvaluateIdle(policy, StateActive, TelemetryWindow{VirtualClusterID: "vcl-a", Complete: true, LastActivityAt: now.Add(-2 * time.Hour), ObservedAt: now.Add(-20 * time.Minute), EvidenceDigest: digest64('a')}, now)
	if decision.Known || decision.Action != "" || decision.MutationAllowed || decision.Blocker != "TELEMETRY_STALE" {
		t.Fatalf("stale telemetry must remain unknown and mutation-free: %#v", decision)
	}
}
