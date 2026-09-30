package daprruntime

import (
	"strings"
	"testing"
)

func lifecycleTestDigest(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }

func TestLifecycleRequestCanonicalDigestIsStable(t *testing.T) {
	in := LifecycleRequest{
		ProjectID: " prj_1 ", ClusterID: " clu_1 ", Action: "install",
		RuntimeLockDigest: lifecycleTestDigest("a"),
	}
	raw, digest, err := MarshalLifecycleRequest(in)
	if err != nil { t.Fatal(err) }
	got, err := ParseLifecycleRequest(raw, digest)
	if err != nil { t.Fatal(err) }
	if got.ProjectID != "prj_1" || got.ClusterID != "clu_1" || got.Action != ActionInstall {
		t.Fatalf("canonical Dapr lifecycle request drift: %#v", got)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("invalid lifecycle request digest: %s", digest)
	}
	if _, err := ParseLifecycleRequest(append(raw, []byte("{}")...), digest); err == nil {
		t.Fatal("Dapr lifecycle request trailing JSON accepted")
	}
}

func TestLifecycleTransitionRequiresObservedAuthority(t *testing.T) {
	target := lifecycleTestDigest("a")
	old := lifecycleTestDigest("b")
	if err := ValidateLifecycleTransition(ActionInstall, nil, target); err != nil {
		t.Fatalf("fresh install rejected: %v", err)
	}
	observed := &ObservedState{Installed: true, RuntimeLockDigest: old}
	if err := ValidateLifecycleTransition(ActionInstall, observed, target); err == nil || err.Error() != "DAPR_ALREADY_INSTALLED" {
		t.Fatalf("duplicate install accepted: %v", err)
	}
	if err := ValidateLifecycleTransition(ActionUpgrade, observed, target); err != nil {
		t.Fatalf("fenced upgrade rejected: %v", err)
	}
	observed.RuntimeLockDigest = target
	if err := ValidateLifecycleTransition(ActionUpgrade, observed, target); err == nil || err.Error() != "DAPR_UPGRADE_TARGET_EQUALS_OBSERVED" {
		t.Fatalf("same-lock upgrade accepted: %v", err)
	}
	if err := ValidateLifecycleTransition(ActionRemove, observed, target); err != nil {
		t.Fatalf("observed remove rejected: %v", err)
	}
	if err := ValidateLifecycleTransition(ActionRemove, nil, target); err == nil || err.Error() != "DAPR_REMOVE_REQUIRES_OBSERVED_INSTALL" {
		t.Fatalf("remove without observed install accepted: %v", err)
	}
}

func TestLifecycleDispatchFenceRejectsObservedDrift(t *testing.T) {
	target := lifecycleTestDigest("a")
	old := lifecycleTestDigest("b")
	observed := &ObservedState{Installed: true, RuntimeLockDigest: old}
	if err := ValidateLifecycleDispatchFence(ActionUpgrade, observed, target, old); err != nil {
		t.Fatalf("matching Dapr observed fence rejected: %v", err)
	}
	if err := ValidateLifecycleDispatchFence(ActionUpgrade, observed, target, lifecycleTestDigest("c")); err == nil || err.Error() != "DAPR_OBSERVED_FENCE_CHANGED" {
		t.Fatalf("Dapr observed fence drift accepted: %v", err)
	}
}
