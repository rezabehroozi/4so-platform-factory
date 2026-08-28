package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/disasterrecovery"
	"platform.4so.io/factory/internal/lifecycle"
)

func TestValidateExclusiveDurableOperationsFailsClosedOnOverlap(t *testing.T) {
	cases := []struct {
		bootstrap, lifecycle, dr bool
	}{
		{true, true, false},
		{true, false, true},
		{false, true, true},
		{true, true, true},
	}
	for _, tc := range cases {
		if err := validateExclusiveDurableOperations(tc.bootstrap, tc.lifecycle, tc.dr); err == nil {
			t.Fatalf("overlapping mutation state unexpectedly admitted: %+v", tc)
		}
	}
	for _, tc := range []struct{ bootstrap, lifecycle, dr bool }{{}, {true, false, false}, {false, true, false}, {false, false, true}} {
		if err := validateExclusiveDurableOperations(tc.bootstrap, tc.lifecycle, tc.dr); err != nil {
			t.Fatalf("single mutation state unexpectedly rejected %+v: %v", tc, err)
		}
	}
}

func TestMutationConflictReadsDurableLifecycleAndDRState(t *testing.T) {
	state := t.TempDir()
	now := time.Now().UTC()
	lifecycleRuns := []lifecycle.Run{{ID: "lifecycle-forgejo-backup-active", Service: "forgejo", ProfileID: "production-standard-ha", ExecutionNode: "manager-a", Action: lifecycle.ActionBackup, State: lifecycle.StateRunning, BackupID: "forgejo-active", CreatedAt: now, StartedAt: &now}}
	raw, _ := json.Marshal(lifecycleRuns)
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	lm, err := lifecycle.New(lifecycle.Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	drm, err := disasterrecovery.New(disasterrecovery.Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	s := &installerServer{lifecycle: lm, disasterRecovery: drm}
	if err := s.mutationConflictLocked("disaster-recovery"); err == nil || !strings.Contains(err.Error(), "lifecycle") {
		t.Fatalf("DR must reject durable lifecycle overlap, got %v", err)
	}

	drRuns := []disasterrecovery.Run{{ID: "dr-backup-active", Action: disasterrecovery.ActionBackup, State: disasterrecovery.StateRunning, BackupID: "appliance-active", CreatedAt: now, StartedAt: &now}}
	drRaw, _ := json.Marshal(drRuns)
	if err := os.WriteFile(filepath.Join(state, "disaster-recovery-runs.json"), drRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	drm, err = disasterrecovery.New(disasterrecovery.Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	s.disasterRecovery = drm
	if err := validateExclusiveDurableOperations(false, lm.HasActive(), drm.HasActive()); err == nil {
		t.Fatal("startup must fail closed when lifecycle and DR durable mutations overlap")
	}
	if err := s.mutationConflictLocked("bootstrap"); err == nil {
		t.Fatal("bootstrap must reject active lifecycle/DR mutations")
	}
}

func TestInterruptedBootstrapBlocksOtherMutationsButAllowsResumePath(t *testing.T) {
	for _, state := range []bootstrap.RunState{bootstrap.RunPending, bootstrap.RunRunning, bootstrap.RunFailed} {
		t.Run(string(state), func(t *testing.T) {
			s := installerServerWithRun(t, state)
			if !s.bootstrapInterrupted() {
				t.Fatalf("persisted %s bootstrap must be treated as requiring resume", state)
			}
			if err := s.mutationConflictLocked("lifecycle"); err == nil || !strings.Contains(err.Error(), "requires resume") {
				t.Fatalf("lifecycle must be blocked by interrupted bootstrap, got %v", err)
			}
			if err := s.mutationConflictLocked("disaster-recovery"); err == nil {
				t.Fatalf("DR must be blocked by interrupted bootstrap, got %v", err)
			}
			if err := s.mutationConflictLocked("bootstrap"); err != nil {
				t.Fatalf("bootstrap resume path must remain available: %v", err)
			}
		})
	}
	if s := installerServerWithRun(t, bootstrap.RunSucceeded); s.bootstrapInterrupted() {
		t.Fatal("SUCCEEDED bootstrap must not be treated as interrupted")
	}
}

func TestDurableSucceededBootstrapOverridesStaleInMemoryActiveFlag(t *testing.T) {
	s := installerServerWithRun(t, bootstrap.RunSucceeded)
	s.bootstrapActive = true
	if s.bootstrapExecutionActiveLocked() {
		t.Fatal("durable SUCCEEDED run must override stale bootstrapActive publication lag")
	}
	if err := s.mutationConflictLocked("lifecycle"); err != nil {
		t.Fatalf("lifecycle must be admitted after durable bootstrap success: %v", err)
	}
}

func TestDurableFailedBootstrapAllowsResumeDespiteStaleInMemoryActiveFlag(t *testing.T) {
	s := installerServerWithRun(t, bootstrap.RunFailed)
	s.bootstrapActive = true
	if s.bootstrapExecutionActiveLocked() {
		t.Fatal("durable FAILED run must permit the resume path after execution has terminally failed")
	}
	if err := s.mutationConflictLocked("bootstrap"); err != nil {
		t.Fatalf("bootstrap resume path must remain admitted after durable failure: %v", err)
	}
	if err := s.mutationConflictLocked("lifecycle"); err == nil {
		t.Fatal("non-bootstrap mutation must still be blocked until failed bootstrap is resumed")
	}
}
