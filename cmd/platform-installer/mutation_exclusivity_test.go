package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		if err := validateExclusiveDurableOperations(tc.bootstrap, tc.lifecycle, tc.dr, false); err == nil {
			t.Fatalf("overlapping mutation state unexpectedly admitted: %+v", tc)
		}
	}
	for _, tc := range []struct{ bootstrap, lifecycle, dr bool }{{}, {true, false, false}, {false, true, false}, {false, false, true}} {
		if err := validateExclusiveDurableOperations(tc.bootstrap, tc.lifecycle, tc.dr, false); err != nil {
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
	if err := validateExclusiveDurableOperations(false, lm.HasActive(), drm.HasActive(), false); err == nil {
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

func TestValidateExclusiveDurableOperationsAllowsResetToOwnTerminalBootstrapAuthority(t *testing.T) {
	if err := validateExclusiveDurableOperations(true, false, false, true); err != nil {
		t.Fatalf("reset must be allowed to own and remove terminal/interrupted bootstrap authority: %v", err)
	}
	for _, tc := range []struct {
		lifecycle bool
		dr        bool
	}{{true, false}, {false, true}, {true, true}} {
		if err := validateExclusiveDurableOperations(false, tc.lifecycle, tc.dr, true); err == nil {
			t.Fatalf("reset must fail closed across lifecycle/DR mutation: %+v", tc)
		}
	}
}

func TestBlockingResetFencesAllOtherMutationsButKeepsResetResumeAvailable(t *testing.T) {
	state := t.TempDir()
	system := &bootstrap.SimulatedSystem{Root: t.TempDir()}
	now := time.Now().UTC()
	resetHistory := map[string]any{
		"authority":     bootstrap.ResetAuthority,
		"schemaVersion": bootstrap.ResetSchemaVersion,
		"runs": []bootstrap.ResetRun{{
			Authority: bootstrap.ResetAuthority, SchemaVersion: bootstrap.ResetSchemaVersion,
			ID: "reset-blocking", SourceRunID: "bootstrap-source", State: bootstrap.ResetStateRunning,
			CreatedAt: now, UpdatedAt: now, Simulation: true,
			Steps: []bootstrap.ResetStep{{Key: "uninstall-local-rke2", Title: "Uninstall local RKE2", State: bootstrap.ResetStateRunning, Attempt: 1, StartedAt: &now}},
		}},
	}
	raw, _ := json.Marshal(resetHistory)
	if err := os.WriteFile(filepath.Join(state, "reset-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, err := bootstrap.NewRunner(bootstrap.RunnerOptions{Version: "test", BundleDir: t.TempDir(), StateDir: state, Simulation: true, System: system})
	if err != nil {
		t.Fatal(err)
	}
	s := &installerServer{runner: runner}
	for _, target := range []string{"bootstrap", "lifecycle", "disaster-recovery"} {
		if err := s.mutationConflictLocked(target); err == nil || !strings.Contains(err.Error(), "reset") {
			t.Fatalf("%s must be fenced by blocking reset, got %v", target, err)
		}
	}
	if err := s.mutationConflictLocked("reset"); err != nil {
		t.Fatalf("explicit reset resume must remain available: %v", err)
	}
}

func TestResumeRejectsMissingAndSucceededDurableAuthority(t *testing.T) {
	stateDir := t.TempDir()
	runner, err := bootstrap.NewRunner(bootstrap.RunnerOptions{Version: "test", BundleDir: t.TempDir(), StateDir: stateDir, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	for name, server := range map[string]*installerServer{
		"missing": {runner: runner, executionEnabled: true},
		"succeeded": func() *installerServer {
			s := installerServerWithRun(t, bootstrap.RunSucceeded)
			s.executionEnabled = true
			return s
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/resume", nil)
			server.resume(rr, req)
			if rr.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "BOOTSTRAP_RESUME_NOT_AVAILABLE") {
				t.Fatalf("body=%s", rr.Body.String())
			}
			server.mutationMu.Lock()
			active := server.bootstrapActive
			server.mutationMu.Unlock()
			if active {
				t.Fatal("rejected resume published bootstrapActive")
			}
		})
	}
}
