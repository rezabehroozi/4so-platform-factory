package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/installation"
)

func installerServerWithRun(t *testing.T, state bootstrap.RunState) *installerServer {
	t.Helper()
	stateDir := t.TempDir()
	run := bootstrap.Run{
		ID:        "bootstrap-dr-contract",
		Version:   "test",
		State:     state,
		Request:   installation.InstallRequest{ProfileID: "production-standard-ha"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(stateDir, "bootstrap-state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, err := bootstrap.NewRunner(bootstrap.RunnerOptions{Version: "test", BundleDir: t.TempDir(), StateDir: stateDir, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	return &installerServer{runner: runner}
}

func TestDisasterRecoveryRequiresSucceededInstallation(t *testing.T) {
	for _, state := range []bootstrap.RunState{bootstrap.RunPending, bootstrap.RunRunning, bootstrap.RunFailed} {
		server := installerServerWithRun(t, state)
		if _, err := server.currentInstallRequest(); err == nil || !strings.Contains(err.Error(), "must be SUCCEEDED") {
			t.Fatalf("state %s unexpectedly admitted for disaster recovery: %v", state, err)
		}
	}
}

func TestDisasterRecoveryAcceptsSucceededInstallation(t *testing.T) {
	server := installerServerWithRun(t, bootstrap.RunSucceeded)
	req, err := server.currentInstallRequest()
	if err != nil {
		t.Fatal(err)
	}
	if req.ProfileID != "production-standard-ha" {
		t.Fatalf("unexpected recovered installation request: %+v", req)
	}
}
