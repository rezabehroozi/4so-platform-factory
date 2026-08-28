package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/installation"
)

type offlineSystemdTestSystem struct{ *SimulatedSystem }

func (s *offlineSystemdTestSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	if name == "systemctl" && slices.Equal(args, []string{"show", "--property=Version", "--value"}) {
		return errors.New("Failed to connect to system scope bus: Host is down")
	}
	return s.SimulatedSystem.Run(ctx, name, args, environment)
}

func TestSystemdOperationalCheckRejectsInstalledButOfflineManager(t *testing.T) {
	system := &offlineSystemdTestSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner := &Runner{system: system}
	if err := runner.verifySystemdOperational(context.Background()); err == nil || !strings.Contains(err.Error(), "not operational") {
		t.Fatalf("offline systemd manager was not rejected: %v", err)
	}
}

func TestFreshInstallDetectsUnitInUsrLocalSystemdSearchPath(t *testing.T) {
	system := &SimulatedSystem{Root: t.TempDir()}
	path := "/usr/local/lib/systemd/system/rke2-server.service"
	if err := system.WriteFile(path, []byte("[Unit]\nDescription=stale RKE2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{system: system}
	residue := runner.existingKubernetesResidue(context.Background())
	if !slices.Contains(residue, path) {
		t.Fatalf("systemd load-path residue was not detected: residue=%v want=%s", residue, path)
	}
}

func TestPublicPreflightCannotOverwriteAcceptedRunEvidence(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	state := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.test", BundleDir: bundle, StateDir: state, Simulation: true, RequireBundleLock: false, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	first, err := runner.Preflight(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.journal.Save(Run{ID: "bootstrap-evidence-owner", State: RunFailed, Request: request, PreflightDigest: first.Digest}); err != nil {
		t.Fatal(err)
	}
	mutated := request
	mutated.Connectivity = installation.ConnectivityDisconnected
	if _, err = runner.Preflight(context.Background(), mutated); err == nil || !errors.Is(err, ErrPreflightEvidenceOwned) {
		t.Fatalf("preflight overwrite after durable run was not rejected: %v", err)
	}
	persisted, err := runner.PreflightStatus()
	if err != nil {
		t.Fatal(err)
	}
	if persisted == nil || persisted.Digest != first.Digest {
		t.Fatalf("accepted preflight evidence changed: got=%+v wantDigest=%s", persisted, first.Digest)
	}
	if _, err := os.Stat(filepath.Join(state, "preflight-report.json")); err != nil {
		t.Fatalf("accepted preflight evidence disappeared: %v", err)
	}
}

func TestPublicPreflightMayEvaluateANewRequestAfterSucceededRun(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	state := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.test", BundleDir: bundle, StateDir: state, Simulation: true, RequireBundleLock: false, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.journal.Save(Run{ID: "bootstrap-complete", State: RunSucceeded}); err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Preflight(context.Background(), bootstrapRequest()); err != nil {
		t.Fatalf("succeeded run must not permanently fence a future preflight evaluation: %v", err)
	}
}

func TestPublicPreflightRejectsConcurrentBootstrapExecution(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	runner, err := NewRunner(RunnerOptions{Version: "0.0.test", BundleDir: bundle, StateDir: t.TempDir(), Simulation: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.active = true
	runner.mu.Unlock()
	if _, err = runner.Preflight(context.Background(), bootstrapRequest()); err == nil || !errors.Is(err, ErrBootstrapExecutionActive) {
		t.Fatalf("concurrent preflight was not rejected: %v", err)
	}
}
