package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func newResetTestRunner(t *testing.T) (*Runner, *SimulatedSystem, string) {
	t.Helper()
	bundle := t.TempDir()
	makeBundle(t, bundle)
	stateDir := t.TempDir()
	system := &SimulatedSystem{Root: t.TempDir()}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: stateDir, Simulation: true, System: system})
	if err != nil {
		t.Fatal(err)
	}
	return runner, system, stateDir
}

func TestJournaledResetPreservesOperatorInputsAndAllowsCleanReinstall(t *testing.T) {
	runner, system, stateDir := newResetTestRunner(t)
	operatorInputs := []string{
		filepath.Join(stateDir, "bootstrap-token"),
		filepath.Join(stateDir, "secrets", "ssh-private-key"),
		filepath.Join(stateDir, "secrets", "ssh-known-hosts"),
	}
	for _, path := range operatorInputs {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("operator-input\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	first, err := runner.Start(context.Background(), bootstrapRequest())
	if err != nil || first.State != RunSucceeded {
		t.Fatalf("first install state=%s err=%v", first.State, err)
	}
	if !system.Exists(bootstrapCredentialRevokedPath) {
		t.Fatal("successful install must leave durable bootstrap revocation evidence")
	}
	// A foreign Kubernetes marker must never be deleted by the product reset.
	if err = system.WriteFile("/etc/rancher/k3s/foreign-marker", []byte("foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	reset, err := runner.StartReset(context.Background(), "reset:"+first.ID)
	if err != nil || reset.State != ResetStateSucceeded {
		t.Fatalf("reset state=%s err=%v last=%s", reset.State, err, reset.LastError)
	}
	if source, err := runner.Status(); err != nil || source != nil {
		t.Fatalf("bootstrap authority must be removed after reset: source=%+v err=%v", source, err)
	}
	if system.Exists(bootstrapCredentialRevokedPath) {
		t.Fatal("reset did not clear bootstrap revocation tombstone")
	}
	for _, path := range operatorInputs {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("operator input %s was not preserved: %v", path, err)
		}
	}
	if !system.Exists("/etc/rancher/k3s/foreign-marker") {
		t.Fatal("reset removed foreign Kubernetes state")
	}
	if residue := runner.productOwnedRKE2Residue(context.Background()); len(residue) != 0 {
		t.Fatalf("product RKE2 residue after reset: %v", residue)
	}

	second, err := runner.Start(context.Background(), bootstrapRequest())
	if err != nil || second.State != RunSucceeded {
		t.Fatalf("clean reinstall state=%s err=%v", second.State, err)
	}
	if second.ID != first.ID {
		t.Fatalf("same normalized install should retain deterministic run identity: first=%s second=%s", first.ID, second.ID)
	}
	runs, err := runner.ResetRuns()
	if err != nil || len(runs) != 1 || runs[0].State != ResetStateSucceeded {
		t.Fatalf("reset evidence=%+v err=%v", runs, err)
	}
}

func TestResetRequiresExactSourceBoundConfirmation(t *testing.T) {
	runner, _, _ := newResetTestRunner(t)
	source, err := runner.Start(context.Background(), bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.StartReset(context.Background(), "RESET"); err == nil {
		t.Fatal("unbound reset confirmation must fail")
	}
	still, err := runner.Status()
	if err != nil || still == nil || still.ID != source.ID {
		t.Fatalf("failed reset confirmation mutated source authority: %+v err=%v", still, err)
	}
}

func TestInterruptedResetRequiresExplicitResumeAndReplaysIdempotently(t *testing.T) {
	runner, _, _ := newResetTestRunner(t)
	source, err := runner.Start(context.Background(), bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	now := runner.now().UTC()
	reset := ResetRun{
		Authority: ResetAuthority, SchemaVersion: ResetSchemaVersion,
		ID: "reset-interrupted", SourceRunID: source.ID, SourceSpecDigest: source.SpecDigest, SourceBundleDigest: source.BundleDigest,
		Request: source.Request, State: ResetStateRunning, CreatedAt: now, UpdatedAt: now, Simulation: true,
	}
	for _, item := range resetSteps {
		reset.Steps = append(reset.Steps, ResetStep{Key: item.key, Title: item.title, State: ResetStateQueued})
	}
	reset.Steps[0].State = ResetStateSucceeded
	reset.Steps[1].State = ResetStateRunning
	reset.Steps[1].Attempt = 1
	reset.Steps[1].StartedAt = &now
	if err = runner.resetJournal.saveRun(reset); err != nil {
		t.Fatal(err)
	}
	if _, err = runner.StartReset(context.Background(), "reset:"+source.ID); err == nil {
		t.Fatal("a blocking reset must require ResumeReset rather than a second reset")
	}
	resumed, err := runner.ResumeReset(context.Background(), reset.ID)
	if err != nil || resumed.State != ResetStateSucceeded {
		t.Fatalf("resumed reset state=%s err=%v last=%s", resumed.State, err, resumed.LastError)
	}
	if resumed.Steps[1].Attempt != 2 {
		t.Fatalf("interrupted idempotent step attempt=%d want 2", resumed.Steps[1].Attempt)
	}
}
