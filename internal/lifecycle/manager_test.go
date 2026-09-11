package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/testsupport"
)

type lifecycleOutputSystem struct {
	*bootstrap.SimulatedSystem
	output []byte
}

func (s *lifecycleOutputSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	command := strings.Join(args, " ")
	if strings.Contains(command, " get deployment platform-zot -o json") {
		return []byte(fmt.Sprintf(`{"metadata":{"uid":"uid-zot","resourceVersion":"7"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"zot","image":%q}]}}}}`, string(s.output))), nil
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func lifecycleBundle(t *testing.T, root string) {
	t.Helper()
	archivePath := filepath.Join(root, "artifacts/workloads.oci.tar")
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatal(err)
	}
	refs, err := testsupport.WriteWorkloadOCIArchive(archivePath, testsupport.WorkloadRepositories("registry/", true))
	if err != nil {
		t.Fatal(err)
	}
	byRepo := testsupport.RefsByRepository(refs)
	files := map[string][]byte{
		"artifacts/install.sh": []byte("#!/bin/sh\n"), "artifacts/rke2.tar.gz": []byte("rke2"), "artifacts/rke2-images.tar.zst": []byte("images"),
		"artifacts/argocd-install.yaml":  []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: argocd\n          image: " + byRepo["registry/argocd"] + "\n"),
		"artifacts/ocm-install.yaml":     []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: ocm\n          image: " + byRepo["registry/ocm"] + "\n"),
		"artifacts/cnpg-install.yaml":    []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: cnpg\n          image: " + byRepo["registry/cnpg"] + "\n"),
		"artifacts/storage-install.yaml": []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: storage\n          image: " + byRepo["registry/storage"] + "\n"),
	}
	for name, data := range files {
		path := filepath.Join(root, name)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(name string) string {
		raw, readErr := os.ReadFile(filepath.Join(root, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		sum := sha256.Sum256(raw)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	var bundle bootstrap.BundleManifest
	bundle.APIVersion = "platform.4so.io/v1alpha1"
	bundle.Kind = "ApplianceBundle"
	bundle.Metadata.Version = "0.0.16"
	bundle.Spec.RKE2.Version = "test"
	bundle.Spec.RKE2.Installer = bootstrap.Artifact{Path: "artifacts/install.sh", SHA256: digest("artifacts/install.sh")}
	bundle.Spec.RKE2.InstallArtifacts = []bootstrap.Artifact{{Path: "artifacts/rke2.tar.gz", SHA256: digest("artifacts/rke2.tar.gz")}}
	bundle.Spec.RKE2.ImageArchives = []bootstrap.Artifact{{Path: "artifacts/rke2-images.tar.zst", SHA256: digest("artifacts/rke2-images.tar.zst")}}
	bundle.Spec.Workloads.ImageArchives = []bootstrap.Artifact{{Path: "artifacts/workloads.oci.tar", SHA256: digest("artifacts/workloads.oci.tar")}}
	bundle.Spec.Workloads.PostgreSQLImage = byRepo["registry/postgres"]
	bundle.Spec.Workloads.PlatformAPIImage = byRepo["registry/platform-api"]
	bundle.Spec.Workloads.ForgejoImage = byRepo["registry/forgejo"]
	bundle.Spec.Workloads.ZotImage = byRepo["registry/zot"]
	bundle.Spec.Workloads.KeycloakImage = byRepo["registry/keycloak"]
	bundle.Spec.Workloads.MaintenanceImage = byRepo["registry/maintenance"]
	bundle.Spec.Workloads.FleetAgentImage = byRepo["registry/platform-agent"]
	bundle.Spec.Workloads.RuntimeProbeImage = byRepo["registry/platform-probe"]
	bundle.Spec.Workloads.GitOpsManifest = bootstrap.Artifact{Path: "artifacts/argocd-install.yaml", SHA256: digest("artifacts/argocd-install.yaml")}
	bundle.Spec.Workloads.CloudNativePGManifest = bootstrap.Artifact{Path: "artifacts/cnpg-install.yaml", SHA256: digest("artifacts/cnpg-install.yaml")}
	bundle.Spec.Workloads.OCMManifest = bootstrap.Artifact{Path: "artifacts/ocm-install.yaml", SHA256: digest("artifacts/ocm-install.yaml")}
	bundle.Spec.Workloads.StorageManifest = bootstrap.Artifact{Path: "artifacts/storage-install.yaml", SHA256: digest("artifacts/storage-install.yaml")}
	images := append([]string(nil), refs...)
	indexRaw, _ := json.Marshal(map[string]any{"version": "0.0.16", "images": images, "artifacts": []string{"artifacts/install.sh", "artifacts/rke2.tar.gz", "artifacts/rke2-images.tar.zst", "artifacts/workloads.oci.tar", "artifacts/argocd-install.yaml", "artifacts/cnpg-install.yaml", "artifacts/ocm-install.yaml", "artifacts/storage-install.yaml"}})
	if err := os.WriteFile(filepath.Join(root, "artifacts/airgap-index.json"), indexRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	indexSum := sha256.Sum256(indexRaw)
	bundle.Spec.Airgap.Complete = true
	bundle.Spec.Airgap.Index = bootstrap.Artifact{Path: "artifacts/airgap-index.json", SHA256: "sha256:" + hex.EncodeToString(indexSum[:])}
	bundle.Spec.Airgap.RequiredImages = images
	raw, _ := json.Marshal(bundle)
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func repeat(value string, count int) string {
	out := ""
	for i := 0; i < count; i++ {
		out += value
	}
	return out
}
func waitRun(t *testing.T, m *Manager, id string) Run {
	t.Helper()
	for i := 0; i < 100; i++ {
		for _, run := range m.List() {
			if run.ID == id && (run.State == StateSucceeded || run.State == StateFailed) {
				return run
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run timeout")
	return Run{}
}

func TestLifecycleAdmissionBindsBundleDigestAndRejectsDrift(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	_, acceptedDigest, err := bootstrap.LoadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	system := &bootstrap.SimulatedSystem{Root: t.TempDir()}
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: system})
	if err != nil {
		t.Fatal(err)
	}
	backup, err := m.StartBackup(context.Background(), "forgejo", "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	backup = waitRun(t, m, backup.ID)
	if backup.State != StateSucceeded || backup.BundleDigest != acceptedDigest {
		t.Fatalf("lifecycle admission did not persist exact bundle authority: %+v want=%s", backup, acceptedDigest)
	}

	manifestPath := filepath.Join(bundle, "bundle.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	// The bundle digest is over the accepted manifest bytes. A formatting-only
	// rewrite must therefore still be detected as exact-artifact drift while
	// remaining structurally and semantically valid.
	if err = os.WriteFile(manifestPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, observedDigest, loadErr := bootstrap.LoadBundle(bundle); loadErr != nil {
		t.Fatalf("drifted bundle must remain structurally valid: %v", loadErr)
	} else if observedDigest == acceptedDigest {
		t.Fatal("test did not change bundle digest")
	}

	err = m.performRestore(context.Background(), "lifecycle-forgejo-restore-drift", "forgejo", backup.BackupID, backup.ProfileID, backup.BundleDigest)
	if err == nil || !strings.Contains(err.Error(), "appliance bundle changed after lifecycle operation admission") {
		t.Fatalf("bundle drift was not rejected before restore replay: %v", err)
	}
	if len(system.Commands) != 0 {
		t.Fatalf("bundle-drift rejection reached runtime side effects: %v", system.Commands)
	}
}

func TestLifecycleUpdateMissingRunFailsClosed(t *testing.T) {
	m := &Manager{stateDir: t.TempDir(), active: map[string]bool{}, reconciling: map[string]bool{}}
	if err := m.update("missing-run", func(*Run) {}); err == nil || !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("missing lifecycle update was silently accepted: %v", err)
	}
}

func TestLifecycleLoadRejectsAmbiguousDuplicateRunIDs(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	runs := []Run{
		{ID: "lifecycle-duplicate", Service: "forgejo", ProfileID: "evaluation-single-node", Action: ActionBackup, State: StateSucceeded, BackupID: "forgejo-one"},
		{ID: "lifecycle-duplicate", Service: "zot", ProfileID: "evaluation-single-node", Action: ActionBackup, State: StateSucceeded, BackupID: "zot-one"},
	}
	raw, err := json.Marshal(runs)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "duplicate lifecycle run id") {
		t.Fatalf("ambiguous lifecycle state was accepted: %v", err)
	}
}

func TestLifecycleLoadRejectsInvalidRunAuthorityBeforeReconcile(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	cases := []struct {
		name string
		run  Run
		want string
	}{
		{
			name: "unknown-service-cannot-fall-through-to-zot",
			run:  Run{ID: "lifecycle-invalid-service", Service: "not-zot", ProfileID: "evaluation-single-node", Action: ActionBackup, State: StateRunning, CreatedAt: time.Now().UTC()},
			want: "invalid service authority",
		},
		{
			name: "malformed-accepted-bundle-digest",
			run:  Run{ID: "lifecycle-invalid-digest", Service: "forgejo", ProfileID: "evaluation-single-node", BundleDigest: "sha256:not-a-digest", Action: ActionBackup, State: StateRunning, CreatedAt: time.Now().UTC()},
			want: "invalid accepted bundle digest",
		},
		{
			name: "unknown-action",
			run:  Run{ID: "lifecycle-invalid-action", Service: "forgejo", ProfileID: "evaluation-single-node", Action: Action("destroy"), State: StateRunning, CreatedAt: time.Now().UTC()},
			want: "invalid action authority",
		},
		{
			name: "unknown-state",
			run:  Run{ID: "lifecycle-invalid-state", Service: "forgejo", ProfileID: "evaluation-single-node", Action: ActionBackup, State: State("MUTATING"), CreatedAt: time.Now().UTC()},
			want: "invalid state authority",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			raw, err := json.Marshal([]Run{tc.run})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err = New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid durable authority was accepted: %v", err)
			}
		})
	}
}

func TestLifecycleIDsRemainUniqueWhenClockRepeats(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	fixed := time.Date(2026, 8, 10, 0, 0, 0, 123, time.UTC)
	manager, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.StartBackup(context.Background(), "forgejo", "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	first = waitRun(t, manager, first.ID)
	if first.State != StateSucceeded {
		t.Fatalf("first=%+v", first)
	}
	second, err := manager.StartBackup(context.Background(), "forgejo", "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID || second.BackupID == first.BackupID {
		t.Fatalf("lifecycle identity collision: first=%+v second=%+v", first, second)
	}
	second = waitRun(t, manager, second.ID)
	if second.State != StateSucceeded {
		t.Fatalf("second=%+v", second)
	}
}

func TestSimulatedLifecycleBackupRestoreUpgrade(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	system := &bootstrap.SimulatedSystem{Root: t.TempDir()}
	manager, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: system})
	if err != nil {
		t.Fatal(err)
	}
	backup, err := manager.StartBackup(context.Background(), "forgejo", "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	backup = waitRun(t, manager, backup.ID)
	if backup.State != StateSucceeded || backup.BackupID == "" {
		t.Fatalf("backup=%+v", backup)
	}
	items, err := manager.Backups("forgejo")
	if err != nil || len(items) != 1 {
		t.Fatalf("backups=%+v err=%v", items, err)
	}
	restore, err := manager.StartRestore(context.Background(), RestoreRequest{Service: "forgejo", BackupID: backup.BackupID}, "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	restore = waitRun(t, manager, restore.ID)
	if restore.State != StateSucceeded {
		t.Fatalf("restore=%+v", restore)
	}
	upgrade, err := manager.StartUpgrade(context.Background(), UpgradeRequest{Service: "zot", Image: "registry/zot@sha256:" + repeat("9", 64)}, "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	upgrade = waitRun(t, manager, upgrade.ID)
	if upgrade.State != StateSucceeded || upgrade.BackupID == "" {
		t.Fatalf("upgrade=%+v", upgrade)
	}
}

func TestLifecycleStateCorruptionFailsClosed(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), []byte("{not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil {
		t.Fatal("expected corrupt lifecycle state to fail startup")
	}
}

func TestLifecycleQueuePersistenceFailureRejectsOperation(t *testing.T) {
	state := t.TempDir()
	m, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(state); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(state, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.StartBackup(context.Background(), "forgejo", "evaluation-single-node"); err == nil {
		t.Fatal("expected lifecycle start to reject undurable queue state")
	}
	if len(m.List()) != 0 {
		t.Fatalf("failed queue persistence must roll back in-memory run: %+v", m.List())
	}
}

func TestInterruptedLifecycleRunRemainsBlockingAfterRestart(t *testing.T) {
	state := t.TempDir()
	now := time.Now().UTC()
	runs := []Run{{ID: "lifecycle-forgejo-backup-interrupted", Service: "forgejo", ProfileID: "evaluation-single-node", Action: ActionBackup, State: StateRunning, CreatedAt: now, StartedAt: &now}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.StartBackup(context.Background(), "forgejo", "evaluation-single-node"); err == nil {
		t.Fatal("interrupted lifecycle run must block overlapping mutation after restart")
	}
}

func TestInterruptedLifecycleRunReconcilesAfterRestart(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	_, bundleDigest, err := bootstrap.LoadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	now := time.Now().UTC()
	runs := []Run{{ID: "lifecycle-forgejo-backup-interrupted", Service: "forgejo", ProfileID: "evaluation-single-node", BundleDigest: bundleDigest, Action: ActionBackup, State: StateRunning, CreatedAt: now, StartedAt: &now}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if resumed := m.Reconcile(context.Background()); resumed != 1 {
		t.Fatalf("reconciled runs=%d", resumed)
	}
	run := waitRun(t, m, runs[0].ID)
	if run.State != StateSucceeded || run.BackupID == "" {
		t.Fatalf("reconciled lifecycle run=%+v", run)
	}
	if run.StartedAt == nil || !run.StartedAt.Equal(now) {
		t.Fatalf("reconcile changed original startedAt: before=%v after=%v", now, run.StartedAt)
	}
	if _, err = os.Stat(filepath.Join(state, "backups", run.BackupID, "backup.json")); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyInterruptedLifecycleRunWithoutBundleDigestFailsClosed(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	now := time.Now().UTC()
	runs := []Run{{ID: "lifecycle-forgejo-backup-legacy", Service: "forgejo", ProfileID: "evaluation-single-node", Action: ActionBackup, State: StateRunning, CreatedAt: now, StartedAt: &now}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if resumed := m.Reconcile(context.Background()); resumed != 1 {
		t.Fatalf("reconciled runs=%d", resumed)
	}
	run := waitRun(t, m, runs[0].ID)
	if run.State != StateFailed || !strings.Contains(run.Error, "missing its accepted bundle digest") {
		t.Fatalf("legacy interrupted run did not fail closed: %+v", run)
	}
	if _, statErr := os.Stat(filepath.Join(state, "backups", run.BackupID, "backup.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("legacy ambiguous replay created backup side effect: %v", statErr)
	}
}

func TestLegacyInterruptedUpgradeWithoutPreviousImageFailsClosed(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	now := time.Now().UTC()
	requested := "registry/zot@sha256:" + repeat("9", 64)
	backupID := "zot-legacy-upgrade"
	runs := []Run{{ID: "lifecycle-zot-upgrade-interrupted", Service: "zot", ProfileID: "evaluation-single-node", ExecutionNode: "manager-a", Action: ActionUpgrade, State: StateRunning, BackupID: backupID, RequestedImage: requested, CreatedAt: now, StartedAt: &now}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(state, "backups", backupID)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("durable-pre-upgrade-backup")
	if err := os.WriteFile(filepath.Join(backupDir, "data.tar.gz"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	meta := BackupMetadata{ID: backupID, Service: "zot", CreatedAt: now, Files: []BackupFile{{Name: "data.tar.gz", SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(data))}}}
	metaRaw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(backupDir, "backup.json"), metaRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	system := &lifecycleOutputSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, output: []byte(requested)}
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: false, System: system})
	if err != nil {
		t.Fatal(err)
	}
	if resumed := m.Reconcile(context.Background()); resumed != 1 {
		t.Fatalf("reconciled runs=%d", resumed)
	}
	run := waitRun(t, m, runs[0].ID)
	if run.State != StateFailed || run.PreviousImage != "" {
		t.Fatalf("legacy ambiguous upgrade must fail without inventing previous image: %+v", run)
	}
	if !strings.Contains(run.Error, "lacks durable phase authority") {
		t.Fatalf("unexpected reconciliation error: %q", run.Error)
	}
	for _, command := range system.Commands {
		if strings.Contains(command, " set image ") {
			t.Fatalf("ambiguous legacy upgrade must not mutate image: %s", command)
		}
	}
}

func TestInterruptedUpgradeRollbackNeverReplaysFailedUpgrade(t *testing.T) {
	state := t.TempDir()
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("9", 64)
	run := Run{
		ID: "lifecycle-zot-upgrade-rollback", Service: "zot", ProfileID: "evaluation-single-node", ExecutionNode: "manager-a",
		Action: ActionUpgrade, State: StateRunning, BackupID: "zot-upgrade-backup", RequestedImage: requested, PreviousImage: previous,
		UpgradePhase: UpgradePhaseRollbackPending, UpgradeFailure: "upgrade rollout failed: injected failure", CreatedAt: time.Now().UTC(),
	}
	system := &lifecycleOutputSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, output: []byte(previous)}
	m := &Manager{stateDir: state, system: system, now: time.Now, runs: []Run{run}, active: map[string]bool{"zot": true}, reconciling: map[string]bool{}}
	_, err := m.performUpgrade(context.Background(), run.ID, run)
	if err == nil || !strings.Contains(err.Error(), "confirmation-bound upgrade recovery") {
		t.Fatalf("expected state-aware recovery requirement, got %v", err)
	}
	stored := m.findLocked(run.ID)
	if stored == nil || stored.UpgradePhase != UpgradePhaseRecoveryRequired {
		t.Fatalf("legacy rollback intent was not converted to recovery-required: %+v", stored)
	}
	for _, command := range system.Commands {
		if strings.Contains(command, requested) {
			t.Fatalf("failed upgrade image was replayed after rollback: %s", command)
		}
	}
}

func TestCompletedUpgradeRollbackIsTerminalAndDoesNotMutate(t *testing.T) {
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("9", 64)
	run := Run{ID: "lifecycle-zot-upgrade-rollback-complete", Service: "zot", ProfileID: "evaluation-single-node", Action: ActionUpgrade, State: StateRunning, BackupID: "backup", RequestedImage: requested, PreviousImage: previous, UpgradePhase: UpgradePhaseRollbackCompleted, UpgradeFailure: "upgrade rollout failed: injected failure"}
	system := &lifecycleOutputSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, output: []byte(previous)}
	m := &Manager{stateDir: t.TempDir(), system: system, now: time.Now, runs: []Run{run}, active: map[string]bool{"zot": true}, reconciling: map[string]bool{}}
	_, err := m.performUpgrade(context.Background(), run.ID, run)
	if err == nil || !strings.Contains(err.Error(), "persistent-state recovery was not proven") {
		t.Fatalf("expected legacy image-only rollback warning, got %v", err)
	}
	if len(system.Commands) != 0 {
		t.Fatalf("completed rollback performed Kubernetes mutation/inspection: %v", system.Commands)
	}
}

func TestCorruptBackupMetadataIsNotSilentlyHidden(t *testing.T) {
	state := t.TempDir()
	m, err := New(Options{StateDir: state, BundleDir: t.TempDir(), Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "backups", "bad-backup")
	if err = os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "backup.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Backups("forgejo"); err == nil {
		t.Fatal("expected corrupt backup metadata to be surfaced")
	}
}

type lifecycleCommandSystem struct {
	*bootstrap.SimulatedSystem
	failSubstring       string
	failed              bool
	podResponses        [][]byte
	outputErr           error
	keycloakReplicas    int
	keycloakInitialized bool
}

func (s *lifecycleCommandSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	command := name + " " + strings.Join(args, " ")
	if s.failSubstring != "" && !s.failed && strings.Contains(command, s.failSubstring) {
		s.Commands = append(s.Commands, command)
		s.failed = true
		return errors.New("injected lifecycle command failure")
	}
	return s.SimulatedSystem.Run(ctx, name, args, environment)
}

func (s *lifecycleCommandSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	if !s.keycloakInitialized {
		s.keycloakReplicas = 2
		s.keycloakInitialized = true
	}
	if strings.Contains(command, " get statefulset platform-keycloak -o json") {
		return []byte(fmt.Sprintf(`{"metadata":{"uid":"uid-keycloak","resourceVersion":"11"},"spec":{"replicas":%d,"template":{"spec":{"containers":[{"name":"keycloak","image":"registry/keycloak@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}}`, s.keycloakReplicas)), nil
	}
	if strings.Contains(command, " patch statefulset platform-keycloak --type=json ") {
		marker := `"path":"/spec/replicas","value":`
		if index := strings.Index(command, marker); index >= 0 {
			tail := command[index+len(marker):]
			end := strings.IndexAny(tail, "},]")
			if end > 0 {
				if value, parseErr := strconv.Atoi(tail[:end]); parseErr == nil {
					s.keycloakReplicas = value
				}
			}
		}
		return []byte(fmt.Sprintf(`{"metadata":{"uid":"uid-keycloak","resourceVersion":"12"},"spec":{"replicas":%d,"template":{"spec":{"containers":[{"name":"keycloak","image":"registry/keycloak@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}}`, s.keycloakReplicas)), nil
	}
	if strings.Contains(command, " get pods ") || strings.Contains(command, " get pods -l ") {
		if s.outputErr != nil {
			return nil, s.outputErr
		}
		if len(s.podResponses) > 0 {
			out := s.podResponses[0]
			s.podResponses = s.podResponses[1:]
			return append([]byte(nil), out...), nil
		}
		return nil, nil
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func testBackupMetadata(service, id string) BackupMetadata {
	files := []BackupFile{}
	for _, name := range backupPayloadNamesMust(service) {
		files = append(files, BackupFile{Name: name, SHA256: "sha256:" + strings.Repeat("a", 64), Size: 123})
	}
	return BackupMetadata{ID: id, Service: service, ProfileID: "production-standard-ha", CreatedAt: time.Now().UTC(), Files: files}
}

func backupPayloadNamesMust(service string) []string {
	names, err := backupPayloadNames(service)
	if err != nil {
		panic(err)
	}
	return names
}

func TestLifecycleRestoreManifestStagesAndReverifiesPayloadBeforeMutation(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.PostgreSQLImage = "registry/postgres@sha256:" + repeat("a", 64)
	bundle.Spec.Workloads.MaintenanceImage = "registry/maintenance@sha256:" + repeat("b", 64)
	meta := BackupMetadata{ID: "backup-verified", Service: "forgejo", ProfileID: "production-standard-ha", CreatedAt: time.Now().UTC(), Files: []BackupFile{
		{Name: "data.tar.gz", SHA256: "sha256:" + strings.Repeat("1", 64), Size: 101},
		{Name: "database.dump", SHA256: "sha256:" + strings.Repeat("2", 64), Size: 202},
	}}
	manifest := restoreJobManifest("forgejo", meta.ID, "restore-job", "operation-a", "/var/lib/backups", bundle, meta.ProfileID, "manager-a", meta)
	for _, required := range []string{
		"name: verify-backup", "emptyDir: {}", "readOnly: true", "sha256sum", "wc -c", "/verified/data.tar.gz", "/verified/database.dump",
		"/backup/backup-verified/data.tar.gz", strings.Repeat("1", 64),
		"pg_restore", "--exit-on-error /verified/database.dump", "tar -C /data -xzf /verified/data.tar.gz",
	} {
		if !strings.Contains(manifest, required) {
			t.Fatalf("restore manifest missing staged integrity contract %q:\n%s", required, manifest)
		}
	}
	if strings.Contains(manifest, "tar -C /data -xzf /backup/") {
		t.Fatalf("data restore must not consume mutable hostPath payload directly:\n%s", manifest)
	}
}

func TestLifecycleHAManifestsUseServiceDatabaseOwners(t *testing.T) {
	bundle := bootstrap.BundleManifest{}
	bundle.Spec.Workloads.PostgreSQLImage = "registry/postgres@sha256:" + repeat("a", 64)
	bundle.Spec.Workloads.MaintenanceImage = "registry/maintenance@sha256:" + repeat("b", 64)
	for _, tc := range []struct{ service, user, secret string }{
		{"forgejo", "forgejo", "platform-forgejo-db"},
		{"keycloak", "keycloak", "platform-keycloak-db"},
	} {
		backup := backupJobManifest(tc.service, "backup-ha", "backup-operation-ha", "operation-ha", "/var/lib/backups", bundle, "production-standard-ha", "manager-a")
		restore := restoreJobManifest(tc.service, "backup-ha", "restore-operation-ha", "operation-ha", "/var/lib/backups", bundle, "production-standard-ha", "manager-a", testBackupMetadata(tc.service, "backup-ha"))
		for _, expected := range []string{"name: " + tc.secret, "-U " + tc.user, "--no-owner", "nodeName: \"manager-a\"", "runAsUser: 0", "allowPrivilegeEscalation: false"} {
			if !strings.Contains(backup, expected) {
				t.Fatalf("%s HA backup missing %q:\n%s", tc.service, expected, backup)
			}
		}
		for _, expected := range []string{"name: " + tc.secret, "-U " + tc.user, "--clean --if-exists --no-owner --exit-on-error", "nodeName: \"manager-a\"", "runAsUser: 0", "allowPrivilegeEscalation: false"} {
			if !strings.Contains(restore, expected) {
				t.Fatalf("%s HA restore missing %q:\n%s", tc.service, expected, restore)
			}
		}
		if strings.Contains(restore, "dropdb ") || strings.Contains(restore, "createdb ") {
			t.Fatalf("%s restore must not require CREATEDB/drop database authority:\n%s", tc.service, restore)
		}
	}
	single := backupJobManifest("forgejo", "backup-single", "backup-operation-single", "operation-single", "/var/lib/backups", bundle, "evaluation-single-node", "manager-a")
	if !strings.Contains(single, "name: platform-database") || !strings.Contains(single, "-U platform") {
		t.Fatalf("single-node lifecycle database authority changed unexpectedly:\n%s", single)
	}
}

func TestLifecycleQuiesceObservesTerminationAndRestoresHAReplicas(t *testing.T) {
	system := &lifecycleCommandSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, podResponses: [][]byte{[]byte("pod/platform-keycloak-0\n"), nil}}
	m := &Manager{system: system, stateDir: t.TempDir()}
	if err := m.quiesceWorkload(context.Background(), "test-op", "statefulset", "platform-keycloak", "keycloak", 2); err != nil {
		t.Fatal(err)
	}
	if err := m.resumeWorkload(context.Background(), "test-op", "statefulset", "platform-keycloak", 2); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(system.Commands, "\n")
	for _, expected := range []string{"patch statefulset platform-keycloak --type=json", "get pods -l app=platform-keycloak", "rollout status statefulset/platform-keycloak --timeout=10m"} {
		if !strings.Contains(commands, expected) {
			t.Fatalf("missing lifecycle quiesce/resume command %q:\n%s", expected, commands)
		}
	}
}

func TestLifecycleQuiesceObservationFailureRecoversService(t *testing.T) {
	system := &lifecycleCommandSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, outputErr: errors.New("injected observation failure")}
	m := &Manager{system: system, stateDir: t.TempDir()}
	err := m.quiesceWorkload(context.Background(), "test-op", "statefulset", "platform-keycloak", "keycloak", 2)
	if err == nil || !strings.Contains(err.Error(), "injected observation failure") {
		t.Fatalf("expected observation failure, got %v", err)
	}
	commands := strings.Join(system.Commands, "\n")
	if !strings.Contains(commands, "patch statefulset platform-keycloak --type=json") || !strings.Contains(commands, "rollout status statefulset/platform-keycloak --timeout=10m") {
		t.Fatalf("quiesce observation failure did not recover HA replicas:\n%s", commands)
	}
}

type lifecycleJobSystem struct {
	*bootstrap.SimulatedSystem
	jobs map[string]map[string]any
}

func (s *lifecycleJobSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	verb := ""
	for _, arg := range args {
		if arg == "get" || arg == "create" {
			verb = arg
			break
		}
	}
	if verb == "get" {
		jobName := ""
		for i, arg := range args {
			if arg == "job" && i+1 < len(args) {
				jobName = args[i+1]
				break
			}
		}
		job := s.jobs[jobName]
		if job == nil {
			return nil, nil
		}
		return json.Marshal(job)
	}
	if verb == "create" {
		jobName := "backup-operation-1"
		job := map[string]any{
			"metadata": map[string]any{
				"name": jobName, "uid": "uid-1", "resourceVersion": "1",
				"annotations": map[string]any{
					"platform.4so.io/job-owner":    "lifecycle",
					"platform.4so.io/operation-id": "operation-1",
					"platform.4so.io/job-name":     jobName,
				},
			},
			"status": map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}},
		}
		s.jobs[jobName] = job
		return json.Marshal(job)
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func TestLifecycleRunJobBindsDurableUIDAndNeverDeletesByName(t *testing.T) {
	system := &lifecycleJobSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, jobs: map[string]map[string]any{}}
	m := &Manager{stateDir: t.TempDir(), system: system}
	manifest := `apiVersion: batch/v1
kind: Job
metadata: {name: backup-operation-1, namespace: platform-system, annotations: {"platform.4so.io/job-owner": "lifecycle", "platform.4so.io/operation-id": "operation-1", "platform.4so.io/job-name": "backup-operation-1"}}
spec: {template: {spec: {restartPolicy: Never, containers: [{name: noop, image: example.invalid/noop}]}}}
`
	if err := m.runJob(context.Background(), "operation-1", "backup-operation-1", "backup-legacy", manifest); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(system.Commands, "\n")
	if strings.Contains(commands, " delete job ") || strings.Contains(commands, " apply -f ") {
		t.Fatalf("lifecycle job runner used name-only delete/apply:\n%s", commands)
	}
	job := system.jobs["backup-operation-1"]
	metadata := job["metadata"].(map[string]any)
	metadata["uid"] = "replacement-uid"
	metadata["resourceVersion"] = "2"
	if err := m.runJob(context.Background(), "operation-1", "backup-operation-1", "backup-legacy", manifest); err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("same-name replacement must fail closed, got %v", err)
	}
}

func TestLifecycleBackupPersistsProfileAndHARejectsLegacyProfilelessBackup(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	run, err := m.StartBackup(context.Background(), "forgejo", "production-standard-ha")
	if err != nil {
		t.Fatal(err)
	}
	run = waitRun(t, m, run.ID)
	if run.State != StateSucceeded || run.ProfileID != "production-standard-ha" {
		t.Fatalf("run=%+v", run)
	}
	meta, err := m.loadBackup("forgejo", run.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ProfileID != "production-standard-ha" {
		t.Fatalf("backup profile not persisted: %+v", meta)
	}
	meta.ProfileID = ""
	raw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(state, "backups", run.BackupID, "backup.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.performRestore(context.Background(), "lifecycle-forgejo-restore-legacy", "forgejo", run.BackupID, "production-standard-ha", run.BundleDigest); err == nil || !strings.Contains(err.Error(), "legacy lifecycle backup") {
		t.Fatalf("profileless legacy HA backup must fail closed, got %v", err)
	}
}

type lifecycleUpgradeDriftSystem struct {
	*bootstrap.SimulatedSystem
	image             string
	driftAfterRollout bool
}

func (s *lifecycleUpgradeDriftSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	if strings.Contains(command, " get deployment platform-zot -o json") {
		return []byte(fmt.Sprintf(`{"metadata":{"uid":"uid-zot","resourceVersion":"11"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"zot","image":%q}]}}}}`, s.image)), nil
	}
	if strings.Contains(command, " patch deployment platform-zot --type=json ") {
		marker := `"path":"/spec/template/spec/containers/0/image","value":"`
		if index := strings.LastIndex(command, marker); index >= 0 {
			tail := command[index+len(marker):]
			if end := strings.Index(tail, `"`); end >= 0 {
				s.image = tail[:end]
			}
		}
		return []byte(fmt.Sprintf(`{"metadata":{"uid":"uid-zot","resourceVersion":"12"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"zot","image":%q}]}}}}`, s.image)), nil
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func (s *lifecycleUpgradeDriftSystem) Run(ctx context.Context, name string, args []string, environment map[string]string) error {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	if strings.Contains(command, " rollout status deployment/platform-zot ") {
		if s.driftAfterRollout {
			s.image = "registry/zot@sha256:" + repeat("c", 64)
		}
		return nil
	}
	return s.SimulatedSystem.Run(ctx, name, args, environment)
}

func TestLifecycleUpgradeRejectsSameUIDImageDriftAfterRollout(t *testing.T) {
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("b", 64)
	run := Run{ID: "lifecycle-zot-upgrade-drift", Service: "zot", ProfileID: "evaluation-single-node", Action: ActionUpgrade, State: StateRunning, BackupID: "backup", RequestedImage: requested, PreviousImage: previous, UpgradePhase: UpgradePhaseApplyPending, CreatedAt: time.Now().UTC()}
	system := &lifecycleUpgradeDriftSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, image: previous, driftAfterRollout: true}
	m := &Manager{stateDir: t.TempDir(), system: system, now: time.Now, runs: []Run{run}, active: map[string]bool{"zot": true}, reconciling: map[string]bool{}}
	_, err := m.performUpgrade(context.Background(), run.ID, run)
	if err == nil || !strings.Contains(err.Error(), "image postcondition mismatch") {
		t.Fatalf("expected same-UID post-rollout image drift rejection, got %v", err)
	}
	stored := m.findLocked(run.ID)
	if stored == nil || stored.UpgradePhase != UpgradePhaseRecoveryRequired {
		t.Fatalf("drifted upgrade did not become recovery-required: %+v", stored)
	}
}

func TestUpgradeRecoveryBindsExactFailedRunBackupAndPreviousDigest(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	backup, err := m.StartBackup(context.Background(), "zot", "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	backup = waitRun(t, m, backup.ID)
	if backup.State != StateSucceeded || backup.BackupID == "" {
		t.Fatalf("backup=%+v", backup)
	}
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("b", 64)
	source := Run{
		ID: "lifecycle-zot-upgrade-recovery-source", Service: "zot", ProfileID: "evaluation-single-node",
		Action: ActionUpgrade, State: StateFailed, BackupID: backup.BackupID, PreviousImage: previous, RequestedImage: requested,
		UpgradePhase: UpgradePhaseRecoveryRequired, UpgradeFailure: "upgrade rollout failed", CreatedAt: time.Now().UTC(),
	}
	m.mu.Lock()
	m.runs = append(m.runs, source)
	if err = m.saveLocked(); err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	m.mu.Unlock()

	recovery, err := m.StartUpgradeRecovery(context.Background(), UpgradeRecoveryRequest{UpgradeRunID: source.ID}, "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	if recovery.SourceUpgradeRunID != source.ID || recovery.BackupID != backup.BackupID || recovery.PreviousImage != previous || recovery.RequestedImage != requested || recovery.UpgradeRecoveryPhase != UpgradeRecoveryPhaseRestorePending {
		t.Fatalf("recovery authority was not bound to exact failed run: %+v", recovery)
	}
	recovery = waitRun(t, m, recovery.ID)
	if recovery.State != StateSucceeded {
		t.Fatalf("simulated recovery=%+v", recovery)
	}
	var closedSource Run
	for _, item := range m.List() {
		if item.ID == source.ID {
			closedSource = item
		}
	}
	if closedSource.UpgradePhase != UpgradePhaseRecoveryCompleted {
		t.Fatalf("successful recovery did not close source authority: %+v", closedSource)
	}
	if _, err = m.StartUpgradeRecovery(context.Background(), UpgradeRecoveryRequest{UpgradeRunID: source.ID}, "evaluation-single-node"); err == nil {
		t.Fatal("completed source accepted a second destructive recovery")
	}
}

func TestLoadRepairsSuccessfulV0146RecoverySourceAuthority(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("b", 64)
	source := Run{ID: "lifecycle-zot-upgrade-old", Service: "zot", ProfileID: "evaluation-single-node", Action: ActionUpgrade, State: StateFailed, BackupID: "zot-old-backup", PreviousImage: previous, RequestedImage: requested, UpgradePhase: UpgradePhaseRecoveryRequired}
	recovery := Run{ID: "lifecycle-zot-upgrade-recovery-old", Service: "zot", ProfileID: "evaluation-single-node", Action: ActionUpgradeRecovery, State: StateSucceeded, BackupID: source.BackupID, PreviousImage: previous, RequestedImage: requested, SourceUpgradeRunID: source.ID}
	raw, _ := json.Marshal([]Run{source, recovery})
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range m.List() {
		if item.ID == source.ID && item.UpgradePhase != UpgradePhaseRecoveryCompleted {
			t.Fatalf("legacy successful recovery source was not repaired: %+v", item)
		}
	}
	if _, err = m.StartUpgradeRecovery(context.Background(), UpgradeRecoveryRequest{UpgradeRunID: source.ID}, "evaluation-single-node"); err == nil {
		t.Fatal("legacy successful recovery still allowed a second destructive recovery")
	}
}

func TestUpgradeRecoveryPostRestoreReplayNeverRewindsBackupAgain(t *testing.T) {
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("b", 64)
	run := Run{
		ID: "lifecycle-zot-upgrade-recovery-resume", Service: "zot", ProfileID: "evaluation-single-node", ExecutionNode: "manager-a",
		Action: ActionUpgradeRecovery, State: StateRunning, BackupID: "missing-after-restore-is-safe", PreviousImage: previous, RequestedImage: requested,
		UpgradeRecoveryPhase: UpgradeRecoveryPhaseRestoreCompleted, SourceUpgradeRunID: "lifecycle-zot-upgrade-source", CreatedAt: time.Now().UTC(),
	}
	source := Run{ID: run.SourceUpgradeRunID, Service: run.Service, ProfileID: run.ProfileID, Action: ActionUpgrade, State: StateFailed, BackupID: run.BackupID, PreviousImage: previous, RequestedImage: requested, UpgradePhase: UpgradePhaseRecoveryRequired}
	system := &lifecycleUpgradeDriftSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, image: previous}
	m := &Manager{stateDir: t.TempDir(), backupDir: t.TempDir(), system: system, now: time.Now, runs: []Run{source, run}, active: map[string]bool{"zot": true}, reconciling: map[string]bool{}}
	if err := m.performUpgradeRecovery(context.Background(), run.ID, run); err != nil {
		t.Fatal(err)
	}
	stored := m.findLocked(run.ID)
	if stored == nil || stored.UpgradeRecoveryPhase != UpgradeRecoveryPhaseResumeVerified {
		t.Fatalf("recovery did not durably advance after resume verification: %+v", stored)
	}
	commands := strings.Join(system.Commands, "\n")
	if strings.Contains(commands, " job ") || strings.Contains(commands, "restore-") || strings.Contains(commands, " apply ") {
		t.Fatalf("post-restore replay attempted a destructive backup restore:\n%s", commands)
	}
}

func TestLegacyInterruptedUpgradeRecoveryWithoutPhaseFailsClosed(t *testing.T) {
	previous := "registry/zot@sha256:" + repeat("a", 64)
	run := Run{ID: "lifecycle-zot-upgrade-recovery-legacy", Service: "zot", ProfileID: "evaluation-single-node", Action: ActionUpgradeRecovery, State: StateRunning, BackupID: "backup", PreviousImage: previous, SourceUpgradeRunID: "source"}
	system := &lifecycleUpgradeDriftSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, image: previous}
	m := &Manager{stateDir: t.TempDir(), backupDir: t.TempDir(), system: system, now: time.Now, runs: []Run{run}, active: map[string]bool{"zot": true}, reconciling: map[string]bool{}}
	err := m.performUpgradeRecovery(context.Background(), run.ID, run)
	if err == nil || !strings.Contains(err.Error(), "lacks durable phase authority") {
		t.Fatalf("ambiguous legacy recovery replay was not rejected: %v", err)
	}
	if len(system.Commands) != 0 {
		t.Fatalf("ambiguous legacy recovery performed runtime mutation/inspection: %v", system.Commands)
	}
}

func TestUpgradeRecoveryRejectsNonRecoveryRequiredSource(t *testing.T) {
	m := &Manager{stateDir: t.TempDir(), backupDir: t.TempDir(), bundleDir: t.TempDir(), simulation: true, system: &bootstrap.SimulatedSystem{Root: t.TempDir()}, now: time.Now, active: map[string]bool{}, reconciling: map[string]bool{}}
	m.runs = []Run{{ID: "lifecycle-zot-upgrade-complete", Service: "zot", ProfileID: "evaluation-single-node", Action: ActionUpgrade, State: StateSucceeded, BackupID: "backup", PreviousImage: "registry/zot@sha256:" + repeat("a", 64), UpgradePhase: UpgradePhaseApplyVerified}}
	if _, err := m.StartUpgradeRecovery(context.Background(), UpgradeRecoveryRequest{UpgradeRunID: "lifecycle-zot-upgrade-complete"}, "evaluation-single-node"); err == nil || !strings.Contains(err.Error(), "RECOVERY_REQUIRED") {
		t.Fatalf("non-recovery-required upgrade was accepted: %v", err)
	}
}

type blockingLifecycleNodeSystem struct {
	*bootstrap.SimulatedSystem
	entered chan struct{}
	release chan struct{}
}

func (s *blockingLifecycleNodeSystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	if strings.Contains(command, " get node ") {
		select {
		case s.entered <- struct{}{}:
		default:
		}
		select {
		case <-s.release:
			return []byte("node/manager-a\n"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func TestUpgradeRecoveryAdmissionRevalidatesSourceAfterRuntimePreparation(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("b", 64)
	source := Run{
		ID: "lifecycle-zot-upgrade-race-source", Service: "zot", ProfileID: "evaluation-single-node",
		Action: ActionUpgrade, State: StateFailed, BackupID: "zot-race-backup", PreviousImage: previous, RequestedImage: requested,
		UpgradePhase: UpgradePhaseRecoveryRequired, CreatedAt: time.Now().UTC(),
	}
	system := &blockingLifecycleNodeSystem{SimulatedSystem: &bootstrap.SimulatedSystem{Root: t.TempDir()}, entered: make(chan struct{}, 1), release: make(chan struct{})}
	m := &Manager{stateDir: t.TempDir(), backupDir: t.TempDir(), bundleDir: bundle, system: system, now: time.Now, runs: []Run{source}, active: map[string]bool{}, reconciling: map[string]bool{}}

	type result struct {
		run Run
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		run, err := m.StartUpgradeRecovery(context.Background(), UpgradeRecoveryRequest{UpgradeRunID: source.ID}, source.ProfileID)
		resultCh <- result{run: run, err: err}
	}()

	select {
	case <-system.entered:
	case <-time.After(time.Second):
		t.Fatal("upgrade recovery did not reach runtime preparation")
	}
	m.mu.Lock()
	stored := m.findLocked(source.ID)
	if stored == nil {
		m.mu.Unlock()
		t.Fatal("source upgrade disappeared")
	}
	stored.UpgradePhase = UpgradePhaseRecoveryCompleted
	if err := m.saveLocked(); err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	m.mu.Unlock()
	close(system.release)

	res := <-resultCh
	if res.err == nil || !strings.Contains(res.err.Error(), "RECOVERY_REQUIRED") {
		t.Fatalf("stale recovery admission was not rejected after source closure: run=%+v err=%v", res.run, res.err)
	}
	for _, run := range m.List() {
		if run.Action == ActionUpgradeRecovery {
			t.Fatalf("stale recovery was durably queued after source closure: %+v", run)
		}
	}
}

func TestUpgradeRecoveryRetryInheritsRestoreCompletedBoundary(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("b", 64)
	source := Run{
		ID: "lifecycle-zot-upgrade-retry-source", Service: "zot", ProfileID: "evaluation-single-node",
		Action: ActionUpgrade, State: StateFailed, BackupID: "zot-restored-backup", PreviousImage: previous, RequestedImage: requested,
		UpgradePhase: UpgradePhaseRecoveryRequired, CreatedAt: time.Now().UTC(),
	}
	prior := Run{
		ID: "lifecycle-zot-upgrade-recovery-prior", Service: source.Service, ProfileID: source.ProfileID,
		Action: ActionUpgradeRecovery, State: StateFailed, BackupID: source.BackupID, PreviousImage: previous, RequestedImage: requested,
		UpgradeRecoveryPhase: UpgradeRecoveryPhaseRestoreCompleted, SourceUpgradeRunID: source.ID, Error: "resume verification persistence failed", CreatedAt: time.Now().UTC(),
	}
	m := &Manager{stateDir: t.TempDir(), backupDir: t.TempDir(), bundleDir: bundle, simulation: true, system: &bootstrap.SimulatedSystem{Root: t.TempDir()}, now: time.Now, runs: []Run{source, prior}, active: map[string]bool{}, reconciling: map[string]bool{}}

	retry, err := m.StartUpgradeRecovery(context.Background(), UpgradeRecoveryRequest{UpgradeRunID: source.ID}, source.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if retry.UpgradeRecoveryPhase != UpgradeRecoveryPhaseRestoreCompleted {
		t.Fatalf("retry lost durable restore boundary and could rewind backup again: %+v", retry)
	}
	retry = waitRun(t, m, retry.ID)
	if retry.State != StateSucceeded || retry.UpgradeRecoveryPhase != UpgradeRecoveryPhaseResumeVerified {
		t.Fatalf("non-destructive recovery continuation did not complete: %+v", retry)
	}
}

func TestUpgradeRecoveryRetryInheritsResumeVerifiedBoundary(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("b", 64)
	source := Run{
		ID: "lifecycle-zot-upgrade-verify-source", Service: "zot", ProfileID: "evaluation-single-node",
		Action: ActionUpgrade, State: StateFailed, BackupID: "zot-verified-backup", PreviousImage: previous, RequestedImage: requested,
		UpgradePhase: UpgradePhaseRecoveryRequired, CreatedAt: time.Now().UTC(),
	}
	prior := Run{
		ID: "lifecycle-zot-upgrade-recovery-verified", Service: source.Service, ProfileID: source.ProfileID,
		Action: ActionUpgradeRecovery, State: StateFailed, BackupID: source.BackupID, PreviousImage: previous, RequestedImage: requested,
		UpgradeRecoveryPhase: UpgradeRecoveryPhaseResumeVerified, SourceUpgradeRunID: source.ID, Error: "final source closure persistence failed", CreatedAt: time.Now().UTC(),
	}
	m := &Manager{stateDir: t.TempDir(), backupDir: t.TempDir(), bundleDir: bundle, simulation: true, system: &bootstrap.SimulatedSystem{Root: t.TempDir()}, now: time.Now, runs: []Run{source, prior}, active: map[string]bool{}, reconciling: map[string]bool{}}

	retry, err := m.StartUpgradeRecovery(context.Background(), UpgradeRecoveryRequest{UpgradeRunID: source.ID}, source.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if retry.UpgradeRecoveryPhase != UpgradeRecoveryPhaseResumeVerified {
		t.Fatalf("retry regressed a read-only recovery boundary: %+v", retry)
	}
	retry = waitRun(t, m, retry.ID)
	if retry.State != StateSucceeded {
		t.Fatalf("read-only recovery finalization retry failed: %+v", retry)
	}
}

func TestUpgradeRecoveryRetryRejectsMismatchedPriorAuthority(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	previous := "registry/zot@sha256:" + repeat("a", 64)
	requested := "registry/zot@sha256:" + repeat("b", 64)
	source := Run{
		ID: "lifecycle-zot-upgrade-corrupt-source", Service: "zot", ProfileID: "evaluation-single-node",
		Action: ActionUpgrade, State: StateFailed, BackupID: "zot-authoritative-backup", PreviousImage: previous, RequestedImage: requested,
		UpgradePhase: UpgradePhaseRecoveryRequired, CreatedAt: time.Now().UTC(),
	}
	prior := Run{
		ID: "lifecycle-zot-upgrade-recovery-corrupt", Service: source.Service, ProfileID: source.ProfileID,
		Action: ActionUpgradeRecovery, State: StateFailed, BackupID: "zot-different-backup", PreviousImage: previous, RequestedImage: requested,
		UpgradeRecoveryPhase: UpgradeRecoveryPhaseRestoreCompleted, SourceUpgradeRunID: source.ID, CreatedAt: time.Now().UTC(),
	}
	m := &Manager{stateDir: t.TempDir(), backupDir: t.TempDir(), bundleDir: bundle, simulation: true, system: &bootstrap.SimulatedSystem{Root: t.TempDir()}, now: time.Now, runs: []Run{source, prior}, active: map[string]bool{}, reconciling: map[string]bool{}}
	if _, err := m.StartUpgradeRecovery(context.Background(), UpgradeRecoveryRequest{UpgradeRunID: source.ID}, source.ProfileID); err == nil || !strings.Contains(err.Error(), "does not match source upgrade authority") {
		t.Fatalf("mismatched prior recovery authority did not fail closed: %v", err)
	}
}

func TestLifecycleDurableRestoreRecoveryFenceBlocksUnrelatedMutationAndClearsAfterRestore(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	m, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	backup, err := m.StartBackup(context.Background(), "forgejo", "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	backup = waitRun(t, m, backup.ID)
	if backup.State != StateSucceeded {
		t.Fatalf("backup=%+v", backup)
	}
	otherBackup, err := m.StartBackup(context.Background(), "forgejo", "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	otherBackup = waitRun(t, m, otherBackup.ID)
	if otherBackup.State != StateSucceeded {
		t.Fatalf("other backup=%+v", otherBackup)
	}
	m.mu.Lock()
	m.runs = append(m.runs, Run{
		ID:               "lifecycle-forgejo-restore-recovery-required",
		Service:          "forgejo",
		ProfileID:        "evaluation-single-node",
		Action:           ActionRestore,
		State:            StateFailed,
		BackupID:         backup.BackupID,
		RecoveryRequired: true,
		Error:            "restore failed after quiesce",
		CreatedAt:        time.Now().UTC(),
	})
	if err = m.saveLocked(); err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	m.mu.Unlock()

	reloaded, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.HasActive() {
		t.Fatal("durable destructive restore recovery requirement did not remain blocking after restart")
	}
	if _, err = reloaded.StartBackup(context.Background(), "forgejo", "evaluation-single-node"); err == nil || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatalf("unrelated backup was admitted across destructive restore recovery fence: %v", err)
	}
	if _, err = reloaded.StartUpgrade(context.Background(), UpgradeRequest{Service: "forgejo", Image: "registry/forgejo@sha256:" + repeat("f", 64)}, "evaluation-single-node"); err == nil || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatalf("unrelated upgrade was admitted across destructive restore recovery fence: %v", err)
	}
	if _, err = reloaded.StartRestore(context.Background(), RestoreRequest{Service: "forgejo", BackupID: otherBackup.BackupID}, "evaluation-single-node"); err == nil || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatalf("different backup was admitted as destructive restore recovery: %v", err)
	}
	restore, err := reloaded.StartRestore(context.Background(), RestoreRequest{Service: "forgejo", BackupID: backup.BackupID}, "evaluation-single-node")
	if err != nil {
		t.Fatal(err)
	}
	restore = waitRun(t, reloaded, restore.ID)
	if restore.State != StateSucceeded {
		t.Fatalf("recovery restore=%+v", restore)
	}
	if reloaded.HasActive() {
		t.Fatalf("successful recovery restore did not clear durable recovery fence: %+v", reloaded.List())
	}
	for _, run := range reloaded.List() {
		if run.ID == "lifecycle-forgejo-restore-recovery-required" && run.RecoveryRequired {
			t.Fatalf("successful recovery restore did not clear blocker: %+v", run)
		}
	}
}

func TestLifecycleLoadRejectsInvalidRecoveryRequiredAuthority(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	runs := []Run{{
		ID: "lifecycle-invalid-recovery-marker", Service: "forgejo", ProfileID: "evaluation-single-node",
		Action: ActionBackup, State: StateFailed, RecoveryRequired: true, CreatedAt: time.Now().UTC(),
	}}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "invalid recoveryRequired authority") {
		t.Fatalf("invalid lifecycle recovery marker was accepted: %v", err)
	}
}

func TestLifecycleLoadRejectsConflictingRecoveryRequiredAuthorities(t *testing.T) {
	bundle := t.TempDir()
	lifecycleBundle(t, bundle)
	state := t.TempDir()
	now := time.Now().UTC()
	runs := []Run{
		{ID: "lifecycle-forgejo-restore-a", Service: "forgejo", ProfileID: "evaluation-single-node", Action: ActionRestore, State: StateFailed, BackupID: "backup-a", RecoveryRequired: true, CreatedAt: now},
		{ID: "lifecycle-forgejo-restore-b", Service: "forgejo", ProfileID: "evaluation-single-node", Action: ActionRestore, State: StateFailed, BackupID: "backup-b", RecoveryRequired: true, CreatedAt: now.Add(time.Second)},
	}
	raw, _ := json.Marshal(runs)
	if err := os.WriteFile(filepath.Join(state, "lifecycle-runs.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{StateDir: state, BundleDir: bundle, Simulation: true, System: &bootstrap.SimulatedSystem{Root: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "conflicting recoveryRequired authorities") {
		t.Fatalf("conflicting lifecycle recovery authorities were accepted: %v", err)
	}
}

func TestRestoreAdmissionRejectsBackupMetadataWithoutPayload(t *testing.T) {
	state := t.TempDir()
	backupID := "zot-empty-backup"
	backupDir := filepath.Join(state, "backups", backupID)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := BackupMetadata{ID: backupID, Service: "zot", ProfileID: "evaluation-single-node", CreatedAt: time.Now().UTC(), Files: nil}
	raw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(backupDir, "backup.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{stateDir: state, backupDir: filepath.Join(state, "backups"), now: time.Now}
	if _, err := m.validateBackupForRestore("zot", backupID, "evaluation-single-node"); err == nil {
		t.Fatal("restore admission accepted backup metadata with no payload files")
	}
}

func TestRestoreAdmissionRejectsBackupMetadataPathEscape(t *testing.T) {
	state := t.TempDir()
	backupID := "zot-path-escape"
	backupDir := filepath.Join(state, "backups", backupID)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(state, "outside-payload")
	payload := []byte("outside")
	if err := os.WriteFile(outside, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	meta := BackupMetadata{
		ID: backupID, Service: "zot", ProfileID: "evaluation-single-node", CreatedAt: time.Now().UTC(),
		Files: []BackupFile{{Name: "../../outside-payload", SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(payload))}},
	}
	raw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(backupDir, "backup.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{stateDir: state, backupDir: filepath.Join(state, "backups"), now: time.Now}
	if _, err := m.validateBackupForRestore("zot", backupID, "evaluation-single-node"); err == nil || !strings.Contains(err.Error(), "unexpected file") {
		t.Fatalf("restore admission must reject metadata path escape before hashing, got %v", err)
	}
}

func TestRestoreAdmissionRejectsSymlinkPayloadEvenWhenDigestMatches(t *testing.T) {
	state := t.TempDir()
	backupID := "zot-symlink-payload"
	backupDir := filepath.Join(state, "backups", backupID)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(state, "outside-data.tar.gz")
	payload := []byte("matching-external-payload")
	if err := os.WriteFile(outside, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(backupDir, "data.tar.gz")); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	meta := BackupMetadata{
		ID: backupID, Service: "zot", ProfileID: "evaluation-single-node", CreatedAt: time.Now().UTC(),
		Files: []BackupFile{{Name: "data.tar.gz", SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(payload))}},
	}
	raw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(backupDir, "backup.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{stateDir: state, backupDir: filepath.Join(state, "backups"), now: time.Now}
	if _, err := m.validateBackupForRestore("zot", backupID, "evaluation-single-node"); err == nil || !strings.Contains(err.Error(), "real regular file") {
		t.Fatalf("restore admission must reject symlink payload, got %v", err)
	}
}

func TestRestoreAdmissionRejectsPayloadSizeAuthorityMismatch(t *testing.T) {
	state := t.TempDir()
	backupID := "zot-size-mismatch"
	backupDir := filepath.Join(state, "backups", backupID)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	if err := os.WriteFile(filepath.Join(backupDir, "data.tar.gz"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	meta := BackupMetadata{
		ID: backupID, Service: "zot", ProfileID: "evaluation-single-node", CreatedAt: time.Now().UTC(),
		Files: []BackupFile{{Name: "data.tar.gz", SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(payload) + 1)}},
	}
	raw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(backupDir, "backup.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{stateDir: state, backupDir: filepath.Join(state, "backups"), now: time.Now}
	if _, err := m.validateBackupForRestore("zot", backupID, "evaluation-single-node"); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("restore admission must reject size mismatch, got %v", err)
	}
}

func TestUpgradeInterruptionRecoveryMatrixCoversEveryDurableBoundary(t *testing.T) {
	matrix := UpgradeInterruptionRecoveryMatrix()
	if UpgradeInterruptionRecoveryMatrixAuthority != "INSTALLER_UPGRADE_INTERRUPTION_RECOVERY_MATRIX_V1" {
		t.Fatalf("authority=%q", UpgradeInterruptionRecoveryMatrixAuthority)
	}
	if len(matrix) != 6 {
		t.Fatalf("matrix scenarios=%d want 6", len(matrix))
	}
	seen := map[string]UpgradeInterruptionRecoveryScenario{}
	for _, scenario := range matrix {
		if scenario.Checkpoint == "" || scenario.PersistedPhase == "" || scenario.RestartBehavior == "" || scenario.RecoveryBoundary == "" {
			t.Fatalf("incomplete scenario: %+v", scenario)
		}
		if _, exists := seen[scenario.PersistedPhase]; exists {
			t.Fatalf("duplicate phase %q", scenario.PersistedPhase)
		}
		seen[scenario.PersistedPhase] = scenario
	}
	for _, phase := range []string{
		string(UpgradePhaseBackupPending), string(UpgradePhaseApplyPending), string(UpgradePhaseApplyVerified),
		string(UpgradePhaseRecoveryRequired), string(UpgradeRecoveryPhaseRestoreCompleted), string(UpgradeRecoveryPhaseResumeVerified),
	} {
		if _, ok := seen[phase]; !ok {
			t.Fatalf("durable interruption phase %q is missing from matrix", phase)
		}
	}
	if seen[string(UpgradePhaseRecoveryRequired)].AutomaticReplay {
		t.Fatal("RECOVERY_REQUIRED must never automatically replay the failed upgrade")
	}
}
