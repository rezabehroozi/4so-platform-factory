package hostdeployment

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bundlebuilder"
)

func TestStagedApplyVerifyRollback(t *testing.T) {
	source := t.TempDir()
	binary := filepath.Join(source, "platform-installer")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 0.0.30; exit 0; fi\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := buildBundle(t, source, "0.0.30")
	root := t.TempDir()
	oldBundle := filepath.Join(root, "opt/4so-platform-factory/bundle")
	if err := os.MkdirAll(oldBundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldBundle, "previous-marker"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldBinary := filepath.Join(root, "usr/local/bin/platform-installer")
	if err := os.MkdirAll(filepath.Dir(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldBinary, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	specPath := writeSpec(t, source, binary, bundle, "127.0.0.1:9080")
	now := time.Date(2026, 8, 6, 20, 0, 0, 0, time.UTC)
	plan, err := BuildPlan(specPath, Options{Root: root, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Version != "0.0.30" || plan.Bundle.Version != "0.0.30" || plan.Confirmation != "DEPLOY" {
		t.Fatalf("unexpected plan %#v", plan)
	}
	if strings.Contains(string(renderEnvironment(mustLoadSpec(t, specPath))), root) || strings.Contains(string(renderUnit()), root) {
		t.Fatal("staged files must contain runtime paths, not staging root")
	}
	if _, err = Apply(context.Background(), specPath, "WRONG", Options{Root: root}); err == nil {
		t.Fatal("expected explicit confirmation failure")
	}
	state, err := Apply(context.Background(), specPath, "DEPLOY", Options{Root: root, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "STAGED" || state.Activated {
		t.Fatalf("unexpected state %#v", state)
	}
	info, err := os.Stat(state.Plan.Paths.State)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %04o", info.Mode().Perm())
	}
	envRaw, err := os.ReadFile(state.Plan.Paths.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envRaw), root) || strings.Contains(strings.ToLower(string(envRaw)), "bootstrap_token") {
		t.Fatalf("unsafe env %s", envRaw)
	}
	result, err := Verify(context.Background(), state.Plan.Paths.State, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || !result.StagedOnly || result.Version != "0.0.30" {
		t.Fatalf("unexpected verify %#v", result)
	}
	if _, err = Rollback(context.Background(), state.Plan.Paths.State, "WRONG", Options{}); err == nil {
		t.Fatal("expected rollback confirmation failure")
	}
	rolled, err := Rollback(context.Background(), state.Plan.Paths.State, "ROLLBACK", Options{Now: func() time.Time { return now.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Status != "ROLLED_BACK" {
		t.Fatalf("unexpected rollback %#v", rolled)
	}
	raw, err := os.ReadFile(oldBinary)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "old-binary" {
		t.Fatalf("binary not restored: %q", raw)
	}
	raw, err = os.ReadFile(filepath.Join(oldBundle, "previous-marker"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "old" {
		t.Fatalf("bundle not restored: %q", raw)
	}
}

func TestPlanRejectsVersionMismatchAndTamperedState(t *testing.T) {
	source := t.TempDir()
	binary := filepath.Join(source, "platform-installer")
	_ = os.WriteFile(binary, []byte("#!/bin/sh\necho 0.0.26\n"), 0o755)
	bundle := buildBundle(t, source, "0.0.30")
	spec := writeSpec(t, source, binary, bundle, "127.0.0.1:9080")
	if _, err := BuildPlan(spec, Options{Root: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "binary version") {
		t.Fatalf("expected version mismatch: %v", err)
	}

	_ = os.WriteFile(binary, []byte("#!/bin/sh\necho 0.0.30\n"), 0o755)
	root := t.TempDir()
	state, err := Apply(context.Background(), spec, "DEPLOY", Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(state.Plan.Paths.State)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err = json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["status"] = "APPLIED"
	raw, _ = json.Marshal(payload)
	if err = os.WriteFile(state.Plan.Paths.State, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadState(state.Plan.Paths.State); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("expected integrity rejection: %v", err)
	}
}

func TestPlanRejectsPublicHTTP(t *testing.T) {
	source := t.TempDir()
	binary := filepath.Join(source, "platform-installer")
	_ = os.WriteFile(binary, []byte("#!/bin/sh\necho 0.0.30\n"), 0o755)
	bundle := buildBundle(t, source, "0.0.30")
	spec := writeSpec(t, source, binary, bundle, "0.0.0.0:9080")
	if _, err := BuildPlan(spec, Options{Root: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "requires TLS") {
		t.Fatalf("expected TLS rejection: %v", err)
	}
}

func writeSpec(t *testing.T, dir, binary, bundle, listen string) string {
	t.Helper()
	spec := Spec{APIVersion: APIVersion, Kind: Kind}
	spec.Metadata.Name = "field-installer"
	spec.Metadata.Version = "0.0.30"
	spec.Spec.InstallerBinary = binary
	spec.Spec.BundleDirectory = bundle
	spec.Spec.Listen = listen
	spec.Spec.ExecutionEnabled = false
	spec.Spec.Admission = &AdmissionPolicy{AllowDowngrade: false}
	spec.Spec.Service.Enable = true
	spec.Spec.Service.Start = true
	raw, _ := json.MarshalIndent(spec, "", "  ")
	path := filepath.Join(dir, "host-deployment.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func mustLoadSpec(t *testing.T, path string) Spec {
	t.Helper()
	spec, _, err := LoadSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func buildBundle(t *testing.T, root, version string) string {
	t.Helper()
	staging := filepath.Join(root, "staging")
	files := map[string]string{"rke2/install.sh": "#!/bin/sh\nexit 0\n", "rke2/rke2.tar.gz": "rke2", "rke2/images.tar.zst": "rke2-images", "workloads/images.tar.zst": "workloads", "manifests/argocd.yaml": testManifest("argocd", "1"), "manifests/cnpg.yaml": testManifest("cnpg", "2"), "manifests/ocm.yaml": testManifest("ocm", "3"), "manifests/storage.yaml": testManifest("storage", "4")}
	for name, content := range files {
		path := filepath.Join(staging, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec := bundlebuilder.BuildSpec{APIVersion: bundlebuilder.BuildAPIVersion, Kind: bundlebuilder.BuildKind}
	spec.Metadata.Version = version
	spec.Metadata.SourceReleaseDigest = "sha256:" + strings.Repeat("7", 64)
	spec.Spec.RKE2.Version = "v1.34.0+rke2r1"
	spec.Spec.RKE2.Installer = "rke2/install.sh"
	spec.Spec.RKE2.InstallArtifacts = []string{"rke2/rke2.tar.gz"}
	spec.Spec.RKE2.ImageArchives = []string{"rke2/images.tar.zst"}
	spec.Spec.Workloads.ImageArchives = []string{"workloads/images.tar.zst"}
	spec.Spec.Workloads.PostgreSQLImage = testImage("postgres", "a")
	spec.Spec.Workloads.PlatformAPIImage = testImage("api", "b")
	spec.Spec.Workloads.ForgejoImage = testImage("forgejo", "c")
	spec.Spec.Workloads.ZotImage = testImage("zot", "d")
	spec.Spec.Workloads.KeycloakImage = testImage("keycloak", "e")
	spec.Spec.Workloads.MaintenanceImage = testImage("maintenance", "f")
	spec.Spec.Workloads.GitOpsManifest = "manifests/argocd.yaml"
	spec.Spec.Workloads.CloudNativePGManifest = "manifests/cnpg.yaml"
	spec.Spec.Workloads.OCMManifest = "manifests/ocm.yaml"
	spec.Spec.Workloads.StorageManifest = "manifests/storage.yaml"
	spec.Spec.Workloads.FleetAgentImage = testImage("agent", "9")
	spec.Spec.Workloads.RuntimeProbeImage = testImage("probe", "8")
	raw, _ := json.MarshalIndent(spec, "", "  ")
	specPath := filepath.Join(root, "bundle-build.json")
	if err := os.WriteFile(specPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "bundle")
	if _, err := bundlebuilder.Build(specPath, staging, output); err != nil {
		t.Fatal(err)
	}
	return output
}
func testImage(name, digit string) string {
	return "registry.local/" + name + "@sha256:" + strings.Repeat(digit, 64)
}
func testManifest(name, digit string) string {
	return "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: " + name + "\n          image: " + testImage(name, digit) + "\n"
}

func TestInterruptedApplyRequiresExplicitRecovery(t *testing.T) {
	for _, interruptStep := range []string{"binary-installed", "bundle-installed", "unit-written"} {
		t.Run(interruptStep, func(t *testing.T) {
			source := t.TempDir()
			binary := filepath.Join(source, "platform-installer")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 0.0.30; exit 0; fi\nexit 1\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			bundle := buildBundle(t, source, "0.0.30")
			root := t.TempDir()
			oldBinary := filepath.Join(root, "usr/local/bin/platform-installer")
			if err := os.MkdirAll(filepath.Dir(oldBinary), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(oldBinary, []byte("old-binary"), 0o755); err != nil {
				t.Fatal(err)
			}
			oldBundle := filepath.Join(root, "opt/4so-platform-factory/bundle")
			if err := os.MkdirAll(oldBundle, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(oldBundle, "previous-marker"), []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			specPath := writeSpec(t, source, binary, bundle, "127.0.0.1:9080")
			state, err := Apply(context.Background(), specPath, "DEPLOY", Options{
				Root: root,
				AfterCheckpoint: func(step string) error {
					if step == interruptStep {
						return errors.New("simulated process interruption")
					}
					return nil
				},
			})
			if err == nil || !strings.Contains(err.Error(), "simulated process interruption") {
				t.Fatalf("expected simulated interruption, state=%#v err=%v", state, err)
			}
			journal, err := LoadState(state.Plan.Paths.State)
			if err != nil {
				t.Fatal(err)
			}
			if journal.Status != "APPLYING" || !journal.BackupPrepared || journal.SchemaVersion != 4 {
				t.Fatalf("unexpected journal %#v", journal)
			}
			if _, err = Apply(context.Background(), specPath, "DEPLOY", Options{Root: root}); err == nil || !strings.Contains(err.Error(), "requires explicit RECOVER") {
				t.Fatalf("unfinished transaction was not rejected: %v", err)
			}
			if _, err = Recover(context.Background(), state.Plan.Paths.State, "WRONG", Options{}); err == nil {
				t.Fatal("expected explicit recovery confirmation failure")
			}
			recovered, err := Recover(context.Background(), state.Plan.Paths.State, "RECOVER", Options{})
			if err != nil {
				t.Fatal(err)
			}
			if recovered.Status != "RECOVERED" || recovered.RecoveryRequired || recovered.RecoveredAt.IsZero() {
				t.Fatalf("unexpected recovered state %#v", recovered)
			}
			raw, err := os.ReadFile(oldBinary)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != "old-binary" {
				t.Fatalf("binary was not restored: %q", raw)
			}
			raw, err = os.ReadFile(filepath.Join(oldBundle, "previous-marker"))
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != "old" {
				t.Fatalf("bundle was not restored: %q", raw)
			}
			if _, err = Recover(context.Background(), state.Plan.Paths.State, "RECOVER", Options{}); err == nil || !strings.Contains(err.Error(), "does not require recovery") {
				t.Fatalf("terminal recovery was not rejected: %v", err)
			}
		})
	}
}

func TestDeploymentLockRejectsConcurrentMutation(t *testing.T) {
	source := t.TempDir()
	binary := filepath.Join(source, "platform-installer")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 0.0.30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := buildBundle(t, source, "0.0.30")
	root := t.TempDir()
	specPath := writeSpec(t, source, binary, bundle, "127.0.0.1:9080")
	plan, err := BuildPlan(specPath, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := acquireDeploymentLock(plan.Paths.Lock)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err = Apply(context.Background(), specPath, "DEPLOY", Options{Root: root}); err == nil || !strings.Contains(err.Error(), "transaction is active") {
		t.Fatalf("expected concurrent transaction rejection: %v", err)
	}
	info, err := os.Stat(plan.Paths.Lock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode %04o", info.Mode().Perm())
	}
}

func TestHostAdmissionBlocksDowngradeUnlessExplicit(t *testing.T) {
	source := t.TempDir()
	binary := filepath.Join(source, "platform-installer")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 0.0.30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := buildBundle(t, source, "0.0.30")
	root := t.TempDir()
	deployedBinary := filepath.Join(root, "usr/local/bin/platform-installer")
	if err := os.MkdirAll(filepath.Dir(deployedBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deployedBinary, []byte("#!/bin/sh\necho 0.0.32\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	currentSource := t.TempDir()
	currentBundle := buildBundle(t, currentSource, "0.0.32")
	deployedBundle := filepath.Join(root, "opt/4so-platform-factory/bundle")
	if err := copyTree(currentBundle, deployedBundle); err != nil {
		t.Fatal(err)
	}
	specPath := writeSpec(t, source, binary, bundle, "127.0.0.1:9080")
	plan, err := BuildPlan(specPath, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Admission.Ready || plan.Admission.UpgradeMode != "DOWNGRADE" || !containsAdmissionStatus(plan.Admission, "version-transition", AdmissionBlocked) {
		t.Fatalf("expected blocked downgrade: %#v", plan.Admission)
	}
	if _, err = Apply(context.Background(), specPath, "DEPLOY", Options{Root: root}); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("expected apply to stop before mutation: %v", err)
	}
	spec, _, err := LoadSpec(specPath)
	if err != nil {
		t.Fatal(err)
	}
	spec.Spec.Admission.AllowDowngrade = true
	raw, _ := json.MarshalIndent(spec, "", "  ")
	if err = os.WriteFile(specPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err = BuildPlan(specPath, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Admission.Ready || !containsAdmissionStatus(plan.Admission, "version-transition", AdmissionWarning) {
		t.Fatalf("explicit downgrade was not admitted: %#v", plan.Admission)
	}
}

func TestHostAdmissionRejectsSymlinkAncestor(t *testing.T) {
	source := t.TempDir()
	binary := filepath.Join(source, "platform-installer")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 0.0.30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := buildBundle(t, source, "0.0.30")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "usr/local")); err != nil {
		t.Fatal(err)
	}
	specPath := writeSpec(t, source, binary, bundle, "127.0.0.1:9080")
	plan, err := BuildPlan(specPath, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Admission.Ready || !containsAdmissionStatus(plan.Admission, "path-safety", AdmissionBlocked) {
		t.Fatalf("expected symlink ancestor rejection: %#v", plan.Admission)
	}
}

func TestVerifyRejectsTamperedAdmissionEvidence(t *testing.T) {
	source := t.TempDir()
	binary := filepath.Join(source, "platform-installer")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 0.0.30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := buildBundle(t, source, "0.0.30")
	root := t.TempDir()
	specPath := writeSpec(t, source, binary, bundle, "127.0.0.1:9080")
	state, err := Apply(context.Background(), specPath, "DEPLOY", Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	state.Plan.Admission.Checks[0].Summary = "tampered"
	state.StateDigest = stateDigest(state)
	raw, _ := json.MarshalIndent(state, "", "  ")
	if err = os.WriteFile(state.Plan.Paths.State, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(context.Background(), state.Plan.Paths.State, Options{}); err == nil || !strings.Contains(err.Error(), "admission evidence") {
		t.Fatalf("expected admission evidence tamper rejection: %v", err)
	}
}

func containsAdmissionStatus(report HostAdmissionReport, id, status string) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}
