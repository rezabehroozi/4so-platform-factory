package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"platform.4so.io/factory/internal/installation"
	"platform.4so.io/factory/internal/testsupport"
)

func makeBundle(t *testing.T, root string) {
	t.Helper()
	archivePath := filepath.Join(root, "artifacts/workloads.oci.tar")
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatal(err)
	}
	refs, err := testsupport.WriteWorkloadOCIArchive(archivePath, testsupport.WorkloadRepositories("registry.local/", true))
	if err != nil {
		t.Fatal(err)
	}
	byRepo := testsupport.RefsByRepository(refs)
	files := map[string][]byte{
		"artifacts/install.sh":           []byte("#!/bin/sh\nexit 0\n"),
		"artifacts/rke2.tar.gz":          []byte("rke2"),
		"artifacts/rke2-images.tar.zst":  []byte("rke2-images"),
		"artifacts/argocd-install.yaml":  []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: argocd\n          image: " + byRepo["registry.local/argocd"] + "\n"),
		"artifacts/ocm-install.yaml":     []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: ocm\n          image: " + byRepo["registry.local/ocm"] + "\n"),
		"artifacts/cnpg-install.yaml":    []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: cnpg\n          image: " + byRepo["registry.local/cnpg"] + "\n"),
		"artifacts/storage-install.yaml": []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: storage\n          image: " + byRepo["registry.local/storage"] + "\n---\napiVersion: storage.k8s.io/v1\nkind: StorageClass\nmetadata:\n  name: replicated-rwx\n  annotations:\n    platform.4so.io/replicated: \"true\"\nprovisioner: example.storage.csi\n"),
	}
	for name, data := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
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
	manifest := BundleManifest{APIVersion: "platform.4so.io/v1alpha1", Kind: "ApplianceBundle"}
	manifest.Metadata.Version = "0.0.16"
	manifest.Metadata.SourceReleaseDigest = "sha256:" + strings.Repeat("6", 64)
	manifest.Spec.RKE2.Version = "test"
	manifest.Spec.RKE2.Installer = Artifact{Path: "artifacts/install.sh", SHA256: digest("artifacts/install.sh")}
	manifest.Spec.RKE2.InstallArtifacts = []Artifact{{Path: "artifacts/rke2.tar.gz", SHA256: digest("artifacts/rke2.tar.gz")}}
	manifest.Spec.RKE2.ImageArchives = []Artifact{{Path: "artifacts/rke2-images.tar.zst", SHA256: digest("artifacts/rke2-images.tar.zst")}}
	manifest.Spec.Workloads.ImageArchives = []Artifact{{Path: "artifacts/workloads.oci.tar", SHA256: digest("artifacts/workloads.oci.tar")}}
	manifest.Spec.Workloads.PostgreSQLImage = byRepo["registry.local/postgres"]
	manifest.Spec.Workloads.PlatformAPIImage = byRepo["registry.local/platform-api"]
	manifest.Spec.Workloads.ForgejoImage = byRepo["registry.local/forgejo"]
	manifest.Spec.Workloads.ZotImage = byRepo["registry.local/zot"]
	manifest.Spec.Workloads.KeycloakImage = byRepo["registry.local/keycloak"]
	manifest.Spec.Workloads.MaintenanceImage = byRepo["registry.local/maintenance"]
	manifest.Spec.Workloads.GitOpsManifest = Artifact{Path: "artifacts/argocd-install.yaml", SHA256: digest("artifacts/argocd-install.yaml")}
	manifest.Spec.Workloads.CloudNativePGManifest = Artifact{Path: "artifacts/cnpg-install.yaml", SHA256: digest("artifacts/cnpg-install.yaml")}
	manifest.Spec.Workloads.OCMManifest = Artifact{Path: "artifacts/ocm-install.yaml", SHA256: digest("artifacts/ocm-install.yaml")}
	manifest.Spec.Workloads.StorageManifest = Artifact{Path: "artifacts/storage-install.yaml", SHA256: digest("artifacts/storage-install.yaml")}
	manifest.Spec.Workloads.FleetAgentImage = byRepo["registry.local/platform-agent"]
	manifest.Spec.Workloads.RuntimeProbeImage = byRepo["registry.local/platform-probe"]
	images := append([]string(nil), refs...)
	indexRaw, _ := json.Marshal(map[string]any{"version": "0.0.16", "images": images, "artifacts": []string{"artifacts/install.sh", "artifacts/rke2.tar.gz", "artifacts/rke2-images.tar.zst", "artifacts/workloads.oci.tar", "artifacts/argocd-install.yaml", "artifacts/cnpg-install.yaml", "artifacts/ocm-install.yaml", "artifacts/storage-install.yaml"}})
	if err := os.WriteFile(filepath.Join(root, "artifacts/airgap-index.json"), indexRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	indexSum := sha256.Sum256(indexRaw)
	manifest.Spec.Airgap.Complete = true
	manifest.Spec.Airgap.Index = Artifact{Path: "artifacts/airgap-index.json", SHA256: "sha256:" + hex.EncodeToString(indexSum[:])}
	manifest.Spec.Airgap.RequiredImages = images
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "bundle.json"), append(raw, '\n'), 0o600); err != nil {
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

func bootstrapRequest() installation.InstallRequest {
	return installation.InstallRequest{
		ProfileID: "evaluation-single-node", Connectivity: installation.ConnectivityConnected,
		Infrastructure: installation.InfrastructureSpec{Provider: "existing-hosts", NodeAddresses: []string{"127.0.0.1"}, CredentialRef: "secret://local/root"},
		Network:        installation.NetworkSpec{PublicEndpoint: "https://platform.example.test", DNSZone: "example.test", TLSMode: "bootstrap-self-signed"},
		Services:       installation.ServicesSpec{Git: installation.GitSpec{}, Registry: installation.ServiceSpec{}, Database: installation.DatabaseSpec{}, ObjectStorage: installation.ServiceSpec{}, Identity: installation.IdentitySpec{AdminEmail: "admin@example.test"}}, AcceptRisk: true,
	}
}

func TestStartPersistsThePlannerEffectiveRequest(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: t.TempDir(), Simulation: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	r := bootstrapRequest()
	r.ProfileID = " evaluation-single-node "
	r.Infrastructure.Provider = " existing-hosts "
	r.Infrastructure.NodeAddresses = []string{" 127.0.0.1 "}
	r.Infrastructure.CredentialRef = " secret://local/root "
	r.Network.PublicEndpoint = " https://platform.example.test "
	r.Network.DNSZone = " example.test. "
	r.Network.TLSMode = " bootstrap-self-signed "
	run, err := runner.Start(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if run.Request.ProfileID != "evaluation-single-node" || run.Request.Infrastructure.NodeAddresses[0] != "127.0.0.1" || run.Request.Network.PublicEndpoint != "https://platform.example.test" || run.Request.Network.DNSZone != "example.test" {
		t.Fatalf("runtime persisted raw request instead of planner effective request: %+v", run.Request)
	}
}

func TestStartRejectsUnfinishedPersistedRunUntilResume(t *testing.T) {
	for _, state := range []RunState{RunPending, RunRunning, RunFailed} {
		t.Run(string(state), func(t *testing.T) {
			bundle := t.TempDir()
			makeBundle(t, bundle)
			stateDir := t.TempDir()
			runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: stateDir, Simulation: true, System: &SimulatedSystem{Root: t.TempDir()}})
			if err != nil {
				t.Fatal(err)
			}
			request := bootstrapRequest()
			plan, bundleDigest, err := runner.PlanUnlocked(request)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			run := Run{ID: "bootstrap-unfinished-" + strings.ToLower(string(state)), Version: "0.0.16", State: state, Request: plan.EffectiveRequest, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest, PreflightDigest: "sha256:" + strings.Repeat("d", 64), CreatedAt: now, UpdatedAt: now}
			if err = runner.journal.Save(run); err != nil {
				t.Fatal(err)
			}
			if _, err = runner.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "must be resumed") {
				t.Fatalf("new start must not overwrite %s run, got %v", state, err)
			}
		})
	}
}

func TestSimulatedBootstrapCompletesAndResumes(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	state := t.TempDir()
	systemRoot := t.TempDir()
	clock := time.Date(2026, 8, 5, 20, 0, 0, 0, time.UTC)
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: state, Simulation: true, System: &SimulatedSystem{Root: systemRoot}, Now: func() time.Time { clock = clock.Add(time.Second); return clock }})
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := runner.Plan(bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable {
		t.Fatalf("plan blockers=%v", plan.Blockers)
	}
	run, err := runner.Start(context.Background(), bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if run.State != RunSucceeded {
		t.Fatalf("state=%s error=%s", run.State, run.LastError)
	}
	for _, step := range run.Steps {
		if step.State != StepSucceeded {
			t.Fatalf("step %s=%s", step.Key, step.State)
		}
	}
	resumed, err := runner.Resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != RunSucceeded {
		t.Fatalf("resume state=%s", resumed.State)
	}
	if _, err = os.Stat(filepath.Join(systemRoot, "var/lib/rancher/rke2/server/manifests/4so-platform-foundation.yaml")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"4so-platform-forgejo.yaml", "4so-platform-zot.yaml", "4so-platform-keycloak.yaml", "4so-platform-exposure.yaml", "4so-platform-argocd.yaml", "4so-platform-gitops-application.yaml", "4so-platform-ocm.yaml"} {
		if _, err = os.Stat(filepath.Join(systemRoot, "var/lib/rancher/rke2/server/manifests", name)); err != nil {
			t.Fatal(err)
		}
	}
	gitOpsRaw, err := os.ReadFile(filepath.Join(systemRoot, "var/lib/rancher/rke2/server/manifests/4so-platform-gitops-application.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	gitOpsText := string(gitOpsRaw)
	if !strings.Contains(gitOpsText, "targetRevision: main") || !strings.Contains(gitOpsText, "platform.4so.io/commit-sha: \""+commit+"\"") {
		t.Fatalf("GitOps application must preserve managed branch delivery while recording the published immutable commit:\n%s", gitOpsText)
	}
	status, err := runner.GitOpsStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.CommitSHA != commit || status.ObservedCommitSHA != commit || status.State != "RECONCILED" {
		t.Fatalf("GitOps handover status is not commit-bound: %+v", status)
	}
}

func TestBundleRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	makeBundle(t, root)
	raw, err := os.ReadFile(filepath.Join(root, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest BundleManifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Spec.RKE2.Installer.Path = "../escape"
	raw, _ = json.Marshal(manifest)
	_ = os.WriteFile(filepath.Join(root, "bundle.json"), raw, 0o600)
	if _, _, err = LoadBundle(root); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func haBootstrapRequest() installation.InstallRequest {
	return installation.InstallRequest{
		ProfileID: "production-standard-ha", Connectivity: installation.ConnectivityDisconnected,
		Infrastructure: installation.InfrastructureSpec{Provider: "existing-hosts", NodeAddresses: []string{"10.0.0.11", "10.0.0.12", "10.0.0.13"}, CredentialRef: sshCredentialRef, SSHUser: "root", StorageClass: "replicated-rwx", StorageDataDevices: []string{"/dev/sdb", "/dev/sdc", "/dev/sdd"}, StorageDeviceMode: "format-empty"},
		Network:        installation.NetworkSpec{PublicEndpoint: "https://platform.example.test", DNSZone: "example.test", TLSMode: "managed-private-ca"},
		Services: installation.ServicesSpec{
			Git:           installation.GitSpec{ServiceSpec: installation.ServiceSpec{Mode: installation.ServiceModeManaged}},
			Registry:      installation.ServiceSpec{Mode: installation.ServiceModeManaged},
			Database:      installation.DatabaseSpec{ServiceSpec: installation.ServiceSpec{Mode: installation.ServiceModeManaged}},
			ObjectStorage: installation.ServiceSpec{Mode: installation.ServiceModeExternal, Provider: "s3-compatible", URL: "https://s3.example.test", CredentialRef: "external-secret://platform-system/s3-credentials", Bucket: "platform-backups", Prefix: "factory"},
			Identity:      installation.IdentitySpec{ServiceSpec: installation.ServiceSpec{Mode: installation.ServiceModeManaged}, AdminEmail: "admin@example.test"},
		}, AcceptRisk: true,
	}
}

func TestSimulatedHABootstrapAndAirgapCompletes(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	state := t.TempDir()
	root := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: state, Simulation: true, System: &SimulatedSystem{Root: root}})
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := runner.Plan(haBootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable {
		t.Fatalf("HA plan blockers=%v", plan.Blockers)
	}
	run, err := runner.Start(context.Background(), haBootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if run.State != RunSucceeded {
		t.Fatalf("state=%s steps=%d err=%s", run.State, len(run.Steps), run.LastError)
	}
	foundRevoke := false
	for _, step := range run.Steps {
		if step.Key == "revoke-bootstrap-credential" && step.State == StepSucceeded {
			foundRevoke = true
		}
	}
	if !foundRevoke {
		t.Fatal("expected successful bootstrap credential revocation step")
	}
	for _, name := range []string{"4so-platform-cloudnative-pg.yaml", "4so-platform-airgap.yaml", "4so-platform-disaster-recovery.yaml"} {
		if _, err = os.Stat(filepath.Join(root, "var/lib/rancher/rke2/server/manifests", name)); err != nil {
			t.Fatal(err)
		}
	}
	foundation, err := os.ReadFile(filepath.Join(root, "var/lib/rancher/rke2/server/manifests/4so-platform-foundation.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(foundation)
	for _, expected := range []string{"kind: Cluster", "instances: 3", "replicas: 3", "platform-postgresql-rw", "minAvailable: 2", "platform-keycloak-db", "platform-forgejo-db", "managed:", "roles:", "kind: Database", "name: keycloak", "name: forgejo", "catalog-signing-key"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("HA foundation missing %q", expected)
		}
	}
	for _, service := range []struct {
		file       string
		user       string
		secretName string
	}{
		{file: "4so-platform-keycloak.yaml", user: "keycloak", secretName: "platform-keycloak-db"},
		{file: "4so-platform-forgejo.yaml", user: "forgejo", secretName: "platform-forgejo-db"},
	} {
		raw, readErr := os.ReadFile(filepath.Join(root, "var/lib/rancher/rke2/server/manifests", service.file))
		if readErr != nil {
			t.Fatal(readErr)
		}
		serviceText := string(raw)
		for _, expected := range []string{service.user, service.secretName} {
			if !strings.Contains(serviceText, expected) {
				t.Fatalf("HA service manifest %s missing %q", service.file, expected)
			}
		}
		for _, forbidden := range []string{"initialize-database", "createdb "} {
			if strings.Contains(serviceText, forbidden) {
				t.Fatalf("HA service manifest %s still performs imperative database bootstrap via %q", service.file, forbidden)
			}
		}
	}
	storageManifestPath := filepath.Join(root, "var/lib/rancher/rke2/server/manifests/4so-platform-replicated-storage.yaml")
	if _, err = os.Stat(storageManifestPath); err != nil {
		t.Fatalf("replicated storage manifest was not staged: %v", err)
	}
	airgapManifest, err := os.ReadFile(filepath.Join(root, "var/lib/rancher/rke2/server/manifests/4so-platform-airgap.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	airgapText := string(airgapManifest)
	for _, expected := range []string{"kind: DaemonSet", "containerd.sock", "/usr/local/bin/crictl", "done < /tmp/required-images", "while true; do sleep 3600; done"} {
		if !strings.Contains(airgapText, expected) {
			t.Fatalf("air-gap verifier missing %q", expected)
		}
	}
	if strings.Contains(airgapText, "< <(") {
		t.Fatal("air-gap verifier must remain POSIX /bin/sh compatible")
	}
	airgap, err := runner.AirgapStatus()
	if err != nil {
		t.Fatal(err)
	}
	if airgap["verified"] != true {
		t.Fatalf("airgap status=%v", airgap)
	}
	ha, err := runner.HAStatus()
	if err != nil {
		t.Fatal(err)
	}
	if ha["selected"] != true {
		t.Fatalf("ha status=%v", ha)
	}
}

func TestHABootstrapRequiresExternalBackup(t *testing.T) {
	req := haBootstrapRequest()
	req.Services.ObjectStorage = installation.ServiceSpec{Mode: installation.ServiceModeManaged}
	plan, err := CreateBootstrapPlanForTest(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable {
		t.Fatal("expected HA plan to reject local backup storage")
	}
}

// CreateBootstrapPlanForTest keeps this package test focused on the runner while using the public planner.
func CreateBootstrapPlanForTest(req installation.InstallRequest) (installation.InstallationPlan, error) {
	return installation.CreateBootstrapPlan(req)
}

func TestBundleLockAdmissionRejectsTamperingAndExtraFiles(t *testing.T) {
	root := t.TempDir()
	makeBundle(t, root)
	status, err := WriteBundleLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Verified || status.LockDigest == "" || status.ArtifactCount == 0 {
		t.Fatalf("unexpected admission status %#v", status)
	}
	foundStorage := false
	for _, artifact := range status.Artifacts {
		if artifact.Path == "artifacts/storage-install.yaml" {
			foundStorage = true
		}
	}
	if !foundStorage {
		t.Fatal("expected storage manifest in sealed bundle")
	}
	if _, err = InspectBundle(root, true); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "unindexed.bin"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = InspectBundle(root, true); err == nil || !strings.Contains(err.Error(), "unindexed file") {
		t.Fatalf("expected unindexed file rejection, got %v", err)
	}
	if err = os.Remove(filepath.Join(root, "unindexed.bin")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "artifacts", "workloads.oci.tar")
	if err = os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = InspectBundle(root, true); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch rejection, got %v", err)
	}
}

func TestBundleLockIsRequiredByConfiguredRunner(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	runner, err := NewRunner(RunnerOptions{Version: "0.0.22", BundleDir: bundle, StateDir: t.TempDir(), Simulation: true, RequireBundleLock: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := runner.Plan(bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable || len(plan.Blockers) == 0 || !strings.Contains(strings.Join(plan.Blockers, " "), "bundle lock") {
		t.Fatalf("expected missing lock blocker, got %#v", plan)
	}
	if _, err = WriteBundleLock(bundle); err != nil {
		t.Fatal(err)
	}
	plan, _, err = runner.Plan(bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable {
		t.Fatalf("sealed bundle should be executable: %v", plan.Blockers)
	}
}

func TestPreflightIsPersistedAndBoundToRun(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	if _, err := WriteBundleLock(bundle); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: state, Simulation: true, RequireBundleLock: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := runner.Preflight(context.Background(), bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() || report.Digest == "" || report.ID == "" {
		t.Fatalf("unexpected preflight %#v", report)
	}
	stored, err := runner.PreflightStatus()
	if err != nil || stored == nil || stored.Digest != report.Digest {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
	run, err := runner.Start(context.Background(), bootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	if run.PreflightDigest != report.Digest {
		t.Fatalf("run preflight=%s report=%s", run.PreflightDigest, report.Digest)
	}
}

func TestPreflightReturnsStructuredBlockers(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	if _, err := WriteBundleLock(bundle); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: t.TempDir(), Simulation: true, RequireBundleLock: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	request.Infrastructure.NodeAddresses = nil
	report, err := runner.Preflight(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed() || report.State != PreflightBlocked {
		t.Fatalf("expected blocked report %#v", report)
	}
	found := false
	for _, check := range report.Checks {
		if check.Key == "topology" && check.State == CheckBlocked {
			found = true
		}
	}
	if !found {
		t.Fatalf("topology blocker missing %#v", report.Checks)
	}
}

func TestSimulatedHAPreflightRejectsDuplicateManagementNodes(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	if _, err := WriteBundleLock(bundle); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: t.TempDir(), Simulation: true, RequireBundleLock: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	request := haBootstrapRequest()
	request.Infrastructure.NodeAddresses = []string{"10.0.0.11", "10.0.0.12", "10.0.0.12"}
	report, err := runner.Preflight(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed() {
		t.Fatal("duplicate HA management nodes unexpectedly passed preflight")
	}
	for _, check := range report.Checks {
		if check.Key == "host-addresses" && check.State == CheckBlocked && strings.Contains(check.Detail, "must be unique") {
			return
		}
	}
	t.Fatalf("duplicate-node blocker missing: %#v", report.Checks)
}

func TestSimulatedHAPreflightSurfacesRemoteReadinessBoundary(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	if _, err := WriteBundleLock(bundle); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: t.TempDir(), Simulation: true, RequireBundleLock: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := runner.Preflight(context.Background(), haBootstrapRequest())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ha-peer-1", "ha-peer-2"} {
		found := false
		for _, check := range report.Checks {
			if check.Key == key && check.State == CheckSkipped {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected simulation to record skipped remote readiness check %s: %#v", key, report.Checks)
		}
	}
}

type statusBlockingSystem struct {
	*SimulatedSystem
	blockOnce sync.Once
	blocked   chan struct{}
	release   chan struct{}
}

func (s *statusBlockingSystem) MkdirAll(path string, mode os.FileMode) error {
	s.blockOnce.Do(func() {
		close(s.blocked)
		<-s.release
	})
	return s.SimulatedSystem.MkdirAll(path, mode)
}

type resumeRejectFreshPreflightSystem struct {
	*SimulatedSystem
}

func (s *resumeRejectFreshPreflightSystem) IsRoot() bool { return false }

func TestResumeAfterMutationDoesNotRequireFreshHostPreflight(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	stateDir := t.TempDir()
	system := &resumeRejectFreshPreflightSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundleDir, StateDir: stateDir, System: system})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	plan, bundleDigest, err := runner.PlanUnlocked(request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable {
		t.Fatalf("fixture plan is not executable: %v", plan.Blockers)
	}
	now := time.Now().UTC()
	run := Run{
		ID:              "bootstrap-resume-after-owned-mutation",
		Version:         "0.0.16",
		State:           RunFailed,
		Request:         request,
		SpecDigest:      plan.SpecDigest,
		BundleDigest:    bundleDigest,
		PreflightDigest: "sha256:" + strings.Repeat("a", 64),
		CreatedAt:       now,
		UpdatedAt:       now,
		Steps: []Step{
			{Key: "preflight", Title: "preflight", State: StepSucceeded, Attempt: 1},
			{Key: "prepare-host", Title: "prepare host", State: StepFailed, Attempt: 1},
		},
	}
	if err = runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	resumed, err := runner.Resume(context.Background())
	if err != nil {
		t.Fatalf("resume must not rerun fresh-host preflight after owned mutation: %v", err)
	}
	if resumed.State != RunSucceeded {
		t.Fatalf("resume state=%s want=%s", resumed.State, RunSucceeded)
	}
	if resumed.PreflightDigest != run.PreflightDigest {
		t.Fatalf("resume replaced accepted preflight evidence: got=%s want=%s", resumed.PreflightDigest, run.PreflightDigest)
	}
}

func TestResumeRevalidatesAcceptedContractAndPersistsEffectiveRequest(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	stateDir := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundleDir, StateDir: stateDir, Simulation: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	raw := bootstrapRequest()
	raw.ProfileID = " evaluation-single-node "
	raw.Infrastructure.Provider = " existing-hosts "
	raw.Infrastructure.CredentialRef = " secret://local/root "
	raw.Network.PublicEndpoint = " https://platform.example.test "
	raw.Network.TLSMode = " bootstrap-self-signed "
	plan, bundleDigest, err := runner.PlanUnlocked(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable {
		t.Fatalf("fixture plan is not executable: %v", plan.Blockers)
	}
	now := time.Now().UTC()
	run := Run{
		ID: "bootstrap-resume-normalization", Version: "0.0.16", State: RunFailed,
		Request: raw, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest,
		PreflightDigest: "sha256:" + strings.Repeat("b", 64), CreatedAt: now, UpdatedAt: now,
		Steps: []Step{{Key: "preflight", Title: "preflight", State: StepSucceeded, Attempt: 1}, {Key: "prepare-host", Title: "prepare host", State: StepFailed, Attempt: 1}},
	}
	if err = runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	resumed, err := runner.Resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Request.ProfileID != "evaluation-single-node" || resumed.Request.Infrastructure.Provider != "existing-hosts" || resumed.Request.Network.PublicEndpoint != "https://platform.example.test" {
		t.Fatalf("resume did not persist planner effective request: %+v", resumed.Request)
	}
}

func TestResumeFailsClosedWhenAcceptedContractIsNoLongerExecutable(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	stateDir := t.TempDir()
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundleDir, StateDir: stateDir, Simulation: true, System: &SimulatedSystem{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	request.Services.Git = installation.GitSpec{ServiceSpec: installation.ServiceSpec{Mode: installation.ServiceModeExternal, Provider: "gitlab", URL: "https://git.example.test", CredentialRef: "secret://git/admin"}, Organization: "platform", Repository: "desired-state"}
	plan, bundleDigest, err := runner.PlanUnlocked(request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable {
		t.Fatal("external Git fixture unexpectedly executable")
	}
	now := time.Now().UTC()
	run := Run{
		ID: "bootstrap-resume-stale-contract", Version: "0.0.16", State: RunFailed,
		Request: plan.EffectiveRequest, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest,
		PreflightDigest: "sha256:" + strings.Repeat("c", 64), CreatedAt: now, UpdatedAt: now,
		Steps: []Step{{Key: "preflight", Title: "preflight", State: StepSucceeded, Attempt: 1}, {Key: "prepare-host", Title: "prepare host", State: StepFailed, Attempt: 1}},
	}
	if err = runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Resume(context.Background()); err == nil || !strings.Contains(err.Error(), "no longer executable") {
		t.Fatalf("resume must fail closed for a stale runtime contract, got %v", err)
	}
}

func TestYAMLScalarEscapesControlCharacters(t *testing.T) {
	got := yamlScalar("value\nnext: injected\\path\"quote")
	if strings.Contains(got, "\nnext:") {
		t.Fatalf("yaml scalar contains an unescaped newline: %q", got)
	}
	if got != `"value\nnext: injected\\path\"quote"` {
		t.Fatalf("unexpected YAML scalar encoding: %q", got)
	}
}

func TestStatusRemainsReadableWhileBootstrapExecutionIsRunning(t *testing.T) {
	bundle := t.TempDir()
	makeBundle(t, bundle)
	state := t.TempDir()
	system := &statusBlockingSystem{
		SimulatedSystem: &SimulatedSystem{Root: t.TempDir()},
		blocked:         make(chan struct{}),
		release:         make(chan struct{}),
	}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.16", BundleDir: bundle, StateDir: state, Simulation: true, System: system})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	result := make(chan error, 1)
	go func() {
		_, startErr := runner.Start(context.Background(), request)
		result <- startErr
	}()
	select {
	case <-system.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("bootstrap did not reach blocked prepare-host execution")
	}
	statusResult := make(chan *Run, 1)
	statusError := make(chan error, 1)
	go func() {
		run, statusErr := runner.Status()
		if statusErr != nil {
			statusError <- statusErr
			return
		}
		statusResult <- run
	}()
	select {
	case statusErr := <-statusError:
		close(system.release)
		t.Fatal(statusErr)
	case run := <-statusResult:
		if run == nil || run.State != RunRunning {
			close(system.release)
			t.Fatalf("status=%+v", run)
		}
	case <-time.After(500 * time.Millisecond):
		close(system.release)
		t.Fatal("Status blocked behind the long-running bootstrap execution")
	}
	close(system.release)
	select {
	case <-result:
	case <-time.After(10 * time.Second):
		t.Fatal("bootstrap did not finish after releasing blocked step")
	}
}

func TestBootstrapStepsSkipOptionalOCMWhenNotBundled(t *testing.T) {
	var bundle BundleManifest
	steps := bootstrapStepsForBundle(bundle, "", "")
	for _, step := range steps {
		if step.key == "deploy-fleet-hub" || step.key == "verify-fleet-hub" {
			t.Fatalf("optional OCM step %q must not be scheduled without an OCM artifact", step.key)
		}
	}
	bundle.Spec.Workloads.OCMManifest = Artifact{Path: "artifacts/ocm.yaml", SHA256: "sha256:" + strings.Repeat("a", 64)}
	steps = bootstrapStepsForBundle(bundle, "", "")
	seen := map[string]bool{}
	for _, step := range steps {
		seen[step.key] = true
	}
	if !seen["deploy-fleet-hub"] || !seen["verify-fleet-hub"] {
		t.Fatal("explicit OCM bundle must retain fleet-hub bootstrap steps")
	}
}

type bootstrapRevocationSystem struct {
	*SimulatedSystem
	deploymentUID               string
	secretUID                   string
	deploymentRV                string
	secretRV                    string
	envPresent                  bool
	secretPresent               bool
	replaceAfterDeploymentPatch bool
	deploymentOwner             string
	secretOwner                 string
	restartValue                string
	namespacePresent            bool
}

func prepareBootstrapRevocationFiles(t *testing.T, system *bootstrapRevocationSystem) {
	t.Helper()
	manifest := `apiVersion: v1
kind: Secret
metadata:
  name: platform-internal-services
  namespace: platform-system
type: Opaque
data:
  session-secret: c2Vzc2lvbg==
  bootstrap-token: Ym9vdHN0cmFw
  catalog-signing-key: c2lnbmluZw==
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: platform-api
  namespace: platform-system
spec:
  template:
    spec:
      containers:
        - name: api
          env:
            - name: PLATFORM_FACTORY_BOOTSTRAP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: platform-internal-services
                  key: bootstrap-token
            - name: PLATFORM_FACTORY_LISTEN
              value: 0.0.0.0:8080
`
	if err := system.WriteFile(foundationManifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := system.WriteFile("/var/lib/4so-platform-installer/secrets/bootstrap-token", []byte("bootstrap-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s *bootstrapRevocationSystem) deploymentJSON() []byte {
	env := `[]`
	if s.envPresent {
		env = `[{"name":"PLATFORM_FACTORY_BOOTSTRAP_TOKEN","valueFrom":{"secretKeyRef":{"name":"platform-internal-services","key":"bootstrap-token"}}}]`
	}
	owner := s.deploymentOwner
	if owner == "" {
		owner = bootstrapObjectOwnerValue
	}
	restart := s.restartValue
	if restart == "" {
		restart = "initial"
	}
	return []byte(fmt.Sprintf(`{"metadata":{"uid":%q,"resourceVersion":%q,"annotations":{"%s":%q}},"spec":{"template":{"metadata":{"annotations":{"%s":%q}},"spec":{"containers":[{"name":"api","env":%s}]}}}}`, s.deploymentUID, s.deploymentRV, bootstrapObjectOwnerAnnotation, owner, bootstrapRestartAnnotation, restart, env))
}
func (s *bootstrapRevocationSystem) secretJSON() []byte {
	data := `{}`
	if s.secretPresent {
		data = `{"bootstrap-token":"dG9rZW4="}`
	}
	owner := s.secretOwner
	if owner == "" {
		owner = bootstrapObjectOwnerValue
	}
	return []byte(fmt.Sprintf(`{"metadata":{"uid":%q,"resourceVersion":%q,"annotations":{"%s":%q}},"data":%s}`, s.secretUID, s.secretRV, bootstrapObjectOwnerAnnotation, owner, data))
}
func (s *bootstrapRevocationSystem) Output(ctx context.Context, name string, args []string, env map[string]string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	switch {
	case strings.Contains(command, " get namespace/platform-system --ignore-not-found -o name"):
		if s.namespacePresent {
			return []byte("namespace/platform-system\n"), nil
		}
		return nil, nil
	case strings.Contains(command, " get deployment/platform-api -o json"):
		return s.deploymentJSON(), nil
	case strings.Contains(command, " get secret/platform-internal-services -o json"):
		return s.secretJSON(), nil
	default:
		return nil, fmt.Errorf("unexpected output command: %s", command)
	}
}
func (s *bootstrapRevocationSystem) Run(ctx context.Context, name string, args []string, env map[string]string) error {
	command := name + " " + strings.Join(args, " ")
	s.Commands = append(s.Commands, command)
	switch {
	case strings.Contains(command, " patch deployment/platform-api --type=json "):
		if !strings.Contains(command, `"path":"/metadata/uid","value":"`+s.deploymentUID+`"`) || !strings.Contains(command, `"path":"/metadata/resourceVersion","value":"`+s.deploymentRV+`"`) {
			return fmt.Errorf("deployment patch missing identity tests")
		}
		if strings.Contains(command, "/spec/template/metadata/annotations/platform.4so.io~1bootstrap-restart") {
			if !strings.Contains(command, `"path":"/metadata/annotations/platform.4so.io~1bootstrap-owner","value":"`+bootstrapObjectOwnerValue+`"`) {
				return fmt.Errorf("deployment restart patch missing ownership test")
			}
			for i, arg := range args {
				if arg != "-p" || i+1 >= len(args) {
					continue
				}
				var ops []map[string]any
				if err := json.Unmarshal([]byte(args[i+1]), &ops); err != nil {
					return err
				}
				for _, op := range ops {
					if op["path"] == "/spec/template/metadata/annotations/platform.4so.io~1bootstrap-restart" {
						s.restartValue, _ = op["value"].(string)
					}
				}
			}
		} else {
			s.envPresent = false
		}
		s.deploymentRV = "12"
		if s.replaceAfterDeploymentPatch {
			s.deploymentUID = "uid-foreign"
			s.deploymentRV = "22"
		}
		return nil
	case strings.Contains(command, " patch secret/platform-internal-services --type=json "):
		if !strings.Contains(command, `"path":"/metadata/uid","value":"`+s.secretUID+`"`) || !strings.Contains(command, `"path":"/metadata/resourceVersion","value":"`+s.secretRV+`"`) {
			return fmt.Errorf("secret patch missing identity tests")
		}
		s.secretPresent = false
		s.secretRV = "13"
		return nil
	case strings.Contains(command, " rollout status deployment/platform-api --timeout=10m"), strings.Contains(command, " rollout status deployment/platform-api --timeout=5m"):
		return nil
	default:
		return fmt.Errorf("unexpected run command: %s", command)
	}
}

func TestRevokeBootstrapCredentialIsUIDAndResourceVersionFenced(t *testing.T) {
	system := &bootstrapRevocationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}, deploymentUID: "uid-api", secretUID: "uid-secret", deploymentRV: "10", secretRV: "11", envPresent: true, secretPresent: true}
	prepareBootstrapRevocationFiles(t, system)
	r := &Runner{stateDir: t.TempDir(), system: system}
	if err := r.revokeBootstrapCredential(context.Background(), "install-run-1"); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(system.Commands, "\n")
	if strings.Contains(commands, " set env ") {
		t.Fatalf("name-only set env remains:\n%s", commands)
	}
	for _, want := range []string{`patch deployment/platform-api --type=json`, `patch secret/platform-internal-services --type=json`, `"path":"/metadata/uid"`, `"path":"/metadata/resourceVersion"`} {
		if !strings.Contains(commands, want) {
			t.Fatalf("missing %q:\n%s", want, commands)
		}
	}
	raw, err := os.ReadFile(system.path(foundationManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "bootstrap-token") || strings.Contains(string(raw), "PLATFORM_FACTORY_BOOTSTRAP_TOKEN") {
		t.Fatalf("authoritative foundation manifest still contains revoked bootstrap credential:\n%s", raw)
	}
	if system.Exists("/var/lib/4so-platform-installer/secrets/bootstrap-token") {
		t.Fatal("revoked bootstrap credential remains in installer state")
	}
}

func TestRevokeBootstrapCredentialRejectsSameNameReplacement(t *testing.T) {
	system := &bootstrapRevocationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}, deploymentUID: "uid-api", secretUID: "uid-secret", deploymentRV: "10", secretRV: "11", envPresent: true, secretPresent: true, replaceAfterDeploymentPatch: true}
	prepareBootstrapRevocationFiles(t, system)
	r := &Runner{stateDir: t.TempDir(), system: system}
	err := r.revokeBootstrapCredential(context.Background(), "install-run-2")
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("expected replacement rejection, got %v", err)
	}
}

func TestBindBootstrapObjectRejectsUnownedFirstBind(t *testing.T) {
	system := &bootstrapRevocationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}, deploymentUID: "uid-foreign", deploymentRV: "7", deploymentOwner: "foreign-controller"}
	r := &Runner{stateDir: t.TempDir(), system: system}
	_, err := r.bindBootstrapObject(context.Background(), "install-run-unowned", "deployment", "platform-api")
	if err == nil || !strings.Contains(err.Error(), "refusing first-bind adoption") {
		t.Fatalf("expected unowned first-bind rejection, got %v", err)
	}
	identityPath := filepath.Join(r.stateDir, "bootstrap-object-identities", "install-run-unowned", "deployment-platform-api.json")
	if _, statErr := os.Stat(identityPath); !os.IsNotExist(statErr) {
		t.Fatalf("foreign object identity was durably adopted: %v", statErr)
	}
}

func TestRestartBootstrapDeploymentIsIdentityAndOwnershipFenced(t *testing.T) {
	system := &bootstrapRevocationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}, deploymentUID: "uid-api", deploymentRV: "10"}
	r := &Runner{stateDir: t.TempDir(), system: system, now: func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }}
	if err := r.restartBootstrapDeployment(context.Background(), "install-run-restart", "platform-api"); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(system.Commands, "\n")
	for _, want := range []string{`patch deployment/platform-api --type=json`, `"path":"/metadata/uid","value":"uid-api"`, `"path":"/metadata/resourceVersion","value":"10"`, `"path":"/metadata/annotations/platform.4so.io~1bootstrap-owner","value":"4so-platform-installer"`, `/spec/template/metadata/annotations/platform.4so.io~1bootstrap-restart`} {
		if !strings.Contains(commands, want) {
			t.Fatalf("restart mutation missing %q:\n%s", want, commands)
		}
	}
	if strings.Contains(commands, " rollout restart ") {
		t.Fatalf("name-only rollout restart remains:\n%s", commands)
	}
}

func TestRestartBootstrapDeploymentRejectsSameNameReplacement(t *testing.T) {
	system := &bootstrapRevocationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}, deploymentUID: "uid-api", deploymentRV: "10", replaceAfterDeploymentPatch: true}
	r := &Runner{stateDir: t.TempDir(), system: system, now: time.Now}
	err := r.restartBootstrapDeployment(context.Background(), "install-run-restart-replaced", "platform-api")
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("expected same-name replacement rejection after restart patch, got %v", err)
	}
}

func TestFoundationManifestsMarkBootstrapOwnedObjects(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	bundle, _, err := LoadBundle(bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	requests := []installation.InstallRequest{bootstrapRequest(), haBootstrapRequest()}
	for _, request := range requests {
		manifest := foundationManifest(bundle, "postgres", "keycloak-db", "forgejo-db", "forgejo-admin", "identity-admin", "session", "bootstrap", "catalog", []byte("ca"), []byte("cert"), []byte("key"), []byte("agent-ca"), []byte("agent-key"), request)
		if strings.Count(manifest, `platform.4so.io/bootstrap-owner: "4so-platform-installer"`) < 2 {
			t.Fatalf("profile %s does not mark both bootstrap-owned live objects:\n%s", request.ProfileID, manifest)
		}
		if !strings.Contains(manifest, `platform.4so.io/bootstrap-restart: "initial"`) {
			t.Fatalf("profile %s is missing durable restart annotation path", request.ProfileID)
		}
		for _, want := range []string{"PLATFORM_FACTORY_POSTGRES_MAX_OPEN_CONNS", "PLATFORM_FACTORY_POSTGRES_MAX_IDLE_CONNS", "PLATFORM_FACTORY_POSTGRES_MIGRATION_MODE", "PLATFORM_FACTORY_SOURCE_RELEASE_DIGEST", "sha256:" + strings.Repeat("6", 64), "terminationGracePeriodSeconds: 75", "startupProbe", "livenessProbe", "resources:"} {
			if !strings.Contains(manifest, want) {
				t.Fatalf("profile %s is missing high-load runtime setting %q", request.ProfileID, want)
			}
		}
		if strings.Contains(manifest, "secretKeyRef:\n                secretKeyRef:") {
			t.Fatalf("profile %s contains duplicate catalog signing secretKeyRef", request.ProfileID)
		}
		if request.ProfileID == "production-standard-ha" {
			for _, want := range []string{"maxUnavailable: 1", "maxSurge: 0", "minReadySeconds: 10"} {
				if !strings.Contains(manifest, want) {
					t.Fatalf("HA profile is missing rolling availability setting %q", want)
				}
			}
		}
	}
}

func TestFoundationMaterializationRejectsPreExistingNamespaceBeforeFirstBind(t *testing.T) {
	system := &bootstrapRevocationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}, namespacePresent: true}
	r := &Runner{stateDir: t.TempDir(), system: system}
	err := r.verifyFoundationMaterializationBoundary(context.Background(), "install-run-foundation")
	if err == nil || !strings.Contains(err.Error(), "refusing implicit adoption") {
		t.Fatalf("expected pre-existing namespace rejection, got %v", err)
	}
}

func TestFoundationMaterializationReplayRequiresCompleteDurableIdentitySet(t *testing.T) {
	system := &bootstrapRevocationSystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}, namespacePresent: true, deploymentUID: "uid-api", deploymentRV: "10", secretUID: "uid-secret", secretRV: "11"}
	r := &Runner{stateDir: t.TempDir(), system: system}
	runID := "install-run-foundation-replay"
	if err := os.MkdirAll(filepath.Dir(r.bootstrapObjectIdentityPath(runID, "deployment", "platform-api")), 0o700); err != nil {
		t.Fatal(err)
	}
	deploymentIdentity, _ := json.Marshal(bootstrapObjectIdentity{Kind: "deployment", Name: "platform-api", UID: "uid-api"})
	if err := os.WriteFile(r.bootstrapObjectIdentityPath(runID, "deployment", "platform-api"), deploymentIdentity, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.verifyFoundationMaterializationBoundary(context.Background(), runID); err == nil || !strings.Contains(err.Error(), "partial durable object identity") {
		t.Fatalf("expected partial identity replay rejection, got %v", err)
	}
	secretIdentity, _ := json.Marshal(bootstrapObjectIdentity{Kind: "secret", Name: "platform-internal-services", UID: "uid-secret"})
	if err := os.WriteFile(r.bootstrapObjectIdentityPath(runID, "secret", "platform-internal-services"), secretIdentity, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.verifyFoundationMaterializationBoundary(context.Background(), runID); err != nil {
		t.Fatalf("complete durable identities should reconcile safely: %v", err)
	}
}

func TestInterruptedBootstrapPoliciesCoverEveryOwnedStep(t *testing.T) {
	for _, step := range bootstrapSteps {
		if _, ok := bootstrapInterruptedPolicies[step.key]; !ok {
			t.Fatalf("bootstrap step %s has no explicit interrupted-execution policy", step.key)
		}
	}
	for key := range bootstrapInterruptedPolicies {
		found := false
		for _, step := range bootstrapSteps {
			if step.key == key {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("interrupted-execution policy exists for unknown bootstrap step %s", key)
		}
	}
}

func TestResumeNeverBlindReplaysInterruptedRKE2Install(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	stateDir := t.TempDir()
	system := &SimulatedSystem{Root: t.TempDir()}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.109", BundleDir: bundleDir, StateDir: stateDir, System: system})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	plan, bundleDigest, err := runner.PlanUnlocked(request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable {
		t.Fatalf("fixture plan is not executable: %v", plan.Blockers)
	}
	now := time.Now().UTC()
	run := Run{
		ID: "bootstrap-interrupted-rke2", Version: "0.0.109", State: RunRunning,
		Request: plan.EffectiveRequest, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest,
		PreflightDigest: "sha256:" + strings.Repeat("d", 64), CreatedAt: now, UpdatedAt: now,
		Steps: []Step{
			{Key: "preflight", Title: "preflight", State: StepSucceeded, Attempt: 1},
			{Key: "install-rke2", Title: "install rke2", State: StepRunning, Attempt: 1, StartedAt: &now},
		},
	}
	if err = runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	resumed, err := runner.Resume(context.Background())
	if err == nil || !strings.Contains(err.Error(), "automatic") && !strings.Contains(err.Error(), "replay is forbidden") {
		t.Fatalf("interrupted RKE2 install must fail closed without replay, got %v", err)
	}
	if resumed.State != RunFailed || !strings.HasPrefix(resumed.Steps[1].Error, interruptedOutcomePrefix) {
		t.Fatalf("interrupted RKE2 outcome was not durably fenced: %+v", resumed.Steps[1])
	}
	for _, command := range system.Commands {
		if strings.Contains(command, "install.sh") {
			t.Fatalf("interrupted RKE2 install was blindly replayed: %s", command)
		}
	}
	persisted, loadErr := runner.journal.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if persisted == nil || !strings.HasPrefix(persisted.Steps[1].Error, interruptedOutcomePrefix) {
		t.Fatalf("uncertain interrupted outcome was not persisted: %+v", persisted)
	}
}

func TestResumeReconcilesAlreadyCompletedInterruptedRKE2WithoutInstallerReplay(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	stateDir := t.TempDir()
	system := &SimulatedSystem{Root: t.TempDir()}
	if err := system.WriteFile("/etc/rancher/rke2/rke2.yaml", []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.109", BundleDir: bundleDir, StateDir: stateDir, System: system})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	plan, bundleDigest, err := runner.PlanUnlocked(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := Run{
		ID: "bootstrap-reconcile-rke2", Version: "0.0.109", State: RunRunning,
		Request: plan.EffectiveRequest, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest,
		PreflightDigest: "sha256:" + strings.Repeat("e", 64), CreatedAt: now, UpdatedAt: now,
		Steps: []Step{
			{Key: "preflight", Title: "preflight", State: StepSucceeded, Attempt: 1},
			{Key: "install-rke2", Title: "install rke2", State: StepRunning, Attempt: 1, StartedAt: &now},
		},
	}
	if err = runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	resumed, err := runner.Resume(context.Background())
	if err != nil {
		t.Fatalf("completed RKE2 postcondition should reconcile without replay: %v", err)
	}
	if resumed.State != RunSucceeded || resumed.Steps[1].State != StepSucceeded || resumed.Steps[1].Attempt != 1 {
		t.Fatalf("RKE2 reconciliation must not increment execution attempt: %+v", resumed.Steps[1])
	}
	for _, command := range system.Commands {
		if strings.Contains(command, "install.sh") {
			t.Fatalf("completed RKE2 install was replayed: %s", command)
		}
	}
}

func TestResumeNeverBlindRepublishesInterruptedGitRevisionWithoutAuthorityEvidence(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	stateDir := t.TempDir()
	system := &SimulatedSystem{Root: t.TempDir()}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.109", BundleDir: bundleDir, StateDir: stateDir, Simulation: true, System: system})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	plan, bundleDigest, err := runner.PlanUnlocked(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := Run{
		ID: "bootstrap-interrupted-git-publish", Version: "0.0.109", State: RunRunning,
		Request: plan.EffectiveRequest, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest,
		PreflightDigest: "sha256:" + strings.Repeat("f", 64), CreatedAt: now, UpdatedAt: now,
		Steps: []Step{
			{Key: "preflight", Title: "preflight", State: StepSucceeded, Attempt: 1},
			{Key: "publish-signed-revision", Title: "publish", State: StepRunning, Attempt: 1, StartedAt: &now},
		},
	}
	if err = runner.prepareHost(run); err != nil {
		t.Fatal(err)
	}
	if err = runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	resumed, err := runner.Resume(context.Background())
	if err == nil || !strings.Contains(err.Error(), "automatic republish is forbidden") {
		t.Fatalf("interrupted publish without authority evidence must fail closed, got %v", err)
	}
	if resumed.State != RunFailed || !strings.HasPrefix(resumed.Steps[1].Error, interruptedOutcomePrefix) {
		t.Fatalf("interrupted Git publish outcome was not fenced: %+v", resumed.Steps[1])
	}
}

func TestResumeReconcilesInterruptedGitRevisionFromDurableStatusWithoutRepublish(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	stateDir := t.TempDir()
	system := &SimulatedSystem{Root: t.TempDir()}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.109", BundleDir: bundleDir, StateDir: stateDir, Simulation: true, System: system})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	plan, bundleDigest, err := runner.PlanUnlocked(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := Run{
		ID: "bootstrap-reconcile-git-publish", Version: "0.0.109", State: RunRunning,
		Request: plan.EffectiveRequest, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest,
		PreflightDigest: "sha256:" + strings.Repeat("1", 64), CreatedAt: now, UpdatedAt: now,
		Steps: []Step{
			{Key: "preflight", Title: "preflight", State: StepSucceeded, Attempt: 1},
			{Key: "publish-signed-revision", Title: "publish", State: StepRunning, Attempt: 1, StartedAt: &now},
		},
	}
	if err = runner.prepareHost(run); err != nil {
		t.Fatal(err)
	}
	revision, organization, repository, err := runner.initialSignedRevision(run)
	if err != nil {
		t.Fatal(err)
	}
	if err = runner.writeGitOpsStatus(GitOpsHandoverStatus{
		State: "REVISION_PUBLISHED", RevisionID: revision.ID, RevisionDigest: revision.Digest,
		CommitSHA: strings.Repeat("a", 40), Repository: organization + "/" + repository,
		Application: "platform-appliance", UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err = runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	resumed, err := runner.Resume(context.Background())
	if err != nil {
		t.Fatalf("durably recorded Git revision should reconcile without republish: %v", err)
	}
	if resumed.State != RunSucceeded || resumed.Steps[1].State != StepSucceeded || resumed.Steps[1].Attempt != 1 {
		t.Fatalf("Git revision reconciliation replayed instead of reconciling: %+v", resumed.Steps[1])
	}
}

type gitRevisionAuthoritySystem struct {
	*SimulatedSystem
	response []byte
}

func (s *gitRevisionAuthoritySystem) Output(ctx context.Context, name string, args []string, environment map[string]string) ([]byte, error) {
	for _, arg := range args {
		if strings.Contains(arg, "/api/v1/system-services/git/revisions?") {
			s.Commands = append(s.Commands, fmt.Sprintf("%s %v", name, args))
			return append([]byte(nil), s.response...), nil
		}
	}
	return s.SimulatedSystem.Output(ctx, name, args, environment)
}

func (s *gitRevisionAuthoritySystem) OutputInput(ctx context.Context, name string, args []string, environment map[string]string, input io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(raw), "/api/v1/system-services/git/revisions?") {
		s.Commands = append(s.Commands, fmt.Sprintf("%s %v <stdin>", name, args))
		return append([]byte(nil), s.response...), nil
	}
	return s.SimulatedSystem.OutputInput(ctx, name, args, environment, strings.NewReader(string(raw)))
}

func TestResumeReconcilesInterruptedGitRevisionFromControlPlaneAuthority(t *testing.T) {
	bundleDir := t.TempDir()
	makeBundle(t, bundleDir)
	stateDir := t.TempDir()
	system := &gitRevisionAuthoritySystem{SimulatedSystem: &SimulatedSystem{Root: t.TempDir()}}
	runner, err := NewRunner(RunnerOptions{Version: "0.0.109", BundleDir: bundleDir, StateDir: stateDir, System: system})
	if err != nil {
		t.Fatal(err)
	}
	request := bootstrapRequest()
	plan, bundleDigest, err := runner.PlanUnlocked(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := Run{
		ID: "bootstrap-reconcile-git-authority", Version: "0.0.109", State: RunRunning,
		Request: plan.EffectiveRequest, SpecDigest: plan.SpecDigest, BundleDigest: bundleDigest,
		PreflightDigest: "sha256:" + strings.Repeat("2", 64), CreatedAt: now, UpdatedAt: now,
		Steps: []Step{
			{Key: "preflight", Title: "preflight", State: StepSucceeded, Attempt: 1},
			{Key: "publish-signed-revision", Title: "publish", State: StepRunning, Attempt: 1, StartedAt: &now},
		},
	}
	if err = runner.prepareHost(run); err != nil {
		t.Fatal(err)
	}
	revision, organization, repository, err := runner.initialSignedRevision(run)
	if err != nil {
		t.Fatal(err)
	}
	system.response, _ = json.Marshal([]map[string]any{{
		"organization": organization, "repository": repository, "revisionId": revision.ID,
		"digest": revision.Digest, "commitSha": strings.Repeat("b", 40),
	}})
	if err = runner.journal.Save(run); err != nil {
		t.Fatal(err)
	}
	resumed, err := runner.Resume(context.Background())
	if err != nil {
		t.Fatalf("control-plane Git authority should reconcile interrupted publish: %v", err)
	}
	if resumed.State != RunSucceeded || resumed.Steps[1].Attempt != 1 {
		t.Fatalf("authority reconciliation must not republish or increment attempt: %+v", resumed.Steps[1])
	}
	status, err := runner.GitOpsStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.RevisionID != revision.ID || status.CommitSHA != strings.Repeat("b", 40) {
		t.Fatalf("recovered Git status does not match control-plane authority: %+v", status)
	}
}

func TestFreshInstallKubernetesResidueDetectionBlocksStateWithoutKubeconfig(t *testing.T) {
	root := t.TempDir()
	system := &SimulatedSystem{Root: root}
	if err := system.MkdirAll("/var/lib/rancher/rke2/server/db", 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{system: system}
	residue := runner.existingKubernetesResidue(context.Background())
	if !slices.Contains(residue, "/var/lib/rancher/rke2") {
		t.Fatalf("stale RKE2 server state was not detected: %#v", residue)
	}
	if system.Exists("/etc/rancher/rke2/rke2.yaml") {
		t.Fatal("negative control unexpectedly created a kubeconfig")
	}
}

func TestFreshInstallKubernetesResidueDetectionBlocksOtherDistributions(t *testing.T) {
	for _, path := range []string{"/var/lib/rancher/k3s/server", "/etc/kubernetes/admin.conf", "/var/lib/kubelet/config.yaml"} {
		t.Run(strings.ReplaceAll(strings.Trim(path, "/"), "/", "-"), func(t *testing.T) {
			system := &SimulatedSystem{Root: t.TempDir()}
			if err := system.WriteFile(path, []byte("stale\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := &Runner{system: system}
			residue := runner.existingKubernetesResidue(context.Background())
			want := path
			if strings.HasPrefix(path, "/var/lib/rancher/k3s/") {
				want = "/var/lib/rancher/k3s"
			} else if strings.HasPrefix(path, "/etc/kubernetes/") {
				want = "/etc/kubernetes"
			} else if strings.HasPrefix(path, "/var/lib/kubelet/") {
				want = "/var/lib/kubelet"
			}
			if !slices.Contains(residue, want) {
				t.Fatalf("residue=%v does not contain %s", residue, want)
			}
		})
	}

}

func TestFreshInstallRejectsGeneratedBootstrapAuthorityResidue(t *testing.T) {
	stateDir := "/var/lib/4so-platform-installer"
	system := &SimulatedSystem{Root: t.TempDir()}
	if err := system.WriteFile(filepath.Join(stateDir, "secrets/postgres-password"), []byte("stale-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{stateDir: stateDir, system: system}
	residue := runner.existingBootstrapAuthorityResidue()
	want := filepath.Join(stateDir, "secrets/postgres-password")
	if !slices.Contains(residue, want) {
		t.Fatalf("stale generated bootstrap secret was not detected: residue=%v want=%s", residue, want)
	}
}

func TestFreshInstallDoesNotTreatOperatorSSHInputsAsGeneratedResidue(t *testing.T) {
	stateDir := "/var/lib/4so-platform-installer"
	system := &SimulatedSystem{Root: t.TempDir()}
	for _, path := range []string{filepath.Join(stateDir, "bootstrap-token"), filepath.Join(stateDir, "secrets/ssh-private-key"), filepath.Join(stateDir, "secrets/ssh-known-hosts")} {
		if err := system.WriteFile(path, []byte("operator-input\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &Runner{stateDir: stateDir, system: system}
	if residue := runner.existingBootstrapAuthorityResidue(); len(residue) != 0 {
		t.Fatalf("operator-provided fresh-install inputs were misclassified as stale generated state: %v", residue)
	}
}

func TestFreshInstallIgnoresEmptyOperationalBackupDirectory(t *testing.T) {
	stateDir := "/var/lib/4so-platform-installer"
	system := &SimulatedSystem{Root: t.TempDir()}
	if err := system.MkdirAll(filepath.Join(stateDir, "backups"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{stateDir: stateDir, system: system}
	if residue := runner.existingBootstrapAuthorityResidue(); len(residue) != 0 {
		t.Fatalf("empty lifecycle backup directory created at process startup must not block fresh install: %v", residue)
	}
}

func TestTLSKeyGeneratorSecurityBoundary(t *testing.T) {
	productionKey, err := ProductionTLSKeyGenerator()
	if err != nil {
		t.Fatal(err)
	}
	if productionKey.N.BitLen() < 3072 {
		t.Fatalf("production TLS key strength regressed: %d bits", productionKey.N.BitLen())
	}
	simulationKey, err := SimulationTLSKeyGenerator()
	if err != nil {
		t.Fatal(err)
	}
	if simulationKey.N.BitLen() >= productionKey.N.BitLen() {
		t.Fatalf("simulation key generator must remain test-only cost reduction: simulation=%d production=%d", simulationKey.N.BitLen(), productionKey.N.BitLen())
	}
}

func TestConfigureRKE2SeparatesAccessAndEastWestAddresses(t *testing.T) {
	state := t.TempDir()
	system := &SimulatedSystem{Root: t.TempDir()}
	if err := system.WriteFile("/var/lib/4so-platform-installer/secrets/rke2-token", []byte("token-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{stateDir: state, system: system}
	req := haBootstrapRequest()
	req.Infrastructure.NodeAddresses = []string{"203.0.113.11", "203.0.113.12", "203.0.113.13"}
	req.Infrastructure.ClusterNodeAddresses = []string{"10.77.0.11", "10.77.0.12", "10.77.0.13"}
	req.Infrastructure.ClusterInterface = "ens224"
	if err := runner.configureRKE2(Run{Request: req}); err != nil {
		t.Fatal(err)
	}

	localRaw, err := os.ReadFile(system.path("/etc/rancher/rke2/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	local := string(localRaw)
	if !strings.Contains(local, `node-ip: "10.77.0.11"`) || strings.Contains(local, `node-ip: "203.0.113.11"`) {
		t.Fatalf("local RKE2 config did not bind east-west address:\n%s", local)
	}

	peerPath := filepath.Join(state, "ha-nodes", "203.0.113.12", "config.yaml")
	peerRaw, err := os.ReadFile(peerPath)
	if err != nil {
		t.Fatal(err)
	}
	peer := string(peerRaw)
	for _, want := range []string{
		`server: https://10.77.0.11:9345`,
		`node-ip: 10.77.0.12`,
		`  - "203.0.113.12"`,
		`  - "10.77.0.12"`,
	} {
		if !strings.Contains(peer, want) {
			t.Fatalf("peer RKE2 config missing %q:\n%s", want, peer)
		}
	}
}

func TestEffectiveClusterNodeAddressesFallsBackWithoutMutation(t *testing.T) {
	req := haBootstrapRequest()
	got := effectiveClusterNodeAddresses(req)
	if len(got) != len(req.Infrastructure.NodeAddresses) || got[0] != req.Infrastructure.NodeAddresses[0] {
		t.Fatalf("legacy HA request must fall back to access addresses: %#v", got)
	}
	req.Infrastructure.ClusterNodeAddresses = []string{"10.77.0.11", "10.77.0.12", "10.77.0.13"}
	got = effectiveClusterNodeAddresses(req)
	if got[0] != "10.77.0.11" || got[2] != "10.77.0.13" {
		t.Fatalf("explicit east-west addresses were not selected: %#v", got)
	}
}

func TestHAStatusExposesAccessAndEastWestTopology(t *testing.T) {
	req := haBootstrapRequest()
	req.Infrastructure.NodeAddresses = []string{"203.0.113.11", "203.0.113.12", "203.0.113.13"}
	req.Infrastructure.ClusterNodeAddresses = []string{"10.77.0.11", "10.77.0.12", "10.77.0.13"}
	req.Infrastructure.ClusterInterface = "ens224"
	runner := &Runner{journal: NewJournal(t.TempDir())}
	if err := runner.journal.Save(Run{ID: "bootstrap-ha-network-status", State: RunRunning, Request: req}); err != nil {
		t.Fatal(err)
	}
	status, err := runner.HAStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status["selected"] != true || status["networkSplit"] != true || status["clusterInterface"] != "ens224" {
		t.Fatalf("HA network status missing split-network authority: %#v", status)
	}
	if status["storageDeviceMode"] != "format-empty" {
		t.Fatalf("HA storage device mode missing from status: %#v", status)
	}
	if devices, ok := status["storageDataDevices"].([]string); !ok || len(devices) != 3 || devices[0] != "/dev/sdb" {
		t.Fatalf("HA storage device authority missing from status: %#v", status["storageDataDevices"])
	}
	if mounts, ok := status["storageMounts"].([]string); !ok || len(mounts) != 3 || mounts[0] != "/var/lib/longhorn/disks/disk-00" {
		t.Fatalf("HA storage mount authority missing from status: %#v", status["storageMounts"])
	}
	access, ok := status["nodes"].([]string)
	if !ok || len(access) != 3 || access[0] != "203.0.113.11" {
		t.Fatalf("HA access-node status invalid: %#v", status["nodes"])
	}
	cluster, ok := status["clusterNodes"].([]string)
	if !ok || len(cluster) != 3 || cluster[0] != "10.77.0.11" {
		t.Fatalf("HA cluster-node status invalid: %#v", status["clusterNodes"])
	}
	availability, ok := status["availabilityContract"].(map[string]any)
	if !ok || availability["authority"] != "MANAGEMENT_HA_AVAILABILITY_V1" {
		t.Fatalf("HA availability contract missing: %#v", status["availabilityContract"])
	}
	forgejo, ok := availability["forgejo"].(map[string]any)
	if !ok || forgejo["mode"] != "RESTART_FAILOVER" || forgejo["maintenanceDisruption"] != "brief" {
		t.Fatalf("Forgejo availability contract must expose restart failover semantics: %#v", forgejo)
	}
	api, ok := availability["platformApi"].(map[string]any)
	if !ok || api["mode"] != "CONTINUOUS_REPLICATED" || api["maintenanceDisruption"] != "none" {
		t.Fatalf("Platform API availability contract must expose continuous replication: %#v", api)
	}
}

func TestBootstrapStepsForFunctionalLabMilestones(t *testing.T) {
	root := t.TempDir()
	makeBundle(t, root)
	bundle, _, err := LoadBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		milestone string
		last      string
	}{
		{"rke2-quorum", "verify-ha-quorum"},
		{"ha-storage", "deploy-replicated-storage"},
		{"full", "revoke-bootstrap-credential"},
		{"", "revoke-bootstrap-credential"},
	} {
		t.Run(tc.milestone, func(t *testing.T) {
			steps := bootstrapStepsForBundle(bundle, tc.milestone, "")
			if len(steps) == 0 || steps[len(steps)-1].key != tc.last {
				t.Fatalf("milestone %q ended at %#v, want %q", tc.milestone, steps, tc.last)
			}
		})
	}
}

func TestBootstrapStepsForStorageContinuationNeverReplayRKE2(t *testing.T) {
	root := t.TempDir()
	makeBundle(t, root)
	bundle, _, err := LoadBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	steps := bootstrapStepsForBundle(bundle, "ha-storage", "prepare-storage-devices")
	if len(steps) != 2 {
		t.Fatalf("storage continuation should contain exactly prepare+deploy storage, got %#v", steps)
	}
	if steps[0].key != "prepare-storage-devices" || steps[1].key != "deploy-replicated-storage" {
		t.Fatalf("unexpected storage continuation steps: %#v", steps)
	}
	for _, step := range steps {
		if step.key == "install-rke2" || step.key == "configure-rke2" || step.key == "stage-bundle" {
			t.Fatalf("storage continuation must never replay RKE2: %#v", steps)
		}
	}
}

func TestZotManifestDoesNotEnableUIWithoutSearchExtension(t *testing.T) {
	bundle := BundleManifest{}
	bundle.Spec.Workloads.ZotImage = "registry.local/zot@sha256:" + strings.Repeat("a", 64)
	request := installation.InstallRequest{}
	request.Infrastructure.StorageClass = "replicated-rwx"
	manifest := zotManifest(bundle, request)
	if strings.Contains(manifest, `"ui": {"enable": true}`) {
		t.Fatalf("managed Zot must not enable UI without the required search extension:\n%s", manifest)
	}
	if !strings.Contains(manifest, `"ui": {"enable": false}`) {
		t.Fatalf("managed Zot manifest must explicitly disable UI when search is not enabled:\n%s", manifest)
	}
}

func TestKeycloakManifestUsesManagementHealthReadiness(t *testing.T) {
	bundle := BundleManifest{}
	bundle.Spec.Workloads.KeycloakImage = "quay.io/keycloak/keycloak@sha256:" + strings.Repeat("a", 64)
	request := installation.InstallRequest{ProfileID: "production-standard-ha"}
	request.Network.PublicEndpoint = "https://platform.example.test"
	request.Network.DNSZone = "example.test"
	manifest := keycloakManifest(bundle, request)
	for _, want := range []string{"path: /health/ready", "port: 9000", "name: management"} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("Keycloak manifest missing readiness contract %q:\n%s", want, manifest)
		}
	}
	if strings.Contains(manifest, "path: /realms/platform/.well-known/openid-configuration\n              port: 8080") {
		t.Fatalf("Keycloak readiness must not use hostname-sensitive public realm endpoint")
	}
}

func TestZotManifestUsesRecreateForSingleWriterRegistry(t *testing.T) {
	bundle := BundleManifest{}
	bundle.Spec.Workloads.ZotImage = "registry.local/zot@sha256:" + strings.Repeat("a", 64)
	request := installation.InstallRequest{}
	request.Infrastructure.StorageClass = "replicated-rwx"
	manifest := zotManifest(bundle, request)
	for _, want := range []string{"name: platform-zot", "strategy:\n    type: Recreate", "claimName: platform-zot-data"} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("managed Zot manifest missing single-writer rollout contract %q:\n%s", want, manifest)
		}
	}
}
