package bundlebuilder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/testsupport"
)

func bindSourceArtifacts(t *testing.T, staging string, spec *BuildSpec) {
	t.Helper()
	paths := []string{spec.Spec.RKE2.Installer, spec.Spec.Workloads.GitOpsManifest, spec.Spec.Workloads.CloudNativePGManifest, spec.Spec.Workloads.StorageManifest}
	if strings.TrimSpace(spec.Spec.Workloads.OCMManifest) != "" {
		paths = append(paths, spec.Spec.Workloads.OCMManifest)
	}
	paths = append(paths, spec.Spec.RKE2.InstallArtifacts...)
	paths = append(paths, spec.Spec.RKE2.ImageArchives...)
	paths = append(paths, spec.Spec.Workloads.ImageArchives...)
	spec.Spec.SourceArtifacts = nil
	for _, relative := range paths {
		raw, err := os.ReadFile(filepath.Join(staging, relative))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		spec.Spec.SourceArtifacts = append(spec.Spec.SourceArtifacts, SourceArtifactBinding{Path: relative, SHA256: "sha256:" + hex.EncodeToString(sum[:]), SizeBytes: int64(len(raw))})
	}
}

func TestBuildCreatesSealedDeterministicBundle(t *testing.T) {
	staging := t.TempDir()
	archivePath := filepath.Join(staging, "workloads/images.oci.tar")
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatal(err)
	}
	refs, err := testsupport.WriteWorkloadOCIArchive(archivePath, testsupport.WorkloadRepositories("registry.local/", true))
	if err != nil {
		t.Fatal(err)
	}
	byRepo := testsupport.RefsByRepository(refs)
	files := map[string]string{
		"rke2/install.sh":        "#!/bin/sh\nexit 0\n",
		"rke2/rke2.tar.gz":       "rke2",
		"rke2/images.tar.zst":    "rke2-images",
		"manifests/argocd.yaml":  manifestRef("argocd", byRepo["registry.local/argocd"]),
		"manifests/cnpg.yaml":    manifestRef("cnpg", byRepo["registry.local/cnpg"]),
		"manifests/ocm.yaml":     manifestRef("ocm", byRepo["registry.local/ocm"]),
		"manifests/storage.yaml": manifestRef("storage", byRepo["registry.local/storage"]),
	}
	for name, content := range files {
		path := filepath.Join(staging, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec := BuildSpec{APIVersion: BuildAPIVersion, Kind: BuildKind}
	spec.Metadata.Version = "0.0.22"
	spec.Metadata.SourceReleaseDigest = "sha256:" + strings.Repeat("7", 64)
	spec.Spec.RKE2.Version = "v1.34.0+rke2r1"
	spec.Spec.RKE2.Installer = "rke2/install.sh"
	spec.Spec.RKE2.InstallArtifacts = []string{"rke2/rke2.tar.gz"}
	spec.Spec.RKE2.ImageArchives = []string{"rke2/images.tar.zst"}
	spec.Spec.Workloads.ImageArchives = []string{"workloads/images.oci.tar"}
	spec.Spec.Workloads.PostgreSQLImage = byRepo["registry.local/postgres"]
	spec.Spec.Workloads.PlatformAPIImage = byRepo["registry.local/platform-api"]
	spec.Spec.Workloads.ForgejoImage = byRepo["registry.local/forgejo"]
	spec.Spec.Workloads.ZotImage = byRepo["registry.local/zot"]
	spec.Spec.Workloads.KeycloakImage = byRepo["registry.local/keycloak"]
	spec.Spec.Workloads.MaintenanceImage = byRepo["registry.local/maintenance"]
	spec.Spec.Workloads.GitOpsManifest = "manifests/argocd.yaml"
	spec.Spec.Workloads.CloudNativePGManifest = "manifests/cnpg.yaml"
	spec.Spec.Workloads.OCMManifest = "manifests/ocm.yaml"
	spec.Spec.Workloads.StorageManifest = "manifests/storage.yaml"
	spec.Spec.Workloads.FleetAgentImage = byRepo["registry.local/platform-agent"]
	spec.Spec.Workloads.RuntimeProbeImage = byRepo["registry.local/platform-probe"]
	bindSourceArtifacts(t, staging, &spec)
	raw, _ := json.MarshalIndent(spec, "", "  ")
	specPath := filepath.Join(t.TempDir(), "build.json")
	if err := os.WriteFile(specPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	result, err := Build(specPath, staging, output)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Admission.Verified || result.Admission.LockDigest == "" || result.Admission.Version != "0.0.22" || result.Admission.SourceReleaseDigest != spec.Metadata.SourceReleaseDigest {
		t.Fatalf("unexpected result %#v", result)
	}
	if _, err = bootstrap.InspectBundle(output, true); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(output, "artifacts", "manifests", "argocd.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRejectsSymlinkAndNonEmptyOutput(t *testing.T) {
	staging := t.TempDir()
	for _, name := range []string{"real", "install-artifact", "rke2-images", "workload-images", "gitops", "cnpg", "ocm", "storage"} {
		content := "x"
		if name == "gitops" || name == "cnpg" || name == "ocm" || name == "storage" {
			content = manifest(name, "a")
		}
		if err := os.WriteFile(filepath.Join(staging, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(staging, "real"), filepath.Join(staging, "link")); err != nil {
		t.Skip("symlink unavailable")
	}
	spec := BuildSpec{APIVersion: BuildAPIVersion, Kind: BuildKind}
	spec.Metadata.Version = "0.0.22"
	spec.Metadata.SourceReleaseDigest = "sha256:" + strings.Repeat("7", 64)
	spec.Spec.RKE2.Version = "test"
	spec.Spec.RKE2.Installer = "link"
	spec.Spec.RKE2.InstallArtifacts = []string{"install-artifact"}
	spec.Spec.RKE2.ImageArchives = []string{"rke2-images"}
	spec.Spec.Workloads.ImageArchives = []string{"workload-images"}
	spec.Spec.Workloads.GitOpsManifest = "gitops"
	spec.Spec.Workloads.CloudNativePGManifest = "cnpg"
	spec.Spec.Workloads.OCMManifest = "ocm"
	spec.Spec.Workloads.StorageManifest = "storage"
	for _, target := range []*string{&spec.Spec.Workloads.PostgreSQLImage, &spec.Spec.Workloads.PlatformAPIImage, &spec.Spec.Workloads.ForgejoImage, &spec.Spec.Workloads.ZotImage, &spec.Spec.Workloads.KeycloakImage, &spec.Spec.Workloads.MaintenanceImage, &spec.Spec.Workloads.FleetAgentImage, &spec.Spec.Workloads.RuntimeProbeImage} {
		*target = image("x", "a")
	}
	bindSourceArtifacts(t, staging, &spec)
	raw, _ := json.Marshal(spec)
	specPath := filepath.Join(t.TempDir(), "spec.json")
	_ = os.WriteFile(specPath, raw, 0o600)
	if _, err := Build(specPath, staging, filepath.Join(t.TempDir(), "bundle")); err == nil || (!strings.Contains(err.Error(), "cannot be opened safely") && !strings.Contains(err.Error(), "non-symlink")) {
		t.Fatalf("expected symlink rejection: %v", err)
	}
}

func TestBuildRejectsSourceBindingDigestMismatch(t *testing.T) {
	staging := t.TempDir()
	archivePath := filepath.Join(staging, "workloads/images.oci.tar")
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatal(err)
	}
	refs, err := testsupport.WriteWorkloadOCIArchive(archivePath, testsupport.WorkloadRepositories("registry.local/", false))
	if err != nil {
		t.Fatal(err)
	}
	byRepo := testsupport.RefsByRepository(refs)
	files := map[string]string{
		"rke2/install.sh": "#!/bin/sh\n", "rke2/rke2.tar.gz": "rke2", "rke2/images.tar.zst": "images",
		"manifests/argocd.yaml":  manifestRef("argocd", byRepo["registry.local/argocd"]),
		"manifests/cnpg.yaml":    manifestRef("cnpg", byRepo["registry.local/cnpg"]),
		"manifests/storage.yaml": manifestRef("storage", byRepo["registry.local/storage"]),
	}
	for name, content := range files {
		path := filepath.Join(staging, name)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec := BuildSpec{APIVersion: BuildAPIVersion, Kind: BuildKind}
	spec.Metadata.Version = "0.0.267"
	spec.Metadata.SourceReleaseDigest = "sha256:" + strings.Repeat("7", 64)
	spec.Spec.RKE2.Version = "test"
	spec.Spec.RKE2.Installer = "rke2/install.sh"
	spec.Spec.RKE2.InstallArtifacts = []string{"rke2/rke2.tar.gz"}
	spec.Spec.RKE2.ImageArchives = []string{"rke2/images.tar.zst"}
	spec.Spec.Workloads.ImageArchives = []string{"workloads/images.oci.tar"}
	spec.Spec.Workloads.PostgreSQLImage = byRepo["registry.local/postgres"]
	spec.Spec.Workloads.PlatformAPIImage = byRepo["registry.local/platform-api"]
	spec.Spec.Workloads.ForgejoImage = byRepo["registry.local/forgejo"]
	spec.Spec.Workloads.ZotImage = byRepo["registry.local/zot"]
	spec.Spec.Workloads.KeycloakImage = byRepo["registry.local/keycloak"]
	spec.Spec.Workloads.MaintenanceImage = byRepo["registry.local/maintenance"]
	spec.Spec.Workloads.FleetAgentImage = byRepo["registry.local/platform-agent"]
	spec.Spec.Workloads.RuntimeProbeImage = byRepo["registry.local/platform-probe"]
	spec.Spec.Workloads.GitOpsManifest = "manifests/argocd.yaml"
	spec.Spec.Workloads.CloudNativePGManifest = "manifests/cnpg.yaml"
	spec.Spec.Workloads.StorageManifest = "manifests/storage.yaml"
	bindSourceArtifacts(t, staging, &spec)
	// Simulate the exact TOCTOU boundary: authority is fixed, then source bytes change.
	if err := os.WriteFile(filepath.Join(staging, "manifests/argocd.yaml"), []byte(strings.Repeat("x", len(files["manifests/argocd.yaml"]))), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(spec)
	specPath := filepath.Join(t.TempDir(), "spec.json")
	_ = os.WriteFile(specPath, raw, 0o600)
	if _, err = Build(specPath, staging, filepath.Join(t.TempDir(), "bundle")); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected source digest mismatch, got %v", err)
	}
}

func TestBuildRejectsSymlinkParentInStagingPath(t *testing.T) {
	staging := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "install.sh"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(staging, "rke2")); err != nil {
		t.Skip("symlink unavailable")
	}
	// The spec is otherwise intentionally incomplete: source open must reject the parent symlink before any bundle can be built.
	spec := BuildSpec{APIVersion: BuildAPIVersion, Kind: BuildKind}
	spec.Metadata.Version = "0.0.267"
	spec.Metadata.SourceReleaseDigest = "sha256:" + strings.Repeat("7", 64)
	spec.Spec.RKE2.Version = "test"
	spec.Spec.RKE2.Installer = "rke2/install.sh"
	spec.Spec.RKE2.InstallArtifacts = []string{"install-artifact"}
	spec.Spec.RKE2.ImageArchives = []string{"rke2-images"}
	spec.Spec.Workloads.ImageArchives = []string{"workload-images"}
	spec.Spec.Workloads.GitOpsManifest = "gitops"
	spec.Spec.Workloads.CloudNativePGManifest = "cnpg"
	spec.Spec.Workloads.StorageManifest = "storage"
	for _, name := range []string{"install-artifact", "rke2-images", "workload-images", "gitops", "cnpg", "storage"} {
		_ = os.WriteFile(filepath.Join(staging, name), []byte("x"), 0o600)
	}
	for _, target := range []*string{&spec.Spec.Workloads.PostgreSQLImage, &spec.Spec.Workloads.PlatformAPIImage, &spec.Spec.Workloads.ForgejoImage, &spec.Spec.Workloads.ZotImage, &spec.Spec.Workloads.KeycloakImage, &spec.Spec.Workloads.MaintenanceImage, &spec.Spec.Workloads.FleetAgentImage, &spec.Spec.Workloads.RuntimeProbeImage} {
		*target = image("x", "a")
	}
	bindSourceArtifacts(t, staging, &spec)
	raw, _ := json.Marshal(spec)
	path := filepath.Join(t.TempDir(), "spec.json")
	_ = os.WriteFile(path, raw, 0o600)
	if _, err := Build(path, staging, filepath.Join(t.TempDir(), "bundle")); err == nil || !strings.Contains(err.Error(), "parent path is unsafe") {
		t.Fatalf("expected parent symlink rejection, got %v", err)
	}
}

func image(name, digit string) string {
	return "registry.local/" + name + "@sha256:" + strings.Repeat(digit, 64)
}
func manifest(name, digit string) string { return manifestRef(name, image(name, digit)) }
func manifestRef(name, ref string) string {
	return "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: " + name + "\n          image: " + ref + "\n"
}

func TestBuildAllowsOCMToBeOmitted(t *testing.T) {
	staging := t.TempDir()
	archivePath := filepath.Join(staging, "workloads/images.oci.tar")
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatal(err)
	}
	refs, err := testsupport.WriteWorkloadOCIArchive(archivePath, testsupport.WorkloadRepositories("registry.local/", false))
	if err != nil {
		t.Fatal(err)
	}
	byRepo := testsupport.RefsByRepository(refs)
	files := map[string]string{
		"rke2/install.sh": "#!/bin/sh\nexit 0\n", "rke2/rke2.tar.gz": "rke2", "rke2/images.tar.zst": "rke2-images",
		"manifests/argocd.yaml":  manifestRef("argocd", byRepo["registry.local/argocd"]),
		"manifests/cnpg.yaml":    manifestRef("cnpg", byRepo["registry.local/cnpg"]),
		"manifests/storage.yaml": manifestRef("storage", byRepo["registry.local/storage"]),
	}
	for name, content := range files {
		path := filepath.Join(staging, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec := BuildSpec{APIVersion: BuildAPIVersion, Kind: BuildKind}
	spec.Metadata.Version = "0.0.91"
	spec.Metadata.SourceReleaseDigest = "sha256:" + strings.Repeat("7", 64)
	spec.Spec.RKE2.Version = "v1.34.0+rke2r1"
	spec.Spec.RKE2.Installer = "rke2/install.sh"
	spec.Spec.RKE2.InstallArtifacts = []string{"rke2/rke2.tar.gz"}
	spec.Spec.RKE2.ImageArchives = []string{"rke2/images.tar.zst"}
	spec.Spec.Workloads.ImageArchives = []string{"workloads/images.oci.tar"}
	spec.Spec.Workloads.PostgreSQLImage = byRepo["registry.local/postgres"]
	spec.Spec.Workloads.PlatformAPIImage = byRepo["registry.local/platform-api"]
	spec.Spec.Workloads.ForgejoImage = byRepo["registry.local/forgejo"]
	spec.Spec.Workloads.ZotImage = byRepo["registry.local/zot"]
	spec.Spec.Workloads.KeycloakImage = byRepo["registry.local/keycloak"]
	spec.Spec.Workloads.MaintenanceImage = byRepo["registry.local/maintenance"]
	spec.Spec.Workloads.FleetAgentImage = byRepo["registry.local/platform-agent"]
	spec.Spec.Workloads.RuntimeProbeImage = byRepo["registry.local/platform-probe"]
	spec.Spec.Workloads.GitOpsManifest = "manifests/argocd.yaml"
	spec.Spec.Workloads.CloudNativePGManifest = "manifests/cnpg.yaml"
	spec.Spec.Workloads.StorageManifest = "manifests/storage.yaml"
	bindSourceArtifacts(t, staging, &spec)
	raw, _ := json.MarshalIndent(spec, "", "  ")
	specPath := filepath.Join(t.TempDir(), "build.json")
	if err := os.WriteFile(specPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle")
	result, err := Build(specPath, staging, out)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Admission.Verified {
		t.Fatalf("bundle admission failed: %#v", result.Admission)
	}
	bundle, _, err := bootstrap.LoadBundle(out)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Spec.Workloads.OCMManifest.Path != "" {
		t.Fatalf("OCM must remain absent: %#v", bundle.Spec.Workloads.OCMManifest)
	}
	for _, image := range bundle.Spec.Airgap.RequiredImages {
		if strings.Contains(image, "/ocm@") {
			t.Fatalf("air-gap inventory unexpectedly requires OCM: %s", image)
		}
	}
}

func TestBuildRejectsWorkloadArchiveInventoryMismatch(t *testing.T) {
	staging := t.TempDir()
	archivePath := filepath.Join(staging, "workloads/images.oci.tar")
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatal(err)
	}
	refs, err := testsupport.WriteWorkloadOCIArchive(archivePath, testsupport.WorkloadRepositories("registry.local/", false))
	if err != nil {
		t.Fatal(err)
	}
	byRepo := testsupport.RefsByRepository(refs)
	for name, content := range map[string]string{"rke2/install.sh": "#!/bin/sh\n", "rke2/rke2.tar.gz": "rke2", "rke2/images.tar.zst": "images", "manifests/argocd.yaml": manifestRef("argocd", byRepo["registry.local/argocd"]), "manifests/cnpg.yaml": manifestRef("cnpg", byRepo["registry.local/cnpg"]), "manifests/storage.yaml": manifestRef("storage", byRepo["registry.local/storage"])} {
		path := filepath.Join(staging, name)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, []byte(content), 0o600)
	}
	spec := BuildSpec{APIVersion: BuildAPIVersion, Kind: BuildKind}
	spec.Metadata.Version = "0.0.91"
	spec.Metadata.SourceReleaseDigest = "sha256:" + strings.Repeat("7", 64)
	spec.Spec.RKE2.Version = "test"
	spec.Spec.RKE2.Installer = "rke2/install.sh"
	spec.Spec.RKE2.InstallArtifacts = []string{"rke2/rke2.tar.gz"}
	spec.Spec.RKE2.ImageArchives = []string{"rke2/images.tar.zst"}
	spec.Spec.Workloads.ImageArchives = []string{"workloads/images.oci.tar"}
	spec.Spec.Workloads.PostgreSQLImage = byRepo["registry.local/postgres"]
	spec.Spec.Workloads.PlatformAPIImage = byRepo["registry.local/platform-api"]
	spec.Spec.Workloads.ForgejoImage = byRepo["registry.local/forgejo"]
	spec.Spec.Workloads.ZotImage = byRepo["registry.local/zot"]
	spec.Spec.Workloads.KeycloakImage = byRepo["registry.local/keycloak"]
	spec.Spec.Workloads.MaintenanceImage = byRepo["registry.local/maintenance"]
	spec.Spec.Workloads.FleetAgentImage = byRepo["registry.local/platform-agent"]
	spec.Spec.Workloads.RuntimeProbeImage = "registry.local/platform-probe@sha256:" + strings.Repeat("f", 64)
	spec.Spec.Workloads.GitOpsManifest = "manifests/argocd.yaml"
	spec.Spec.Workloads.CloudNativePGManifest = "manifests/cnpg.yaml"
	spec.Spec.Workloads.StorageManifest = "manifests/storage.yaml"
	bindSourceArtifacts(t, staging, &spec)
	raw, _ := json.Marshal(spec)
	specPath := filepath.Join(t.TempDir(), "spec.json")
	_ = os.WriteFile(specPath, raw, 0o600)
	if _, err := Build(specPath, staging, filepath.Join(t.TempDir(), "bundle")); err == nil || !strings.Contains(err.Error(), "must contain exactly all required") {
		t.Fatalf("expected archive/image mismatch rejection, got %v", err)
	}
}
