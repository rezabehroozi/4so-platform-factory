package bundlebuilder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/bootstrap"
)

func TestBuildCreatesSealedDeterministicBundle(t *testing.T) {
	staging := t.TempDir()
	files := map[string]string{
		"rke2/install.sh":          "#!/bin/sh\nexit 0\n",
		"rke2/rke2.tar.gz":         "rke2",
		"rke2/images.tar.zst":      "rke2-images",
		"workloads/images.tar.zst": "workloads",
		"manifests/argocd.yaml":    manifest("argocd", "1"),
		"manifests/cnpg.yaml":      manifest("cnpg", "2"),
		"manifests/ocm.yaml":       manifest("ocm", "3"),
		"manifests/storage.yaml":   manifest("storage", "4"),
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
	spec.Spec.Workloads.ImageArchives = []string{"workloads/images.tar.zst"}
	spec.Spec.Workloads.PostgreSQLImage = image("postgres", "a")
	spec.Spec.Workloads.PlatformAPIImage = image("api", "b")
	spec.Spec.Workloads.ForgejoImage = image("forgejo", "c")
	spec.Spec.Workloads.ZotImage = image("zot", "d")
	spec.Spec.Workloads.KeycloakImage = image("keycloak", "e")
	spec.Spec.Workloads.MaintenanceImage = image("maintenance", "f")
	spec.Spec.Workloads.GitOpsManifest = "manifests/argocd.yaml"
	spec.Spec.Workloads.CloudNativePGManifest = "manifests/cnpg.yaml"
	spec.Spec.Workloads.OCMManifest = "manifests/ocm.yaml"
	spec.Spec.Workloads.StorageManifest = "manifests/storage.yaml"
	spec.Spec.Workloads.FleetAgentImage = image("agent", "9")
	spec.Spec.Workloads.RuntimeProbeImage = image("probe", "8")
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
	raw, _ := json.Marshal(spec)
	specPath := filepath.Join(t.TempDir(), "spec.json")
	_ = os.WriteFile(specPath, raw, 0o600)
	if _, err := Build(specPath, staging, filepath.Join(t.TempDir(), "bundle")); err == nil || !strings.Contains(err.Error(), "non-empty regular non-symlink") {
		t.Fatalf("expected symlink rejection: %v", err)
	}
}

func image(name, digit string) string {
	return "registry.local/" + name + "@sha256:" + strings.Repeat(digit, 64)
}
func manifest(name, digit string) string {
	return "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: " + name + "\n          image: " + image(name, digit) + "\n"
}

func TestBuildAllowsOCMToBeOmitted(t *testing.T) {
	staging := t.TempDir()
	files := map[string]string{
		"rke2/install.sh":          "#!/bin/sh\nexit 0\n",
		"rke2/rke2.tar.gz":         "rke2",
		"rke2/images.tar.zst":      "rke2-images",
		"workloads/images.tar.zst": "workloads",
		"manifests/argocd.yaml":    manifest("argocd", "1"),
		"manifests/cnpg.yaml":      manifest("cnpg", "2"),
		"manifests/storage.yaml":   manifest("storage", "4"),
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
	spec.Spec.Workloads.ImageArchives = []string{"workloads/images.tar.zst"}
	spec.Spec.Workloads.PostgreSQLImage = image("postgres", "a")
	spec.Spec.Workloads.PlatformAPIImage = image("api", "b")
	spec.Spec.Workloads.ForgejoImage = image("forgejo", "c")
	spec.Spec.Workloads.ZotImage = image("zot", "d")
	spec.Spec.Workloads.KeycloakImage = image("keycloak", "e")
	spec.Spec.Workloads.MaintenanceImage = image("maintenance", "f")
	spec.Spec.Workloads.GitOpsManifest = "manifests/argocd.yaml"
	spec.Spec.Workloads.CloudNativePGManifest = "manifests/cnpg.yaml"
	spec.Spec.Workloads.StorageManifest = "manifests/storage.yaml"
	spec.Spec.Workloads.FleetAgentImage = image("agent", "9")
	spec.Spec.Workloads.RuntimeProbeImage = image("probe", "8")
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
