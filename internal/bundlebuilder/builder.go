package bundlebuilder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/bootstrap"
)

const (
	BuildAPIVersion = "platform.4so.io/v1alpha1"
	BuildKind       = "ApplianceBundleBuild"
)

type BuildSpec struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Version             string `json:"version"`
		SourceReleaseDigest string `json:"sourceReleaseDigest"`
	} `json:"metadata"`
	Spec struct {
		RKE2 struct {
			Version          string   `json:"version"`
			Installer        string   `json:"installer"`
			InstallArtifacts []string `json:"installArtifacts"`
			ImageArchives    []string `json:"imageArchives"`
		} `json:"rke2"`
		Workloads struct {
			ImageArchives         []string `json:"imageArchives"`
			PostgreSQLImage       string   `json:"postgresqlImage"`
			PlatformAPIImage      string   `json:"platformApiImage"`
			ForgejoImage          string   `json:"forgejoImage"`
			ZotImage              string   `json:"zotImage"`
			KeycloakImage         string   `json:"keycloakImage"`
			MaintenanceImage      string   `json:"maintenanceImage"`
			GitOpsManifest        string   `json:"gitOpsManifest"`
			CloudNativePGManifest string   `json:"cloudNativePGManifest"`
			StorageManifest       string   `json:"storageManifest"`
			OCMManifest           string   `json:"ocmManifest"`
			FleetAgentImage       string   `json:"fleetAgentImage"`
			RuntimeProbeImage     string   `json:"runtimeProbeImage"`
		} `json:"workloads"`
	} `json:"spec"`
}

type BuildResult struct {
	Output           string                          `json:"output"`
	SourceSpecDigest string                          `json:"sourceSpecDigest"`
	Admission        bootstrap.BundleAdmissionStatus `json:"admission"`
}

func LoadSpec(path string) (BuildSpec, string, error) {
	var spec BuildSpec
	raw, err := os.ReadFile(path)
	if err != nil {
		return spec, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&spec); err != nil {
		return spec, "", err
	}
	var extra any
	if err = dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return spec, "", err
	}
	if err = validateSpec(spec); err != nil {
		return spec, "", err
	}
	sum := sha256.Sum256(raw)
	return spec, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func Build(specPath, stagingDir, outputDir string) (BuildResult, error) {
	spec, specDigest, err := LoadSpec(specPath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("load build spec: %w", err)
	}
	stagingRoot, err := filepath.Abs(stagingDir)
	if err != nil {
		return BuildResult{}, err
	}
	if info, statErr := os.Stat(stagingRoot); statErr != nil || !info.IsDir() {
		return BuildResult{}, fmt.Errorf("staging directory is not readable")
	}
	outputRoot, err := filepath.Abs(outputDir)
	if err != nil {
		return BuildResult{}, err
	}
	if err = ensureEmptyOutput(outputRoot); err != nil {
		return BuildResult{}, err
	}
	if err = os.MkdirAll(filepath.Join(outputRoot, "artifacts"), 0o755); err != nil {
		return BuildResult{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(outputRoot)
		}
	}()

	copyOne := func(relative string) (bootstrap.Artifact, error) {
		clean, source, err := safeSource(stagingRoot, relative)
		if err != nil {
			return bootstrap.Artifact{}, err
		}
		destinationRel := filepath.ToSlash(filepath.Join("artifacts", clean))
		destination := filepath.Join(outputRoot, filepath.FromSlash(destinationRel))
		if err = os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return bootstrap.Artifact{}, err
		}
		if err = copyRegular(source, destination); err != nil {
			return bootstrap.Artifact{}, err
		}
		digest, err := fileDigest(destination)
		if err != nil {
			return bootstrap.Artifact{}, err
		}
		return bootstrap.Artifact{Path: destinationRel, SHA256: digest}, nil
	}
	copyMany := func(values []string) ([]bootstrap.Artifact, error) {
		out := make([]bootstrap.Artifact, 0, len(values))
		for _, value := range values {
			artifact, err := copyOne(value)
			if err != nil {
				return nil, err
			}
			out = append(out, artifact)
		}
		return out, nil
	}

	installer, err := copyOne(spec.Spec.RKE2.Installer)
	if err != nil {
		return BuildResult{}, err
	}
	installArtifacts, err := copyMany(spec.Spec.RKE2.InstallArtifacts)
	if err != nil {
		return BuildResult{}, err
	}
	rke2Archives, err := copyMany(spec.Spec.RKE2.ImageArchives)
	if err != nil {
		return BuildResult{}, err
	}
	workloadArchives, err := copyMany(spec.Spec.Workloads.ImageArchives)
	if err != nil {
		return BuildResult{}, err
	}
	gitops, err := copyOne(spec.Spec.Workloads.GitOpsManifest)
	if err != nil {
		return BuildResult{}, err
	}
	cnpg, err := copyOne(spec.Spec.Workloads.CloudNativePGManifest)
	if err != nil {
		return BuildResult{}, err
	}
	var ocm bootstrap.Artifact
	if strings.TrimSpace(spec.Spec.Workloads.OCMManifest) != "" {
		ocm, err = copyOne(spec.Spec.Workloads.OCMManifest)
		if err != nil {
			return BuildResult{}, err
		}
	}
	storage, err := copyOne(spec.Spec.Workloads.StorageManifest)
	if err != nil {
		return BuildResult{}, err
	}

	manifest := bootstrap.BundleManifest{APIVersion: "platform.4so.io/v1alpha1", Kind: "ApplianceBundle"}
	manifest.Metadata.Version = spec.Metadata.Version
	manifest.Metadata.SourceReleaseDigest = spec.Metadata.SourceReleaseDigest
	manifest.Spec.RKE2.Version = spec.Spec.RKE2.Version
	manifest.Spec.RKE2.Installer = installer
	manifest.Spec.RKE2.InstallArtifacts = installArtifacts
	manifest.Spec.RKE2.ImageArchives = rke2Archives
	manifest.Spec.Workloads.ImageArchives = workloadArchives
	manifest.Spec.Workloads.PostgreSQLImage = spec.Spec.Workloads.PostgreSQLImage
	manifest.Spec.Workloads.PlatformAPIImage = spec.Spec.Workloads.PlatformAPIImage
	manifest.Spec.Workloads.ForgejoImage = spec.Spec.Workloads.ForgejoImage
	manifest.Spec.Workloads.ZotImage = spec.Spec.Workloads.ZotImage
	manifest.Spec.Workloads.KeycloakImage = spec.Spec.Workloads.KeycloakImage
	manifest.Spec.Workloads.MaintenanceImage = spec.Spec.Workloads.MaintenanceImage
	manifest.Spec.Workloads.GitOpsManifest = gitops
	manifest.Spec.Workloads.CloudNativePGManifest = cnpg
	manifest.Spec.Workloads.OCMManifest = ocm
	manifest.Spec.Workloads.StorageManifest = storage
	manifest.Spec.Workloads.FleetAgentImage = spec.Spec.Workloads.FleetAgentImage
	manifest.Spec.Workloads.RuntimeProbeImage = spec.Spec.Workloads.RuntimeProbeImage
	images := []string{spec.Spec.Workloads.PostgreSQLImage, spec.Spec.Workloads.PlatformAPIImage, spec.Spec.Workloads.ForgejoImage, spec.Spec.Workloads.ZotImage, spec.Spec.Workloads.KeycloakImage, spec.Spec.Workloads.MaintenanceImage, spec.Spec.Workloads.FleetAgentImage, spec.Spec.Workloads.RuntimeProbeImage}
	manifestInputs := []struct {
		name string
		path string
	}{{"GitOps", gitops.Path}, {"CloudNativePG", cnpg.Path}, {"replicated storage", storage.Path}}
	if strings.TrimSpace(ocm.Path) != "" {
		manifestInputs = append(manifestInputs, struct{ name, path string }{"OCM", ocm.Path})
	}
	for _, item := range manifestInputs {
		manifestImages, imageErr := extractManifestImages(filepath.Join(outputRoot, filepath.FromSlash(item.path)))
		if imageErr != nil {
			return BuildResult{}, fmt.Errorf("%s manifest images: %w", item.name, imageErr)
		}
		if len(manifestImages) == 0 {
			return BuildResult{}, fmt.Errorf("%s manifest must declare at least one digest-pinned image", item.name)
		}
		images = append(images, manifestImages...)
	}
	images = sortedUnique(images)
	manifest.Spec.Airgap.Complete = true
	manifest.Spec.Airgap.RequiredImages = images

	indexArtifacts := append([]bootstrap.Artifact{installer}, installArtifacts...)
	indexArtifacts = append(indexArtifacts, rke2Archives...)
	indexArtifacts = append(indexArtifacts, workloadArchives...)
	indexArtifacts = append(indexArtifacts, gitops, cnpg, storage)
	if strings.TrimSpace(ocm.Path) != "" {
		indexArtifacts = append(indexArtifacts, ocm)
	}
	artifactPaths := make([]string, 0, len(indexArtifacts))
	artifactDigests := map[string]string{}
	for _, artifact := range indexArtifacts {
		artifactPaths = append(artifactPaths, artifact.Path)
		artifactDigests[artifact.Path] = artifact.SHA256
	}
	sort.Strings(artifactPaths)
	index := struct {
		Version         string            `json:"version"`
		Images          []string          `json:"images"`
		Artifacts       []string          `json:"artifacts"`
		ArtifactDigests map[string]string `json:"artifactDigests"`
	}{Version: spec.Metadata.Version, Images: images, Artifacts: artifactPaths, ArtifactDigests: artifactDigests}
	indexRaw, _ := json.MarshalIndent(index, "", "  ")
	indexRaw = append(indexRaw, '\n')
	indexPath := filepath.Join(outputRoot, "artifacts", "airgap-index.json")
	if err = os.WriteFile(indexPath, indexRaw, 0o600); err != nil {
		return BuildResult{}, err
	}
	indexDigest, err := fileDigest(indexPath)
	if err != nil {
		return BuildResult{}, err
	}
	manifest.Spec.Airgap.Index = bootstrap.Artifact{Path: "artifacts/airgap-index.json", SHA256: indexDigest}

	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BuildResult{}, err
	}
	manifestRaw = append(manifestRaw, '\n')
	if err = os.WriteFile(filepath.Join(outputRoot, "bundle.json"), manifestRaw, 0o600); err != nil {
		return BuildResult{}, err
	}
	admission, err := bootstrap.WriteBundleLock(outputRoot)
	if err != nil {
		return BuildResult{}, fmt.Errorf("seal bundle: %w", err)
	}
	cleanup = false
	return BuildResult{Output: outputRoot, SourceSpecDigest: specDigest, Admission: admission}, nil
}

func validateSpec(spec BuildSpec) error {
	if spec.APIVersion != BuildAPIVersion || spec.Kind != BuildKind {
		return errors.New("unsupported appliance bundle build contract")
	}
	if strings.TrimSpace(spec.Metadata.Version) == "" || strings.TrimSpace(spec.Spec.RKE2.Version) == "" {
		return errors.New("bundle and RKE2 versions are required")
	}
	if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(strings.TrimSpace(spec.Metadata.SourceReleaseDigest)) {
		return errors.New("metadata.sourceReleaseDigest must be a lowercase sha256 digest")
	}
	paths := []string{spec.Spec.RKE2.Installer, spec.Spec.Workloads.GitOpsManifest, spec.Spec.Workloads.CloudNativePGManifest, spec.Spec.Workloads.StorageManifest}
	if strings.TrimSpace(spec.Spec.Workloads.OCMManifest) != "" {
		paths = append(paths, spec.Spec.Workloads.OCMManifest)
	}
	paths = append(paths, spec.Spec.RKE2.InstallArtifacts...)
	paths = append(paths, spec.Spec.RKE2.ImageArchives...)
	paths = append(paths, spec.Spec.Workloads.ImageArchives...)
	if len(spec.Spec.RKE2.InstallArtifacts) == 0 || len(spec.Spec.RKE2.ImageArchives) == 0 || len(spec.Spec.Workloads.ImageArchives) == 0 {
		return errors.New("RKE2 install artifacts, RKE2 image archives and workload image archives are required")
	}
	seen := map[string]bool{}
	for _, path := range paths {
		clean := filepath.Clean(strings.TrimSpace(path))
		if clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("artifact path %q must be relative to the staging directory", path)
		}
		if seen[clean] {
			return fmt.Errorf("duplicate artifact path %q", path)
		}
		seen[clean] = true
	}
	for _, image := range []string{spec.Spec.Workloads.PostgreSQLImage, spec.Spec.Workloads.PlatformAPIImage, spec.Spec.Workloads.ForgejoImage, spec.Spec.Workloads.ZotImage, spec.Spec.Workloads.KeycloakImage, spec.Spec.Workloads.MaintenanceImage, spec.Spec.Workloads.FleetAgentImage, spec.Spec.Workloads.RuntimeProbeImage} {
		parts := strings.Split(image, "@sha256:")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || len(parts[1]) != 64 {
			return fmt.Errorf("image reference must be digest-pinned: %s", image)
		}
		if _, err := hex.DecodeString(parts[1]); err != nil {
			return fmt.Errorf("image reference must contain a valid sha256 digest: %s", image)
		}
	}
	return nil
}

func ensureEmptyOutput(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output exists and is not a directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("output directory must not already contain files")
	}
	return nil
}

func safeSource(root, relative string) (string, string, error) {
	clean := filepath.Clean(strings.TrimSpace(relative))
	if clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("artifact path %q escapes the staging directory", relative)
	}
	path := filepath.Join(root, clean)
	resolved, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	if resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
		return "", "", fmt.Errorf("artifact path %q escapes the staging directory", relative)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", "", fmt.Errorf("artifact %q: %w", relative, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", "", fmt.Errorf("artifact %q must be a non-empty regular non-symlink file", relative)
	}
	return clean, resolved, nil
}

func copyRegular(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err = io.Copy(h, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

var manifestImagePattern = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^"' #\t\r\n]+)`)

func extractManifestImages(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	images := []string{}
	for _, match := range manifestImagePattern.FindAllSubmatch(raw, -1) {
		image := strings.TrimSpace(string(match[1]))
		parts := strings.Split(image, "@sha256:")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || len(parts[1]) != 64 {
			return nil, fmt.Errorf("manifest image must be digest-pinned: %s", image)
		}
		if _, err = hex.DecodeString(parts[1]); err != nil {
			return nil, fmt.Errorf("manifest image must contain a valid sha256 digest: %s", image)
		}
		images = append(images, image)
	}
	return sortedUnique(images), nil
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
