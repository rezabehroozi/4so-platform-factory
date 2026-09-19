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
	"syscall"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/ociarchive"
)

const (
	BuildAPIVersion                = "platform.4so.io/v1alpha1"
	BuildKind                      = "ApplianceBundleBuild"
	SourceArtifactBindingAuthority = "BUNDLE_SOURCE_ARTIFACT_BINDING_AUTHORITY_V1"
)

type SourceArtifactBinding struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

type BuildSpec struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Version             string `json:"version"`
		SourceReleaseDigest string `json:"sourceReleaseDigest"`
	} `json:"metadata"`
	Spec struct {
		SourceArtifacts []SourceArtifactBinding `json:"sourceArtifacts"`
		RKE2            struct {
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
			GitOpsHAManifest      string   `json:"gitOpsHAManifest,omitempty"`
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
	info, statErr := os.Lstat(stagingRoot)
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return BuildResult{}, fmt.Errorf("staging directory must be a readable non-symlink directory")
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

	bindings := make(map[string]SourceArtifactBinding, len(spec.Spec.SourceArtifacts))
	for _, binding := range spec.Spec.SourceArtifacts {
		bindings[binding.Path] = binding
	}
	copyOne := func(relative string) (bootstrap.Artifact, error) {
		clean, err := cleanArtifactPath(relative)
		if err != nil {
			return bootstrap.Artifact{}, err
		}
		binding, ok := bindings[clean]
		if !ok {
			return bootstrap.Artifact{}, fmt.Errorf("artifact %q is not bound by spec.sourceArtifacts", clean)
		}
		destinationRel := filepath.ToSlash(filepath.Join("artifacts", clean))
		destination := filepath.Join(outputRoot, filepath.FromSlash(destinationRel))
		if err = os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return bootstrap.Artifact{}, err
		}
		digest, err := copyBoundRegular(stagingRoot, clean, destination, binding)
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
	var gitopsHA bootstrap.Artifact
	if strings.TrimSpace(spec.Spec.Workloads.GitOpsHAManifest) != "" {
		gitopsHA, err = copyOne(spec.Spec.Workloads.GitOpsHAManifest)
		if err != nil {
			return BuildResult{}, err
		}
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
	manifest.Spec.Workloads.GitOpsHAManifest = gitopsHA
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
	if strings.TrimSpace(gitopsHA.Path) != "" {
		manifestInputs = append(manifestInputs, struct{ name, path string }{"GitOps HA", gitopsHA.Path})
	}
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
	archiveImages := []string{}
	for _, artifact := range workloadArchives {
		archivePath := filepath.Join(outputRoot, filepath.FromSlash(artifact.Path))
		inventory, inspectErr := ociarchive.Inspect(archivePath)
		if inspectErr != nil {
			return BuildResult{}, fmt.Errorf("workload OCI archive %q: %w", artifact.Path, inspectErr)
		}
		archiveImages = append(archiveImages, inventory.Images...)
	}
	if len(archiveImages) != len(images) || !equalStringSlices(sortedUnique(archiveImages), images) {
		return BuildResult{}, fmt.Errorf("workload OCI archives must contain exactly all required product and operator/storage images")
	}
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
	if strings.TrimSpace(spec.Spec.Workloads.GitOpsHAManifest) != "" {
		paths = append(paths, spec.Spec.Workloads.GitOpsHAManifest)
	}
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
	for _, value := range paths {
		clean, err := cleanArtifactPath(value)
		if err != nil {
			return err
		}
		if seen[clean] {
			return fmt.Errorf("duplicate artifact path %q", value)
		}
		seen[clean] = true
	}
	if len(spec.Spec.SourceArtifacts) != len(seen) {
		return fmt.Errorf("spec.sourceArtifacts must bind exactly all %d artifact paths", len(seen))
	}
	bound := map[string]bool{}
	for _, binding := range spec.Spec.SourceArtifacts {
		clean, err := cleanArtifactPath(binding.Path)
		if err != nil {
			return fmt.Errorf("source artifact binding: %w", err)
		}
		if clean != binding.Path {
			return fmt.Errorf("source artifact binding path %q must be canonical", binding.Path)
		}
		if !seen[clean] {
			return fmt.Errorf("source artifact binding %q does not belong to the build artifact universe", clean)
		}
		if bound[clean] {
			return fmt.Errorf("duplicate source artifact binding %q", clean)
		}
		if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(binding.SHA256) {
			return fmt.Errorf("source artifact binding %q must contain a lowercase sha256 digest", clean)
		}
		if binding.SizeBytes <= 0 || binding.SizeBytes > 64<<30 {
			return fmt.Errorf("source artifact binding %q has invalid sizeBytes", clean)
		}
		bound[clean] = true
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

func cleanArtifactPath(relative string) (string, error) {
	raw := strings.TrimSpace(relative)
	if raw == "" || raw != relative || strings.Contains(raw, "\\") {
		return "", fmt.Errorf("artifact path %q must be a canonical relative path", relative)
	}
	clean := filepath.Clean(raw)
	if clean != raw || clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact path %q must be a canonical relative path", relative)
	}
	return clean, nil
}

// openBoundSource walks each path component beneath the already-admitted staging
// root with openat(O_NOFOLLOW). This prevents a parent-directory symlink swap
// from redirecting a bundle build outside the staging authority after validation.
func openBoundSource(root, relative string) (*os.File, error) {
	clean, err := cleanArtifactPath(relative)
	if err != nil {
		return nil, err
	}
	rootFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open staging root safely: %w", err)
	}
	currentFD := rootFD
	parts := strings.Split(filepath.ToSlash(clean), "/")
	for _, part := range parts[:len(parts)-1] {
		nextFD, openErr := syscall.Openat(currentFD, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if currentFD != rootFD {
			_ = syscall.Close(currentFD)
		}
		if openErr != nil {
			_ = syscall.Close(rootFD)
			return nil, fmt.Errorf("artifact %q parent path is unsafe: %w", clean, openErr)
		}
		currentFD = nextFD
	}
	fd, openErr := syscall.Openat(currentFD, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if currentFD != rootFD {
		_ = syscall.Close(currentFD)
	}
	_ = syscall.Close(rootFD)
	if openErr != nil {
		return nil, fmt.Errorf("artifact %q cannot be opened safely: %w", clean, openErr)
	}
	file := os.NewFile(uintptr(fd), clean)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("artifact %q cannot be represented as a file", clean)
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		_ = file.Close()
		return nil, fmt.Errorf("artifact %q must be a non-empty regular non-symlink file", clean)
	}
	return file, nil
}

func copyBoundRegular(root, relative, destination string, binding SourceArtifactBinding) (string, error) {
	input, err := openBoundSource(root, relative)
	if err != nil {
		return "", err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() != binding.SizeBytes {
		return "", fmt.Errorf("source artifact %q size mismatch expected=%d actual=%d", relative, binding.SizeBytes, info.Size())
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, h), input)
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if syncErr != nil {
		return "", syncErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written != binding.SizeBytes {
		return "", fmt.Errorf("source artifact %q copied size mismatch expected=%d actual=%d", relative, binding.SizeBytes, written)
	}
	digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if digest != binding.SHA256 {
		return "", fmt.Errorf("source artifact %q digest mismatch expected=%s actual=%s", relative, binding.SHA256, digest)
	}
	return digest, nil
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

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
