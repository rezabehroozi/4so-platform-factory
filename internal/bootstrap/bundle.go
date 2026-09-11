package bootstrap

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

	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/ociarchive"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var imagePattern = regexp.MustCompile(`^[^[:space:]@]+@sha256:[a-f0-9]{64}$`)

const (
	BundleLockAPIVersion = "platform.4so.io/v1alpha1"
	BundleLockKind       = "ApplianceBundleLock"
)

type BundleLockArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type BundleLock struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		BundleVersion       string `json:"bundleVersion"`
		SourceReleaseDigest string `json:"sourceReleaseDigest"`
	} `json:"metadata"`
	ManifestDigest string               `json:"manifestDigest"`
	Artifacts      []BundleLockArtifact `json:"artifacts"`
	RequiredImages []string             `json:"requiredImages"`
}

type BundleAdmissionStatus struct {
	Verified            bool                 `json:"verified"`
	Version             string               `json:"version"`
	RKE2Version         string               `json:"rke2Version"`
	SourceReleaseDigest string               `json:"sourceReleaseDigest"`
	BundleDigest        string               `json:"bundleDigest"`
	LockDigest          string               `json:"lockDigest,omitempty"`
	LockRequired        bool                 `json:"lockRequired"`
	ArtifactCount       int                  `json:"artifactCount"`
	TotalBytes          int64                `json:"totalBytes"`
	RequiredImages      []string             `json:"requiredImages"`
	Artifacts           []BundleLockArtifact `json:"artifacts"`
}

func LoadBundle(dir string) (BundleManifest, string, error) {
	var bundle BundleManifest
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return bundle, "", fmt.Errorf("read bundle manifest: %w", err)
	}
	if err = decodeStrictJSON(raw, &bundle); err != nil {
		return bundle, "", fmt.Errorf("decode bundle manifest: %w", err)
	}
	if err = validateBundle(dir, bundle); err != nil {
		return bundle, "", err
	}
	return bundle, sha256Digest(raw), nil
}

func InspectBundle(dir string, requireLock bool) (BundleAdmissionStatus, error) {
	bundle, bundleDigest, err := LoadBundle(dir)
	if err != nil {
		return BundleAdmissionStatus{}, err
	}
	artifacts, total, err := bundleArtifactRecords(dir, bundle)
	if err != nil {
		return BundleAdmissionStatus{}, err
	}
	status := BundleAdmissionStatus{
		Verified: true, Version: bundle.Metadata.Version, RKE2Version: bundle.Spec.RKE2.Version, SourceReleaseDigest: bundle.Metadata.SourceReleaseDigest,
		BundleDigest: bundleDigest, LockRequired: requireLock, ArtifactCount: len(artifacts), TotalBytes: total,
		RequiredImages: sortedUnique(bundle.Spec.Airgap.RequiredImages), Artifacts: artifacts,
	}
	lockPath := filepath.Join(dir, "bundle.lock.json")
	lockRaw, readErr := os.ReadFile(lockPath)
	if readErr != nil {
		if requireLock || !errors.Is(readErr, os.ErrNotExist) {
			return BundleAdmissionStatus{}, fmt.Errorf("read bundle lock: %w", readErr)
		}
		if err := rejectUnindexedBundleFiles(dir, artifacts, false); err != nil {
			return BundleAdmissionStatus{}, err
		}
		return status, nil
	}
	var lock BundleLock
	if err := decodeStrictJSON(lockRaw, &lock); err != nil {
		return BundleAdmissionStatus{}, fmt.Errorf("decode bundle lock: %w", err)
	}
	if err := validateBundleLock(lock, bundle, bundleDigest, artifacts); err != nil {
		return BundleAdmissionStatus{}, err
	}
	if err := rejectUnindexedBundleFiles(dir, artifacts, true); err != nil {
		return BundleAdmissionStatus{}, err
	}
	status.LockDigest = sha256Digest(lockRaw)
	return status, nil
}

func WriteBundleLock(dir string) (BundleAdmissionStatus, error) {
	bundle, bundleDigest, err := LoadBundle(dir)
	if err != nil {
		return BundleAdmissionStatus{}, err
	}
	artifacts, _, err := bundleArtifactRecords(dir, bundle)
	if err != nil {
		return BundleAdmissionStatus{}, err
	}
	lock := BundleLock{APIVersion: BundleLockAPIVersion, Kind: BundleLockKind, ManifestDigest: bundleDigest, Artifacts: artifacts, RequiredImages: sortedUnique(bundle.Spec.Airgap.RequiredImages)}
	lock.Metadata.BundleVersion = bundle.Metadata.Version
	lock.Metadata.SourceReleaseDigest = bundle.Metadata.SourceReleaseDigest
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return BundleAdmissionStatus{}, err
	}
	raw = append(raw, '\n')
	path := filepath.Join(dir, "bundle.lock.json")
	if err = writeAtomicFile(path, raw, 0o600); err != nil {
		return BundleAdmissionStatus{}, fmt.Errorf("write bundle lock: %w", err)
	}
	return InspectBundle(dir, true)
}

func validateBundle(dir string, bundle BundleManifest) error {
	if bundle.APIVersion != "platform.4so.io/v1alpha1" || bundle.Kind != "ApplianceBundle" {
		return fmt.Errorf("unsupported appliance bundle contract")
	}
	if strings.TrimSpace(bundle.Metadata.Version) == "" || strings.TrimSpace(bundle.Spec.RKE2.Version) == "" {
		return fmt.Errorf("bundle and RKE2 versions are required")
	}
	if strings.TrimSpace(bundle.Metadata.SourceReleaseDigest) != "" && !digestPattern.MatchString(strings.TrimSpace(bundle.Metadata.SourceReleaseDigest)) {
		return fmt.Errorf("bundle sourceReleaseDigest must be a lowercase sha256 digest when present")
	}
	images := map[string]string{
		"PostgreSQL": bundle.Spec.Workloads.PostgreSQLImage, "platform API": bundle.Spec.Workloads.PlatformAPIImage,
		"Forgejo": bundle.Spec.Workloads.ForgejoImage, "zot": bundle.Spec.Workloads.ZotImage,
		"Keycloak": bundle.Spec.Workloads.KeycloakImage, "maintenance": bundle.Spec.Workloads.MaintenanceImage,
		"fleet agent": bundle.Spec.Workloads.FleetAgentImage, "runtime probe": bundle.Spec.Workloads.RuntimeProbeImage,
	}
	for name, image := range images {
		if !imagePattern.MatchString(image) {
			return fmt.Errorf("%s image must be pinned by sha256 digest", name)
		}
	}
	if strings.TrimSpace(bundle.Spec.Workloads.GitOpsManifest.Path) == "" || strings.TrimSpace(bundle.Spec.Workloads.CloudNativePGManifest.Path) == "" || strings.TrimSpace(bundle.Spec.Workloads.StorageManifest.Path) == "" {
		return fmt.Errorf("digest-locked GitOps, CloudNativePG and replicated-storage install manifests are required")
	}
	if !bundle.Spec.Airgap.Complete || strings.TrimSpace(bundle.Spec.Airgap.Index.Path) == "" {
		return fmt.Errorf("complete air-gap index is required")
	}
	if len(bundle.Spec.RKE2.InstallArtifacts) == 0 || len(bundle.Spec.RKE2.ImageArchives) == 0 || len(bundle.Spec.Workloads.ImageArchives) == 0 {
		return fmt.Errorf("RKE2 and workload image archives are required")
	}
	artifacts := allBundleArtifacts(bundle)
	seenPaths := map[string]bool{}
	for _, artifact := range artifacts {
		if seenPaths[artifact.Path] {
			return fmt.Errorf("duplicate bundle artifact path %q", artifact.Path)
		}
		seenPaths[artifact.Path] = true
		path, err := safeBundlePath(dir, artifact.Path)
		if err != nil {
			return err
		}
		if !digestPattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("artifact %q requires sha256 digest", artifact.Path)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("open bundle artifact %q: %w", artifact.Path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("bundle artifact %q must be a regular non-symlink file", artifact.Path)
		}
		if info.Size() <= 0 {
			return fmt.Errorf("bundle artifact %q must not be empty", artifact.Path)
		}
		got, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash bundle artifact %q: %w", artifact.Path, err)
		}
		if got != artifact.SHA256 {
			return fmt.Errorf("bundle artifact %q digest mismatch", artifact.Path)
		}
	}
	requiredImages := []string{bundle.Spec.Workloads.PostgreSQLImage, bundle.Spec.Workloads.PlatformAPIImage, bundle.Spec.Workloads.ForgejoImage, bundle.Spec.Workloads.ZotImage, bundle.Spec.Workloads.KeycloakImage, bundle.Spec.Workloads.MaintenanceImage, bundle.Spec.Workloads.FleetAgentImage, bundle.Spec.Workloads.RuntimeProbeImage}
	operatorManifests := map[string]Artifact{"GitOps install manifest": bundle.Spec.Workloads.GitOpsManifest, "CloudNativePG install manifest": bundle.Spec.Workloads.CloudNativePGManifest, "replicated-storage install manifest": bundle.Spec.Workloads.StorageManifest}
	if strings.TrimSpace(bundle.Spec.Workloads.OCMManifest.Path) != "" {
		operatorManifests["OCM install manifest"] = bundle.Spec.Workloads.OCMManifest
	}
	for name, artifact := range operatorManifests {
		path, _ := safeBundlePath(dir, artifact.Path)
		manifestImages, err := digestPinnedManifestImages(path)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		requiredImages = append(requiredImages, manifestImages...)
	}
	requiredImages = sortedUnique(requiredImages)
	if !equalStrings(sortedUnique(bundle.Spec.Airgap.RequiredImages), requiredImages) || len(bundle.Spec.Airgap.RequiredImages) != len(requiredImages) {
		return fmt.Errorf("air-gap requiredImages must exactly match product and operator/storage manifest images")
	}
	archiveImages := []string{}
	for _, artifact := range bundle.Spec.Workloads.ImageArchives {
		archivePath, pathErr := safeBundlePath(dir, artifact.Path)
		if pathErr != nil {
			return pathErr
		}
		inventory, inspectErr := ociarchive.Inspect(archivePath)
		if inspectErr != nil {
			return fmt.Errorf("workload OCI archive %q: %w", artifact.Path, inspectErr)
		}
		archiveImages = append(archiveImages, inventory.Images...)
	}
	if len(archiveImages) != len(requiredImages) || !equalStrings(sortedUnique(archiveImages), requiredImages) {
		return fmt.Errorf("workload OCI archives must contain exactly all required product and operator/storage images")
	}
	return validateAirgapIndex(dir, bundle)
}

func validateAirgapIndex(dir string, bundle BundleManifest) error {
	indexPath, err := safeBundlePath(dir, bundle.Spec.Airgap.Index.Path)
	if err != nil {
		return err
	}
	indexRaw, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("read air-gap index: %w", err)
	}
	var index struct {
		Version         string            `json:"version"`
		Images          []string          `json:"images"`
		Artifacts       []string          `json:"artifacts"`
		ArtifactDigests map[string]string `json:"artifactDigests,omitempty"`
	}
	if err = decodeStrictJSON(indexRaw, &index); err != nil {
		return fmt.Errorf("decode air-gap index: %w", err)
	}
	if index.Version != bundle.Metadata.Version {
		return fmt.Errorf("air-gap index version does not match bundle version")
	}
	expectedImages := sortedUnique(bundle.Spec.Airgap.RequiredImages)
	if !equalStrings(sortedUnique(index.Images), expectedImages) || len(index.Images) != len(expectedImages) {
		return fmt.Errorf("air-gap index images do not exactly match requiredImages")
	}
	expectedArtifacts := []string{}
	for _, artifact := range allBundleArtifacts(bundle) {
		if artifact.Path != bundle.Spec.Airgap.Index.Path {
			expectedArtifacts = append(expectedArtifacts, artifact.Path)
		}
	}
	expectedArtifacts = sortedUnique(expectedArtifacts)
	if !equalStrings(sortedUnique(index.Artifacts), expectedArtifacts) || len(index.Artifacts) != len(expectedArtifacts) {
		return fmt.Errorf("air-gap index artifacts do not exactly match the bundle manifest")
	}
	if len(index.ArtifactDigests) > 0 {
		if len(index.ArtifactDigests) != len(expectedArtifacts) {
			return fmt.Errorf("air-gap artifactDigests is incomplete")
		}
		for _, artifact := range allBundleArtifacts(bundle) {
			if artifact.Path == bundle.Spec.Airgap.Index.Path {
				continue
			}
			if index.ArtifactDigests[artifact.Path] != artifact.SHA256 {
				return fmt.Errorf("air-gap index digest mismatch for %q", artifact.Path)
			}
		}
	}
	return nil
}

func allBundleArtifacts(bundle BundleManifest) []Artifact {
	artifacts := []Artifact{bundle.Spec.RKE2.Installer}
	artifacts = append(artifacts, bundle.Spec.RKE2.InstallArtifacts...)
	artifacts = append(artifacts, bundle.Spec.RKE2.ImageArchives...)
	artifacts = append(artifacts, bundle.Spec.Workloads.ImageArchives...)
	artifacts = append(artifacts, bundle.Spec.Workloads.GitOpsManifest, bundle.Spec.Workloads.CloudNativePGManifest, bundle.Spec.Workloads.StorageManifest)
	if strings.TrimSpace(bundle.Spec.Workloads.OCMManifest.Path) != "" {
		artifacts = append(artifacts, bundle.Spec.Workloads.OCMManifest)
	}
	artifacts = append(artifacts, bundle.Spec.Airgap.Index)
	return artifacts
}

func bundleArtifactRecords(dir string, bundle BundleManifest) ([]BundleLockArtifact, int64, error) {
	records := make([]BundleLockArtifact, 0, len(allBundleArtifacts(bundle)))
	var total int64
	for _, artifact := range allBundleArtifacts(bundle) {
		path, err := safeBundlePath(dir, artifact.Path)
		if err != nil {
			return nil, 0, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, 0, err
		}
		records = append(records, BundleLockArtifact{Path: artifact.Path, SHA256: artifact.SHA256, Size: info.Size()})
		total += info.Size()
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, total, nil
}

func validateBundleLock(lock BundleLock, bundle BundleManifest, bundleDigest string, artifacts []BundleLockArtifact) error {
	if lock.APIVersion != BundleLockAPIVersion || lock.Kind != BundleLockKind {
		return fmt.Errorf("unsupported appliance bundle lock contract")
	}
	if lock.Metadata.BundleVersion != bundle.Metadata.Version || lock.Metadata.SourceReleaseDigest != bundle.Metadata.SourceReleaseDigest || lock.ManifestDigest != bundleDigest {
		return fmt.Errorf("bundle lock does not match bundle.json")
	}
	locked := append([]BundleLockArtifact(nil), lock.Artifacts...)
	sort.Slice(locked, func(i, j int) bool { return locked[i].Path < locked[j].Path })
	if len(locked) != len(artifacts) {
		return fmt.Errorf("bundle lock artifact count mismatch")
	}
	for i := range artifacts {
		if locked[i] != artifacts[i] {
			return fmt.Errorf("bundle lock artifact mismatch for %q", artifacts[i].Path)
		}
	}
	if !equalStrings(sortedUnique(lock.RequiredImages), sortedUnique(bundle.Spec.Airgap.RequiredImages)) || len(lock.RequiredImages) != len(sortedUnique(lock.RequiredImages)) {
		return fmt.Errorf("bundle lock requiredImages mismatch")
	}
	return nil
}

func rejectUnindexedBundleFiles(dir string, artifacts []BundleLockArtifact, lockPresent bool) error {
	allowed := map[string]bool{"bundle.json": true}
	if lockPresent {
		allowed["bundle.lock.json"] = true
	}
	for _, artifact := range artifacts {
		allowed[filepath.Clean(artifact.Path)] = true
	}
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == dir || entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle contains symlink %q", filepath.ToSlash(rel))
		}
		if !allowed[filepath.Clean(rel)] {
			return fmt.Errorf("bundle contains unindexed file %q", filepath.ToSlash(rel))
		}
		return nil
	})
}

func digestPinnedManifestImages(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	images := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "image:") {
			continue
		}
		value := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "image:")), "\"'")
		if !imagePattern.MatchString(value) {
			return nil, fmt.Errorf("image reference %q is not digest-pinned", value)
		}
		images = append(images, value)
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("no image references found")
	}
	return sortedUnique(images), nil
}

func validateDigestPinnedManifest(path string) error {
	_, err := digestPinnedManifestImages(path)
	return err
}

func safeBundlePath(root, relative string) (string, error) {
	if filepath.IsAbs(relative) || strings.TrimSpace(relative) == "" {
		return "", fmt.Errorf("bundle artifact path must be relative")
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("bundle artifact path escapes bundle directory")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	full, err := filepath.Abs(filepath.Join(rootAbs, clean))
	if err != nil {
		return "", err
	}
	if full != rootAbs && !strings.HasPrefix(full, rootAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("bundle artifact path escapes bundle directory")
	}
	return full, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func sha256Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
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

func decodeStrictJSON(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func writeAtomicFile(path string, raw []byte, mode os.FileMode) error {
	return durablefile.Replace(path, raw, 0o755, mode)
}
