package catalogbundle

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/durablefile"
)

const (
	MaxBundleBytes = 256 << 20
	MaxFileBytes   = 192 << 20
)

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var exactReleaseRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var kubeVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var componentNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var errUpstreamAdmissionComponentMissing = errors.New("upstream admission component missing")

var requiredFiles = []string{
	"artifact.bin",
	"bundle-manifest.json",
	"component.json",
	"image-inventory.json",
	"licenses.json",
	"provenance.json",
	"render-manifest.json",
	"sbom.spdx.json",
	"source-lock.json",
}

type Upstream struct {
	URL                string `json:"url"`
	Revision           string `json:"revision"`
	Artifact           string `json:"artifact"`
	ArtifactDigest     string `json:"artifactDigest"`
	VerificationMethod string `json:"verificationMethod"`
}

type Manifest struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Component  string            `json:"component"`
	Version    string            `json:"version"`
	SourceType string            `json:"sourceType"`
	BundleKey  string            `json:"bundleKey"`
	Upstream   Upstream          `json:"upstream"`
	Files      map[string]string `json:"files"`
}

type Verified struct {
	Manifest      Manifest
	Component     catalog.Component
	Files         map[string][]byte
	BundleDigest  string
	ResourceCount int
	ImageCount    int
	LicenseCount  int
	OfflineReady  bool
}

type renderValueInput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type renderGeneration struct {
	Tool                 string             `json:"tool"`
	ToolVersion          string             `json:"toolVersion"`
	ReleaseName          string             `json:"releaseName"`
	Namespace            string             `json:"namespace"`
	IncludeCRDs          bool               `json:"includeCRDs"`
	KubernetesVersions   []string           `json:"kubernetesVersions"`
	Values               []renderValueInput `json:"values"`
	ImageResolver        string             `json:"imageResolver"`
	ImageResolverVersion string             `json:"imageResolverVersion"`
}

type sourceLock struct {
	Component              string            `json:"component"`
	Version                string            `json:"version"`
	SourceType             string            `json:"sourceType"`
	UpstreamURL            string            `json:"upstreamUrl"`
	UpstreamRevision       string            `json:"upstreamRevision"`
	UpstreamArtifact       string            `json:"upstreamArtifact"`
	UpstreamArtifactDigest string            `json:"upstreamArtifactDigest"`
	NetworkFetchRequired   bool              `json:"networkFetchRequired"`
	Renderer               string            `json:"renderer"`
	UpstreamVerification   string            `json:"upstreamVerification"`
	Generation             *renderGeneration `json:"generation,omitempty"`
}

type imageInventory struct {
	Images []struct {
		Reference string `json:"reference"`
	} `json:"images"`
}

type licensesDoc struct {
	Licenses []struct {
		File           string `json:"file"`
		SPDXExpression string `json:"spdxExpression"`
		SHA256         string `json:"sha256,omitempty"`
	} `json:"licenses"`
}

type sbomDoc struct {
	SPDXVersion string `json:"spdxVersion"`
	SPDXID      string `json:"SPDXID"`
	Name        string `json:"name"`
	Packages    []struct {
		SPDXID      string `json:"SPDXID"`
		Name        string `json:"name"`
		VersionInfo string `json:"versionInfo"`
	} `json:"packages"`
}

type provenanceDoc struct {
	Component            string            `json:"component"`
	Version              string            `json:"version"`
	SourceURL            string            `json:"sourceUrl"`
	SourceRevision       string            `json:"sourceRevision"`
	ArtifactDigest       string            `json:"artifactDigest"`
	BundleMode           string            `json:"bundleMode"`
	NetworkFetchRequired bool              `json:"networkFetchRequired"`
	UpstreamVerification string            `json:"upstreamVerification"`
	Generation           *renderGeneration `json:"generation,omitempty"`
}

type taggedSourceSetIndex struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Component  string `json:"component"`
	Version    string `json:"version"`
	Upstream   struct {
		Project            string `json:"project"`
		ReleaseURL         string `json:"releaseUrl"`
		Revision           string `json:"revision"`
		ReleaseCommitShort string `json:"releaseCommitShort"`
		Channel            string `json:"channel"`
	} `json:"upstream"`
	Files []struct {
		Path   string `json:"path"`
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
	Assembly struct {
		NetworkFetchRequired bool   `json:"networkFetchRequired"`
		Method               string `json:"method"`
		Note                 string `json:"note"`
	} `json:"assembly"`
}

const maxHelmChartEntries = 8192

type helmChartIdentity struct {
	Name    string
	Version string
}

func parseYAMLScalar(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	if strings.HasPrefix(v, "\"") {
		out, err := strconv.Unquote(v)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(out), nil
	}
	if strings.HasPrefix(v, "'") {
		if len(v) < 2 || !strings.HasSuffix(v, "'") {
			return "", fmt.Errorf("unterminated single-quoted scalar")
		}
		return strings.TrimSpace(strings.ReplaceAll(v[1:len(v)-1], "''", "'")), nil
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v), nil
}

func parseHelmChartYAML(raw []byte) (helmChartIdentity, error) {
	var out helmChartIdentity
	apiVersion := ""
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key != "apiVersion" && key != "name" && key != "version" {
			continue
		}
		value, err := parseYAMLScalar(parts[1])
		if err != nil {
			return out, fmt.Errorf("parse Chart.yaml %s: %w", key, err)
		}
		switch key {
		case "apiVersion":
			apiVersion = value
		case "name":
			out.Name = value
		case "version":
			out.Version = value
		}
	}
	if apiVersion != "v2" || strings.TrimSpace(out.Name) == "" || !exactVersion(strings.TrimPrefix(strings.TrimSpace(out.Version), "v")) {
		return out, fmt.Errorf("Helm Chart.yaml must declare apiVersion v2 with exact name/version")
	}
	return out, nil
}

func verifyHelmChartArtifact(raw []byte, expectedName, expectedVersion string) error {
	if len(raw) == 0 || len(raw) > MaxFileBytes {
		return fmt.Errorf("helm-chart artifact size is invalid")
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("helm-chart artifact is not a gzip-compressed Helm chart: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, MaxFileBytes+1))
	root := ""
	entries := 0
	var total int64
	var chartYAML []byte
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read helm-chart tar: %w", err)
		}
		entries++
		if entries > maxHelmChartEntries {
			return fmt.Errorf("helm-chart has too many entries")
		}
		name := strings.TrimSpace(h.Name)
		if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
			return fmt.Errorf("helm-chart contains unsafe path %q", h.Name)
		}
		pathForClean := name
		if h.Typeflag == tar.TypeDir {
			pathForClean = strings.TrimSuffix(pathForClean, "/")
		}
		clean := filepath.ToSlash(filepath.Clean(pathForClean))
		if clean != pathForClean || clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
			return fmt.Errorf("helm-chart contains unsafe path %q", h.Name)
		}
		parts := strings.Split(clean, "/")
		if root == "" {
			root = parts[0]
		} else if parts[0] != root {
			return fmt.Errorf("helm-chart must have one top-level directory")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return fmt.Errorf("helm-chart contains unsupported entry type for %q", h.Name)
		}
		if h.Size < 0 || h.Size > MaxFileBytes {
			return fmt.Errorf("helm-chart entry %q exceeds size limit", h.Name)
		}
		total += h.Size
		if total > MaxFileBytes {
			return fmt.Errorf("helm-chart uncompressed payload exceeds size limit")
		}
		if clean == root+"/Chart.yaml" {
			if chartYAML != nil {
				return fmt.Errorf("helm-chart contains duplicate Chart.yaml")
			}
			if h.Size > 1<<20 {
				return fmt.Errorf("Chart.yaml exceeds size limit")
			}
			chartYAML, err = io.ReadAll(io.LimitReader(tr, (1<<20)+1))
			if err != nil {
				return fmt.Errorf("read Chart.yaml: %w", err)
			}
			if len(chartYAML) > 1<<20 {
				return fmt.Errorf("Chart.yaml exceeds size limit")
			}
		}
	}
	if chartYAML == nil {
		return fmt.Errorf("helm-chart is missing top-level Chart.yaml")
	}
	identity, err := parseHelmChartYAML(chartYAML)
	if err != nil {
		return err
	}
	if identity.Name != strings.TrimSpace(expectedName) {
		return fmt.Errorf("helm-chart name mismatch: expected=%q got=%q", expectedName, identity.Name)
	}
	chartVersion := strings.TrimPrefix(strings.TrimSpace(identity.Version), "v")
	if chartVersion != strings.TrimSpace(expectedVersion) {
		return fmt.Errorf("helm-chart version mismatch: expected=%q got=%q", expectedVersion, identity.Version)
	}
	return nil
}

func collectRenderImages(v any, out map[string]bool) {
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			collectRenderImages(item, out)
		}
	case map[string]any:
		for key, value := range x {
			if key == "image" {
				if ref, ok := value.(string); ok && strings.TrimSpace(ref) != "" {
					out[strings.TrimSpace(ref)] = true
				}
			}
			collectRenderImages(value, out)
		}
	}
}

func verifyRenderImageParity(resources []map[string]any, images imageInventory) error {
	manifestImages := map[string]bool{}
	for _, resource := range resources {
		collectRenderImages(resource, manifestImages)
	}
	inventoryImages := map[string]bool{}
	for _, image := range images.Images {
		ref := strings.TrimSpace(image.Reference)
		parts := strings.Split(ref, "@")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || !digestRE.MatchString(parts[1]) {
			return fmt.Errorf("image reference is not digest-pinned: %s", ref)
		}
		if inventoryImages[ref] {
			return fmt.Errorf("duplicate image inventory reference %s", ref)
		}
		inventoryImages[ref] = true
	}
	for ref := range manifestImages {
		parts := strings.Split(ref, "@")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || !digestRE.MatchString(parts[1]) {
			return fmt.Errorf("render manifest image is not digest-pinned: %s", ref)
		}
		if !inventoryImages[ref] {
			return fmt.Errorf("render manifest image %s is missing from image inventory", ref)
		}
	}
	for ref := range inventoryImages {
		if !manifestImages[ref] {
			return fmt.Errorf("image inventory reference %s is not used by render manifest", ref)
		}
	}
	return nil
}

func verifyTaggedSourceSet(raw []byte, component, version, upstreamURL, upstreamRevision string) error {
	files, err := readZip(raw)
	if err != nil {
		return fmt.Errorf("tagged source-set: %w", err)
	}
	idxRaw, ok := files["source-index.json"]
	if !ok {
		return fmt.Errorf("tagged source-set missing source-index.json")
	}
	var idx taggedSourceSetIndex
	if err := decodeStrict(idxRaw, &idx); err != nil {
		return fmt.Errorf("decode tagged source index: %w", err)
	}
	if idx.APIVersion != "platform.4so.io/v1alpha1" || idx.Kind != "UpstreamSourceSet" || idx.Component != component || idx.Version != version || idx.Upstream.Revision != "v"+version || idx.Upstream.Revision != strings.TrimSpace(upstreamRevision) || idx.Upstream.ReleaseURL != strings.TrimSpace(upstreamURL) || idx.Assembly.NetworkFetchRequired || idx.Assembly.Method != "deterministic-zip-from-official-tag-files" || len(idx.Files) == 0 {
		return fmt.Errorf("tagged source-set identity/offline contract mismatch")
	}
	seen := map[string]bool{}
	for _, f := range idx.Files {
		if f.Path == "source-index.json" || strings.TrimSpace(f.Path) == "" || strings.TrimSpace(f.URL) == "" || !digestRE.MatchString(f.SHA256) {
			return fmt.Errorf("invalid tagged source index entry %q", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("duplicate tagged source index path %q", f.Path)
		}
		seen[f.Path] = true
		b, ok := files[f.Path]
		if !ok {
			return fmt.Errorf("tagged source-set missing indexed file %q", f.Path)
		}
		if sha(b) != f.SHA256 {
			return fmt.Errorf("tagged source-set digest mismatch for %s", f.Path)
		}
	}
	if len(files) != len(idx.Files)+1 {
		return fmt.Errorf("tagged source-set contains unindexed payload files")
	}
	return nil
}

func sha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing json content")
	}
	return nil
}

func safeBundleKey(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "/") || strings.Contains(v, "\\") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(v))
	return clean == v && clean != "." && !strings.HasPrefix(clean, "../") && !strings.Contains(clean, "/../")
}

func exactVersion(v string) bool {
	return exactReleaseRE.MatchString(strings.TrimSpace(v))
}

func releaseConstraintMatches(constraint, version string) bool {
	constraint = strings.TrimSpace(strings.ToLower(constraint))
	version = strings.TrimSpace(strings.ToLower(version))
	if !exactVersion(version) {
		return false
	}
	if exactVersion(constraint) {
		return constraint == version
	}
	parts := strings.Split(constraint, ".")
	vparts := strings.Split(version, ".")
	if len(parts) != 3 || len(vparts) != 3 || parts[2] != "x" {
		return false
	}
	return parts[0] == vparts[0] && parts[1] == vparts[1]
}

func componentKubeRenderVersion(v string) string {
	v = strings.TrimSpace(v)
	if kubeVersionRE.MatchString(v) {
		return v
	}
	if regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(v) {
		return v + ".0"
	}
	return ""
}

func validRenderGeneration(g *renderGeneration, component catalog.Component) error {
	if g == nil {
		return fmt.Errorf("helm-chart source requires render generation evidence")
	}
	if strings.TrimSpace(g.Tool) != "helm-template" || strings.TrimSpace(g.ToolVersion) == "" {
		return fmt.Errorf("helm render generation must identify helm-template and exact tool version")
	}
	if strings.ContainsAny(g.ToolVersion, "\r\n\t") || len(g.ToolVersion) > 128 {
		return fmt.Errorf("helm render tool version is invalid")
	}
	if strings.TrimSpace(g.ReleaseName) != "platform-factory" {
		return fmt.Errorf("helm render release name must be platform-factory")
	}
	if strings.TrimSpace(g.Namespace) != strings.TrimSpace(component.Spec.Namespace) {
		return fmt.Errorf("helm render namespace does not match component namespace")
	}
	if !g.IncludeCRDs {
		return fmt.Errorf("helm render generation must include CRDs")
	}
	wantKube := []string{componentKubeRenderVersion(component.Spec.Compatibility.Kubernetes.MinVersion), componentKubeRenderVersion(component.Spec.Compatibility.Kubernetes.MaxVersion)}
	if wantKube[0] == "" || wantKube[1] == "" || len(g.KubernetesVersions) != 2 || g.KubernetesVersions[0] != wantKube[0] || g.KubernetesVersions[1] != wantKube[1] {
		return fmt.Errorf("helm render Kubernetes versions do not match component compatibility window")
	}
	if strings.TrimSpace(g.ImageResolver) != "crane-digest" || strings.TrimSpace(g.ImageResolverVersion) == "" {
		return fmt.Errorf("helm render generation must identify crane-digest image resolution tool and version")
	}
	if strings.ContainsAny(g.ImageResolverVersion, "\r\n\t") || len(g.ImageResolverVersion) > 128 {
		return fmt.Errorf("image resolver version is invalid")
	}
	seen := map[string]bool{}
	for _, value := range g.Values {
		p := strings.TrimSpace(value.Path)
		if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
			return fmt.Errorf("helm values path is invalid")
		}
		clean := filepath.ToSlash(filepath.Clean(p))
		if clean != p || clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
			return fmt.Errorf("helm values path is not a safe repository-relative path")
		}
		if seen[p] {
			return fmt.Errorf("helm values path is duplicated")
		}
		seen[p] = true
		if !digestRE.MatchString(strings.TrimSpace(value.SHA256)) {
			return fmt.Errorf("helm values digest is invalid")
		}
	}
	return nil
}

func validHelmSourceURL(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "oci://") || strings.HasPrefix(v, "https://")
}

func supportedExternalSourceType(v string) bool {
	switch strings.TrimSpace(v) {
	case "helm-chart", "external-tagged-source-set":
		return true
	default:
		return false
	}
}

func readZip(raw []byte) (map[string][]byte, error) {
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("bundle size must be between 1 byte and %d bytes", MaxBundleBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	if len(zr.File) == 0 || len(zr.File) > 32 {
		return nil, fmt.Errorf("bundle file count is invalid")
	}
	out := map[string][]byte{}
	var total int64
	for _, f := range zr.File {
		name := f.Name
		if strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || strings.Contains(name, "../") || filepath.ToSlash(filepath.Clean(name)) != name || strings.Contains(name, "/") {
			return nil, fmt.Errorf("unsafe or nested zip entry %q", name)
		}
		if f.FileInfo().Mode()&os.ModeSymlink != 0 || f.FileInfo().IsDir() {
			return nil, fmt.Errorf("symlink/directory entry %q is not allowed", name)
		}
		if _, ok := out[name]; ok {
			return nil, fmt.Errorf("duplicate zip entry %q", name)
		}
		if f.UncompressedSize64 > MaxFileBytes {
			return nil, fmt.Errorf("file %q exceeds limit", name)
		}
		total += int64(f.UncompressedSize64)
		if total > MaxBundleBytes {
			return nil, fmt.Errorf("uncompressed bundle exceeds limit")
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, MaxFileBytes+1))
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		if len(b) > MaxFileBytes {
			return nil, fmt.Errorf("file %q exceeds limit", name)
		}
		out[name] = b
	}
	return out, nil
}

func Verify(raw []byte) (Verified, error) {
	files, err := readZip(raw)
	if err != nil {
		return Verified{}, err
	}
	for _, name := range requiredFiles {
		if _, ok := files[name]; !ok {
			return Verified{}, fmt.Errorf("required file %s is missing", name)
		}
	}
	if len(files) != len(requiredFiles) {
		return Verified{}, fmt.Errorf("bundle contains unexpected files")
	}

	var manifest Manifest
	if err := decodeStrict(files["bundle-manifest.json"], &manifest); err != nil {
		return Verified{}, fmt.Errorf("decode bundle manifest: %w", err)
	}
	if manifest.APIVersion != "platform.4so.io/v1alpha1" || manifest.Kind != "ExternalCatalogBundle" {
		return Verified{}, fmt.Errorf("unsupported bundle apiVersion/kind")
	}
	if strings.TrimSpace(manifest.Component) == "" || !exactVersion(manifest.Version) || !supportedExternalSourceType(manifest.SourceType) || !safeBundleKey(manifest.BundleKey) {
		return Verified{}, fmt.Errorf("bundle identity is incomplete, non-exact, or uses unsupported source type")
	}
	if strings.TrimSpace(manifest.Upstream.URL) == "" || strings.TrimSpace(manifest.Upstream.Revision) == "" || strings.TrimSpace(manifest.Upstream.Artifact) == "" || !digestRE.MatchString(manifest.Upstream.ArtifactDigest) || manifest.Upstream.VerificationMethod != "sha256-pinned-offline" {
		return Verified{}, fmt.Errorf("upstream identity must be exact and digest-pinned")
	}
	expectedNames := append([]string(nil), requiredFiles...)
	sort.Strings(expectedNames)
	if len(manifest.Files) != len(requiredFiles)-1 {
		return Verified{}, fmt.Errorf("manifest files map must cover every payload file except itself")
	}
	for _, name := range requiredFiles {
		if name == "bundle-manifest.json" {
			continue
		}
		want, ok := manifest.Files[name]
		if !ok || !digestRE.MatchString(want) {
			return Verified{}, fmt.Errorf("manifest digest for %s is missing or invalid", name)
		}
		if got := sha(files[name]); got != want {
			return Verified{}, fmt.Errorf("digest mismatch for %s: want=%s got=%s", name, want, got)
		}
	}
	if sha(files["artifact.bin"]) != manifest.Upstream.ArtifactDigest {
		return Verified{}, fmt.Errorf("upstream artifact digest does not match artifact.bin")
	}

	var component catalog.Component
	if err := decodeStrict(files["component.json"], &component); err != nil {
		return Verified{}, fmt.Errorf("decode component: %w", err)
	}
	if component.Metadata.Name != manifest.Component || component.Spec.Release != manifest.Version {
		return Verified{}, fmt.Errorf("component identity does not match bundle")
	}
	if manifest.BundleKey != manifest.Component+"/"+manifest.Version {
		return Verified{}, fmt.Errorf("bundleKey must equal component/version")
	}
	src := component.Spec.Source
	if !src.Resolved || src.Type != manifest.SourceType || src.BundleKey != manifest.BundleKey {
		return Verified{}, fmt.Errorf("component must be resolved with matching source/bundle")
	}
	if component.Spec.Delivery.Type != "native-manifest" && component.Spec.Delivery.Type != "helm" {
		return Verified{}, fmt.Errorf("component delivery type %q is not supported for immutable external bundles", component.Spec.Delivery.Type)
	}
	if !strings.EqualFold(strings.TrimSpace(src.SignatureVerification), "sha256-pinned-offline") {
		return Verified{}, fmt.Errorf("component artifact verification contract must be sha256-pinned-offline")
	}
	if src.Type == "external-tagged-source-set" {
		if err := verifyTaggedSourceSet(files["artifact.bin"], manifest.Component, manifest.Version, manifest.Upstream.URL, manifest.Upstream.Revision); err != nil {
			return Verified{}, err
		}
	}
	if src.Type == "helm-chart" {
		if component.Spec.Delivery.Type != "helm" {
			return Verified{}, fmt.Errorf("helm-chart source requires helm delivery")
		}
		if !validHelmSourceURL(manifest.Upstream.URL) || !strings.HasSuffix(strings.ToLower(manifest.Upstream.Artifact), ".tgz") {
			return Verified{}, fmt.Errorf("helm-chart source requires https:// or oci:// upstream URL and .tgz artifact identity")
		}
		if err := verifyHelmChartArtifact(files["artifact.bin"], component.Spec.Delivery.Chart, manifest.Version); err != nil {
			return Verified{}, err
		}
	}
	digestContracts := map[string]string{
		"artifact.bin":         src.ArtifactDigest,
		"render-manifest.json": src.RenderManifestDigest,
		"source-lock.json":     src.SourceLockDigest,
		"image-inventory.json": src.ImageInventoryDigest,
		"licenses.json":        src.LicenseManifestDigest,
		"sbom.spdx.json":       src.SBOM,
		"provenance.json":      src.Provenance,
	}
	for name, want := range digestContracts {
		if !digestRE.MatchString(want) || manifest.Files[name] != want {
			return Verified{}, fmt.Errorf("component digest contract mismatch for %s", name)
		}
	}

	var lock sourceLock
	if err := decodeStrict(files["source-lock.json"], &lock); err != nil {
		return Verified{}, fmt.Errorf("decode source lock: %w", err)
	}
	if lock.Component != manifest.Component || lock.Version != manifest.Version || lock.SourceType != manifest.SourceType || lock.UpstreamURL != manifest.Upstream.URL || lock.UpstreamRevision != manifest.Upstream.Revision || lock.UpstreamArtifact != manifest.Upstream.Artifact || lock.UpstreamArtifactDigest != manifest.Upstream.ArtifactDigest || lock.NetworkFetchRequired || lock.Renderer != "json-resource-list-v1" || lock.UpstreamVerification != "sha256-pinned-offline" {
		return Verified{}, fmt.Errorf("source lock identity/renderer/offline contract mismatch")
	}
	if manifest.SourceType == "helm-chart" {
		if err := validRenderGeneration(lock.Generation, component); err != nil {
			return Verified{}, fmt.Errorf("source lock render generation invalid: %w", err)
		}
	} else if lock.Generation != nil {
		return Verified{}, fmt.Errorf("non-Helm source lock must not carry Helm render generation evidence")
	}

	var resources []map[string]any
	if err := decodeStrict(files["render-manifest.json"], &resources); err != nil {
		return Verified{}, fmt.Errorf("decode render manifest: %w", err)
	}
	if len(resources) == 0 {
		return Verified{}, fmt.Errorf("render manifest has no resources")
	}
	seen := map[string]bool{}
	for i, r := range resources {
		apiVersion, _ := r["apiVersion"].(string)
		kind, _ := r["kind"].(string)
		md, _ := r["metadata"].(map[string]any)
		name, _ := md["name"].(string)
		ns, _ := md["namespace"].(string)
		if strings.TrimSpace(apiVersion) == "" || strings.TrimSpace(kind) == "" || strings.TrimSpace(name) == "" {
			return Verified{}, fmt.Errorf("render resource %d missing apiVersion/kind/name", i)
		}
		id := apiVersion + "|" + kind + "|" + ns + "|" + name
		if seen[id] {
			return Verified{}, fmt.Errorf("duplicate render resource %s", id)
		}
		seen[id] = true
		enc, _ := json.Marshal(r)
		if bytes.Contains(enc, []byte("example.invalid")) || bytes.Contains(enc, []byte("${")) {
			return Verified{}, fmt.Errorf("render resource contains placeholder/reserved endpoint")
		}
	}

	var images imageInventory
	if err := decodeStrict(files["image-inventory.json"], &images); err != nil {
		return Verified{}, fmt.Errorf("decode image inventory: %w", err)
	}
	if err := verifyRenderImageParity(resources, images); err != nil {
		return Verified{}, err
	}

	var licenses licensesDoc
	if err := decodeStrict(files["licenses.json"], &licenses); err != nil {
		return Verified{}, fmt.Errorf("decode licenses: %w", err)
	}
	if len(licenses.Licenses) == 0 {
		return Verified{}, fmt.Errorf("license manifest is empty")
	}
	for _, lic := range licenses.Licenses {
		if strings.TrimSpace(lic.File) == "" || strings.TrimSpace(lic.SPDXExpression) == "" || (lic.SHA256 != "" && !digestRE.MatchString(lic.SHA256)) {
			return Verified{}, fmt.Errorf("license manifest entry is invalid")
		}
	}
	for _, l := range licenses.Licenses {
		if strings.TrimSpace(l.File) == "" || strings.TrimSpace(l.SPDXExpression) == "" {
			return Verified{}, fmt.Errorf("license entry is incomplete")
		}
	}

	var sbom sbomDoc
	if err := json.Unmarshal(files["sbom.spdx.json"], &sbom); err != nil {
		return Verified{}, fmt.Errorf("decode sbom: %w", err)
	}
	if !strings.HasPrefix(sbom.SPDXVersion, "SPDX-2.") || strings.TrimSpace(sbom.SPDXID) == "" || strings.TrimSpace(sbom.Name) == "" || len(sbom.Packages) == 0 {
		return Verified{}, fmt.Errorf("SPDX SBOM identity/package inventory is invalid")
	}
	chartPackage := manifest.Component
	if manifest.SourceType == "helm-chart" {
		chartPackage = strings.TrimSpace(component.Spec.Delivery.Chart)
	}
	versionCovered := false
	for _, pkg := range sbom.Packages {
		if strings.TrimSpace(pkg.SPDXID) == "" || strings.TrimSpace(pkg.Name) == "" {
			return Verified{}, fmt.Errorf("SPDX SBOM package identity is invalid")
		}
		if strings.TrimSpace(pkg.Name) == chartPackage && strings.TrimPrefix(strings.TrimSpace(pkg.VersionInfo), "v") == manifest.Version {
			versionCovered = true
		}
	}
	if !versionCovered {
		return Verified{}, fmt.Errorf("SPDX SBOM does not describe imported chart %s@%s", chartPackage, manifest.Version)
	}

	var provenance provenanceDoc
	if err := decodeStrict(files["provenance.json"], &provenance); err != nil {
		return Verified{}, fmt.Errorf("decode provenance: %w", err)
	}
	if provenance.Component != manifest.Component || provenance.Version != manifest.Version || provenance.SourceURL != manifest.Upstream.URL || provenance.SourceRevision != manifest.Upstream.Revision || provenance.ArtifactDigest != manifest.Upstream.ArtifactDigest || provenance.NetworkFetchRequired || provenance.BundleMode != "offline-immutable" || provenance.UpstreamVerification != "sha256-pinned-offline" {
		return Verified{}, fmt.Errorf("provenance identity/offline contract mismatch")
	}
	if manifest.SourceType == "helm-chart" {
		if err := validRenderGeneration(provenance.Generation, component); err != nil {
			return Verified{}, fmt.Errorf("provenance render generation invalid: %w", err)
		}
		lockGeneration, _ := canonicalJSON(lock.Generation)
		provenanceGeneration, _ := canonicalJSON(provenance.Generation)
		if !bytes.Equal(lockGeneration, provenanceGeneration) {
			return Verified{}, fmt.Errorf("source lock/provenance render generation mismatch")
		}
	} else if provenance.Generation != nil {
		return Verified{}, fmt.Errorf("non-Helm provenance must not carry Helm render generation evidence")
	}

	sum := sha256.Sum256(raw)
	return Verified{Manifest: manifest, Component: component, Files: files, BundleDigest: "sha256:" + hex.EncodeToString(sum[:]), ResourceCount: len(resources), ImageCount: len(images.Images), LicenseCount: len(licenses.Licenses), OfflineReady: true}, nil
}

func VerifyFile(path string) (Verified, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Verified{}, err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > MaxBundleBytes {
		return Verified{}, fmt.Errorf("bundle file is not a regular file within size limit")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Verified{}, err
	}
	return Verify(raw)
}

func atomicWrite(path string, raw []byte, mode os.FileMode) error {
	return durablefile.Replace(path, raw, 0o755, mode)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func cleanupStaleDurableTemps(dir, label string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".durable-") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("stale %s durable temp %s is not a real regular file", label, entry.Name())
		}
		if err = os.Remove(path); err != nil {
			return fmt.Errorf("remove stale %s durable temp %s: %w", label, entry.Name(), err)
		}
		removed = true
	}
	if removed {
		return syncDirectory(dir)
	}
	return nil
}

func cleanupStaleRuntimeStages(parent, runtimeBase string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	prefix := "." + runtimeBase + ".partial-"
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("stale runtime staging path %s is not a real directory", entry.Name())
		}
		if err = os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove stale runtime staging path %s: %w", entry.Name(), err)
		}
		removed = true
	}
	if removed {
		return syncDirectory(parent)
	}
	return nil
}

func installRuntimeBundle(runtimeDir string, files map[string][]byte) error {
	parent := filepath.Dir(runtimeDir)
	runtimeRoot := filepath.Dir(parent)
	catalogDir := filepath.Dir(runtimeRoot)
	if err := requireRealDirectory(catalogDir, "catalog directory"); err != nil {
		return err
	}
	if info, err := os.Lstat(runtimeRoot); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("catalog runtime path is not a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err = os.Mkdir(runtimeRoot, 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(parent); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("runtime component path is not a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err = os.Mkdir(parent, 0o755); err != nil {
		return err
	}
	if err := cleanupStaleRuntimeStages(parent, filepath.Base(runtimeDir)); err != nil {
		return err
	}
	if st, err := os.Lstat(runtimeDir); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("runtime bundle destination is not a real directory")
		}
		// A crash while repairing a missing file in an already-created immutable
		// runtime bundle can leave durablefile.Replace's product-owned temp file
		// behind in the final directory. The repository install lock guarantees no
		// cooperating repair writer is active here; remove only real regular files
		// with durablefile's reserved temp prefix and fail closed on special paths.
		if err := cleanupStaleDurableTemps(runtimeDir, "runtime bundle"); err != nil {
			return err
		}
		entries, err := os.ReadDir(runtimeDir)
		if err != nil {
			return err
		}
		expected := map[string]struct{}{}
		for _, name := range requiredFiles {
			if name != "component.json" {
				expected[name] = struct{}{}
			}
		}
		for _, entry := range entries {
			if _, ok := expected[entry.Name()]; !ok {
				if entry.IsDir() {
					return fmt.Errorf("existing runtime bundle contains unexpected directory %s", entry.Name())
				}
				return fmt.Errorf("existing runtime bundle contains unexpected file %s", entry.Name())
			}
			if err := requireRealRegularFile(filepath.Join(runtimeDir, entry.Name()), "runtime bundle file "+entry.Name()); err != nil {
				return err
			}
		}
		for name := range expected {
			p := filepath.Join(runtimeDir, name)
			existing, readErr := readRealRegularFile(p, "runtime bundle file "+name)
			if readErr == nil {
				if !bytes.Equal(existing, files[name]) {
					return fmt.Errorf("existing runtime bundle %s differs; refusing overwrite", filepath.ToSlash(runtimeDir))
				}
				continue
			}
			if !errors.Is(readErr, os.ErrNotExist) {
				return readErr
			}
			// Repair only a missing file in an otherwise matching immutable bundle.
			// A differing or unexpected file remains fail-closed above.
			if err := atomicWrite(p, files[name], 0o644); err != nil {
				return err
			}
		}
		return syncDirectory(runtimeDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	staging, err := os.MkdirTemp(parent, "."+filepath.Base(runtimeDir)+".partial-")
	if err != nil {
		return err
	}
	if err = os.Chmod(staging, 0o755); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	defer os.RemoveAll(staging)
	for _, name := range requiredFiles {
		if name == "component.json" {
			continue
		}
		if err = atomicWrite(filepath.Join(staging, name), files[name], 0o644); err != nil {
			return err
		}
	}
	if err = syncDirectory(staging); err != nil {
		return err
	}
	if err = os.Rename(staging, runtimeDir); err != nil {
		return err
	}
	return syncDirectory(parent)
}

type upstreamAdmissionDocument struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Components []upstreamAdmissionEntry `json:"components"`
		Policy     struct {
			AllowLatestResolution      bool   `json:"allowLatestResolution"`
			AutoWidenCatalogConstraint bool   `json:"autoWidenCatalogConstraint"`
			RuntimeCertification       string `json:"runtimeCertification"`
			SourceAuthority            string `json:"sourceAuthority"`
			SourceResolution           string `json:"sourceResolution"`
			VersionSelection           string `json:"versionSelection"`
		} `json:"policy"`
	} `json:"spec"`
}

type upstreamAdmissionEntry struct {
	CatalogConstraint string  `json:"catalogConstraint"`
	Chart             string  `json:"chart"`
	Component         string  `json:"component"`
	Rationale         string  `json:"rationale"`
	SelectedVersion   *string `json:"selectedVersion"`
	Source            string  `json:"source"`
	Status            string  `json:"status"`
	UpstreamVersion   *string `json:"upstreamVersion"`
}

func normalizedExternalVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

func requireRealDirectory(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s unavailable: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a real directory", label)
	}
	return nil
}

func requireRealRegularFile(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s unavailable: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a real regular file", label)
	}
	return nil
}

// readRealRegularFile keeps repository-owned authority/runtime reads from following
// a final-path symlink between validation and open. O_NONBLOCK also prevents a
// concurrently substituted FIFO from turning an install attempt into an unbounded read.
func readRealRegularFile(path, label string) ([]byte, error) {
	if err := requireRealRegularFile(path, label); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s unavailable: %w", label, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s unavailable: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a real regular file", label)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	return raw, nil
}

func loadCanonicalUpstreamAdmission(repoRoot string) (upstreamAdmissionDocument, error) {
	catalogDir := filepath.Join(repoRoot, "catalog")
	if err := requireRealDirectory(catalogDir, "catalog directory"); err != nil {
		return upstreamAdmissionDocument{}, fmt.Errorf("upstream admission authority unavailable: %w", err)
	}
	authorityPath := filepath.Join(catalogDir, "upstream-admission.json")
	raw, err := readRealRegularFile(authorityPath, "upstream admission authority")
	if err != nil {
		return upstreamAdmissionDocument{}, err
	}
	var doc upstreamAdmissionDocument
	if err := decodeStrict(raw, &doc); err != nil {
		return upstreamAdmissionDocument{}, fmt.Errorf("upstream admission authority invalid: %w", err)
	}
	if doc.APIVersion != "platform.4so.io/v1alpha1" || doc.Kind != "CatalogUpstreamAdmission" || strings.TrimSpace(doc.Metadata.Name) == "" {
		return upstreamAdmissionDocument{}, fmt.Errorf("upstream admission authority identity is invalid")
	}
	if doc.Spec.Policy.AllowLatestResolution || doc.Spec.Policy.AutoWidenCatalogConstraint || doc.Spec.Policy.RuntimeCertification != "separate-runtime-evidence-required" || doc.Spec.Policy.SourceAuthority != "official-upstream-only" || doc.Spec.Policy.SourceResolution != "separate-immutable-acquisition-required" || doc.Spec.Policy.VersionSelection != "exact-semver-no-prerelease" {
		return upstreamAdmissionDocument{}, fmt.Errorf("upstream admission authority policy is invalid")
	}
	seen := map[string]bool{}
	for _, entry := range doc.Spec.Components {
		name := strings.TrimSpace(entry.Component)
		if name == "" || seen[name] {
			return upstreamAdmissionDocument{}, fmt.Errorf("upstream admission component identity is invalid or duplicated: %s", name)
		}
		seen[name] = true
	}
	return doc, nil
}

func loadUnresolvedHelmComponents(repoRoot string) (map[string]catalog.Component, error) {
	componentsDir := filepath.Join(repoRoot, "catalog", "components")
	if err := requireRealDirectory(componentsDir, "catalog components directory"); err != nil {
		return nil, fmt.Errorf("read catalog component contracts: %w", err)
	}
	entries, err := os.ReadDir(componentsDir)
	if err != nil {
		return nil, fmt.Errorf("read catalog component contracts: %w", err)
	}
	out := map[string]catalog.Component{}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("catalog component contract %s is a symlink", entry.Name())
		}
		raw, err := readRealRegularFile(filepath.Join(componentsDir, entry.Name()), "catalog component contract "+entry.Name())
		if err != nil {
			return nil, err
		}
		var component catalog.Component
		if err = decodeStrict(raw, &component); err != nil {
			return nil, fmt.Errorf("decode catalog component contract %s: %w", entry.Name(), err)
		}
		name := strings.TrimSpace(component.Metadata.Name)
		if !componentNameRE.MatchString(name) || seen[name] {
			return nil, fmt.Errorf("catalog component identity is invalid or duplicated: %s", name)
		}
		seen[name] = true
		if component.Spec.Source.Type == "helm-chart" && !component.Spec.Source.Resolved {
			out[name] = component
		}
	}
	return out, nil
}

func validAdmissionConstraint(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if exactVersion(v) {
		return true
	}
	parts := strings.Split(v, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] == "x" &&
		regexp.MustCompile(`^[0-9]+$`).MatchString(parts[0]) && regexp.MustCompile(`^[0-9]+$`).MatchString(parts[1])
}

func validateCanonicalUpstreamAdmissionCoverage(repoRoot string, doc upstreamAdmissionDocument) error {
	unresolved, err := loadUnresolvedHelmComponents(repoRoot)
	if err != nil {
		return fmt.Errorf("upstream admission catalog authority invalid: %w", err)
	}
	if len(doc.Spec.Components) != len(unresolved) {
		return fmt.Errorf("upstream admission coverage mismatch: authority=%d unresolved-helm=%d", len(doc.Spec.Components), len(unresolved))
	}
	allowedStatus := map[string]bool{
		"ready-for-acquisition":        true,
		"architecture-review-required": true,
		"dependency-review-required":   true,
		"version-selection-required":   true,
		"version-review-required":      true,
	}
	seen := map[string]bool{}
	for _, entry := range doc.Spec.Components {
		name := strings.TrimSpace(entry.Component)
		component, ok := unresolved[name]
		if !ok || seen[name] || !componentNameRE.MatchString(name) {
			return fmt.Errorf("upstream admission coverage contains invalid component %s", name)
		}
		seen[name] = true
		if !allowedStatus[entry.Status] {
			return fmt.Errorf("upstream admission status is invalid for %s: %s", name, entry.Status)
		}
		constraint := strings.TrimSpace(entry.CatalogConstraint)
		if !validAdmissionConstraint(constraint) {
			return fmt.Errorf("upstream admission constraint is invalid for %s: %s", name, constraint)
		}
		if strings.TrimSpace(entry.Chart) == "" || strings.TrimSpace(entry.Chart) != strings.TrimSpace(component.Spec.Delivery.Chart) {
			return fmt.Errorf("upstream admission chart mismatch for %s", name)
		}
		source := strings.TrimSpace(entry.Source)
		if !(strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "oci://")) {
			return fmt.Errorf("upstream admission source is invalid for %s", name)
		}
		if strings.TrimSpace(entry.Rationale) == "" {
			return fmt.Errorf("upstream admission rationale is missing for %s", name)
		}
		selected := ""
		if entry.SelectedVersion != nil {
			selected = normalizedExternalVersion(*entry.SelectedVersion)
			if !exactVersion(selected) || !releaseConstraintMatches(constraint, selected) {
				return fmt.Errorf("upstream admission selected version is invalid for %s", name)
			}
			if entry.UpstreamVersion == nil || normalizedExternalVersion(*entry.UpstreamVersion) != selected {
				return fmt.Errorf("upstream admission upstream version mismatch for %s", name)
			}
		}
		if entry.Status == "ready-for-acquisition" {
			if selected == "" {
				return fmt.Errorf("upstream admission ready component %s has no selected version", name)
			}
			if strings.TrimSpace(component.Spec.Release) != selected {
				return fmt.Errorf("upstream admission catalog pin mismatch for %s", name)
			}
			if component.Spec.VersionPolicy != "exact-upstream-admitted-pending-source-acquisition" {
				return fmt.Errorf("upstream admission version policy mismatch for %s", name)
			}
		} else if strings.TrimSpace(component.Spec.Release) != constraint {
			return fmt.Errorf("upstream admission review component %s no longer matches its constraint", name)
		}
	}
	if len(seen) != len(unresolved) {
		return fmt.Errorf("upstream admission coverage is incomplete")
	}
	return nil
}

func findUpstreamAdmissionEntry(doc *upstreamAdmissionDocument, component string) (*upstreamAdmissionEntry, error) {
	for i := range doc.Spec.Components {
		if doc.Spec.Components[i].Component == component {
			return &doc.Spec.Components[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s", errUpstreamAdmissionComponentMissing, component)
}

func verifyHelmAdmissionEntry(match *upstreamAdmissionEntry, manifest Manifest, component catalog.Component) error {
	if match.Status != "ready-for-acquisition" {
		return fmt.Errorf("upstream admission blocks component %s with status %s", manifest.Component, match.Status)
	}
	if match.SelectedVersion == nil || normalizedExternalVersion(*match.SelectedVersion) != manifest.Version {
		return fmt.Errorf("upstream admission version mismatch for %s", manifest.Component)
	}
	if strings.TrimSpace(match.Source) != strings.TrimSpace(manifest.Upstream.URL) {
		return fmt.Errorf("upstream admission source mismatch for %s", manifest.Component)
	}
	if match.UpstreamVersion == nil || normalizedExternalVersion(*match.UpstreamVersion) != normalizedExternalVersion(manifest.Upstream.Revision) {
		return fmt.Errorf("upstream admission revision mismatch for %s", manifest.Component)
	}
	if strings.TrimSpace(match.Chart) == "" || strings.TrimSpace(match.Chart) != strings.TrimSpace(component.Spec.Delivery.Chart) {
		return fmt.Errorf("upstream admission chart mismatch for %s", manifest.Component)
	}
	if !releaseConstraintMatches(strings.TrimSpace(match.CatalogConstraint), manifest.Version) {
		return fmt.Errorf("upstream admission catalog constraint mismatch for %s", manifest.Component)
	}
	return nil
}

func verifyCanonicalHelmAdmission(repoRoot string, manifest Manifest, component catalog.Component) error {
	if manifest.SourceType != "helm-chart" {
		return nil
	}
	doc, err := loadCanonicalUpstreamAdmission(repoRoot)
	if err != nil {
		return err
	}
	if err = validateCanonicalUpstreamAdmissionCoverage(repoRoot, doc); err != nil {
		return err
	}
	match, err := findUpstreamAdmissionEntry(&doc, manifest.Component)
	if err != nil {
		return err
	}
	return verifyHelmAdmissionEntry(match, manifest, component)
}

// verifyResolvedHelmAdmissionRecoveryState accepts exactly one crash-recovery shape:
// the target component is already the verified resolved contract, while its own
// previously valid admission row is the sole extra row left behind. All remaining
// unresolved Helm components must still have strict canonical admission coverage.
func verifyResolvedHelmAdmissionRecoveryState(repoRoot string, manifest Manifest, component catalog.Component) error {
	doc, err := loadCanonicalUpstreamAdmission(repoRoot)
	if err != nil {
		return err
	}
	match, err := findUpstreamAdmissionEntry(&doc, manifest.Component)
	if errors.Is(err, errUpstreamAdmissionComponentMissing) {
		return validateCanonicalUpstreamAdmissionCoverage(repoRoot, doc)
	}
	if err != nil {
		return err
	}
	if err = verifyHelmAdmissionEntry(match, manifest, component); err != nil {
		return fmt.Errorf("resolved component admission recovery rejected: %w", err)
	}

	withoutTarget := doc
	withoutTarget.Spec.Components = make([]upstreamAdmissionEntry, 0, len(doc.Spec.Components)-1)
	for _, entry := range doc.Spec.Components {
		if entry.Component != manifest.Component {
			withoutTarget.Spec.Components = append(withoutTarget.Spec.Components, entry)
		}
	}
	if err = validateCanonicalUpstreamAdmissionCoverage(repoRoot, withoutTarget); err != nil {
		return fmt.Errorf("resolved component admission recovery rejected: %w", err)
	}
	return nil
}

func retireCanonicalHelmAdmission(repoRoot, component string) error {
	doc, err := loadCanonicalUpstreamAdmission(repoRoot)
	if err != nil {
		return err
	}
	idx := -1
	for i := range doc.Spec.Components {
		if doc.Spec.Components[i].Component == component {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	doc.Spec.Components = append(doc.Spec.Components[:idx], doc.Spec.Components[idx+1:]...)
	raw, err := canonicalJSON(doc)
	if err != nil {
		return err
	}
	if err = atomicWrite(filepath.Join(repoRoot, "catalog", "upstream-admission.json"), raw, 0o644); err != nil {
		return fmt.Errorf("retire upstream admission for %s: %w", component, err)
	}
	return nil
}

func verifyInstallComponentContract(current, resolved catalog.Component, manifest Manifest) error {
	if current.Metadata.Name != manifest.Component {
		return fmt.Errorf("component contract identity mismatch for %s", manifest.Component)
	}
	if current.Spec.Source.Resolved {
		currentRaw, _ := canonicalJSON(current)
		resolvedRaw, _ := canonicalJSON(resolved)
		if !bytes.Equal(currentRaw, resolvedRaw) {
			return fmt.Errorf("component %s is already resolved; refusing implicit replacement", manifest.Component)
		}
		return nil
	}
	if !releaseConstraintMatches(current.Spec.Release, manifest.Version) {
		return fmt.Errorf("component contract release %s does not admit %s", current.Spec.Release, manifest.Version)
	}
	expected := current
	expected.Spec.Release = manifest.Version
	expected.Spec.VersionPolicy = "exact-offline-import"
	expected.Spec.Delivery.RepositoryKey = "offline-catalog-bundle"
	expected.Spec.Source = resolved.Spec.Source
	expected.Spec.Certification.Status = "candidate"
	expected.Spec.Certification.Profiles = nil
	expected.Spec.Certification.EvidenceDigest = ""
	expectedRaw, _ := canonicalJSON(expected)
	resolvedRaw, _ := canonicalJSON(resolved)
	if !bytes.Equal(expectedRaw, resolvedRaw) {
		return fmt.Errorf("component contract substitution detected for %s", manifest.Component)
	}
	return nil
}

type catalogInstallLock struct {
	file *os.File
}

func acquireCatalogInstallLock(repoRoot string) (*catalogInstallLock, error) {
	stateDir := filepath.Join(repoRoot, ".state")
	if info, err := os.Lstat(stateDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("catalog install state path is not a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if err = os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(stateDir, "catalog-bundle-install.lock")
	if info, err := os.Lstat(lockPath); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, fmt.Errorf("catalog install lock path is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire catalog install transaction lock: %w", err)
	}
	return &catalogInstallLock{file: file}, nil
}

func (lock *catalogInstallLock) release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return fmt.Errorf("release catalog install transaction lock: %w", unlockErr)
	}
	return closeErr
}

func Install(v Verified, repoRoot string) error {
	repoRoot, err := filepath.Abs(strings.TrimSpace(repoRoot))
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(repoRoot, "VERSION")); err != nil {
		return fmt.Errorf("repo root missing VERSION: %w", err)
	}
	lock, err := acquireCatalogInstallLock(repoRoot)
	if err != nil {
		return err
	}
	defer func() { _ = lock.release() }()
	catalogDir := filepath.Join(repoRoot, "catalog")
	componentsDir := filepath.Join(catalogDir, "components")
	if err = requireRealDirectory(catalogDir, "catalog directory"); err != nil {
		return err
	}
	if err = requireRealDirectory(componentsDir, "catalog components directory"); err != nil {
		return err
	}
	// Catalog install is repository-serialized. A process crash can leave
	// durablefile.Replace's reserved temp files beside the component or shared
	// admission authority before the final rename. Remove only real regular
	// product-owned temps while holding the install fence so they cannot leak
	// into a subsequent source/release artifact.
	if err = cleanupStaleDurableTemps(catalogDir, "catalog authority"); err != nil {
		return err
	}
	if err = cleanupStaleDurableTemps(componentsDir, "catalog component"); err != nil {
		return err
	}
	runtimeDir := filepath.Join(repoRoot, "catalog", "runtime", filepath.FromSlash(v.Manifest.BundleKey))
	if !strings.HasPrefix(runtimeDir, filepath.Join(repoRoot, "catalog", "runtime")+string(os.PathSeparator)) {
		return fmt.Errorf("bundle destination escapes runtime root")
	}
	componentPath := filepath.Join(componentsDir, v.Manifest.Component+".json")
	old, err := readRealRegularFile(componentPath, "component contract "+v.Manifest.Component)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("component contract %s is not present in repository", v.Manifest.Component)
		}
		return err
	}
	var current catalog.Component
	if err = decodeStrict(old, &current); err != nil {
		return fmt.Errorf("decode existing component contract %s: %w", v.Manifest.Component, err)
	}
	var resolved catalog.Component
	if err = decodeStrict(v.Files["component.json"], &resolved); err != nil {
		return fmt.Errorf("decode verified component payload %s: %w", v.Manifest.Component, err)
	}
	if resolved.Metadata.Name != v.Manifest.Component || resolved.Spec.Release != v.Manifest.Version || resolved.Spec.Source.BundleKey != v.Manifest.BundleKey {
		return fmt.Errorf("verified component payload no longer matches bundle manifest")
	}
	if err = verifyInstallComponentContract(current, resolved, v.Manifest); err != nil {
		return err
	}
	if v.Manifest.SourceType == "helm-chart" {
		if current.Spec.Source.Resolved {
			err = verifyResolvedHelmAdmissionRecoveryState(repoRoot, v.Manifest, resolved)
		} else {
			err = verifyCanonicalHelmAdmission(repoRoot, v.Manifest, resolved)
		}
		if err != nil {
			return err
		}
	}
	if err := installRuntimeBundle(runtimeDir, v.Files); err != nil {
		return err
	}
	if err := atomicWrite(componentPath, v.Files["component.json"], 0o644); err != nil {
		return err
	}
	if v.Manifest.SourceType == "helm-chart" {
		if err := retireCanonicalHelmAdmission(repoRoot, v.Manifest.Component); err != nil {
			return err
		}
	}
	return nil
}

type AssembleInput struct {
	BaseComponent          []byte
	Artifact               []byte
	RenderManifest         []byte
	ImageInventory         []byte
	Licenses               []byte
	SBOM                   []byte
	RenderGeneration       []byte
	Version                string
	SourceType             string
	SourceURL              string
	SourceRevision         string
	UpstreamArtifact       string
	ExpectedArtifactDigest string
	BundleKey              string
}

func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func Assemble(in AssembleInput) ([]byte, Verified, error) {
	if !exactVersion(in.Version) || !supportedExternalSourceType(in.SourceType) || strings.TrimSpace(in.SourceURL) == "" || strings.TrimSpace(in.SourceRevision) == "" || strings.TrimSpace(in.UpstreamArtifact) == "" || !digestRE.MatchString(strings.TrimSpace(in.ExpectedArtifactDigest)) {
		return nil, Verified{}, fmt.Errorf("assemble requires exact version, supported source type, source URL/revision, upstream artifact name and expected sha256 digest")
	}
	artifactDigest := sha(in.Artifact)
	if artifactDigest != strings.TrimSpace(in.ExpectedArtifactDigest) {
		return nil, Verified{}, fmt.Errorf("upstream artifact digest mismatch: expected=%s got=%s", strings.TrimSpace(in.ExpectedArtifactDigest), artifactDigest)
	}
	if !safeBundleKey(in.BundleKey) {
		return nil, Verified{}, fmt.Errorf("assemble bundleKey is unsafe")
	}
	var component catalog.Component
	if err := decodeStrict(in.BaseComponent, &component); err != nil {
		return nil, Verified{}, fmt.Errorf("decode base component: %w", err)
	}
	if strings.TrimSpace(component.Metadata.Name) == "" {
		return nil, Verified{}, fmt.Errorf("base component name is required")
	}
	if !releaseConstraintMatches(component.Spec.Release, in.Version) {
		return nil, Verified{}, fmt.Errorf("imported version %s does not satisfy component release constraint %s", in.Version, component.Spec.Release)
	}
	if in.BundleKey != component.Metadata.Name+"/"+in.Version {
		return nil, Verified{}, fmt.Errorf("bundleKey must equal component/version")
	}
	var generation *renderGeneration
	if in.SourceType == "helm-chart" {
		var decoded renderGeneration
		if len(in.RenderGeneration) == 0 {
			return nil, Verified{}, fmt.Errorf("helm-chart assembly requires render generation evidence")
		}
		if err := decodeStrict(in.RenderGeneration, &decoded); err != nil {
			return nil, Verified{}, fmt.Errorf("render generation invalid: %w", err)
		}
		if err := validRenderGeneration(&decoded, component); err != nil {
			return nil, Verified{}, fmt.Errorf("render generation invalid: %w", err)
		}
		generation = &decoded
	} else if len(in.RenderGeneration) != 0 {
		return nil, Verified{}, fmt.Errorf("render generation evidence is only valid for helm-chart sources")
	}
	if in.SourceType == "external-tagged-source-set" {
		if err := verifyTaggedSourceSet(in.Artifact, component.Metadata.Name, in.Version, in.SourceURL, in.SourceRevision); err != nil {
			return nil, Verified{}, err
		}
	}
	if in.SourceType == "helm-chart" {
		if strings.TrimSpace(component.Spec.Delivery.Type) != "helm" {
			return nil, Verified{}, fmt.Errorf("helm-chart source requires helm delivery")
		}
		if !validHelmSourceURL(in.SourceURL) || !strings.HasSuffix(strings.ToLower(strings.TrimSpace(in.UpstreamArtifact)), ".tgz") {
			return nil, Verified{}, fmt.Errorf("helm-chart source requires https:// or oci:// source URL and .tgz upstream artifact name")
		}
		if err := verifyHelmChartArtifact(in.Artifact, component.Spec.Delivery.Chart, in.Version); err != nil {
			return nil, Verified{}, err
		}
	}
	// Validate supplied evidence documents before creating any resolved contract.
	var resources []map[string]any
	if err := decodeStrict(in.RenderManifest, &resources); err != nil || len(resources) == 0 {
		if err == nil {
			err = fmt.Errorf("no resources")
		}
		return nil, Verified{}, fmt.Errorf("render manifest invalid: %w", err)
	}
	var images imageInventory
	if err := decodeStrict(in.ImageInventory, &images); err != nil {
		return nil, Verified{}, fmt.Errorf("image inventory invalid: %w", err)
	}
	if err := verifyRenderImageParity(resources, images); err != nil {
		return nil, Verified{}, err
	}
	var licenses licensesDoc
	if err := decodeStrict(in.Licenses, &licenses); err != nil || len(licenses.Licenses) == 0 {
		return nil, Verified{}, fmt.Errorf("license manifest invalid or empty")
	}
	for _, lic := range licenses.Licenses {
		if strings.TrimSpace(lic.File) == "" || strings.TrimSpace(lic.SPDXExpression) == "" || (lic.SHA256 != "" && !digestRE.MatchString(lic.SHA256)) {
			return nil, Verified{}, fmt.Errorf("license manifest entry is invalid")
		}
	}
	var sbom sbomDoc
	if err := json.Unmarshal(in.SBOM, &sbom); err != nil || !strings.HasPrefix(sbom.SPDXVersion, "SPDX-2.") || strings.TrimSpace(sbom.SPDXID) == "" || strings.TrimSpace(sbom.Name) == "" || len(sbom.Packages) == 0 {
		return nil, Verified{}, fmt.Errorf("SPDX SBOM invalid or missing package inventory")
	}
	chartPackage := component.Metadata.Name
	if in.SourceType == "helm-chart" {
		chartPackage = strings.TrimSpace(component.Spec.Delivery.Chart)
	}
	versionCovered := false
	for _, pkg := range sbom.Packages {
		if strings.TrimSpace(pkg.SPDXID) == "" || strings.TrimSpace(pkg.Name) == "" {
			return nil, Verified{}, fmt.Errorf("SPDX SBOM package identity is invalid")
		}
		if strings.TrimSpace(pkg.Name) == chartPackage && strings.TrimPrefix(strings.TrimSpace(pkg.VersionInfo), "v") == in.Version {
			versionCovered = true
		}
	}
	if !versionCovered {
		return nil, Verified{}, fmt.Errorf("SPDX SBOM does not describe imported chart %s@%s", chartPackage, in.Version)
	}

	lock := sourceLock{Component: component.Metadata.Name, Version: in.Version, SourceType: in.SourceType, UpstreamURL: in.SourceURL, UpstreamRevision: in.SourceRevision, UpstreamArtifact: in.UpstreamArtifact, UpstreamArtifactDigest: artifactDigest, NetworkFetchRequired: false, Renderer: "json-resource-list-v1", UpstreamVerification: "sha256-pinned-offline", Generation: generation}
	lockRaw, _ := canonicalJSON(lock)
	prov := provenanceDoc{Component: component.Metadata.Name, Version: in.Version, SourceURL: in.SourceURL, SourceRevision: in.SourceRevision, ArtifactDigest: artifactDigest, BundleMode: "offline-immutable", NetworkFetchRequired: false, UpstreamVerification: "sha256-pinned-offline", Generation: generation}
	provRaw, _ := canonicalJSON(prov)

	component.Spec.Release = in.Version
	component.Spec.VersionPolicy = "exact-offline-import"
	deliveryType := strings.TrimSpace(component.Spec.Delivery.Type)
	if deliveryType != "native-manifest" && deliveryType != "helm" {
		return nil, Verified{}, fmt.Errorf("base component delivery type %q is not supported for immutable external bundles", deliveryType)
	}
	component.Spec.Delivery.RepositoryKey = "offline-catalog-bundle"
	component.Spec.Source.Type = in.SourceType
	component.Spec.Source.Resolved = true
	component.Spec.Source.BundleKey = in.BundleKey
	component.Spec.Source.ArtifactDigest = artifactDigest
	component.Spec.Source.RenderManifestDigest = sha(in.RenderManifest)
	component.Spec.Source.SourceLockDigest = sha(lockRaw)
	component.Spec.Source.ImageInventoryDigest = sha(in.ImageInventory)
	component.Spec.Source.LicenseManifestDigest = sha(in.Licenses)
	component.Spec.Source.SBOM = sha(in.SBOM)
	component.Spec.Source.Provenance = sha(provRaw)
	component.Spec.Source.SignatureVerification = "sha256-pinned-offline"
	component.Spec.Certification.Status = "candidate"
	component.Spec.Certification.Profiles = nil
	component.Spec.Certification.EvidenceDigest = ""
	componentRaw, _ := canonicalJSON(component)

	payloads := map[string][]byte{
		"artifact.bin": in.Artifact, "component.json": componentRaw, "image-inventory.json": in.ImageInventory, "licenses.json": in.Licenses, "provenance.json": provRaw, "render-manifest.json": in.RenderManifest, "sbom.spdx.json": in.SBOM, "source-lock.json": lockRaw,
	}
	manifest := Manifest{APIVersion: "platform.4so.io/v1alpha1", Kind: "ExternalCatalogBundle", Component: component.Metadata.Name, Version: in.Version, SourceType: in.SourceType, BundleKey: in.BundleKey, Upstream: Upstream{URL: in.SourceURL, Revision: in.SourceRevision, Artifact: in.UpstreamArtifact, ArtifactDigest: artifactDigest, VerificationMethod: "sha256-pinned-offline"}, Files: map[string]string{}}
	for name, raw := range payloads {
		manifest.Files[name] = sha(raw)
	}
	manifestRaw, _ := canonicalJSON(manifest)
	payloads["bundle-manifest.json"] = manifestRaw

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(payloads))
	for name := range payloads {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0o644)
		h.Modified = time.Unix(315532800, 0).UTC()
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, Verified{}, err
		}
		if _, err = w.Write(payloads[name]); err != nil {
			return nil, Verified{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, Verified{}, err
	}
	raw := buf.Bytes()
	verified, err := Verify(raw)
	if err != nil {
		return nil, Verified{}, fmt.Errorf("assembled bundle failed self-verification: %w", err)
	}
	return raw, verified, nil
}
