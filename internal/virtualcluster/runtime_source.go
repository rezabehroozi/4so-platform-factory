package virtualcluster

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	RuntimeSourceAuthority = "VIRTUAL_CLUSTER_RUNTIME_SOURCE_AUTHORITY_V1"
	RuntimeEngineVClusterOSS = "vcluster-oss"
	RuntimeSelectedVersion = "0.37.1"
	RuntimeChartRepository = "https://charts.loft.sh"
	RuntimeChartName = "vcluster"
	RuntimeReleaseURL = "https://github.com/loft-sh/vcluster/releases/tag/v0.37.1"
	RuntimeValuesPath = "runtime/virtualcluster/vcluster-oss-values.yaml"
	RuntimeImageRegistry = "ghcr.io"
	RuntimeImageRepository = "loft-sh/vcluster-oss"
)

type RuntimeSource struct {
	Authority            string   `json:"authority"`
	Engine               string   `json:"engine"`
	Version              string   `json:"version"`
	ChartRepository      string   `json:"chartRepository"`
	ChartName            string   `json:"chartName"`
	ReleaseURL           string   `json:"releaseUrl"`
	ValuesPath           string   `json:"valuesPath"`
	ImageRegistry        string   `json:"imageRegistry"`
	ImageRepository      string   `json:"imageRepository"`
	ChartSHA256          string   `json:"chartSha256,omitempty"`
	ValuesSHA256         string   `json:"valuesSha256,omitempty"`
	RenderManifestSHA256 string   `json:"renderManifestSha256,omitempty"`
	ImageReferences      []string `json:"imageReferences,omitempty"`
	ImageDigests         []string `json:"imageDigests,omitempty"`
	ChartArtifactPath    string   `json:"chartArtifactPath,omitempty"`
	ExecutorImageReference string   `json:"executorImageReference,omitempty"`
	MirrorImageReferences []string `json:"mirrorImageReferences,omitempty"`
	Resolved             bool     `json:"resolved"`
	MirrorReady          bool     `json:"mirrorReady"`
	OfflineAcquisitionRequired bool `json:"offlineAcquisitionRequired"`
	PlatformDependency   bool     `json:"platformDependency"`
}

type RuntimeSourceResolution struct {
	Version         string
	ChartRepository string
	ChartName       string
	ChartSHA256          string
	ValuesSHA256         string
	RenderManifestSHA256 string
	ImageReferences      []string
	ChartArtifactPath    string
	ExecutorImageReference string
	MirrorImageReferences []string
	MirrorReady          bool
}

var runtimeSHA256Pattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
var runtimeExecutorImagePattern = regexp.MustCompile(`^[^\\s@]+/virtual-cluster-runtime@sha256:[0-9a-f]{64}$`)

func SelectedRuntimeSource() RuntimeSource {
	return RuntimeSource{
		Authority: RuntimeSourceAuthority,
		Engine: RuntimeEngineVClusterOSS,
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		ReleaseURL: RuntimeReleaseURL,
		ValuesPath: RuntimeValuesPath,
		ImageRegistry: RuntimeImageRegistry,
		ImageRepository: RuntimeImageRepository,
		Resolved: false,
		OfflineAcquisitionRequired: true,
		PlatformDependency: false,
	}
}

func normalizeRuntimeImageReferences(values []string) ([]string, []string, error) {
	seenRefs := map[string]bool{}
	seenDigests := map[string]bool{}
	refs := make([]string, 0, len(values))
	digests := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		at := strings.LastIndex(value, "@")
		if at <= 0 || at == len(value)-1 {
			return nil, nil, fmt.Errorf("runtime image reference must be digest pinned: %q", raw)
		}
		digest := value[at+1:]
		if !runtimeSHA256Pattern.MatchString(digest) {
			return nil, nil, fmt.Errorf("runtime image reference digest must be exact lowercase sha256: %q", raw)
		}
		if seenRefs[value] {
			return nil, nil, fmt.Errorf("duplicate runtime image reference: %q", value)
		}
		seenRefs[value] = true
		refs = append(refs, value)
		if !seenDigests[digest] {
			seenDigests[digest] = true
			digests = append(digests, digest)
		}
	}
	if len(refs) == 0 {
		return nil, nil, errors.New("at least one exact runtime image reference is required")
	}
	sort.Strings(refs)
	sort.Strings(digests)
	return refs, digests, nil
}

func safeRuntimeArtifactPath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return "", errors.New("runtime chart artifact path must be repository-relative")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("runtime chart artifact path is unsafe")
		}
	}
	return value, nil
}

func ResolveRuntimeSource(input RuntimeSourceResolution) (RuntimeSource, error) {
	selected := SelectedRuntimeSource()
	input.Version = strings.TrimSpace(input.Version)
	input.ChartRepository = strings.TrimSpace(input.ChartRepository)
	input.ChartName = strings.TrimSpace(input.ChartName)
	input.ChartSHA256 = strings.TrimSpace(input.ChartSHA256)

	if input.Version != selected.Version {
		return RuntimeSource{}, fmt.Errorf("runtime version %q is not the selected version %q", input.Version, selected.Version)
	}
	if input.ChartRepository != selected.ChartRepository || input.ChartName != selected.ChartName {
		return RuntimeSource{}, errors.New("runtime chart identity does not match selected vCluster OSS authority")
	}
	if !runtimeSHA256Pattern.MatchString(input.ChartSHA256) {
		return RuntimeSource{}, errors.New("runtime chartSha256 must be an exact lowercase sha256 digest")
	}
	if !runtimeSHA256Pattern.MatchString(strings.TrimSpace(input.ValuesSHA256)) {
		return RuntimeSource{}, errors.New("runtime valuesSha256 must be an exact lowercase sha256 digest")
	}
	if !runtimeSHA256Pattern.MatchString(strings.TrimSpace(input.RenderManifestSHA256)) {
		return RuntimeSource{}, errors.New("runtime renderManifestSha256 must be an exact lowercase sha256 digest")
	}
	refs, digests, err := normalizeRuntimeImageReferences(input.ImageReferences)
	if err != nil {
		return RuntimeSource{}, err
	}
	if !strings.Contains(strings.Join(refs, "\n"), RuntimeImageRepository+"@sha256:") {
		return RuntimeSource{}, errors.New("runtime image inventory does not contain the required vCluster OSS image")
	}
	for _, ref := range refs {
		if strings.Contains(ref, "vcluster-pro") || strings.Contains(ref, "vcluster-platform") {
			return RuntimeSource{}, errors.New("vCluster Pro/Platform image is not admitted")
		}
	}
	artifactPath, err := safeRuntimeArtifactPath(input.ChartArtifactPath)
	if err != nil {
		return RuntimeSource{}, err
	}
	selected.ChartSHA256 = input.ChartSHA256
	selected.ValuesSHA256 = strings.TrimSpace(input.ValuesSHA256)
	selected.RenderManifestSHA256 = strings.TrimSpace(input.RenderManifestSHA256)
	selected.ImageReferences = refs
	selected.ImageDigests = digests
	selected.ChartArtifactPath = artifactPath
	selected.ExecutorImageReference = strings.TrimSpace(input.ExecutorImageReference)
	if !runtimeExecutorImagePattern.MatchString(selected.ExecutorImageReference) {
		return RuntimeSource{}, errors.New("virtual cluster executor image must be digest pinned and use the virtual-cluster-runtime repository")
	}
	selected.Resolved = true
	selected.MirrorReady = input.MirrorReady
	if input.MirrorReady {
		mirrorRefs, mirrorDigests, mirrorErr := normalizeRuntimeImageReferences(input.MirrorImageReferences)
		if mirrorErr != nil {
			return RuntimeSource{}, fmt.Errorf("runtime mirror inventory: %w", mirrorErr)
		}
		if strings.Join(mirrorDigests, "\n") != strings.Join(digests, "\n") {
			return RuntimeSource{}, errors.New("runtime mirror inventory digest set does not match acquired source images")
		}
		selected.MirrorImageReferences = mirrorRefs
	}
	return selected, nil
}

func ValidateRuntimeExecutionSource(source RuntimeSource) error {
	if source.Authority != RuntimeSourceAuthority || source.Engine != RuntimeEngineVClusterOSS {
		return errors.New("virtual cluster runtime source authority is invalid")
	}
	if source.PlatformDependency {
		return errors.New("vCluster Platform is not an admitted runtime dependency")
	}
	if source.Version != RuntimeSelectedVersion || source.ChartRepository != RuntimeChartRepository || source.ChartName != RuntimeChartName ||
		source.ReleaseURL != RuntimeReleaseURL || source.ValuesPath != RuntimeValuesPath ||
		source.ImageRegistry != RuntimeImageRegistry || source.ImageRepository != RuntimeImageRepository {
		return errors.New("virtual cluster runtime source selection drift")
	}
	if !source.Resolved {
		return errors.New("virtual cluster runtime source is unresolved")
	}
	if !runtimeSHA256Pattern.MatchString(strings.TrimSpace(source.ChartSHA256)) ||
		!runtimeSHA256Pattern.MatchString(strings.TrimSpace(source.ValuesSHA256)) ||
		!runtimeSHA256Pattern.MatchString(strings.TrimSpace(source.RenderManifestSHA256)) {
		return errors.New("virtual cluster runtime source digests are incomplete")
	}
	refs, digests, err := normalizeRuntimeImageReferences(source.ImageReferences)
	if err != nil {
		return err
	}
	if strings.Join(refs, "\n") != strings.Join(source.ImageReferences, "\n") ||
		strings.Join(digests, "\n") != strings.Join(source.ImageDigests, "\n") {
		return errors.New("virtual cluster runtime image inventory is not canonical")
	}
	if !runtimeExecutorImagePattern.MatchString(strings.TrimSpace(source.ExecutorImageReference)) {
		return errors.New("virtual cluster executor image is not exact digest-pinned runtime authority")
	}
	if !source.MirrorReady {
		return errors.New("virtual cluster runtime images are not proven mirrored to local zot authority")
	}
	mirrorRefs, mirrorDigests, err := normalizeRuntimeImageReferences(source.MirrorImageReferences)
	if err != nil {
		return fmt.Errorf("runtime mirror inventory: %w", err)
	}
	if strings.Join(mirrorDigests, "\n") != strings.Join(digests, "\n") || len(mirrorRefs) != len(source.MirrorImageReferences) {
		return errors.New("virtual cluster runtime mirror inventory does not match source digests")
	}
	if _, err := safeRuntimeArtifactPath(source.ChartArtifactPath); err != nil {
		return err
	}
	return nil
}


func RuntimeSourceDigest(source RuntimeSource) (string, error) {
	if err := ValidateRuntimeExecutionSource(source); err != nil {
		return "", err
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return "", fmt.Errorf("encode virtual cluster runtime source: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func LoadRuntimeExecutionSource(path string) (RuntimeSource, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return RuntimeSource{}, "", errors.New("virtual cluster runtime source file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return RuntimeSource{}, "", fmt.Errorf("stat virtual cluster runtime source: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return RuntimeSource{}, "", errors.New("virtual cluster runtime source must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > 1<<20 {
		return RuntimeSource{}, "", errors.New("virtual cluster runtime source file must be between 1 byte and 1 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return RuntimeSource{}, "", fmt.Errorf("open virtual cluster runtime source: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return RuntimeSource{}, "", fmt.Errorf("read virtual cluster runtime source: %w", err)
	}
	if len(raw) > 1<<20 {
		return RuntimeSource{}, "", errors.New("virtual cluster runtime source exceeds 1 MiB")
	}
	var source RuntimeSource
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return RuntimeSource{}, "", fmt.Errorf("decode virtual cluster runtime source: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return RuntimeSource{}, "", errors.New("virtual cluster runtime source contains trailing JSON")
	}
	if err := ValidateRuntimeExecutionSource(source); err != nil {
		return RuntimeSource{}, "", err
	}
	digest, err := RuntimeSourceDigest(source)
	if err != nil {
		return RuntimeSource{}, "", err
	}
	return source, digest, nil
}
