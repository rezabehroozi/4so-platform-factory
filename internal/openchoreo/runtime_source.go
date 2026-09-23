package openchoreo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	RuntimeSourceAuthority = "OPENCHOREO_RUNTIME_SOURCE_AUTHORITY_V1"
	RuntimeVersion         = "1.3.0"
	UpstreamRepository     = "https://github.com/openchoreo/openchoreo"
	ReviewedUpstreamCommit = "1aeed89856d088dc5160c0f3eaa39796d4a93611"
	ChartRepository        = "oci://ghcr.io/openchoreo/helm-charts"
)

var (
	sha256RE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type PlaneSource struct {
	Name                 string `json:"name"`
	ChartRepository      string `json:"chartRepository"`
	ChartName            string `json:"chartName"`
	ChartVersion         string `json:"chartVersion"`
	ChartSHA256          string `json:"chartSha256"`
	ValuesSHA256         string `json:"valuesSha256"`
	RenderManifestSHA256 string `json:"renderManifestSha256"`
}

type ImageMirror struct {
	SourceReference string `json:"sourceReference"`
	Digest          string `json:"digest"`
	MirrorReference string `json:"mirrorReference"`
}

type RuntimeSource struct {
	Authority                 string        `json:"authority"`
	Version                   string        `json:"version"`
	UpstreamRepository        string        `json:"upstreamRepository"`
	UpstreamCommit            string        `json:"upstreamCommit"`
	SourceArchiveSHA256       string        `json:"sourceArchiveSha256"`
	Planes                    []PlaneSource `json:"planes"`
	Images                    []ImageMirror `json:"images"`
	ExecutorImageReference    string        `json:"executorImageReference"`
	ExecutorImageDigest       string        `json:"executorImageDigest"`
	Resolved                  bool          `json:"resolved"`
	MirrorReady               bool          `json:"mirrorReady"`
	BackstageEnabled          bool          `json:"backstageEnabled"`
	WorkflowPlaneEnabled      bool          `json:"workflowPlaneEnabled"`
	ObservabilityPlaneEnabled bool          `json:"observabilityPlaneEnabled"`
	OpenChoreoMCPEnabled      bool          `json:"openChoreoMcpEnabled"`
	ExternalOIDCRequired      bool          `json:"externalOidcRequired"`
	BuildAuthority            string        `json:"buildAuthority"`
	RegistryAuthority         string        `json:"registryAuthority"`
}

func SelectedRuntimeSource() RuntimeSource {
	return RuntimeSource{
		Authority: RuntimeSourceAuthority, Version: RuntimeVersion,
		UpstreamRepository: UpstreamRepository, UpstreamCommit: ReviewedUpstreamCommit,
		Planes: []PlaneSource{
			{Name: "control-plane", ChartRepository: ChartRepository, ChartName: "openchoreo-control-plane", ChartVersion: RuntimeVersion},
			{Name: "data-plane", ChartRepository: ChartRepository, ChartName: "openchoreo-data-plane", ChartVersion: RuntimeVersion},
		},
		ExternalOIDCRequired: true,
		BuildAuthority: "buildkit",
		RegistryAuthority: "zot",
	}
}

func validDigest(v string) bool { return sha256RE.MatchString(strings.ToLower(strings.TrimSpace(v))) }

func digestFromReference(ref string) string {
	i := strings.LastIndex(strings.TrimSpace(ref), "@sha256:")
	if i < 0 {
		return ""
	}
	return "sha256:" + strings.ToLower(ref[i+8:])
}

func normalizeRuntimeSource(in RuntimeSource) RuntimeSource {
	in.Authority = strings.TrimSpace(in.Authority)
	in.Version = strings.TrimSpace(in.Version)
	in.UpstreamRepository = strings.TrimRight(strings.TrimSpace(in.UpstreamRepository), "/")
	in.UpstreamCommit = strings.ToLower(strings.TrimSpace(in.UpstreamCommit))
	in.SourceArchiveSHA256 = strings.ToLower(strings.TrimSpace(in.SourceArchiveSHA256))
	in.ExecutorImageReference = strings.TrimSpace(in.ExecutorImageReference)
	in.ExecutorImageDigest = strings.ToLower(strings.TrimSpace(in.ExecutorImageDigest))
	in.BuildAuthority = strings.ToLower(strings.TrimSpace(in.BuildAuthority))
	in.RegistryAuthority = strings.ToLower(strings.TrimSpace(in.RegistryAuthority))
	for i := range in.Planes {
		p := &in.Planes[i]
		p.Name = strings.ToLower(strings.TrimSpace(p.Name))
		p.ChartRepository = strings.TrimRight(strings.TrimSpace(p.ChartRepository), "/")
		p.ChartName = strings.TrimSpace(p.ChartName)
		p.ChartVersion = strings.TrimSpace(p.ChartVersion)
		p.ChartSHA256 = strings.ToLower(strings.TrimSpace(p.ChartSHA256))
		p.ValuesSHA256 = strings.ToLower(strings.TrimSpace(p.ValuesSHA256))
		p.RenderManifestSHA256 = strings.ToLower(strings.TrimSpace(p.RenderManifestSHA256))
	}
	for i := range in.Images {
		v := &in.Images[i]
		v.SourceReference = strings.TrimSpace(v.SourceReference)
		v.Digest = strings.ToLower(strings.TrimSpace(v.Digest))
		v.MirrorReference = strings.TrimSpace(v.MirrorReference)
	}
	sort.Slice(in.Planes, func(i, j int) bool { return in.Planes[i].Name < in.Planes[j].Name })
	sort.Slice(in.Images, func(i, j int) bool {
		if in.Images[i].Digest == in.Images[j].Digest {
			return in.Images[i].SourceReference < in.Images[j].SourceReference
		}
		return in.Images[i].Digest < in.Images[j].Digest
	})
	return in
}

func ValidateRuntimeExecutionSource(source RuntimeSource) error {
	s := normalizeRuntimeSource(source)
	if s.Authority != RuntimeSourceAuthority || s.Version != RuntimeVersion || s.UpstreamRepository != UpstreamRepository || s.UpstreamCommit != ReviewedUpstreamCommit || !commitRE.MatchString(s.UpstreamCommit) {
		return fmt.Errorf("OPENCHOREO_EXACT_SOURCE_IDENTITY_INVALID")
	}
	if !s.Resolved || !s.MirrorReady || !validDigest(s.SourceArchiveSHA256) {
		return fmt.Errorf("OPENCHOREO_EXACT_SOURCE_NOT_RESOLVED")
	}
	if s.BackstageEnabled || s.WorkflowPlaneEnabled || s.ObservabilityPlaneEnabled || s.OpenChoreoMCPEnabled {
		return fmt.Errorf("OPENCHOREO_DUPLICATE_PRODUCT_PLANE_FORBIDDEN")
	}
	if !s.ExternalOIDCRequired || s.BuildAuthority != "buildkit" || s.RegistryAuthority != "zot" {
		return fmt.Errorf("OPENCHOREO_FACTORY_AUTHORITY_BOUNDARY_INVALID")
	}
	if len(s.Planes) != 2 {
		return fmt.Errorf("OPENCHOREO_RUNTIME_PLANES_MUST_BE_CONTROL_AND_DATA_ONLY")
	}
	wantPlanes := map[string]string{"control-plane": "openchoreo-control-plane", "data-plane": "openchoreo-data-plane"}
	seenPlanes := map[string]bool{}
	for _, p := range s.Planes {
		wantChart, ok := wantPlanes[p.Name]
		if !ok || seenPlanes[p.Name] || p.ChartRepository != ChartRepository || p.ChartName != wantChart || p.ChartVersion != RuntimeVersion {
			return fmt.Errorf("OPENCHOREO_PLANE_SOURCE_INVALID %s", p.Name)
		}
		if !validDigest(p.ChartSHA256) || !validDigest(p.ValuesSHA256) || !validDigest(p.RenderManifestSHA256) {
			return fmt.Errorf("OPENCHOREO_PLANE_DIGEST_INVALID %s", p.Name)
		}
		seenPlanes[p.Name] = true
	}
	if len(s.Images) == 0 {
		return fmt.Errorf("OPENCHOREO_IMAGE_INVENTORY_EMPTY")
	}
	seenDigests := map[string]bool{}
	for _, image := range s.Images {
		if image.SourceReference == "" || image.MirrorReference == "" || !validDigest(image.Digest) {
			return fmt.Errorf("OPENCHOREO_IMAGE_MIRROR_INVALID")
		}
		if digestFromReference(image.SourceReference) != image.Digest || digestFromReference(image.MirrorReference) != image.Digest {
			return fmt.Errorf("OPENCHOREO_IMAGE_MIRROR_DIGEST_MISMATCH")
		}
		if seenDigests[image.Digest] {
			return fmt.Errorf("OPENCHOREO_IMAGE_DIGEST_DUPLICATE")
		}
		seenDigests[image.Digest] = true
	}
	if !validDigest(s.ExecutorImageDigest) || digestFromReference(s.ExecutorImageReference) != s.ExecutorImageDigest || !strings.Contains(s.ExecutorImageReference, "openchoreo-runtime@sha256:") {
		return fmt.Errorf("OPENCHOREO_EXECUTOR_IMAGE_NOT_DIGEST_PINNED")
	}
	return nil
}

func RuntimeSourceDigest(source RuntimeSource) (string, error) {
	s := normalizeRuntimeSource(source)
	if err := ValidateRuntimeExecutionSource(s); err != nil {
		return "", err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal OpenChoreo runtime source: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func LoadRuntimeExecutionSource(path string) (RuntimeSource, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return RuntimeSource{}, "", fmt.Errorf("OPENCHOREO_RUNTIME_SOURCE_FILE_REQUIRED")
	}
	info, err := os.Stat(path)
	if err != nil {
		return RuntimeSource{}, "", err
	}
	if info.IsDir() || info.Size() <= 0 || info.Size() > 4<<20 {
		return RuntimeSource{}, "", fmt.Errorf("OPENCHOREO_RUNTIME_SOURCE_FILE_INVALID")
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return RuntimeSource{}, "", err
	}
	var source RuntimeSource
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&source); err != nil {
		return RuntimeSource{}, "", fmt.Errorf("decode OpenChoreo runtime source: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return RuntimeSource{}, "", fmt.Errorf("OPENCHOREO_RUNTIME_SOURCE_TRAILING_DATA")
		}
		return RuntimeSource{}, "", fmt.Errorf("decode OpenChoreo runtime source trailing data: %w", err)
	}
	source = normalizeRuntimeSource(source)
	digest, err := RuntimeSourceDigest(source)
	if err != nil {
		return RuntimeSource{}, "", err
	}
	return source, digest, nil
}
