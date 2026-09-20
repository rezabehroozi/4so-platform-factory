package virtualcluster

import (
	"errors"
	"fmt"
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
)

type RuntimeSource struct {
	Authority            string   `json:"authority"`
	Engine               string   `json:"engine"`
	Version              string   `json:"version"`
	ChartRepository      string   `json:"chartRepository"`
	ChartName            string   `json:"chartName"`
	ChartSHA256          string   `json:"chartSha256,omitempty"`
	ImageDigests         []string `json:"imageDigests,omitempty"`
	Resolved             bool     `json:"resolved"`
	OfflineAcquisitionRequired bool `json:"offlineAcquisitionRequired"`
	PlatformDependency   bool     `json:"platformDependency"`
}

type RuntimeSourceResolution struct {
	Version         string
	ChartRepository string
	ChartName       string
	ChartSHA256     string
	ImageDigests   []string
}

var runtimeSHA256Pattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")

func SelectedRuntimeSource() RuntimeSource {
	return RuntimeSource{
		Authority: RuntimeSourceAuthority,
		Engine: RuntimeEngineVClusterOSS,
		Version: RuntimeSelectedVersion,
		ChartRepository: RuntimeChartRepository,
		ChartName: RuntimeChartName,
		Resolved: false,
		OfflineAcquisitionRequired: true,
		PlatformDependency: false,
	}
}

func normalizeRuntimeImageDigests(values []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if !runtimeSHA256Pattern.MatchString(value) {
			return nil, fmt.Errorf("runtime image digest must be an exact lowercase sha256 digest: %q", raw)
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one exact runtime image digest is required")
	}
	sort.Strings(out)
	return out, nil
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
	images, err := normalizeRuntimeImageDigests(input.ImageDigests)
	if err != nil {
		return RuntimeSource{}, err
	}
	selected.ChartSHA256 = input.ChartSHA256
	selected.ImageDigests = images
	selected.Resolved = true
	return selected, nil
}

func ValidateRuntimeExecutionSource(source RuntimeSource) error {
	if source.Authority != RuntimeSourceAuthority || source.Engine != RuntimeEngineVClusterOSS {
		return errors.New("virtual cluster runtime source authority is invalid")
	}
	if source.PlatformDependency {
		return errors.New("vCluster Platform is not an admitted runtime dependency")
	}
	if source.Version != RuntimeSelectedVersion || source.ChartRepository != RuntimeChartRepository || source.ChartName != RuntimeChartName {
		return errors.New("virtual cluster runtime source selection drift")
	}
	if !source.Resolved {
		return errors.New("virtual cluster runtime source is unresolved")
	}
	if !runtimeSHA256Pattern.MatchString(strings.TrimSpace(source.ChartSHA256)) {
		return errors.New("virtual cluster runtime chart digest is not exact")
	}
	images, err := normalizeRuntimeImageDigests(source.ImageDigests)
	if err != nil {
		return err
	}
	if len(images) != len(source.ImageDigests) {
		return errors.New("virtual cluster runtime image digest inventory contains duplicates")
	}
	return nil
}
