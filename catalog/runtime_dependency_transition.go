package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const RuntimeDependencyTransitionAuthority = "RUNTIME_DEPENDENCY_TRANSITION_V1"

var runtimeDependencySHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

type RuntimeDependencyTransitionAsset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type RuntimeDependencyTransition struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Authority string `json:"authority"`
		Status    string `json:"status"`
		Policy    struct {
			SourceAcquisitionIndependentOfRuntimeSuitability bool `json:"sourceAcquisitionIndependentOfRuntimeSuitability"`
			MutationBeforeSourceResolution                   bool `json:"mutationBeforeSourceResolution"`
			RuntimeCertificationRequired                     bool `json:"runtimeCertificationRequired"`
			PhysicalPassInference                            bool `json:"physicalPassInference"`
		} `json:"policy"`
		GatewayAPI struct {
			CurrentRelease        string                             `json:"currentRelease"`
			CurrentSourceResolved bool                               `json:"currentSourceResolved"`
			TargetRelease         string                             `json:"targetRelease"`
			ReleaseURL            string                             `json:"releaseUrl"`
			ReleaseCommitShort    string                             `json:"releaseCommitShort"`
			Assets                []RuntimeDependencyTransitionAsset `json:"assets"`
			SourceStatus          string                             `json:"sourceStatus"`
		} `json:"gatewayApi"`
		KGateway struct {
			TargetRelease           string `json:"targetRelease"`
			Source                  string `json:"source"`
			GatewayAPICompatibility string `json:"gatewayApiCompatibility"`
			SourceStatus            string `json:"sourceStatus"`
		} `json:"kgateway"`
		Cilium struct {
			TargetRelease             string `json:"targetRelease"`
			Source                    string `json:"source"`
			RequiredGatewayAPIRelease string `json:"requiredGatewayApiRelease"`
			SourceStatus              string `json:"sourceStatus"`
			RuntimeStatus             string `json:"runtimeStatus"`
		} `json:"cilium"`
		Ordering []string `json:"ordering"`
		Evidence []struct {
			Kind    string `json:"kind"`
			URL     string `json:"url"`
			Summary string `json:"summary"`
		} `json:"evidence"`
	} `json:"spec"`
}

func LoadRuntimeDependencyTransition() (RuntimeDependencyTransition, error) {
	raw, err := catalogFiles.ReadFile("runtime-dependency-transition.json")
	if err != nil {
		return RuntimeDependencyTransition{}, err
	}
	var out RuntimeDependencyTransition
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return RuntimeDependencyTransition{}, fmt.Errorf("parse runtime dependency transition: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return RuntimeDependencyTransition{}, fmt.Errorf("parse runtime dependency transition: trailing JSON")
	}
	return out, nil
}

func ValidateRuntimeDependencyTransition(t RuntimeDependencyTransition, components map[string]Component, admission UpstreamAdmission) error {
	if t.APIVersion != "platform.4so.io/v1alpha1" || t.Kind != "RuntimeDependencyTransition" || strings.TrimSpace(t.Metadata.Name) == "" || t.Spec.Authority != RuntimeDependencyTransitionAuthority {
		return fmt.Errorf("runtime dependency transition identity is invalid")
	}
	p := t.Spec.Policy
	if !p.SourceAcquisitionIndependentOfRuntimeSuitability || p.MutationBeforeSourceResolution || !p.RuntimeCertificationRequired || p.PhysicalPassInference {
		return fmt.Errorf("runtime dependency transition truth policy is invalid")
	}
	gateway, ok := components["gateway-api"]
	if !ok || t.Spec.GatewayAPI.CurrentRelease != gateway.Spec.Release || t.Spec.GatewayAPI.CurrentSourceResolved != gateway.Spec.Source.Resolved || t.Spec.GatewayAPI.TargetRelease != "1.6.1" {
		return fmt.Errorf("runtime dependency gateway-api transition drift")
	}
	expectedAssets := map[string]struct {
		size int64
		sha  string
	}{
		"standard-install.yaml":     {1170953, "24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73"},
		"experimental-install.yaml": {1402117, "d7fa77650e4ef28fca0411536fcb5e237deb4d50301cfded3be49d9a1b7bbd02"},
	}
	if len(t.Spec.GatewayAPI.Assets) != len(expectedAssets) {
		return fmt.Errorf("runtime dependency gateway-api asset coverage is invalid")
	}
	seen := map[string]bool{}
	for _, asset := range t.Spec.GatewayAPI.Assets {
		expected, ok := expectedAssets[asset.Name]
		if !ok || seen[asset.Name] || asset.Size != expected.size || asset.SHA256 != expected.sha || !runtimeDependencySHA.MatchString(asset.SHA256) || !strings.HasPrefix(asset.URL, "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/") {
			return fmt.Errorf("runtime dependency gateway-api asset %q is invalid", asset.Name)
		}
		seen[asset.Name] = true
	}
	rows := make(map[string]UpstreamAdmissionComponent, len(admission.Spec.Components))
	for _, row := range admission.Spec.Components {
		rows[row.Component] = row
	}
	kg, ok := components["kgateway"]
	if !ok || t.Spec.KGateway.TargetRelease != kg.Spec.Release || t.Spec.KGateway.GatewayAPICompatibility != "1.4-1.6" {
		return fmt.Errorf("runtime dependency kgateway target drift")
	}
	kgRow, kgAdmitted := rows["kgateway"]
	if kg.Spec.Source.Resolved {
		if kgAdmitted || t.Spec.KGateway.SourceStatus != "source-acquired" {
			return fmt.Errorf("runtime dependency kgateway resolved-source drift")
		}
	} else if !kgAdmitted || kgRow.SelectedVersion == nil || *kgRow.SelectedVersion != t.Spec.KGateway.TargetRelease || kgRow.Status != "ready-for-acquisition" || kgRow.RuntimeStatus != "eligible-after-source-resolution" || t.Spec.KGateway.SourceStatus != "pending-byte-acquisition" {
		return fmt.Errorf("runtime dependency kgateway admission drift")
	}
	ci, ok := components["cilium"]
	if !ok || t.Spec.Cilium.TargetRelease != ci.Spec.Release || t.Spec.Cilium.RequiredGatewayAPIRelease != t.Spec.GatewayAPI.TargetRelease || t.Spec.Cilium.RuntimeStatus != "dependency-transition-required" {
		return fmt.Errorf("runtime dependency cilium target drift")
	}
	ciRow, ciAdmitted := rows["cilium"]
	if ci.Spec.Source.Resolved {
		if ciAdmitted || t.Spec.Cilium.SourceStatus != "source-acquired" {
			return fmt.Errorf("runtime dependency cilium resolved-source drift")
		}
	} else if !ciAdmitted || ciRow.SelectedVersion == nil || *ciRow.SelectedVersion != t.Spec.Cilium.TargetRelease || ciRow.Status != "ready-for-acquisition" || ciRow.RuntimeStatus != "dependency-transition-required" || t.Spec.Cilium.SourceStatus != "pending-byte-acquisition" {
		return fmt.Errorf("runtime dependency cilium admission drift")
	}
	switch t.Spec.GatewayAPI.SourceStatus {
	case "pending-byte-acquisition":
		if t.Spec.Status != "acquisition-pending" {
			return fmt.Errorf("runtime dependency transition status is inflated")
		}
	case "source-acquired":
		if t.Spec.Status != "runtime-certification-pending" && t.Spec.Status != "complete" {
			return fmt.Errorf("runtime dependency transition status is inflated")
		}
		for _, asset := range t.Spec.GatewayAPI.Assets {
			embeddedPath := fmt.Sprintf("runtime-dependencies/gateway-api/%s/%s", t.Spec.GatewayAPI.TargetRelease, asset.Name)
			raw, err := catalogFiles.ReadFile(embeddedPath)
			if err != nil {
				return fmt.Errorf("runtime dependency gateway-api embedded asset missing %s: %w", asset.Name, err)
			}
			sum := sha256.Sum256(raw)
			if int64(len(raw)) != asset.Size || fmt.Sprintf("%x", sum[:]) != asset.SHA256 {
				return fmt.Errorf("runtime dependency gateway-api embedded asset mismatch %s", asset.Name)
			}
		}
	default:
		return fmt.Errorf("runtime dependency gateway-api source status is invalid")
	}
	if len(t.Spec.Ordering) != 6 || len(t.Spec.Evidence) < 3 {
		return fmt.Errorf("runtime dependency transition execution/evidence contract is incomplete")
	}
	return nil
}
