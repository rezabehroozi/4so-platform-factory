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
var runtimeDependencyDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var runtimeDependencyCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
var runtimeDependencyDecimal = regexp.MustCompile(`^[0-9]+$`)

type RuntimeDependencyTransitionAsset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type RuntimeDependencyRuntimeEvidence struct {
	Authority                  string `json:"authority"`
	SourceCommitSHA            string `json:"sourceCommitSHA"`
	SourceRunID                string `json:"sourceRunId"`
	ArtifactID                 string `json:"artifactId"`
	ArtifactDigest             string `json:"artifactDigest"`
	RKE2Version                string `json:"rke2Version"`
	Topology                   string `json:"topology"`
	GatewayAPIRelease          string `json:"gatewayApiRelease"`
	CiliumRelease              string `json:"ciliumRelease"`
	KGatewayRelease            string `json:"kgatewayRelease"`
	SingleNodeRKE2Certified    bool   `json:"singleNodeRKE2Certified"`
	ProductTopologyHACertified bool   `json:"productTopologyHACertified"`
	PhysicalCertified          bool   `json:"physicalCertified"`
	HoldAutoReleased           bool   `json:"holdAutoReleased"`
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
		RuntimeEvidence *RuntimeDependencyRuntimeEvidence `json:"runtimeEvidence,omitempty"`
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
	if !ok || t.Spec.Cilium.TargetRelease != ci.Spec.Release || t.Spec.Cilium.RequiredGatewayAPIRelease != t.Spec.GatewayAPI.TargetRelease {
		return fmt.Errorf("runtime dependency cilium target drift")
	}
	expectedCiliumStatus := "dependency-transition-required"
	if t.Spec.Status == "runtime-certification-partial" {
		expectedCiliumStatus = "single-node-rke2-certified-ha-pending"
	}
	if t.Spec.Cilium.RuntimeStatus != expectedCiliumStatus {
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
		if t.Spec.Status != "runtime-certification-pending" && t.Spec.Status != "runtime-certification-partial" && t.Spec.Status != "complete" {
			return fmt.Errorf("runtime dependency transition status is inflated")
		}
		if t.Spec.Status == "runtime-certification-pending" && t.Spec.RuntimeEvidence != nil {
			return fmt.Errorf("runtime dependency pending transition carries runtime evidence")
		}
		if t.Spec.Status == "runtime-certification-partial" {
			ev := t.Spec.RuntimeEvidence
			if ev == nil ||
				ev.Authority != "RKE2_NETWORK_RUNTIME_CERTIFICATION_V1" ||
				ev.RKE2Version != "v1.34.10+rke2r1" ||
				ev.Topology != "single-node" ||
				ev.GatewayAPIRelease != "1.6.1" ||
				ev.CiliumRelease != "1.20.1" ||
				ev.KGatewayRelease != "2.4.1" ||
				!ev.SingleNodeRKE2Certified ||
				ev.ProductTopologyHACertified ||
				ev.PhysicalCertified ||
				ev.HoldAutoReleased ||
				!runtimeDependencyCommit.MatchString(ev.SourceCommitSHA) ||
				!runtimeDependencyDecimal.MatchString(ev.SourceRunID) ||
				!runtimeDependencyDecimal.MatchString(ev.ArtifactID) ||
				!runtimeDependencyDigest.MatchString(ev.ArtifactDigest) {
				return fmt.Errorf("runtime dependency partial certification evidence is invalid")
			}
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
