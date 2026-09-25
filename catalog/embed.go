package catalog

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// Machine-readable catalog contracts are embedded into both API and CLI.
//
//go:embed components/*.json tenancy/plans.json upstream-admission.json component-runtime-certification.json runtime-dependency-transition.json runtime/** runtime-dependencies/**
var catalogFiles embed.FS

type VersionRange struct {
	MinVersion string `json:"minVersion"`
	MaxVersion string `json:"maxVersion"`
}

type Compatibility struct {
	Kubernetes           VersionRange `json:"kubernetes"`
	Architectures        []string     `json:"architectures"`
	DistributionProfiles []string     `json:"distributionProfiles"`
	Providers            []string     `json:"providers"`
}

type SourceContract struct {
	Type                  string `json:"type"`
	Resolved              bool   `json:"resolved"`
	BundleKey             string `json:"bundleKey,omitempty"`
	ArtifactDigest        string `json:"artifactDigest"`
	RenderManifestDigest  string `json:"renderManifestDigest,omitempty"`
	SourceLockDigest      string `json:"sourceLockDigest"`
	ImageInventoryDigest  string `json:"imageInventoryDigest"`
	LicenseManifestDigest string `json:"licenseManifestDigest"`
	SignatureVerification string `json:"signatureVerification"`
	SBOM                  string `json:"sbom"`
	Provenance            string `json:"provenance"`
}

type Component struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec ComponentSpec `json:"spec"`
}

type ComponentSpec struct {
	DisplayName           string        `json:"displayName"`
	Category              string        `json:"category"`
	Release               string        `json:"release"`
	VersionPolicy         string        `json:"versionPolicy"`
	SupportTier           string        `json:"supportTier"`
	Mandatory             bool          `json:"mandatory"`
	Dependencies          []string      `json:"dependencies"`
	Provides              []string      `json:"provides"`
	RequiresCapabilities  []string      `json:"requiresCapabilities"`
	ExclusiveCapabilities []string      `json:"exclusiveCapabilities"`
	ConflictsWith         []string      `json:"conflictsWith"`
	Risk                  string        `json:"risk"`
	Capabilities          []string      `json:"capabilities"`
	Namespace             string        `json:"namespace"`
	Wave                  int           `json:"wave"`
	SettingsSchemaRef     string        `json:"settingsSchemaRef"`
	Compatibility         Compatibility `json:"compatibility"`
	Delivery              struct {
		Type          string `json:"type"`
		RepositoryKey string `json:"repositoryKey"`
		Chart         string `json:"chart"`
	} `json:"delivery"`
	Source     SourceContract    `json:"source"`
	Operations map[string]string `json:"operations"`
	Readiness  []string          `json:"readiness"`
	Rollback   struct {
		Strategy string `json:"strategy"`
	} `json:"rollback"`
	EvidenceRequired []string `json:"evidenceRequired"`
	Certification    struct {
		Status         string   `json:"status"`
		Profiles       []string `json:"profiles"`
		EvidenceDigest string   `json:"evidenceDigest"`
	} `json:"certification"`
}

type TenantStoragePolicy struct {
	ClassSelector string `json:"classSelector"`
	RequestQuota  string `json:"requestQuota"`
	MaxPVCSize    string `json:"maxPVCSize"`
}

type TenantBackupPolicy struct {
	Provider  string `json:"provider"`
	Schedule  string `json:"schedule"`
	Retention string `json:"retention"`
}

type TenantSecurityPolicy struct {
	PodSecurityLevel   string `json:"podSecurityLevel"`
	DefaultDenyIngress bool   `json:"defaultDenyIngress"`
	DefaultDenyEgress  bool   `json:"defaultDenyEgress"`
	AllowDNS           bool   `json:"allowDNS"`
}

type TenantPlan struct {
	Name     string               `json:"name"`
	Quota    map[string]string    `json:"quota"`
	Storage  TenantStoragePolicy  `json:"storage"`
	Backup   TenantBackupPolicy   `json:"backup"`
	Security TenantSecurityPolicy `json:"security"`
}

type tenantPlanDocument struct {
	Spec struct {
		Plans []TenantPlan `json:"plans"`
	} `json:"spec"`
}

func Load() (map[string]Component, error) {
	names, err := fs.Glob(catalogFiles, "components/*.json")
	if err != nil {
		return nil, err
	}
	result := make(map[string]Component, len(names))
	for _, name := range names {
		raw, err := catalogFiles.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var c Component
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		if c.Metadata.Name == "" {
			return nil, fmt.Errorf("component %s has empty name", name)
		}
		if _, exists := result[c.Metadata.Name]; exists {
			return nil, fmt.Errorf("duplicate component %s", c.Metadata.Name)
		}
		if err := verifyResolvedComponent(c); err != nil {
			return nil, fmt.Errorf("component %s source verification: %w", c.Metadata.Name, err)
		}
		result[c.Metadata.Name] = c
	}
	return result, nil
}

func LoadTenantPlans() (map[string]TenantPlan, error) {
	raw, err := catalogFiles.ReadFile("tenancy/plans.json")
	if err != nil {
		return nil, err
	}
	var doc tenantPlanDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse tenancy plans: %w", err)
	}
	out := make(map[string]TenantPlan, len(doc.Spec.Plans))
	for _, p := range doc.Spec.Plans {
		if p.Name == "" {
			return nil, fmt.Errorf("tenant plan has empty name")
		}
		if _, ok := out[p.Name]; ok {
			return nil, fmt.Errorf("duplicate tenant plan %s", p.Name)
		}
		out[p.Name] = p
	}
	return out, nil
}

func Sorted(m map[string]Component) []Component {
	out := make([]Component, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Spec.Wave == out[j].Spec.Wave {
			return out[i].Metadata.Name < out[j].Metadata.Name
		}
		return out[i].Spec.Wave < out[j].Spec.Wave
	})
	return out
}

func Digest(m map[string]Component) string {
	raw, _ := json.Marshal(Sorted(m))
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SourceLockDigest binds certification to the ordered immutable source locks of
// the whole catalog without including mutable certification metadata.
func SourceLockDigest(m map[string]Component) string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	locks := make([]string, 0, len(names))
	for _, name := range names {
		locks = append(locks, name+"="+strings.TrimSpace(m[name].Spec.Source.SourceLockDigest))
	}
	raw, _ := json.Marshal(locks)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalReleasePayload validates a release component set, sorts it by the
// same catalog ordering contract used by Digest, and returns immutable JSON.
func CanonicalReleasePayload(components []Component) ([]byte, map[string]Component, error) {
	items := make(map[string]Component, len(components))
	for _, component := range components {
		name := strings.TrimSpace(component.Metadata.Name)
		if name == "" || strings.TrimSpace(component.APIVersion) == "" || strings.TrimSpace(component.Kind) == "" {
			return nil, nil, fmt.Errorf("component apiVersion, kind and metadata.name are required")
		}
		if _, exists := items[name]; exists {
			return nil, nil, fmt.Errorf("duplicate component %s", name)
		}
		component.Metadata.Name = name
		items[name] = component
	}
	if len(items) == 0 {
		return nil, nil, fmt.Errorf("catalog release requires at least one component")
	}
	raw, err := json.Marshal(Sorted(items))
	if err != nil {
		return nil, nil, err
	}
	return raw, items, nil
}

func ParseReleasePayload(raw []byte) (map[string]Component, error) {
	var components []Component
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&components); err != nil {
		return nil, fmt.Errorf("decode catalog release payload: %w", err)
	}
	canonical, items, err := CanonicalReleasePayload(components)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, canonical) {
		return nil, fmt.Errorf("catalog release payload is not canonical")
	}
	return items, nil
}

func exactDigest(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func exactReleaseLabel(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value != "" && !strings.Contains(value, "x") && !strings.ContainsAny(value, "*<>^~ ")
}

// AdmissionBlockers returns the reasons a signed catalog cannot be promoted to
// the requested channel. Candidate permits unresolved research contracts;
// higher channels require immutable resolved supply-chain material.
func AdmissionBlockers(channel string, components map[string]Component) []string {
	blockers := []string{}
	if len(components) == 0 {
		return []string{"catalog contains no components"}
	}
	channel = strings.ToUpper(strings.TrimSpace(channel))
	if channel == "CANDIDATE" {
		return blockers
	}
	for _, component := range Sorted(components) {
		name := component.Metadata.Name
		source := component.Spec.Source
		if source.Resolved {
			if err := verifyResolvedComponent(component); err != nil {
				blockers = append(blockers, name+": resolved source bundle verification failed: "+err.Error())
			}
		}
		if !source.Resolved {
			blockers = append(blockers, name+": source is unresolved")
		}
		if !exactReleaseLabel(component.Spec.Release) {
			blockers = append(blockers, name+": release is not exact/pinned")
		}
		digestFields := map[string]string{
			"artifactDigest":        source.ArtifactDigest,
			"sourceLockDigest":      source.SourceLockDigest,
			"imageInventoryDigest":  source.ImageInventoryDigest,
			"licenseManifestDigest": source.LicenseManifestDigest,
			"sbom":                  source.SBOM,
			"provenance":            source.Provenance,
		}
		if source.Type != "embedded-native" {
			digestFields["renderManifestDigest"] = source.RenderManifestDigest
		}
		for label, value := range digestFields {
			if !exactDigest(value) {
				blockers = append(blockers, name+": "+label+" must be an exact sha256 digest")
			}
		}
		if source.Type == "embedded-native" {
			if !strings.EqualFold(strings.TrimSpace(source.SignatureVerification), "sha256-pinned-offline") {
				blockers = append(blockers, name+": embedded source is not sha256-pinned offline")
			}
			if err := verifyResolvedComponent(component); err != nil {
				blockers = append(blockers, name+": embedded source verification failed: "+err.Error())
			}
		} else if !strings.EqualFold(strings.TrimSpace(source.SignatureVerification), "sha256-pinned-offline") {
			blockers = append(blockers, name+": external source bundle is not sha256-pinned offline")
		}
		if channel == "RUNTIME" || channel == "PRODUCTION" {
			status := strings.ToLower(strings.TrimSpace(component.Spec.Certification.Status))
			if status != "target-runtime-certified" && status != "upgrade-certified" {
				blockers = append(blockers, name+": target runtime certification evidence is missing")
			}
			if !exactDigest(component.Spec.Certification.EvidenceDigest) {
				blockers = append(blockers, name+": certification evidenceDigest must be sha256")
			}
		}
		if channel == "PRODUCTION" && !strings.EqualFold(strings.TrimSpace(component.Spec.Certification.Status), "upgrade-certified") {
			blockers = append(blockers, name+": production channel requires upgrade-certified status")
		}
	}
	sort.Strings(blockers)
	return blockers
}
