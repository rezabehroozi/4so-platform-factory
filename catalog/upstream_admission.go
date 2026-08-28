package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// UpstreamAdmission is the product-owned review authority for unresolved
// external catalog sources. It is deliberately separate from immutable source
// acquisition and runtime certification evidence.
type UpstreamAdmission struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Components []UpstreamAdmissionComponent `json:"components"`
		Policy     map[string]any               `json:"policy"`
	} `json:"spec"`
}

type UpstreamAdmissionComponent struct {
	CatalogConstraint string  `json:"catalogConstraint"`
	Chart             string  `json:"chart"`
	Component         string  `json:"component"`
	Rationale         string  `json:"rationale"`
	SelectedVersion   *string `json:"selectedVersion"`
	Source            string  `json:"source"`
	Status            string  `json:"status"`
	UpstreamVersion   *string `json:"upstreamVersion"`
}

var upstreamAdmissionExactVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var upstreamAdmissionConstraint = regexp.MustCompile(`^[0-9]+\.[0-9]+\.(?:[0-9]+|x)$`)

var upstreamAdmissionStatuses = map[string]struct{}{
	"ready-for-acquisition":        {},
	"architecture-review-required": {},
	"dependency-review-required":   {},
	"version-selection-required":   {},
	"version-review-required":      {},
}

func LoadUpstreamAdmission() (UpstreamAdmission, error) {
	raw, err := catalogFiles.ReadFile("upstream-admission.json")
	if err != nil {
		return UpstreamAdmission{}, err
	}
	var admission UpstreamAdmission
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&admission); err != nil {
		return UpstreamAdmission{}, fmt.Errorf("parse upstream admission: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return UpstreamAdmission{}, fmt.Errorf("parse upstream admission: trailing JSON value")
		}
		return UpstreamAdmission{}, fmt.Errorf("parse upstream admission: trailing JSON: %w", err)
	}
	if strings.TrimSpace(admission.APIVersion) == "" || strings.TrimSpace(admission.Kind) == "" || strings.TrimSpace(admission.Metadata.Name) == "" {
		return UpstreamAdmission{}, fmt.Errorf("upstream admission identity is incomplete")
	}
	seen := make(map[string]struct{}, len(admission.Spec.Components))
	for _, component := range admission.Spec.Components {
		name := strings.TrimSpace(component.Component)
		if name == "" {
			return UpstreamAdmission{}, fmt.Errorf("upstream admission contains an empty component name")
		}
		if _, exists := seen[name]; exists {
			return UpstreamAdmission{}, fmt.Errorf("upstream admission contains duplicate component %q", name)
		}
		seen[name] = struct{}{}
	}
	return admission, nil
}

// ValidateUpstreamAdmission enforces the same product-owned authority contract
// used by the release acquisition tooling. A ReleaseReadiness consumer must not
// classify an admission row as complete merely because its component name and
// status string exist; the row must still match the live embedded Catalog.
func ValidateUpstreamAdmission(admission UpstreamAdmission, components map[string]Component) error {
	if admission.APIVersion != "platform.4so.io/v1alpha1" || admission.Kind != "CatalogUpstreamAdmission" || strings.TrimSpace(admission.Metadata.Name) == "" {
		return fmt.Errorf("upstream admission type/identity is invalid")
	}
	expectedPolicy := map[string]any{
		"sourceAuthority":            "official-upstream-only",
		"versionSelection":           "exact-semver-no-prerelease",
		"sourceResolution":           "separate-immutable-acquisition-required",
		"runtimeCertification":       "separate-runtime-evidence-required",
		"autoWidenCatalogConstraint": false,
		"allowLatestResolution":      false,
	}
	for key, expected := range expectedPolicy {
		actual, ok := admission.Spec.Policy[key]
		if !ok || actual != expected {
			return fmt.Errorf("upstream admission policy %q is invalid", key)
		}
	}

	unresolved := make(map[string]Component)
	for name, component := range components {
		if component.Spec.Source.Type == "helm-chart" && !component.Spec.Source.Resolved {
			unresolved[name] = component
		}
	}
	rows := make(map[string]UpstreamAdmissionComponent, len(admission.Spec.Components))
	for _, row := range admission.Spec.Components {
		name := strings.TrimSpace(row.Component)
		if name == "" {
			return fmt.Errorf("upstream admission contains an empty component name")
		}
		if _, exists := rows[name]; exists {
			return fmt.Errorf("upstream admission contains duplicate component %q", name)
		}
		rows[name] = row
	}
	if len(rows) != len(unresolved) {
		return fmt.Errorf("upstream admission coverage mismatch: rows=%d unresolvedHelm=%d", len(rows), len(unresolved))
	}

	for name, component := range unresolved {
		row, ok := rows[name]
		if !ok {
			return fmt.Errorf("unresolved Helm component %q has no upstream admission row", name)
		}
		if _, ok := upstreamAdmissionStatuses[row.Status]; !ok {
			return fmt.Errorf("upstream admission component %q has invalid status %q", name, row.Status)
		}
		constraint := normalizeUpstreamAdmissionVersion(row.CatalogConstraint)
		if !upstreamAdmissionConstraint.MatchString(constraint) {
			return fmt.Errorf("upstream admission component %q has invalid catalog constraint %q", name, row.CatalogConstraint)
		}
		if strings.TrimSpace(row.Chart) != component.Spec.Delivery.Chart {
			return fmt.Errorf("upstream admission component %q chart mismatch: %q != %q", name, row.Chart, component.Spec.Delivery.Chart)
		}
		source := strings.TrimSpace(row.Source)
		if !strings.HasPrefix(source, "https://") && !strings.HasPrefix(source, "oci://") {
			return fmt.Errorf("upstream admission component %q has invalid source %q", name, row.Source)
		}
		if strings.TrimSpace(row.Rationale) == "" {
			return fmt.Errorf("upstream admission component %q is missing rationale", name)
		}

		selected := ""
		if row.SelectedVersion != nil {
			selected = normalizeUpstreamAdmissionVersion(*row.SelectedVersion)
			if !upstreamAdmissionExactVersion.MatchString(selected) || !upstreamAdmissionConstraintMatches(constraint, selected) {
				return fmt.Errorf("upstream admission component %q selected version %q is outside %q", name, selected, constraint)
			}
			if row.UpstreamVersion == nil || normalizeUpstreamAdmissionVersion(*row.UpstreamVersion) != selected {
				return fmt.Errorf("upstream admission component %q upstream version does not match selected version %q", name, selected)
			}
		}

		if row.Status == "ready-for-acquisition" {
			if selected == "" {
				return fmt.Errorf("upstream admission component %q is ready without an exact selected version", name)
			}
			if component.Spec.Release != selected {
				return fmt.Errorf("upstream admission component %q catalog pin mismatch: %q != %q", name, component.Spec.Release, selected)
			}
			if component.Spec.VersionPolicy != "exact-upstream-admitted-pending-source-acquisition" {
				return fmt.Errorf("upstream admission component %q has invalid ready version policy %q", name, component.Spec.VersionPolicy)
			}
		} else if component.Spec.Release != constraint {
			return fmt.Errorf("upstream admission component %q review constraint drift: catalog=%q authority=%q", name, component.Spec.Release, constraint)
		}
	}
	for name := range rows {
		if _, ok := unresolved[name]; !ok {
			return fmt.Errorf("upstream admission contains non-unresolved component %q", name)
		}
	}
	return nil
}

func normalizeUpstreamAdmissionVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "v")
}

func upstreamAdmissionConstraintMatches(constraint, version string) bool {
	c := normalizeUpstreamAdmissionVersion(strings.ToLower(constraint))
	v := normalizeUpstreamAdmissionVersion(version)
	if !upstreamAdmissionExactVersion.MatchString(v) {
		return false
	}
	if upstreamAdmissionExactVersion.MatchString(c) {
		return c == v
	}
	cp := strings.Split(c, ".")
	vp := strings.Split(v, ".")
	return len(cp) == 3 && len(vp) == 3 && cp[2] == "x" && cp[0] == vp[0] && cp[1] == vp[1]
}
