package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	PlatformPolicySetAuthority = "PLATFORM_POLICY_SET_AUTHORITY_V1"
	PlatformTemplateAuthority  = "PLATFORM_TEMPLATE_AUTHORITY_V1"

	TemplateImpactTargetPreviewRequired = "TARGET_PREVIEW_REQUIRED"

	CertificationSourceSemantics  = "source-semantics"
	CertificationGeneratedRuntime = "generated-runtime"
	CertificationRuntimeRealism   = "runtime-realism"
	CertificationExactSHAPhysical = "exact-sha-physical"
)

type PlatformMaintenancePolicy struct {
	RiskClass                 string `json:"riskClass"`
	RequireApproval           bool   `json:"requireApproval"`
	MaxUnavailable            int    `json:"maxUnavailable"`
	RequireRecoveryCheckpoint bool   `json:"requireRecoveryCheckpoint"`
}

type PlatformBackupPolicy struct {
	Required  bool   `json:"required"`
	Provider  string `json:"provider,omitempty"`
	Schedule  string `json:"schedule,omitempty"`
	Retention string `json:"retention,omitempty"`
}

type PlatformSecurityPolicy struct {
	PodSecurityLevel   string `json:"podSecurityLevel"`
	DefaultDenyIngress bool   `json:"defaultDenyIngress"`
	DefaultDenyEgress  bool   `json:"defaultDenyEgress"`
	AllowDNS           bool   `json:"allowDNS"`
}

// PlatformPolicySet is immutable and reusable. It intentionally owns only the
// cross-workflow policy choices needed by a PlatformTemplate; execution
// engines remain authoritative for their own mutable runs/campaigns.
type PlatformPolicySet struct {
	ResourceMeta
	ProjectID   string                    `json:"projectId"`
	Name        string                    `json:"name"`
	Version     string                    `json:"version"`
	Digest      string                    `json:"digest"`
	Maintenance PlatformMaintenancePolicy `json:"maintenance"`
	Backup      PlatformBackupPolicy      `json:"backup"`
	Security    PlatformSecurityPolicy    `json:"security"`
	CreatedBy   string                    `json:"createdBy"`
}

type PlatformTemplateImpact struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// PlatformTemplate binds only immutable/versioned authorities. It never stores
// resolved secret values and never becomes desired-state authority itself.
type PlatformTemplate struct {
	ResourceMeta
	ProjectID                 string                 `json:"projectId"`
	Name                      string                 `json:"name"`
	Version                   string                 `json:"version"`
	Digest                    string                 `json:"digest"`
	BlueprintReleaseID        string                 `json:"blueprintReleaseId"`
	BlueprintDigest           string                 `json:"blueprintDigest"`
	VariableSchemaID          string                 `json:"variableSchemaId"`
	VariableSchemaDigest      string                 `json:"variableSchemaDigest"`
	PolicySetID               string                 `json:"policySetId"`
	PolicySetDigest           string                 `json:"policySetDigest"`
	AllowedTargetClasses      []string               `json:"allowedTargetClasses"`
	CertificationRequirements []string               `json:"certificationRequirements"`
	Impact                    PlatformTemplateImpact `json:"impact"`
	CreatedBy                 string                 `json:"createdBy"`
}

type PlatformTemplateAdmission struct {
	Authority                 string   `json:"authority"`
	TemplateID                string   `json:"templateId"`
	TemplateDigest            string   `json:"templateDigest"`
	TargetClass               string   `json:"targetClass"`
	BindingValid              bool     `json:"bindingValid"`
	TargetAllowed             bool     `json:"targetAllowed"`
	AdoptionReady             bool     `json:"adoptionReady"`
	ImpactStatus              string   `json:"impactStatus"`
	CertificationRequirements []string `json:"certificationRequirements"`
	Blockers                  []string `json:"blockers,omitempty"`
}

var platformTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)*$`)

func clonePlatformPolicySet(in PlatformPolicySet) PlatformPolicySet { return in }

func clonePlatformTemplate(in PlatformTemplate) PlatformTemplate {
	out := in
	out.AllowedTargetClasses = append([]string(nil), in.AllowedTargetClasses...)
	out.CertificationRequirements = append([]string(nil), in.CertificationRequirements...)
	out.Impact.Reasons = append([]string(nil), in.Impact.Reasons...)
	return out
}

func normalizeCanonicalTokens(values []string, min, max int, field string) ([]string, error) {
	if len(values) < min || len(values) > max {
		return nil, fmt.Errorf("%w: %s requires %d..%d values", ErrValidation, field, min, max)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if len(value) > 96 || !platformTokenPattern.MatchString(value) || seen[value] {
			return nil, fmt.Errorf("%w: %s contains invalid or duplicate value %q", ErrValidation, field, raw)
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func NormalizePlatformPolicySet(in PlatformPolicySet) (PlatformPolicySet, error) {
	out := clonePlatformPolicySet(in)
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.Version = strings.TrimSpace(out.Version)
	out.CreatedBy = strings.TrimSpace(out.CreatedBy)
	if out.ProjectID == "" || out.Name == "" || out.Version == "" {
		return PlatformPolicySet{}, fmt.Errorf("%w: projectId, name and version are required", ErrValidation)
	}
	if !variableNamePattern.MatchString(out.Name) || !schemaVersionPattern.MatchString(out.Version) {
		return PlatformPolicySet{}, fmt.Errorf("%w: policy-set name/version are not canonical", ErrValidation)
	}
	out.Maintenance.RiskClass = strings.ToUpper(strings.TrimSpace(out.Maintenance.RiskClass))
	switch out.Maintenance.RiskClass {
	case "DEVELOPMENT", "STAGING", "PRODUCTION":
	default:
		return PlatformPolicySet{}, fmt.Errorf("%w: maintenance riskClass must be DEVELOPMENT, STAGING or PRODUCTION", ErrValidation)
	}
	if out.Maintenance.MaxUnavailable < 1 || out.Maintenance.MaxUnavailable > 100 {
		return PlatformPolicySet{}, fmt.Errorf("%w: maintenance maxUnavailable must be 1..100", ErrValidation)
	}
	out.Backup.Provider = strings.ToLower(strings.TrimSpace(out.Backup.Provider))
	out.Backup.Schedule = strings.TrimSpace(out.Backup.Schedule)
	out.Backup.Retention = strings.TrimSpace(out.Backup.Retention)
	if out.Backup.Required && (out.Backup.Provider == "" || out.Backup.Schedule == "" || out.Backup.Retention == "") {
		return PlatformPolicySet{}, fmt.Errorf("%w: required backup policy needs provider, schedule and retention", ErrValidation)
	}
	if len(out.Backup.Provider) > 64 || len(out.Backup.Schedule) > 128 || len(out.Backup.Retention) > 64 {
		return PlatformPolicySet{}, fmt.Errorf("%w: backup policy field exceeds limit", ErrValidation)
	}
	out.Security.PodSecurityLevel = strings.ToLower(strings.TrimSpace(out.Security.PodSecurityLevel))
	switch out.Security.PodSecurityLevel {
	case "restricted", "baseline", "privileged":
	default:
		return PlatformPolicySet{}, fmt.Errorf("%w: podSecurityLevel must be restricted, baseline or privileged", ErrValidation)
	}
	material := struct {
		Name        string                    `json:"name"`
		Version     string                    `json:"version"`
		Maintenance PlatformMaintenancePolicy `json:"maintenance"`
		Backup      PlatformBackupPolicy      `json:"backup"`
		Security    PlatformSecurityPolicy    `json:"security"`
	}{out.Name, out.Version, out.Maintenance, out.Backup, out.Security}
	raw, _ := json.Marshal(material)
	sum := sha256.Sum256(raw)
	out.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return out, nil
}

func NormalizePlatformTemplate(in PlatformTemplate) (PlatformTemplate, error) {
	out := clonePlatformTemplate(in)
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.Version = strings.TrimSpace(out.Version)
	out.BlueprintReleaseID = strings.TrimSpace(out.BlueprintReleaseID)
	out.BlueprintDigest = strings.TrimSpace(out.BlueprintDigest)
	out.VariableSchemaID = strings.TrimSpace(out.VariableSchemaID)
	out.VariableSchemaDigest = strings.TrimSpace(out.VariableSchemaDigest)
	out.PolicySetID = strings.TrimSpace(out.PolicySetID)
	out.PolicySetDigest = strings.TrimSpace(out.PolicySetDigest)
	out.CreatedBy = strings.TrimSpace(out.CreatedBy)
	if out.ProjectID == "" || out.Name == "" || out.Version == "" || out.BlueprintReleaseID == "" || out.VariableSchemaID == "" || out.PolicySetID == "" {
		return PlatformTemplate{}, fmt.Errorf("%w: projectId, name, version and all authority references are required", ErrValidation)
	}
	if !variableNamePattern.MatchString(out.Name) || !schemaVersionPattern.MatchString(out.Version) {
		return PlatformTemplate{}, fmt.Errorf("%w: template name/version are not canonical", ErrValidation)
	}
	var err error
	out.AllowedTargetClasses, err = normalizeCanonicalTokens(out.AllowedTargetClasses, 1, 16, "allowedTargetClasses")
	if err != nil {
		return PlatformTemplate{}, err
	}
	out.CertificationRequirements, err = normalizeCanonicalTokens(out.CertificationRequirements, 1, 16, "certificationRequirements")
	if err != nil {
		return PlatformTemplate{}, err
	}
	allowedCert := map[string]bool{
		CertificationSourceSemantics:  true,
		CertificationGeneratedRuntime: true,
		CertificationRuntimeRealism:   true,
		CertificationExactSHAPhysical: true,
	}
	for _, requirement := range out.CertificationRequirements {
		if !allowedCert[requirement] {
			return PlatformTemplate{}, fmt.Errorf("%w: unsupported certification requirement %q", ErrValidation, requirement)
		}
	}
	for field, digest := range map[string]string{"blueprintDigest": out.BlueprintDigest, "variableSchemaDigest": out.VariableSchemaDigest, "policySetDigest": out.PolicySetDigest} {
		if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(digest) {
			return PlatformTemplate{}, fmt.Errorf("%w: %s must be sha256 digest", ErrValidation, field)
		}
	}
	out.Impact = PlatformTemplateImpact{
		Status: TemplateImpactTargetPreviewRequired,
		Reasons: []string{
			"target inventory/capabilities are not template authority and must be evaluated immediately before adoption",
			"disruptive changes and rollback feasibility are target-specific and cannot be inferred from source composition alone",
		},
	}
	material := struct {
		Name                      string   `json:"name"`
		Version                   string   `json:"version"`
		BlueprintReleaseID        string   `json:"blueprintReleaseId"`
		BlueprintDigest           string   `json:"blueprintDigest"`
		VariableSchemaID          string   `json:"variableSchemaId"`
		VariableSchemaDigest      string   `json:"variableSchemaDigest"`
		PolicySetID               string   `json:"policySetId"`
		PolicySetDigest           string   `json:"policySetDigest"`
		AllowedTargetClasses      []string `json:"allowedTargetClasses"`
		CertificationRequirements []string `json:"certificationRequirements"`
	}{out.Name, out.Version, out.BlueprintReleaseID, out.BlueprintDigest, out.VariableSchemaID, out.VariableSchemaDigest, out.PolicySetID, out.PolicySetDigest, out.AllowedTargetClasses, out.CertificationRequirements}
	raw, _ := json.Marshal(material)
	sum := sha256.Sum256(raw)
	out.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return out, nil
}

func EvaluatePlatformTemplateAdmission(template PlatformTemplate, blueprint BlueprintRelease, schema VariableSchema, policy PlatformPolicySet, targetClass string) PlatformTemplateAdmission {
	targetClass = strings.ToLower(strings.TrimSpace(targetClass))
	out := PlatformTemplateAdmission{
		Authority: PlatformTemplateAuthority, TemplateID: template.ID, TemplateDigest: template.Digest, TargetClass: targetClass,
		ImpactStatus:              TemplateImpactTargetPreviewRequired,
		CertificationRequirements: append([]string(nil), template.CertificationRequirements...),
	}
	blockers := []string{}
	bindingValid := blueprint.ProjectID == template.ProjectID && schema.ProjectID == template.ProjectID && policy.ProjectID == template.ProjectID &&
		blueprint.ID == template.BlueprintReleaseID && schema.ID == template.VariableSchemaID && policy.ID == template.PolicySetID &&
		blueprint.CurrentBlueprintDigest == template.BlueprintDigest && schema.Digest == template.VariableSchemaDigest && policy.Digest == template.PolicySetDigest
	if !bindingValid {
		blockers = append(blockers, "TEMPLATE_AUTHORITY_BINDING_DRIFT")
	}
	if blueprint.State != BlueprintPublished {
		blockers = append(blockers, "BLUEPRINT_RELEASE_NOT_PUBLISHED")
	}
	if !blueprint.ExecutionReady {
		blockers = append(blockers, "BLUEPRINT_RELEASE_NOT_EXECUTION_READY")
	}
	targetAllowed := false
	for _, allowed := range template.AllowedTargetClasses {
		if allowed == targetClass {
			targetAllowed = true
			break
		}
	}
	if targetClass == "" {
		blockers = append(blockers, "TARGET_CLASS_REQUIRED")
	} else if !targetAllowed {
		blockers = append(blockers, "TARGET_CLASS_NOT_ALLOWED")
	}
	sort.Strings(blockers)
	out.BindingValid = bindingValid
	out.TargetAllowed = targetAllowed
	out.AdoptionReady = false // target-specific impact preview/certification remains mandatory by design.
	out.Blockers = blockers
	return out
}
