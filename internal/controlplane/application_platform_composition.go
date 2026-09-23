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
	WorkloadTypeAuthority           = "WORKLOAD_TYPE_AUTHORITY_V1"
	CapabilityTraitAuthority        = "CAPABILITY_TRAIT_AUTHORITY_V1"
	WorkloadCompositionAuthority    = "WORKLOAD_COMPOSITION_AUTHORITY_V1"
	ManagedResourceTypeAuthority    = "MANAGED_RESOURCE_TYPE_AUTHORITY_V1"
	WorkspaceProfileAuthority       = "WORKSPACE_PROFILE_AUTHORITY_V1"
	ApplicationReleaseAuthority     = "APPLICATION_RELEASE_AUTHORITY_V1"
	EnvironmentBindingAuthority     = "ENVIRONMENT_BINDING_AUTHORITY_V1"
)

const (
	TraitDecisionApply          = "APPLY"
	TraitDecisionSuppressNative = "SUPPRESS_NATIVE"
)

var applicationPlatformDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type WorkloadType struct {
	ResourceMeta
	ProjectID         string   `json:"projectId"`
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	InputSchemaDigest string   `json:"inputSchemaDigest"`
	AllowedTraitKinds []string `json:"allowedTraitKinds"`
	Digest            string   `json:"digest"`
}

type CapabilityTrait struct {
	ResourceMeta
	ProjectID         string `json:"projectId"`
	Name              string `json:"name"`
	Version           string `json:"version"`
	Kind              string `json:"kind"`
	Capability        string `json:"capability"`
	InputSchemaDigest string `json:"inputSchemaDigest"`
	NativeSuppression bool   `json:"nativeSuppression"`
	Digest            string `json:"digest"`
}

type WorkloadTraitDecision struct {
	TraitDigest string `json:"traitDigest"`
	Capability string `json:"capability"`
	Action     string `json:"action"`
	Reason     string `json:"reason"`
}

type WorkloadComposition struct {
	Authority        string                  `json:"authority"`
	WorkloadDigest   string                  `json:"workloadDigest"`
	TraitDigests     []string                `json:"traitDigests"`
	ObservedNative   []string                `json:"observedNativeCapabilities,omitempty"`
	Decisions        []WorkloadTraitDecision `json:"decisions"`
	ResolutionDigest string                  `json:"resolutionDigest"`
}

type ManagedResourceOutput struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Sensitive       bool   `json:"sensitive,omitempty"`
	SecretReference bool   `json:"secretReference,omitempty"`
}

type ManagedResourceType struct {
	ResourceMeta
	ProjectID           string                  `json:"projectId"`
	Name                string                  `json:"name"`
	Version             string                  `json:"version"`
	Category            string                  `json:"category"`
	Provisioner         string                  `json:"provisioner"`
	InputSchemaDigest   string                  `json:"inputSchemaDigest"`
	Outputs             []ManagedResourceOutput `json:"outputs"`
	DeletePolicy        string                  `json:"deletePolicy"`
	RetentionPolicy     string                  `json:"retentionPolicy,omitempty"`
	ReadinessConditions []string                `json:"readinessConditions"`
	Digest              string                  `json:"digest"`
}

type ApplicationAuthorityRef struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type WorkspaceProfile struct {
	ResourceMeta
	ProjectID     string                    `json:"projectId"`
	Name          string                    `json:"name"`
	Version       string                    `json:"version"`
	AuthorityRefs []ApplicationAuthorityRef `json:"authorityRefs"`
	Digest        string                    `json:"digest"`
}

type ApplicationRelease struct {
	ResourceMeta
	ProjectID              string   `json:"projectId"`
	Name                   string   `json:"name"`
	Version                string   `json:"version"`
	WorkloadTypeDigest     string   `json:"workloadTypeDigest"`
	TraitDigests           []string `json:"traitDigests"`
	ManagedResourceDigests []string `json:"managedResourceDigests"`
	WorkspaceProfileDigest string   `json:"workspaceProfileDigest"`
	SourceDigest           string   `json:"sourceDigest"`
	Digest                 string   `json:"digest"`
}

type EnvironmentBinding struct {
	ResourceMeta
	ProjectID                  string `json:"projectId"`
	ReleaseID                  string `json:"releaseId"`
	ReleaseDigest              string `json:"releaseDigest"`
	WorkspaceID                string `json:"workspaceId"`
	ClusterID                  string `json:"clusterId"`
	Namespace                  string `json:"namespace"`
	Environment                string `json:"environment"`
	CapabilityResolutionDigest string `json:"capabilityResolutionDigest"`
	Digest                     string `json:"digest"`
}

func digestApplicationPlatformMaterial(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func requireApplicationDigest(field, value string) error {
	if !applicationPlatformDigestPattern.MatchString(strings.TrimSpace(value)) {
		return fmt.Errorf("%w: %s must be a sha256 digest", ErrValidation, field)
	}
	return nil
}

func canonicalApplicationTokens(values []string, min, max int, field string) ([]string, error) {
	if len(values) < min || len(values) > max {
		return nil, fmt.Errorf("%w: %s requires %d..%d values", ErrValidation, field, min, max)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" || len(value) > 96 || !platformTokenPattern.MatchString(value) || seen[value] {
			return nil, fmt.Errorf("%w: %s contains invalid or duplicate value %q", ErrValidation, field, raw)
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func canonicalDigestSet(values []string, max int, field string) ([]string, error) {
	if len(values) > max {
		return nil, fmt.Errorf("%w: %s exceeds %d values", ErrValidation, field, max)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if err := requireApplicationDigest(field, value); err != nil {
			return nil, err
		}
		if seen[value] {
			return nil, fmt.Errorf("%w: %s contains duplicate digest", ErrValidation, field)
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func NormalizeWorkloadType(in WorkloadType) (WorkloadType, error) {
	out := in
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.Version = strings.TrimSpace(out.Version)
	out.InputSchemaDigest = strings.TrimSpace(out.InputSchemaDigest)
	if out.ProjectID == "" || !variableNamePattern.MatchString(out.Name) || !schemaVersionPattern.MatchString(out.Version) {
		return WorkloadType{}, fmt.Errorf("%w: workload type requires projectId, canonical name and semantic version", ErrValidation)
	}
	if err := requireApplicationDigest("inputSchemaDigest", out.InputSchemaDigest); err != nil {
		return WorkloadType{}, err
	}
	var err error
	out.AllowedTraitKinds, err = canonicalApplicationTokens(out.AllowedTraitKinds, 0, 32, "allowedTraitKinds")
	if err != nil {
		return WorkloadType{}, err
	}
	allowed := map[string]bool{"storage": true, "ingress": true, "autoscale": true, "observability": true, "security": true, "backup": true, "network": true, "sidecar": true}
	for _, kind := range out.AllowedTraitKinds {
		if !allowed[kind] {
			return WorkloadType{}, fmt.Errorf("%w: unsupported trait kind %q", ErrValidation, kind)
		}
	}
	out.Digest = digestApplicationPlatformMaterial(struct {
		Name              string   `json:"name"`
		Version           string   `json:"version"`
		InputSchemaDigest string   `json:"inputSchemaDigest"`
		AllowedTraitKinds []string `json:"allowedTraitKinds"`
	}{out.Name, out.Version, out.InputSchemaDigest, out.AllowedTraitKinds})
	return out, nil
}

func NormalizeCapabilityTrait(in CapabilityTrait) (CapabilityTrait, error) {
	out := in
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.Version = strings.TrimSpace(out.Version)
	out.Kind = strings.ToLower(strings.TrimSpace(out.Kind))
	out.Capability = strings.ToLower(strings.TrimSpace(out.Capability))
	out.InputSchemaDigest = strings.TrimSpace(out.InputSchemaDigest)
	if out.ProjectID == "" || !variableNamePattern.MatchString(out.Name) || !schemaVersionPattern.MatchString(out.Version) || !platformTokenPattern.MatchString(out.Capability) {
		return CapabilityTrait{}, fmt.Errorf("%w: capability trait identity is invalid", ErrValidation)
	}
	if err := requireApplicationDigest("inputSchemaDigest", out.InputSchemaDigest); err != nil {
		return CapabilityTrait{}, err
	}
	allowed := map[string]bool{"storage": true, "ingress": true, "autoscale": true, "observability": true, "security": true, "backup": true, "network": true, "sidecar": true}
	if !allowed[out.Kind] {
		return CapabilityTrait{}, fmt.Errorf("%w: unsupported trait kind %q", ErrValidation, out.Kind)
	}
	out.Digest = digestApplicationPlatformMaterial(struct {
		Name              string `json:"name"`
		Version           string `json:"version"`
		Kind              string `json:"kind"`
		Capability        string `json:"capability"`
		InputSchemaDigest string `json:"inputSchemaDigest"`
		NativeSuppression bool   `json:"nativeSuppression"`
	}{out.Name, out.Version, out.Kind, out.Capability, out.InputSchemaDigest, out.NativeSuppression})
	return out, nil
}

func ResolveWorkloadComposition(workload WorkloadType, traits []CapabilityTrait, observedNative []string) (WorkloadComposition, error) {
	workload, err := NormalizeWorkloadType(workload)
	if err != nil {
		return WorkloadComposition{}, err
	}
	observed, err := canonicalApplicationTokens(observedNative, 0, 128, "observedNativeCapabilities")
	if err != nil {
		return WorkloadComposition{}, err
	}
	native := map[string]bool{}
	for _, capability := range observed {
		native[capability] = true
	}
	allowedKinds := map[string]bool{}
	for _, kind := range workload.AllowedTraitKinds {
		allowedKinds[kind] = true
	}
	normalized := make([]CapabilityTrait, 0, len(traits))
	seenCapability := map[string]bool{}
	for _, trait := range traits {
		trait, err = NormalizeCapabilityTrait(trait)
		if err != nil {
			return WorkloadComposition{}, err
		}
		if trait.ProjectID != workload.ProjectID {
			return WorkloadComposition{}, fmt.Errorf("%w: workload and trait must belong to the same project", ErrValidation)
		}
		if !allowedKinds[trait.Kind] {
			return WorkloadComposition{}, fmt.Errorf("%w: trait kind %q is not allowed by workload type", ErrValidation, trait.Kind)
		}
		if seenCapability[trait.Capability] {
			return WorkloadComposition{}, fmt.Errorf("%w: multiple traits claim capability %q", ErrValidation, trait.Capability)
		}
		seenCapability[trait.Capability] = true
		if native[trait.Capability] && !trait.NativeSuppression {
			return WorkloadComposition{}, fmt.Errorf("%w: target already owns capability %q and trait does not permit native suppression", ErrValidation, trait.Capability)
		}
		normalized = append(normalized, trait)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Capability != normalized[j].Capability {
			return normalized[i].Capability < normalized[j].Capability
		}
		return normalized[i].Digest < normalized[j].Digest
	})
	out := WorkloadComposition{Authority: WorkloadCompositionAuthority, WorkloadDigest: workload.Digest, ObservedNative: observed}
	for _, trait := range normalized {
		action := TraitDecisionApply
		reason := "trait capability is not owned by the observed target and must be rendered by the product composition"
		if native[trait.Capability] {
			action = TraitDecisionSuppressNative
			reason = "observed target already owns this capability; product trait is suppressed to prevent a duplicate stack"
		}
		out.TraitDigests = append(out.TraitDigests, trait.Digest)
		out.Decisions = append(out.Decisions, WorkloadTraitDecision{TraitDigest: trait.Digest, Capability: trait.Capability, Action: action, Reason: reason})
	}
	out.ResolutionDigest = digestApplicationPlatformMaterial(struct {
		Authority      string                  `json:"authority"`
		WorkloadDigest string                  `json:"workloadDigest"`
		TraitDigests   []string                `json:"traitDigests"`
		ObservedNative []string                `json:"observedNativeCapabilities"`
		Decisions      []WorkloadTraitDecision `json:"decisions"`
	}{out.Authority, out.WorkloadDigest, out.TraitDigests, out.ObservedNative, out.Decisions})
	return out, nil
}

func NormalizeManagedResourceType(in ManagedResourceType) (ManagedResourceType, error) {
	out := in
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.Version = strings.TrimSpace(out.Version)
	out.Category = strings.ToLower(strings.TrimSpace(out.Category))
	out.Provisioner = strings.ToLower(strings.TrimSpace(out.Provisioner))
	out.InputSchemaDigest = strings.TrimSpace(out.InputSchemaDigest)
	out.DeletePolicy = strings.ToLower(strings.TrimSpace(out.DeletePolicy))
	out.RetentionPolicy = strings.TrimSpace(out.RetentionPolicy)
	if out.ProjectID == "" || !variableNamePattern.MatchString(out.Name) || !schemaVersionPattern.MatchString(out.Version) {
		return ManagedResourceType{}, fmt.Errorf("%w: managed resource type identity is invalid", ErrValidation)
	}
	if err := requireApplicationDigest("inputSchemaDigest", out.InputSchemaDigest); err != nil {
		return ManagedResourceType{}, err
	}
	if !map[string]bool{"database": true, "cache": true, "queue": true, "object-storage": true, "external-service": true}[out.Category] {
		return ManagedResourceType{}, fmt.Errorf("%w: unsupported managed resource category %q", ErrValidation, out.Category)
	}
	if !map[string]bool{"product-api": true, "crossplane": true, "external-adapter": true}[out.Provisioner] {
		return ManagedResourceType{}, fmt.Errorf("%w: unsupported managed resource provisioner %q", ErrValidation, out.Provisioner)
	}
	if !map[string]bool{"delete": true, "retain": true}[out.DeletePolicy] {
		return ManagedResourceType{}, fmt.Errorf("%w: deletePolicy must be delete or retain", ErrValidation)
	}
	if out.DeletePolicy == "retain" && out.RetentionPolicy == "" {
		return ManagedResourceType{}, fmt.Errorf("%w: retained resources require retentionPolicy", ErrValidation)
	}
	if out.DeletePolicy == "delete" && out.RetentionPolicy != "" {
		return ManagedResourceType{}, fmt.Errorf("%w: retentionPolicy is only valid with retain deletePolicy", ErrValidation)
	}
	if len(out.Outputs) == 0 || len(out.Outputs) > 64 {
		return ManagedResourceType{}, fmt.Errorf("%w: managed resource type requires 1..64 outputs", ErrValidation)
	}
	seen := map[string]bool{}
	allowedOutputTypes := map[string]bool{"string": true, "number": true, "boolean": true, "endpoint": true, "secret-reference": true}
	for i := range out.Outputs {
		out.Outputs[i].Name = normalizeName(out.Outputs[i].Name)
		out.Outputs[i].Type = strings.ToLower(strings.TrimSpace(out.Outputs[i].Type))
		if !variableNamePattern.MatchString(out.Outputs[i].Name) || seen[out.Outputs[i].Name] || !allowedOutputTypes[out.Outputs[i].Type] {
			return ManagedResourceType{}, fmt.Errorf("%w: invalid or duplicate managed resource output", ErrValidation)
		}
		if out.Outputs[i].Sensitive && (!out.Outputs[i].SecretReference || out.Outputs[i].Type != "secret-reference") {
			return ManagedResourceType{}, fmt.Errorf("%w: sensitive output %q must be represented only as secret-reference", ErrValidation, out.Outputs[i].Name)
		}
		if out.Outputs[i].SecretReference && out.Outputs[i].Type != "secret-reference" {
			return ManagedResourceType{}, fmt.Errorf("%w: secretReference output %q must use secret-reference type", ErrValidation, out.Outputs[i].Name)
		}
		seen[out.Outputs[i].Name] = true
	}
	sort.Slice(out.Outputs, func(i, j int) bool { return out.Outputs[i].Name < out.Outputs[j].Name })
	var err error
	out.ReadinessConditions, err = canonicalApplicationTokens(out.ReadinessConditions, 1, 16, "readinessConditions")
	if err != nil {
		return ManagedResourceType{}, err
	}
	out.Digest = digestApplicationPlatformMaterial(struct {
		Name                string                  `json:"name"`
		Version             string                  `json:"version"`
		Category            string                  `json:"category"`
		Provisioner         string                  `json:"provisioner"`
		InputSchemaDigest   string                  `json:"inputSchemaDigest"`
		Outputs             []ManagedResourceOutput `json:"outputs"`
		DeletePolicy        string                  `json:"deletePolicy"`
		RetentionPolicy     string                  `json:"retentionPolicy,omitempty"`
		ReadinessConditions []string                `json:"readinessConditions"`
	}{out.Name, out.Version, out.Category, out.Provisioner, out.InputSchemaDigest, out.Outputs, out.DeletePolicy, out.RetentionPolicy, out.ReadinessConditions})
	return out, nil
}

func NormalizeWorkspaceProfile(in WorkspaceProfile) (WorkspaceProfile, error) {
	out := in
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.Version = strings.TrimSpace(out.Version)
	if out.ProjectID == "" || !variableNamePattern.MatchString(out.Name) || !schemaVersionPattern.MatchString(out.Version) {
		return WorkspaceProfile{}, fmt.Errorf("%w: workspace profile identity is invalid", ErrValidation)
	}
	if len(out.AuthorityRefs) == 0 || len(out.AuthorityRefs) > 32 {
		return WorkspaceProfile{}, fmt.Errorf("%w: workspace profile requires 1..32 authority references", ErrValidation)
	}
	allowedKinds := map[string]bool{
		"policy-set": true, "quota-policy": true, "network-policy": true, "security-policy": true,
		"backup-policy": true, "observability-policy": true, "catalog-policy": true,
		"virtual-cluster-policy": true, "cost-policy": true,
	}
	seen := map[string]bool{}
	for i := range out.AuthorityRefs {
		out.AuthorityRefs[i].Kind = strings.ToLower(strings.TrimSpace(out.AuthorityRefs[i].Kind))
		out.AuthorityRefs[i].ID = strings.TrimSpace(out.AuthorityRefs[i].ID)
		out.AuthorityRefs[i].Digest = strings.TrimSpace(out.AuthorityRefs[i].Digest)
		key := out.AuthorityRefs[i].Kind + ":" + out.AuthorityRefs[i].ID
		if !allowedKinds[out.AuthorityRefs[i].Kind] || out.AuthorityRefs[i].ID == "" || seen[key] {
			return WorkspaceProfile{}, fmt.Errorf("%w: invalid or duplicate workspace profile authority reference", ErrValidation)
		}
		if err := requireApplicationDigest("authorityRefs.digest", out.AuthorityRefs[i].Digest); err != nil {
			return WorkspaceProfile{}, err
		}
		seen[key] = true
	}
	sort.Slice(out.AuthorityRefs, func(i, j int) bool {
		if out.AuthorityRefs[i].Kind != out.AuthorityRefs[j].Kind {
			return out.AuthorityRefs[i].Kind < out.AuthorityRefs[j].Kind
		}
		return out.AuthorityRefs[i].ID < out.AuthorityRefs[j].ID
	})
	out.Digest = digestApplicationPlatformMaterial(struct {
		Name          string                    `json:"name"`
		Version       string                    `json:"version"`
		AuthorityRefs []ApplicationAuthorityRef `json:"authorityRefs"`
	}{out.Name, out.Version, out.AuthorityRefs})
	return out, nil
}

func NormalizeApplicationRelease(in ApplicationRelease) (ApplicationRelease, error) {
	out := in
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.Version = strings.TrimSpace(out.Version)
	out.WorkloadTypeDigest = strings.TrimSpace(out.WorkloadTypeDigest)
	out.WorkspaceProfileDigest = strings.TrimSpace(out.WorkspaceProfileDigest)
	out.SourceDigest = strings.TrimSpace(out.SourceDigest)
	if out.ProjectID == "" || !variableNamePattern.MatchString(out.Name) || !schemaVersionPattern.MatchString(out.Version) {
		return ApplicationRelease{}, fmt.Errorf("%w: application release identity is invalid", ErrValidation)
	}
	for field, digest := range map[string]string{
		"workloadTypeDigest": out.WorkloadTypeDigest,
		"workspaceProfileDigest": out.WorkspaceProfileDigest,
		"sourceDigest": out.SourceDigest,
	} {
		if err := requireApplicationDigest(field, digest); err != nil {
			return ApplicationRelease{}, err
		}
	}
	var err error
	out.TraitDigests, err = canonicalDigestSet(out.TraitDigests, 32, "traitDigests")
	if err != nil {
		return ApplicationRelease{}, err
	}
	out.ManagedResourceDigests, err = canonicalDigestSet(out.ManagedResourceDigests, 32, "managedResourceDigests")
	if err != nil {
		return ApplicationRelease{}, err
	}
	out.Digest = digestApplicationPlatformMaterial(struct {
		Name                   string   `json:"name"`
		Version                string   `json:"version"`
		WorkloadTypeDigest     string   `json:"workloadTypeDigest"`
		TraitDigests           []string `json:"traitDigests"`
		ManagedResourceDigests []string `json:"managedResourceDigests"`
		WorkspaceProfileDigest string   `json:"workspaceProfileDigest"`
		SourceDigest           string   `json:"sourceDigest"`
	}{out.Name, out.Version, out.WorkloadTypeDigest, out.TraitDigests, out.ManagedResourceDigests, out.WorkspaceProfileDigest, out.SourceDigest})
	return out, nil
}

func NormalizeEnvironmentBinding(in EnvironmentBinding) (EnvironmentBinding, error) {
	out := in
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.ReleaseID = strings.TrimSpace(out.ReleaseID)
	out.ReleaseDigest = strings.TrimSpace(out.ReleaseDigest)
	out.WorkspaceID = strings.TrimSpace(out.WorkspaceID)
	out.ClusterID = strings.TrimSpace(out.ClusterID)
	out.Namespace = strings.ToLower(strings.TrimSpace(out.Namespace))
	out.Environment = strings.ToLower(strings.TrimSpace(out.Environment))
	out.CapabilityResolutionDigest = strings.TrimSpace(out.CapabilityResolutionDigest)
	if out.ProjectID == "" || out.ReleaseID == "" || out.WorkspaceID == "" || out.ClusterID == "" || !workspaceNamespacePattern.MatchString(out.Namespace) {
		return EnvironmentBinding{}, fmt.Errorf("%w: environment binding scope is incomplete or invalid", ErrValidation)
	}
	if !map[string]bool{"development": true, "staging": true, "production": true}[out.Environment] {
		return EnvironmentBinding{}, fmt.Errorf("%w: unsupported environment %q", ErrValidation, out.Environment)
	}
	if err := requireApplicationDigest("releaseDigest", out.ReleaseDigest); err != nil {
		return EnvironmentBinding{}, err
	}
	if err := requireApplicationDigest("capabilityResolutionDigest", out.CapabilityResolutionDigest); err != nil {
		return EnvironmentBinding{}, err
	}
	out.Digest = digestApplicationPlatformMaterial(struct {
		ReleaseID                  string `json:"releaseId"`
		ReleaseDigest              string `json:"releaseDigest"`
		WorkspaceID                string `json:"workspaceId"`
		ClusterID                  string `json:"clusterId"`
		Namespace                  string `json:"namespace"`
		Environment                string `json:"environment"`
		CapabilityResolutionDigest string `json:"capabilityResolutionDigest"`
	}{out.ReleaseID, out.ReleaseDigest, out.WorkspaceID, out.ClusterID, out.Namespace, out.Environment, out.CapabilityResolutionDigest})
	return out, nil
}
