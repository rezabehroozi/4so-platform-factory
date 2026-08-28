package blueprint

import (
	"encoding/json"
	"fmt"
	"net/url"
	"platform.4so.io/factory/catalog"
	compatauth "platform.4so.io/factory/internal/compatibility"
	"platform.4so.io/factory/internal/domain"
	"platform.4so.io/factory/internal/gitops"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	dnsLabel       = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	semver         = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	registryHost   = regexp.MustCompile(`^[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._/-]+)?$`)
	sensitiveKey   = regexp.MustCompile(`(?i)(password|token|secret|private.?key|credential)`)
	validRisk      = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	validCertLevel = map[string]bool{"render": true, "ephemeral-runtime": true, "target-runtime": true, "upgrade": true, "production": true}
)

func Validate(b domain.Blueprint, components map[string]catalog.Component) domain.ValidationResult {
	findings := make([]domain.Finding, 0)
	add := func(code, severity, path, message string) {
		findings = append(findings, domain.Finding{Code: code, Severity: severity, Path: path, Message: message})
	}

	if b.APIVersion != "platform.4so.io/v1alpha1" {
		add("BLUEPRINT_API_VERSION", "error", "apiVersion", "unsupported apiVersion")
	}
	if b.Kind != "PlatformBlueprint" {
		add("BLUEPRINT_KIND", "error", "kind", "kind must be PlatformBlueprint")
	}
	if !dnsLabel.MatchString(b.Metadata.Name) || len(b.Metadata.Name) > 63 {
		add("BLUEPRINT_NAME", "error", "metadata.name", "name must be a DNS label no longer than 63 characters")
	}
	if !semver.MatchString(b.Metadata.Version) {
		add("BLUEPRINT_VERSION", "error", "metadata.version", "version must be x.y.z")
	}
	if strings.TrimSpace(b.Spec.Description) == "" {
		add("BLUEPRINT_DESCRIPTION", "error", "spec.description", "description is required")
	}

	validateDelivery(b.Spec.Delivery, add)
	validateCompatibility(b.Spec.Compatibility, add)
	validateGovernance(b.Spec.Governance, add)
	validateTenancy(b.Spec.Tenancy, add)
	validateFieldOwnership(b.Spec.FieldOwnership, add)
	if !validCertLevel[b.Spec.Certification.RequiredLevel] {
		add("CERTIFICATION_LEVEL", "error", "spec.certification.requiredLevel", "unsupported certification level")
	}
	if b.Spec.Certification.EvidenceRetentionDays < 30 || b.Spec.Certification.EvidenceRetentionDays > 3650 {
		add("EVIDENCE_RETENTION", "error", "spec.certification.evidenceRetentionDays", "evidence retention must be between 30 and 3650 days")
	}

	seen := map[string]bool{}
	enabled := map[string]bool{}
	for i, sel := range b.Spec.Components {
		path := fmt.Sprintf("spec.components[%d]", i)
		if !dnsLabel.MatchString(sel.Name) {
			add("COMPONENT_NAME", "error", path+".name", "component name must be a DNS label")
		}
		if seen[sel.Name] {
			add("DUPLICATE_COMPONENT", "error", path, "component is selected more than once")
		}
		seen[sel.Name] = true
		c, ok := components[sel.Name]
		if !ok {
			add("UNKNOWN_COMPONENT", "error", path, "component does not exist in catalog")
			continue
		}
		if strings.Contains(strings.ToLower(c.Spec.Release), "latest") {
			add("MUTABLE_COMPONENT_RELEASE", "error", path, "component release cannot use latest")
		}
		if sel.Enabled {
			enabled[sel.Name] = true
		}
		if hasEmbeddedSecret(sel.Settings) {
			add("PLAINTEXT_COMPONENT_SETTING", "error", path+".settings", "settings must use secret references, not embedded credentials")
		}
	}

	componentNames := sortedComponentNames(components)
	for _, name := range componentNames {
		c := components[name]
		if c.Spec.Mandatory && !enabled[name] {
			add("MANDATORY_COMPONENT_MISSING", "error", "spec.components", fmt.Sprintf("mandatory component %s is not enabled", name))
		}
	}

	provided := map[string][]string{}
	for _, name := range sortedEnabledNames(enabled) {
		c := components[name]
		for _, dep := range c.Spec.Dependencies {
			if !enabled[dep] {
				add("DEPENDENCY_MISSING", "error", "spec.components", fmt.Sprintf("%s requires %s", name, dep))
				continue
			}
			if components[dep].Spec.Wave > c.Spec.Wave {
				add("DEPENDENCY_WAVE_INVALID", "error", "catalog.components."+name+".wave", fmt.Sprintf("dependency %s is scheduled after %s", dep, name))
			}
		}
		for _, conflict := range c.Spec.ConflictsWith {
			if enabled[conflict] {
				add("COMPONENT_CONFLICT", "error", "spec.components", fmt.Sprintf("%s conflicts with %s", name, conflict))
			}
		}
		for _, capability := range c.Spec.Provides {
			provided[capability] = append(provided[capability], name)
		}
		validateComponentCompatibility(name, c, b.Spec.Compatibility, add)
	}

	for _, name := range sortedEnabledNames(enabled) {
		c := components[name]
		for _, capability := range c.Spec.RequiresCapabilities {
			if len(provided[capability]) == 0 {
				add("CAPABILITY_MISSING", "error", "spec.components", fmt.Sprintf("%s requires capability %s", name, capability))
			}
		}
		for _, capability := range c.Spec.ExclusiveCapabilities {
			providers := append([]string(nil), provided[capability]...)
			sort.Strings(providers)
			if len(providers) > 1 {
				add("EXCLUSIVE_CAPABILITY_CONFLICT", "error", "spec.components", fmt.Sprintf("capability %s has multiple providers: %s", capability, strings.Join(providers, ", ")))
			}
		}
	}
	if cycle := detectCycle(enabled, components); len(cycle) > 0 {
		add("DEPENDENCY_CYCLE", "error", "spec.components", strings.Join(cycle, " -> "))
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Message < findings[j].Message
	})
	valid := true
	for _, f := range findings {
		if f.Severity == "error" {
			valid = false
			break
		}
	}
	return domain.ValidationResult{Valid: valid, Findings: findings}
}

func validateDelivery(d domain.Delivery, add func(string, string, string, string)) {
	if d.Mode != "gitops" {
		add("DELIVERY_MODE", "error", "spec.delivery.mode", "only gitops planning is currently supported")
	}
	if d.Repository == "" {
		add("DELIVERY_REPOSITORY", "error", "spec.delivery.repository", "repository is required")
	} else if u, err := url.Parse(d.Repository); err != nil || !validRepositoryURL(u) {
		add("DELIVERY_REPOSITORY_FORMAT", "error", "spec.delivery.repository", "repository must be https/ssh, or cluster-local http for the embedded Git service, without embedded credentials")
	}
	if d.OCIRegistry == "" || !registryHost.MatchString(d.OCIRegistry) || strings.Contains(d.OCIRegistry, "://") {
		add("DELIVERY_REGISTRY_FORMAT", "error", "spec.delivery.ociRegistry", "OCI registry must be host[:port][/path] without credentials or scheme")
	}
	if d.Revision == "" {
		add("DELIVERY_REVISION", "error", "spec.delivery.revision", "revision is required")
	}
	switch d.RevisionType {
	case "commit":
		if !gitops.IsFullCommitSHA(d.Revision) {
			add("DELIVERY_COMMIT_FORMAT", "error", "spec.delivery.revision", "commit revision must be a 40 or 64 character hexadecimal digest")
		}
	case "tag":
		if strings.EqualFold(d.Revision, "latest") || strings.TrimSpace(d.Revision) == "" {
			add("MUTABLE_TAG", "error", "spec.delivery.revision", "tag must be non-empty and cannot be latest")
		}
	case "branch":
		add("MUTABLE_REVISION_TYPE", "warning", "spec.delivery.revisionType", "branch revisions are valid for planning but block execution until resolved to a commit")
	default:
		add("DELIVERY_REVISION_TYPE", "error", "spec.delivery.revisionType", "revisionType must be commit, tag, or branch")
	}
	if strings.Contains(d.Repository, "example.invalid") {
		add("EXAMPLE_GIT_ENDPOINT", "warning", "spec.delivery.repository", "example endpoint must be replaced before execution")
	}
	if strings.Contains(d.OCIRegistry, "example.invalid") {
		add("EXAMPLE_OCI_ENDPOINT", "warning", "spec.delivery.ociRegistry", "example endpoint must be replaced before execution")
	}
}

func validRepositoryURL(u *url.URL) bool {
	if u == nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" || u.Scheme == "ssh" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasSuffix(host, ".svc.cluster.local")
}

func validateCompatibility(c domain.Compatibility, add func(string, string, string, string)) {
	min, minErr := minor(c.Kubernetes.MinVersion)
	max, maxErr := minor(c.Kubernetes.MaxVersion)
	if minErr != nil {
		add("KUBERNETES_MIN_VERSION", "error", "spec.compatibility.kubernetes.minVersion", minErr.Error())
	}
	if maxErr != nil {
		add("KUBERNETES_MAX_VERSION", "error", "spec.compatibility.kubernetes.maxVersion", maxErr.Error())
	}
	if minErr == nil && maxErr == nil {
		if min > max {
			add("KUBERNETES_VERSION_RANGE", "error", "spec.compatibility.kubernetes", "minVersion cannot exceed maxVersion")
		}
	}
	if len(c.Architectures) == 0 {
		add("ARCHITECTURE_EMPTY", "error", "spec.compatibility.architectures", "at least one architecture is required")
	}
	seenArch := map[string]bool{}
	for i, arch := range c.Architectures {
		if arch != "amd64" && arch != "arm64" {
			add("ARCHITECTURE_UNSUPPORTED", "error", fmt.Sprintf("spec.compatibility.architectures[%d]", i), "only amd64 and arm64 are modeled")
		}
		if seenArch[arch] {
			add("ARCHITECTURE_DUPLICATE", "error", fmt.Sprintf("spec.compatibility.architectures[%d]", i), "architecture is duplicated")
		}
		seenArch[arch] = true
	}
	if len(c.DistributionProfiles) == 0 {
		add("DISTRIBUTION_PROFILE_EMPTY", "error", "spec.compatibility.distributionProfiles", "at least one distribution profile is required")
	}
	seenDist := map[string]bool{}
	for i, profile := range c.DistributionProfiles {
		if !dnsLabel.MatchString(profile) {
			add("DISTRIBUTION_PROFILE_INVALID", "error", fmt.Sprintf("spec.compatibility.distributionProfiles[%d]", i), "distribution profile must be a DNS label")
		}
		if seenDist[profile] {
			add("DISTRIBUTION_PROFILE_DUPLICATE", "error", fmt.Sprintf("spec.compatibility.distributionProfiles[%d]", i), "distribution profile is duplicated")
		}
		seenDist[profile] = true
	}
}

func validateGovernance(g domain.Governance, add func(string, string, string, string)) {
	if g.AllowPlaintextSecrets {
		add("PLAINTEXT_SECRETS", "error", "spec.governance.allowPlaintextSecrets", "plaintext secrets are forbidden")
	}
	if !g.EnforceDigestImages {
		add("IMAGE_DIGEST_POLICY", "error", "spec.governance.enforceDigestImages", "digest image policy must be enabled")
	}
	seen := map[string]bool{}
	for i, risk := range g.ApprovalRequiredFor {
		if !validRisk[risk] {
			add("APPROVAL_RISK_INVALID", "error", fmt.Sprintf("spec.governance.approvalRequiredFor[%d]", i), "invalid risk level")
		}
		if seen[risk] {
			add("APPROVAL_RISK_DUPLICATE", "error", fmt.Sprintf("spec.governance.approvalRequiredFor[%d]", i), "risk level is duplicated")
		}
		seen[risk] = true
	}
	for _, required := range []string{"high", "critical"} {
		if !seen[required] {
			add("APPROVAL_POLICY_INCOMPLETE", "error", "spec.governance.approvalRequiredFor", required+" risk changes require approval")
		}
	}
}

func validateFieldOwnership(rules []domain.FieldOwnershipRule, add func(string, string, string, string)) {
	valid := map[string]bool{"BLUEPRINT_ONLY": true, "PROVIDER_ONLY": true, "ENVIRONMENT_ONLY": true, "PROVIDER_THEN_ENVIRONMENT": true}
	seen := map[string]bool{}
	for i, rule := range rules {
		path := strings.TrimSpace(rule.Path)
		policy := strings.TrimSpace(rule.Policy)
		base := fmt.Sprintf("spec.fieldOwnership[%d]", i)
		if !strings.HasPrefix(path, "/spec/") || strings.HasPrefix(path, "/spec/fieldOwnership") {
			add("FIELD_OWNERSHIP_PATH", "error", base+".path", "ownership path must be an exact /spec JSON Pointer and cannot target fieldOwnership itself")
		}
		if seen[path] {
			add("FIELD_OWNERSHIP_DUPLICATE", "error", base+".path", "ownership path is duplicated")
		}
		seen[path] = true
		if !valid[policy] {
			add("FIELD_OWNERSHIP_POLICY", "error", base+".policy", "policy must be BLUEPRINT_ONLY, PROVIDER_ONLY, ENVIRONMENT_ONLY or PROVIDER_THEN_ENVIRONMENT")
		}
	}
}

func validateTenancy(t domain.Tenancy, add func(string, string, string, string)) {
	if t.Mode != "namespace" {
		add("TENANCY_MODE", "error", "spec.tenancy.mode", "only namespace tenancy is currently modeled")
	}
	if t.DeletionPolicy != "approval-and-backup-required" {
		add("TENANT_DELETION_POLICY", "error", "spec.tenancy.deletionPolicy", "safe deletion requires approval and backup")
	}
	plans, err := catalog.LoadTenantPlans()
	if err != nil {
		add("TENANT_PLAN_CATALOG", "error", "catalog.tenancy", err.Error())
		return
	}
	if len(t.Plans) == 0 {
		add("TENANT_PLAN_EMPTY", "error", "spec.tenancy.plans", "at least one tenant plan is required")
	}
	seen := map[string]bool{}
	for i, name := range t.Plans {
		if _, ok := plans[name]; !ok {
			add("TENANT_PLAN_UNKNOWN", "error", fmt.Sprintf("spec.tenancy.plans[%d]", i), "tenant plan does not exist")
		}
		if seen[name] {
			add("TENANT_PLAN_DUPLICATE", "error", fmt.Sprintf("spec.tenancy.plans[%d]", i), "tenant plan is duplicated")
		}
		seen[name] = true
	}
}

func validateComponentCompatibility(name string, c catalog.Component, wanted domain.Compatibility, add func(string, string, string, string)) {
	outer := compatauth.Constraint{Name: "component/" + name, KubernetesMinVersion: c.Spec.Compatibility.Kubernetes.MinVersion, KubernetesMaxVersion: c.Spec.Compatibility.Kubernetes.MaxVersion, Architectures: c.Spec.Compatibility.Architectures, Distributions: c.Spec.Compatibility.DistributionProfiles, Providers: c.Spec.Compatibility.Providers}
	inner := compatauth.Constraint{Name: "blueprint", KubernetesMinVersion: wanted.Kubernetes.MinVersion, KubernetesMaxVersion: wanted.Kubernetes.MaxVersion, Architectures: wanted.Architectures, Distributions: wanted.DistributionProfiles}
	if err := compatauth.CoversConstraint(outer, inner); err != nil {
		add("COMPONENT_COMPATIBILITY_INCOMPATIBLE", "error", "catalog.components."+name+".compatibility", "component does not cover blueprint compatibility: "+err.Error())
	}
	if len(c.Spec.Compatibility.Providers) == 0 {
		add("COMPONENT_PROVIDER_COMPATIBILITY_EMPTY", "error", "catalog.components."+name+".compatibility.providers", "component must declare provider compatibility")
	}
}

func hasEmbeddedSecret(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, value := range x {
			low := strings.ToLower(k)
			if sensitiveKey.MatchString(k) && !strings.Contains(low, "ref") {
				if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
					return true
				}
			}
			if hasEmbeddedSecret(value) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if hasEmbeddedSecret(value) {
				return true
			}
		}
	default:
		_, _ = json.Marshal(x)
	}
	return false
}

func minor(v string) (int, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("version must be major.minor")
	}
	if parts[0] != "1" {
		return 0, fmt.Errorf("only Kubernetes major version 1 is supported")
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("minor version is invalid")
	}
	return n, nil
}

func makeSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		out[v] = true
	}
	return out
}
func sortedEnabledNames(enabled map[string]bool) []string {
	out := make([]string, 0, len(enabled))
	for n := range enabled {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
func sortedComponentNames(cs map[string]catalog.Component) []string {
	out := make([]string, 0, len(cs))
	for n := range cs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func detectCycle(enabled map[string]bool, cs map[string]catalog.Component) []string {
	visiting := map[string]bool{}
	visited := map[string]bool{}
	stack := []string{}
	var dfs func(string) []string
	dfs = func(n string) []string {
		if visiting[n] {
			for i, x := range stack {
				if x == n {
					return append(append([]string{}, stack[i:]...), n)
				}
			}
			return []string{n, n}
		}
		if visited[n] {
			return nil
		}
		visiting[n] = true
		stack = append(stack, n)
		deps := append([]string(nil), cs[n].Spec.Dependencies...)
		sort.Strings(deps)
		for _, d := range deps {
			if enabled[d] {
				if c := dfs(d); len(c) > 0 {
					return c
				}
			}
		}
		stack = stack[:len(stack)-1]
		visiting[n] = false
		visited[n] = true
		return nil
	}
	for _, n := range sortedEnabledNames(enabled) {
		if c := dfs(n); len(c) > 0 {
			return c
		}
	}
	return nil
}
