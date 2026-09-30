package targetmodel

import (
	"sort"
	"strings"
)

const (
	DaprApplicationRuntimeAuthority  = "DAPR_APPLICATION_RUNTIME_EXTENSION_V1"
	DaprApplicationRuntimeCapability = "application-runtime.dapr"
	DaprReviewedRuntimeVersion       = "v1.18.4"
)

type DaprFeatureDecision struct {
	Feature  string `json:"feature"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type DaprApplicationRuntimeDescriptor struct {
	Authority                       string                `json:"authority"`
	ReviewedDate                    string                `json:"reviewedDate"`
	ReviewedRuntimeVersion          string                `json:"reviewedRuntimeVersion"`
	UpstreamRepository              string                `json:"upstreamRepository"`
	UpstreamLicense                 string                `json:"upstreamLicense"`
	Capability                      string                `json:"capability"`
	TraitKind                       string                `json:"traitKind"`
	DefaultEnabled                  bool                  `json:"defaultEnabled"`
	TargetOnly                      bool                  `json:"targetOnly"`
	ManagementPlaneInstall          bool                  `json:"managementPlaneInstall"`
	DeploymentMode                  string                `json:"deploymentMode"`
	SharedDeploymentEnabled         bool                  `json:"sharedDeploymentEnabled"`
	PostgreSQLSoTPreserved          bool                  `json:"postgresqlSoTPreserved"`
	ProductDurableOpsPreserved      bool                  `json:"productDurableOpsPreserved"`
	ProductSecretRefsPreserved      bool                  `json:"productSecretRefsPreserved"`
	ExistingObservabilityPreserved  bool                  `json:"existingObservabilityPreserved"`
	ImplicitBrokerInstallAllowed    bool                  `json:"implicitBrokerInstallAllowed"`
	MTLSRequired                    bool                  `json:"mtlsRequired"`
	APIAllowListRequired            bool                  `json:"apiAllowListRequired"`
	ServiceInvocationDefaultDeny    bool                  `json:"serviceInvocationDefaultDeny"`
	NamespaceAndAppScopesRequired   bool                  `json:"namespaceAndAppScopesRequired"`
	CrossNamespaceInvocationDefault bool                  `json:"crossNamespaceInvocationDefault"`
	RequiredTargetServices          []string              `json:"requiredTargetServices"`
	DisabledTargetServices          []string              `json:"disabledTargetServices"`
	FeatureDecisions                []DaprFeatureDecision `json:"featureDecisions"`
	AdmissionRequirements           []string              `json:"admissionRequirements"`
}

func DaprApplicationRuntimeModel() DaprApplicationRuntimeDescriptor {
	return DaprApplicationRuntimeDescriptor{
		Authority:                       DaprApplicationRuntimeAuthority,
		ReviewedDate:                    "2026-09-30",
		ReviewedRuntimeVersion:          DaprReviewedRuntimeVersion,
		UpstreamRepository:              "https://github.com/dapr/dapr",
		UpstreamLicense:                 "Apache-2.0",
		Capability:                      DaprApplicationRuntimeCapability,
		TraitKind:                       "sidecar",
		DefaultEnabled:                  false,
		TargetOnly:                      true,
		ManagementPlaneInstall:          false,
		DeploymentMode:                  "SIDECAR",
		SharedDeploymentEnabled:         false,
		PostgreSQLSoTPreserved:          true,
		ProductDurableOpsPreserved:      true,
		ProductSecretRefsPreserved:      true,
		ExistingObservabilityPreserved:  true,
		ImplicitBrokerInstallAllowed:    false,
		MTLSRequired:                    true,
		APIAllowListRequired:            true,
		ServiceInvocationDefaultDeny:    true,
		NamespaceAndAppScopesRequired:   true,
		CrossNamespaceInvocationDefault: false,
		RequiredTargetServices: []string{
			"dapr-operator",
			"dapr-sidecar-injector",
			"dapr-sentry",
		},
		DisabledTargetServices: []string{
			"dapr-placement",
			"dapr-scheduler",
			"dapr-dashboard",
		},
		FeatureDecisions: []DaprFeatureDecision{
			{Feature: "service-invocation", Decision: "ALLOW_APPLICATION_RUNTIME", Reason: "portable app-to-app invocation with mTLS, tracing and explicit default-deny access policy"},
			{Feature: "pubsub", Decision: "ALLOW_APPLICATION_RUNTIME", Reason: "may bind only to an explicitly provisioned project-owned broker reference; Dapr must not install a broker implicitly"},
			{Feature: "bindings", Decision: "ALLOW_APPLICATION_RUNTIME", Reason: "useful adapter boundary for application-owned external integrations when component and application scopes are explicit"},
			{Feature: "resiliency", Decision: "ALLOW_APPLICATION_RUNTIME", Reason: "retry, timeout and circuit-breaker policy is useful at the application communication boundary"},
			{Feature: "observability", Decision: "ALLOW_APPLICATION_RUNTIME", Reason: "Dapr metrics and traces feed existing 4SO observability as telemetry only and never become a monitoring source of truth"},
			{Feature: "state-management", Decision: "DEFER_DUPLICATE_AUTHORITY", Reason: "must not become 4SO control-plane state; future use may be admitted only for explicitly application-owned state"},
			{Feature: "workflows", Decision: "DEFER_DUPLICATE_AUTHORITY", Reason: "4SO durable operations remain the lifecycle authority; enabling Dapr Workflow would also activate scheduler/state semantics"},
			{Feature: "jobs", Decision: "DEFER_DUPLICATE_AUTHORITY", Reason: "4SO scheduler and durable operation contracts remain canonical and Dapr Scheduler introduces independent etcd-backed job authority"},
			{Feature: "actors", Decision: "DEFER_COMPLEXITY", Reason: "requires placement plus state/reminder semantics and adds a second distributed execution model"},
			{Feature: "distributed-lock", Decision: "DEFER_DUPLICATE_AUTHORITY", Reason: "4SO revision, lease and fence-token semantics remain authoritative for mutations"},
			{Feature: "secrets", Decision: "DEFER_DUPLICATE_AUTHORITY", Reason: "4SO passes secret references only; Dapr must not become a second secret authority"},
			{Feature: "configuration", Decision: "DEFER_DUPLICATE_AUTHORITY", Reason: "desired application configuration remains product/GitOps authority rather than a parallel Dapr configuration store"},
			{Feature: "cryptography", Decision: "DEFER_SECURITY_REVIEW", Reason: "admit only after key ownership, rotation, evidence and disconnected semantics are explicitly modeled"},
			{Feature: "conversation", Decision: "DEFER_DUPLICATE_AUTHORITY", Reason: "4SO AI/MCP policy, provider and evidence authorities remain canonical"},
		},
		AdmissionRequirements: []string{
			"fresh target capability discovery confirms Kubernetes admission webhook and sidecar injection compatibility",
			"OKD targets pass SCC/PSA compatibility without weakening target security policy",
			"exact Dapr Helm/image/source identities are digest-pinned and admitted through existing supply-chain and disconnected mirror authority",
			"component definitions are namespace-scoped and application-scoped; unrestricted shared components are forbidden",
			"only required Dapr APIs are enabled and service invocation uses default-deny access control",
			"sidecar CPU and memory requests/limits are explicitly sized per workload profile before production admission",
			"pubsub and binding components reference already-provisioned ManagedResourceType outputs or approved external endpoints; no implicit broker/database is installed",
			"target-native application-runtime.dapr capability suppresses duplicate installation through WorkloadComposition resolution",
			"runtime installation and removal execute only through revision-fenced durable 4SO operations and observed readback",
			"disconnected targets require product-zot mirrored Dapr images and no hidden network acquisition",
		},
	}
}

func ValidateDaprApplicationRuntimeModel(model DaprApplicationRuntimeDescriptor) []string {
	issues := []string{}
	if model.Authority != DaprApplicationRuntimeAuthority || model.ReviewedRuntimeVersion != DaprReviewedRuntimeVersion {
		issues = append(issues, "dapr-review-identity-invalid")
	}
	if model.Capability != DaprApplicationRuntimeCapability || model.TraitKind != "sidecar" {
		issues = append(issues, "dapr-capability-boundary-invalid")
	}
	if model.DefaultEnabled || !model.TargetOnly || model.ManagementPlaneInstall || model.DeploymentMode != "SIDECAR" || model.SharedDeploymentEnabled {
		issues = append(issues, "dapr-deployment-boundary-invalid")
	}
	if !model.PostgreSQLSoTPreserved || !model.ProductDurableOpsPreserved || !model.ProductSecretRefsPreserved || !model.ExistingObservabilityPreserved || model.ImplicitBrokerInstallAllowed {
		issues = append(issues, "dapr-product-authority-boundary-invalid")
	}
	if !model.MTLSRequired || !model.APIAllowListRequired || !model.ServiceInvocationDefaultDeny || !model.NamespaceAndAppScopesRequired || model.CrossNamespaceInvocationDefault {
		issues = append(issues, "dapr-security-baseline-invalid")
	}
	required := map[string]bool{"dapr-operator": false, "dapr-sidecar-injector": false, "dapr-sentry": false}
	for _, service := range model.RequiredTargetServices {
		if _, ok := required[service]; ok {
			required[service] = true
		}
	}
	for _, ok := range required {
		if !ok {
			issues = append(issues, "dapr-required-target-services-incomplete")
			break
		}
	}
	disabled := map[string]bool{}
	for _, service := range model.DisabledTargetServices {
		disabled[service] = true
	}
	for _, service := range []string{"dapr-placement", "dapr-scheduler", "dapr-dashboard"} {
		if !disabled[service] {
			issues = append(issues, "dapr-disabled-target-services-incomplete")
			break
		}
	}
	decisions := map[string]string{}
	for _, decision := range model.FeatureDecisions {
		if decision.Feature == "" || decision.Decision == "" || decision.Reason == "" || decisions[decision.Feature] != "" {
			issues = append(issues, "dapr-feature-decision-invalid")
			continue
		}
		decisions[decision.Feature] = decision.Decision
	}
	for _, feature := range []string{"service-invocation", "pubsub", "bindings", "resiliency", "observability"} {
		if decisions[feature] != "ALLOW_APPLICATION_RUNTIME" {
			issues = append(issues, "dapr-safe-feature-profile-incomplete")
			break
		}
	}
	for _, feature := range []string{"state-management", "workflows", "jobs", "actors", "distributed-lock", "secrets", "configuration", "cryptography", "conversation"} {
		if decisions[feature] == "" || decisions[feature] == "ALLOW_APPLICATION_RUNTIME" {
			issues = append(issues, "dapr-deferred-feature-profile-invalid")
			break
		}
	}
	if len(model.AdmissionRequirements) < 8 {
		issues = append(issues, "dapr-admission-requirements-incomplete")
	}
	return issues
}

const (
	DaprRuntimeSourcePlanAuthority = "DAPR_RUNTIME_SOURCE_PLAN_V1"
	DaprUpstreamRepository         = "https://github.com/dapr/dapr"
	DaprUpstreamRef                = "v1.18.4"
	DaprUpstreamCommit             = "6d1c53f430205c0c0f3bc3589ce5a3ec3f6f1647"
	DaprHelmChartPath              = "charts/dapr"
)

type DaprHelmOverride struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

type DaprRuntimeImageRole struct {
	Role       string `json:"role"`
	Repository string `json:"repository"`
}

type DaprRuntimeSourcePlan struct {
	Authority                  string                 `json:"authority"`
	Version                    string                 `json:"version"`
	UpstreamRepository         string                 `json:"upstreamRepository"`
	UpstreamRef                string                 `json:"upstreamRef"`
	UpstreamCommit             string                 `json:"upstreamCommit"`
	HelmChartPath              string                 `json:"helmChartPath"`
	HelmOverrides              []DaprHelmOverride     `json:"helmOverrides"`
	RequiredImages             []DaprRuntimeImageRole `json:"requiredImages"`
	ForbiddenImageRepositories []string               `json:"forbiddenImageRepositories"`
	RequireExactSourceLock     bool                   `json:"requireExactSourceLock"`
	RequireDigestPinnedImages  bool                   `json:"requireDigestPinnedImages"`
	RequireProductZotMirror    bool                   `json:"requireProductZotMirror"`
	NetworkFetchAtRuntime      bool                   `json:"networkFetchAtRuntime"`
}

func DaprRuntimeSourcePlanModel() DaprRuntimeSourcePlan {
	return DaprRuntimeSourcePlan{
		Authority:          DaprRuntimeSourcePlanAuthority,
		Version:            DaprReviewedRuntimeVersion,
		UpstreamRepository: DaprUpstreamRepository,
		UpstreamRef:        DaprUpstreamRef,
		UpstreamCommit:     DaprUpstreamCommit,
		HelmChartPath:      DaprHelmChartPath,
		HelmOverrides: []DaprHelmOverride{
			{Path: "global.actors.enabled", Value: "false"},
			{Path: "global.scheduler.enabled", Value: "false"},
			{Path: "global.mtls.enabled", Value: "true"},
			{Path: "global.prometheus.enabled", Value: "true"},
			{Path: "dapr_config.dapr_config_chart_included", Value: "false"},
			{Path: "dapr_sidecar_injector.sidecarRunAsNonRoot", Value: "true"},
			{Path: "dapr_sidecar_injector.sidecarReadOnlyRootFilesystem", Value: "true"},
			{Path: "dapr_sidecar_injector.sidecarDropALLCapabilities", Value: "true"},
		},
		RequiredImages: []DaprRuntimeImageRole{
			{Role: "sidecar", Repository: "ghcr.io/dapr/daprd"},
			{Role: "operator", Repository: "ghcr.io/dapr/operator"},
			{Role: "injector", Repository: "ghcr.io/dapr/injector"},
			{Role: "sentry", Repository: "ghcr.io/dapr/sentry"},
		},
		ForbiddenImageRepositories: []string{
			"ghcr.io/dapr/placement",
			"ghcr.io/dapr/scheduler",
		},
		RequireExactSourceLock:    true,
		RequireDigestPinnedImages: true,
		RequireProductZotMirror:   true,
		NetworkFetchAtRuntime:     false,
	}
}

func ValidateDaprRuntimeSourcePlan(plan DaprRuntimeSourcePlan) []string {
	issues := []string{}
	if plan.Authority != DaprRuntimeSourcePlanAuthority || plan.Version != DaprReviewedRuntimeVersion ||
		plan.UpstreamRepository != DaprUpstreamRepository || plan.UpstreamRef != DaprUpstreamRef ||
		plan.UpstreamCommit != DaprUpstreamCommit || plan.HelmChartPath != DaprHelmChartPath {
		issues = append(issues, "dapr-source-identity-invalid")
	}
	if len(plan.UpstreamCommit) != 40 {
		issues = append(issues, "dapr-source-commit-invalid")
	} else {
		for _, ch := range plan.UpstreamCommit {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				issues = append(issues, "dapr-source-commit-invalid")
				break
			}
		}
	}
	overrides := map[string]string{}
	for _, item := range plan.HelmOverrides {
		if item.Path == "" || item.Value == "" || overrides[item.Path] != "" {
			issues = append(issues, "dapr-helm-overrides-invalid")
			continue
		}
		overrides[item.Path] = item.Value
	}
	requiredOverrides := map[string]string{
		"global.actors.enabled": "false",
		"global.scheduler.enabled": "false",
		"global.mtls.enabled": "true",
		"dapr_config.dapr_config_chart_included": "false",
		"dapr_sidecar_injector.sidecarRunAsNonRoot": "true",
		"dapr_sidecar_injector.sidecarReadOnlyRootFilesystem": "true",
		"dapr_sidecar_injector.sidecarDropALLCapabilities": "true",
	}
	for path, value := range requiredOverrides {
		if overrides[path] != value {
			issues = append(issues, "dapr-required-helm-override-missing")
			break
		}
	}
	images := map[string]string{}
	repositories := map[string]bool{}
	for _, image := range plan.RequiredImages {
		role, repository := strings.TrimSpace(image.Role), strings.TrimSpace(image.Repository)
		if role == "" || repository == "" || images[role] != "" || repositories[repository] {
			issues = append(issues, "dapr-required-images-invalid")
			continue
		}
		images[role], repositories[repository] = repository, true
	}
	for role, repository := range map[string]string{
		"sidecar": "ghcr.io/dapr/daprd",
		"operator": "ghcr.io/dapr/operator",
		"injector": "ghcr.io/dapr/injector",
		"sentry": "ghcr.io/dapr/sentry",
	} {
		if images[role] != repository {
			issues = append(issues, "dapr-required-images-incomplete")
			break
		}
	}
	forbidden := map[string]bool{}
	for _, repository := range plan.ForbiddenImageRepositories {
		forbidden[strings.TrimSpace(repository)] = true
	}
	for _, repository := range []string{"ghcr.io/dapr/placement", "ghcr.io/dapr/scheduler"} {
		if !forbidden[repository] || repositories[repository] {
			issues = append(issues, "dapr-forbidden-images-invalid")
			break
		}
	}
	if !plan.RequireExactSourceLock || !plan.RequireDigestPinnedImages || !plan.RequireProductZotMirror || plan.NetworkFetchAtRuntime {
		issues = append(issues, "dapr-supply-chain-boundary-invalid")
	}
	return issues
}

const DaprRuntimeSupplyChainAuthority = "DAPR_RUNTIME_SUPPLY_CHAIN_LOCK_V1"

type DaprRuntimeImageLock struct {
	Role             string `json:"role"`
	SourceRepository string `json:"sourceRepository"`
	SourceDigest     string `json:"sourceDigest"`
	MirrorReference  string `json:"mirrorReference"`
	MirrorDigest     string `json:"mirrorDigest"`
}

type DaprRuntimeSupplyChainLock struct {
	Authority           string                 `json:"authority"`
	SourcePlanAuthority string                 `json:"sourcePlanAuthority"`
	Version             string                 `json:"version"`
	UpstreamRepository  string                 `json:"upstreamRepository"`
	UpstreamRef         string                 `json:"upstreamRef"`
	UpstreamCommit      string                 `json:"upstreamCommit"`
	SourceArchiveDigest string                 `json:"sourceArchiveDigest"`
	HelmChartDigest     string                 `json:"helmChartDigest"`
	ImageLocks          []DaprRuntimeImageLock `json:"imageLocks"`
	ZotMirrorVerified   bool                   `json:"zotMirrorVerified"`
	OfflineReplayReady  bool                   `json:"offlineReplayReady"`
	Admitted            bool                   `json:"admitted"`
}

func daprSHA256Digest(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, ch := range value[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}

func ValidateDaprRuntimeSupplyChainLock(lock DaprRuntimeSupplyChainLock) []string {
	issues := []string{}
	plan := DaprRuntimeSourcePlanModel()
	if lock.Authority != DaprRuntimeSupplyChainAuthority || lock.SourcePlanAuthority != plan.Authority ||
		lock.Version != plan.Version || lock.UpstreamRepository != plan.UpstreamRepository ||
		lock.UpstreamRef != plan.UpstreamRef || lock.UpstreamCommit != plan.UpstreamCommit {
		issues = append(issues, "dapr-supply-chain-source-identity-invalid")
	}
	if !daprSHA256Digest(lock.SourceArchiveDigest) || !daprSHA256Digest(lock.HelmChartDigest) {
		issues = append(issues, "dapr-supply-chain-source-digest-invalid")
	}
	expected := map[string]string{}
	for _, image := range plan.RequiredImages {
		expected[image.Role] = image.Repository
	}
	seenRoles := map[string]bool{}
	seenSources := map[string]bool{}
	for _, image := range lock.ImageLocks {
		role := strings.TrimSpace(image.Role)
		repository := strings.TrimSpace(image.SourceRepository)
		if expected[role] == "" || expected[role] != repository || seenRoles[role] || seenSources[repository] {
			issues = append(issues, "dapr-supply-chain-image-identity-invalid")
			continue
		}
		if !daprSHA256Digest(image.SourceDigest) || !daprSHA256Digest(image.MirrorDigest) || image.SourceDigest != image.MirrorDigest {
			issues = append(issues, "dapr-supply-chain-image-digest-invalid")
		}
		mirror := strings.TrimSpace(image.MirrorReference)
		if mirror == "" || !strings.Contains(mirror, "@"+image.MirrorDigest) || !strings.Contains(mirror, "/dapr/") {
			issues = append(issues, "dapr-supply-chain-mirror-reference-invalid")
		}
		seenRoles[role], seenSources[repository] = true, true
	}
	if len(seenRoles) != len(expected) {
		issues = append(issues, "dapr-supply-chain-image-set-incomplete")
	}
	if !lock.ZotMirrorVerified || !lock.OfflineReplayReady {
		issues = append(issues, "dapr-supply-chain-mirror-evidence-incomplete")
	}
	expectedAdmitted := len(issues) == 0
	if lock.Admitted != expectedAdmitted {
		issues = append(issues, "dapr-supply-chain-admission-claim-invalid")
	}
	return issues
}

func DaprRuntimeSupplyChainAdmitted(lock DaprRuntimeSupplyChainLock) bool {
	return len(ValidateDaprRuntimeSupplyChainLock(lock)) == 0 && lock.Admitted
}

const (
	DaprTargetAdmissionAuthority       = "DAPR_TARGET_ADMISSION_V1"
	DaprSidecarSecurityCapability      = "application-runtime.dapr-sidecar-security-compatible"
	DaprComponentScopeCapability       = "application-runtime.dapr-component-scope-enforced"
	DaprResourceSizingCapability       = "application-runtime.dapr-resource-sizing-ready"
)

type DaprTargetAdmissionInput struct {
	DistributionIdentity        string   `json:"distributionIdentity"`
	TargetAdmitted              bool     `json:"targetAdmitted"`
	TargetMutationReady         bool     `json:"targetMutationReady"`
	CapabilityDiscoveryComplete bool     `json:"capabilityDiscoveryComplete"`
	ObservedCapabilities        []string `json:"observedCapabilities,omitempty"`
	ExactSourceAdmitted         bool     `json:"exactSourceAdmitted"`
	Disconnected                bool     `json:"disconnected"`
	DisconnectedMirrorAdmitted  bool     `json:"disconnectedMirrorAdmitted"`
	DurableLifecycleReady       bool     `json:"durableLifecycleReady"`
}

type DaprTargetAdmission struct {
	Authority                     string   `json:"authority"`
	Capability                    string   `json:"capability"`
	Eligible                      bool     `json:"eligible"`
	Mode                          string   `json:"mode"`
	DistributionIdentity          string   `json:"distributionIdentity"`
	InstallSuppressed             bool     `json:"installSuppressed"`
	Blockers                      []string `json:"blockers,omitempty"`
	PhysicalCertificationInferred bool     `json:"physicalCertificationInferred"`
}

func EvaluateDaprTargetAdmission(in DaprTargetAdmissionInput) DaprTargetAdmission {
	distribution := strings.ToLower(strings.TrimSpace(in.DistributionIdentity))
	out := DaprTargetAdmission{
		Authority: DaprTargetAdmissionAuthority, Capability: DaprApplicationRuntimeCapability,
		DistributionIdentity: distribution, Mode: "INSTALL_REQUIRED",
	}
	switch distribution {
	case "rke2", "okd":
	default:
		out.Blockers = append(out.Blockers, "UNSUPPORTED_TARGET_DISTRIBUTION")
	}
	if !in.TargetAdmitted {
		out.Blockers = append(out.Blockers, "TARGET_NOT_ADMITTED")
	}
	if !in.TargetMutationReady {
		out.Blockers = append(out.Blockers, "TARGET_MUTATION_RBAC_NOT_READY")
	}
	if !in.CapabilityDiscoveryComplete {
		out.Blockers = append(out.Blockers, "CAPABILITY_DISCOVERY_INCOMPLETE")
	}
	capabilities := map[string]bool{}
	for _, raw := range in.ObservedCapabilities {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != "" {
			capabilities[value] = true
		}
	}
	if capabilities[DaprApplicationRuntimeCapability] {
		out.Mode = "USE_NATIVE"
		out.InstallSuppressed = true
	} else {
		if !in.ExactSourceAdmitted {
			out.Blockers = append(out.Blockers, "DAPR_EXACT_SOURCE_AUTHORITY_PENDING")
		}
		if in.Disconnected && !in.DisconnectedMirrorAdmitted {
			out.Blockers = append(out.Blockers, "DAPR_DISCONNECTED_MIRROR_PENDING")
		}
	}
	if !capabilities[DaprSidecarSecurityCapability] {
		out.Blockers = append(out.Blockers, "DAPR_SIDECAR_SECURITY_COMPATIBILITY_PENDING")
	}
	if !capabilities[DaprComponentScopeCapability] {
		out.Blockers = append(out.Blockers, "DAPR_COMPONENT_SCOPE_ENFORCEMENT_PENDING")
	}
	if !capabilities[DaprResourceSizingCapability] {
		out.Blockers = append(out.Blockers, "DAPR_RESOURCE_SIZING_PENDING")
	}
	if out.Mode == "INSTALL_REQUIRED" && !in.DurableLifecycleReady {
		out.Blockers = append(out.Blockers, "DAPR_DURABLE_LIFECYCLE_CONTRACT_PENDING")
	}
	sort.Strings(out.Blockers)
	out.Eligible = len(out.Blockers) == 0
	return out
}
