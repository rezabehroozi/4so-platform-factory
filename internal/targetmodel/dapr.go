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
