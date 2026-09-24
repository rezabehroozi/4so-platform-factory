package targetmodel

import (
	"fmt"
	"sort"
	"strings"
)

const OpenChoreoReferenceAuthority = "OPENCHOREO_REFERENCE_ADOPTION_V1"

type OpenChoreoAdoptionDecision string

const (
	OpenChoreoAdaptPattern            OpenChoreoAdoptionDecision = "ADAPT_PATTERN"
	OpenChoreoAuditSelectiveReuse     OpenChoreoAdoptionDecision = "AUDIT_SELECTIVE_REUSE"
	OpenChoreoExtendExistingAuthority OpenChoreoAdoptionDecision = "EXTEND_EXISTING_AUTHORITY"
	OpenChoreoOptionalTargetAdapter   OpenChoreoAdoptionDecision = "OPTIONAL_TARGET_ADAPTER"
	OpenChoreoRejectCoreReplacement   OpenChoreoAdoptionDecision = "REJECT_AS_CORE_REPLACEMENT"
)

type OpenChoreoReferencePattern struct {
	ID               string                     `json:"id"`
	UpstreamConcept  string                     `json:"upstreamConcept"`
	Decision         OpenChoreoAdoptionDecision `json:"decision"`
	FourSOConcept    string                     `json:"fourSoConcept"`
	OwnerPhases      []string                   `json:"ownerPhases"`
	UpstreamMaturity string                     `json:"upstreamMaturity,omitempty"`
	Requirements     []string                   `json:"requirements"`
}

type OpenChoreoOptionalAdapterDescriptor struct {
	Capability       string   `json:"capability"`
	Status           string   `json:"status"`
	DefaultEnabled   bool     `json:"defaultEnabled"`
	TargetOnly       bool     `json:"targetOnly"`
	Preconditions    []string `json:"preconditions"`
	ForbiddenEffects []string `json:"forbiddenEffects"`
}

type OpenChoreoAdoptionDescriptor struct {
	Authority                   string                              `json:"authority"`
	ReviewedDate                string                              `json:"reviewedDate"`
	DocsBaseline                string                              `json:"docsBaseline"`
	UpstreamRepository          string                              `json:"upstreamRepository"`
	ReviewedUpstreamCommit      string                              `json:"reviewedUpstreamCommit"`
	Role                        string                              `json:"role"`
	PostgreSQLSoTPreserved      bool                                `json:"postgresqlSoTPreserved"`
	ManagementPlaneRemainsRKE2  bool                                `json:"managementPlaneRemainsRke2"`
	BuildKitZotCanonical        bool                                `json:"buildKitZotCanonical"`
	KeycloakCanonical           bool                                `json:"keycloakCanonical"`
	OperatorConsoleProductOwned bool                                `json:"operatorConsoleProductOwned"`
	Patterns                    []OpenChoreoReferencePattern        `json:"patterns"`
	ForbiddenCoreReplacements   []string                            `json:"forbiddenCoreReplacements"`
	OptionalAdapter             OpenChoreoOptionalAdapterDescriptor `json:"optionalAdapter"`
}

func OpenChoreoAdoptionModel() OpenChoreoAdoptionDescriptor {
	patterns := []OpenChoreoReferencePattern{
		{
			ID: "component-type-trait", UpstreamConcept: "ComponentType + Trait", Decision: OpenChoreoAdaptPattern,
			FourSOConcept: "product-owned WorkloadType plus composable CapabilityTrait overlays resolved through existing Blueprint/Catalog capability ownership",
			OwnerPhases: []string{"E-certified-platform-template-workspace-foundation", "J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"base workload schema and trait schema are immutable/versioned product authority",
				"traits compose cross-cutting storage, ingress, autoscale, observability and security intent without multiplying blueprint variants",
				"target capability resolution may suppress or translate a trait when the distribution already owns the capability",
			},
		},
		{
			ID: "resource-type", UpstreamConcept: "ResourceType", Decision: OpenChoreoAdaptPattern,
			FourSOConcept: "ManagedResourceType intent over Product API adapters for database, cache, queue, object storage, external DBaaS or Crossplane-backed resources",
			OwnerPhases: []string{"E-certified-platform-template-workspace-foundation", "J1-automation-external-integrations", "J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"PostgreSQL remains desired/lifecycle authority and a target CRD or Crossplane claim is executor state only",
				"outputs are typed references and secret material is represented only by secret references, never copied into catalog/template authority",
				"retention/delete policy and readiness conditions are explicit before a resource can be bound to an environment",
			},
		},
		{
			ID: "project-type", UpstreamConcept: "ProjectType", Decision: OpenChoreoAdaptPattern,
			FourSOConcept: "WorkspaceProfile composing quota, RBAC, NetworkPolicy, security, backup, observability, catalog allow-list, virtual-cluster and cost policy",
			OwnerPhases: []string{"E-certified-platform-template-workspace-foundation", "J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"WorkspaceProfile is immutable/versioned and references existing policy authorities rather than persisting runtime truth",
				"environment-specific values are bounded typed configuration, not an unrestricted templating language",
				"resolved namespace/project resources remain owned by their existing runtime authorities",
			},
		},
		{
			ID: "immutable-release-binding", UpstreamConcept: "ComponentRelease/ResourceRelease + ReleaseBinding", Decision: OpenChoreoAdaptPattern,
			FourSOConcept: "Desired Resource -> Immutable Release -> Environment Binding -> Resolved Capability Set -> Rendered Runtime -> Observed Runtime",
			OwnerPhases: []string{"E-certified-platform-template-workspace-foundation", "J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"promotion creates or advances an explicit binding and never mutates an immutable release snapshot",
				"binding records target/environment identity, authority digests and resolved capability decisions",
				"rendered and observed runtime are derived evidence and cannot overwrite desired product authority",
			},
		},
		{
			ID: "cluster-agent-gateway", UpstreamConcept: "outbound cluster-agent + cluster-gateway", Decision: OpenChoreoAuditSelectiveReuse,
			FourSOConcept: "Fleet Agent transport hardening over existing 4SO enrollment, certificate, inventory, task-fence and durable-operation authorities",
			OwnerPhases: []string{"G1-operational-runtime-hardening", "J6-fleet-reliability-incident-intelligence", "J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"target initiates outbound-only persistent transport where streaming is selected; inbound target management ports are not required",
				"mutual TLS identity, certificate rotation/revocation and project/cluster binding are mandatory",
				"heartbeat, reconnect backoff, session epoch, gateway draining and duplicate-session handling are explicit",
				"stream transport never bypasses existing task lease, mutation fence, dispatch acknowledgement or recovery-required semantics",
			},
		},
		{
			ID: "mcp-authorization", UpstreamConcept: "MCP toolsets + delegated authorization", Decision: OpenChoreoAuditSelectiveReuse,
			FourSOConcept: "typed 4SO MCP action registry and effective tool filtering over Product API/RBAC/delegation grants",
			OwnerPhases: []string{"C7-ai-mcp-delegated-operations", "C7W-mcp-user-admin-write-parity", "J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"end-user identity is re-authorized by Product API for every protected request",
				"tool filtering improves discoverability but is never the authorization boundary",
				"mutating AI/MCP actions create the same durable fenced jobs used by UI/API",
			},
		},
		{
			ID: "ai-operator-patterns", UpstreamConcept: "SRE Agent + FinOps Agent + Portal Assistant", Decision: OpenChoreoExtendExistingAuthority,
			FourSOConcept: "Operator Diagnosis, Failure RCA, FinOps, Capacity, Upgrade and Recovery advisors over existing evidence/read models",
			OwnerPhases: []string{"C7-ai-mcp-delegated-operations", "J6-fleet-reliability-incident-intelligence", "J7-finops-v2-budget-forecast-rightsizing", "J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"assistant/read paths remain evidence-grounded and resource-scoped",
				"AI never becomes lifecycle authority; proposals flow through Product API preview, approval, durable operation and evidence",
				"provider/model egress remains policy-controlled and disconnected profiles can select local inference",
			},
		},
		{
			ID: "cost-insights", UpstreamConcept: "Cost Insights", Decision: OpenChoreoExtendExistingAuthority,
			FourSOConcept: "derived FinOps attribution/right-sizing views over FINOPS_USAGE_MEASUREMENT and versioned rate-card authority",
			OwnerPhases: []string{"J2-finops-usage", "J7-finops-v2-budget-forecast-rightsizing", "J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"missing telemetry is missing, never numeric zero",
				"virtual-cluster/workspace/project attribution reuses measured evidence and existing immutable scope guards",
				"new cost dimensions remain explicitly unsupported until measured and rate-covered",
			},
		},
		{
			ID: "delivery-insights", UpstreamConcept: "Delivery Insights / DORA", Decision: OpenChoreoExtendExistingAuthority,
			FourSOConcept: "derived delivery-intelligence projection linked to releases, durable operations, incidents and audit evidence",
			OwnerPhases: []string{"J6-fleet-reliability-incident-intelligence", "J8-application-platform-abstraction-composition"},
			UpstreamMaturity: "ALPHA_REFERENCE",
			Requirements: []string{
				"DORA metrics are projections from timestamped release/deployment/incident evidence and never hand-entered success counters",
				"query windows, populations and missing-data state are explicit",
				"delivery analytics cannot become a release or physical-certification gate without independent 4SO validation",
			},
		},
		{
			ID: "audit-logging", UpstreamConcept: "separate audit logging", Decision: OpenChoreoExtendExistingAuthority,
			FourSOConcept: "existing append-only scoped 4SO Audit authority with independent retention/export projections",
			OwnerPhases: []string{"G5-enterprise-identity-compliance", "J6-fleet-reliability-incident-intelligence", "J8-application-platform-abstraction-composition"},
			UpstreamMaturity: "BETA_REFERENCE",
			Requirements: []string{
				"audit events remain separate from operational log search and preserve actor/action/resource/result scope",
				"MCP, UI, API and automation mutations converge on the same product audit authority",
				"external search/export backends are rebuildable projections and cannot replace PostgreSQL audit authority",
			},
		},
		{
			ID: "air-gap", UpstreamConcept: "air-gapped plane installation", Decision: OpenChoreoAuditSelectiveReuse,
			FourSOConcept: "4SO disconnected acquire -> verify -> digest-pin -> inventory -> mirror -> seal -> admission pipeline",
			OwnerPhases: []string{"B-target-capability-supplychain-foundation", "S1-exact-supply-chain-acquisition-closure", "I1-disconnected-okd-core"},
			Requirements: []string{
				"no hidden internet dependency is permitted after seal",
				"application/base/builder images are part of explicit acquisition planning when a selected profile consumes them",
				"4SO keeps stricter exact-byte/source-lock and independent verification semantics",
			},
		},
		{
			ID: "optional-openchoreo-target", UpstreamConcept: "OpenChoreo application platform", Decision: OpenChoreoOptionalTargetAdapter,
			FourSOConcept: "optional managed Application Platform capability installed on an admitted 4SO-managed target",
			OwnerPhases: []string{"J8-application-platform-abstraction-composition"},
			Requirements: []string{
				"disabled by default and never installed on the 4SO management plane",
				"target distribution/capability discovery suppresses duplicate networking, monitoring, tenancy and ingress stacks",
				"4SO remains cluster/product lifecycle authority; the optional platform owns only its bounded application-platform runtime",
			},
		},
	}
	sort.Slice(patterns, func(i, j int) bool { return patterns[i].ID < patterns[j].ID })
	return OpenChoreoAdoptionDescriptor{
		Authority:                   OpenChoreoReferenceAuthority,
		ReviewedDate:                "2026-09-24",
		DocsBaseline:                "v1.3.x",
		UpstreamRepository:          "https://github.com/openchoreo/openchoreo",
		ReviewedUpstreamCommit:      "178dfbde3e3343e5ac151b88a2f203f523f97480",
		Role:                        "reference-implementation-and-optional-target-adapter-not-control-plane-authority",
		PostgreSQLSoTPreserved:      true,
		ManagementPlaneRemainsRKE2:  true,
		BuildKitZotCanonical:        true,
		KeycloakCanonical:           true,
		OperatorConsoleProductOwned: true,
		Patterns:                    patterns,
		ForbiddenCoreReplacements: []string{
			"backstage-as-4so-operator-console",
			"git-or-kubernetes-crds-as-4so-product-sot",
			"mandatory-argo-workflows-or-buildpacks-build-plane",
			"openchoreo-control-plane-as-4so-control-plane",
			"openchoreo-observability-stack-as-okd-default",
			"openchoreo-registry-as-zot-replacement",
			"openchoreo-secret-plane-as-product-secret-authority",
			"thunderid-as-keycloak-replacement",
		},
		OptionalAdapter: OpenChoreoOptionalAdapterDescriptor{
			Capability:     "application-platform.openchoreo",
			Status:         "PLANNED_SOURCE_ADAPTER_NOT_RUNTIME_ADMITTED",
			DefaultEnabled: false,
			TargetOnly:     true,
			Preconditions: []string{
				"admitted target distribution and infrastructure identity",
				"capability discovery and duplicate-stack resolution complete",
				"exact source/image/chart acquisition and disconnected mirror admission complete",
				"Product API durable install/upgrade/remove operation contract implemented",
			},
			ForbiddenEffects: []string{
				"change management-plane distribution",
				"replace PostgreSQL, Forgejo, zot or Keycloak authority",
				"install duplicate OKD networking, monitoring or tenancy defaults",
				"make Argo Workflows or Buildpacks a Factory build-plane dependency",
			},
		},
	}
}

func ValidateOpenChoreoAdoption(model OpenChoreoAdoptionDescriptor) []string {
	issues := []string{}
	if model.Authority != OpenChoreoReferenceAuthority {
		issues = append(issues, "authority-invalid")
	}
	if model.DocsBaseline != "v1.3.x" || len(model.ReviewedUpstreamCommit) != 40 || strings.Trim(model.ReviewedUpstreamCommit, "0123456789abcdef") != "" {
		issues = append(issues, "upstream-review-identity-invalid")
	}
	if !model.PostgreSQLSoTPreserved || !model.ManagementPlaneRemainsRKE2 || !model.BuildKitZotCanonical || !model.KeycloakCanonical || !model.OperatorConsoleProductOwned {
		issues = append(issues, "canonical-authority-regression")
	}
	if model.OptionalAdapter.DefaultEnabled || !model.OptionalAdapter.TargetOnly || model.OptionalAdapter.Capability != "application-platform.openchoreo" {
		issues = append(issues, "optional-adapter-boundary-invalid")
	}
	allowed := map[OpenChoreoAdoptionDecision]bool{
		OpenChoreoAdaptPattern: true, OpenChoreoAuditSelectiveReuse: true, OpenChoreoExtendExistingAuthority: true,
		OpenChoreoOptionalTargetAdapter: true, OpenChoreoRejectCoreReplacement: true,
	}
	seen := map[string]bool{}
	optionalCount := 0
	for _, pattern := range model.Patterns {
		if strings.TrimSpace(pattern.ID) == "" || seen[pattern.ID] {
			issues = append(issues, "pattern-identity-invalid:"+pattern.ID)
			continue
		}
		seen[pattern.ID] = true
		if !allowed[pattern.Decision] || len(pattern.OwnerPhases) == 0 || len(pattern.Requirements) == 0 {
			issues = append(issues, fmt.Sprintf("pattern-contract-incomplete:%s", pattern.ID))
		}
		if pattern.Decision == OpenChoreoOptionalTargetAdapter {
			optionalCount++
		}
	}
	for _, required := range []string{"component-type-trait", "resource-type", "project-type", "immutable-release-binding", "cluster-agent-gateway", "mcp-authorization", "ai-operator-patterns", "cost-insights", "delivery-insights", "audit-logging", "air-gap", "optional-openchoreo-target"} {
		if !seen[required] {
			issues = append(issues, "required-pattern-missing:"+required)
		}
	}
	if optionalCount != 1 {
		issues = append(issues, "optional-adapter-cardinality-invalid")
	}
	forbidden := map[string]bool{}
	for _, item := range model.ForbiddenCoreReplacements {
		forbidden[item] = true
	}
	for _, required := range []string{"openchoreo-control-plane-as-4so-control-plane", "git-or-kubernetes-crds-as-4so-product-sot", "mandatory-argo-workflows-or-buildpacks-build-plane", "openchoreo-observability-stack-as-okd-default", "thunderid-as-keycloak-replacement", "backstage-as-4so-operator-console"} {
		if !forbidden[required] {
			issues = append(issues, "forbidden-boundary-missing:"+required)
		}
	}
	sort.Strings(issues)
	return issues
}


const OpenChoreoTargetAdapterAdmissionAuthority = "OPENCHOREO_TARGET_ADAPTER_ADMISSION_V1"

type OpenChoreoTargetAdapterAdmissionInput struct {
	DistributionIdentity        string   `json:"distributionIdentity"`
	TargetAdmitted              bool     `json:"targetAdmitted"`
	TargetMutationReady          bool     `json:"targetMutationReady"`
	ExecutorRBACReady            bool     `json:"executorRbacReady"`
	CertificateManagerReady      bool     `json:"certificateManagerReady"`
	CapabilityDiscoveryComplete bool     `json:"capabilityDiscoveryComplete"`
	ObservedCapabilities        []string `json:"observedCapabilities,omitempty"`
	ExactSourceAdmitted         bool     `json:"exactSourceAdmitted"`
	Disconnected                bool     `json:"disconnected"`
	DisconnectedMirrorAdmitted  bool     `json:"disconnectedMirrorAdmitted"`
	DurableLifecycleReady       bool     `json:"durableLifecycleReady"`
	DuplicateStackResolved      bool     `json:"duplicateStackResolved"`
}

type OpenChoreoTargetAdapterAdmission struct {
	Authority                     string   `json:"authority"`
	Capability                    string   `json:"capability"`
	Eligible                      bool     `json:"eligible"`
	DistributionIdentity          string   `json:"distributionIdentity"`
	Blockers                      []string `json:"blockers,omitempty"`
	NativeCapabilitySuppressions  []string `json:"nativeCapabilitySuppressions,omitempty"`
	PhysicalCertificationInferred bool     `json:"physicalCertificationInferred"`
}

func EvaluateOpenChoreoTargetAdapterAdmission(in OpenChoreoTargetAdapterAdmissionInput) OpenChoreoTargetAdapterAdmission {
	distribution := strings.ToLower(strings.TrimSpace(in.DistributionIdentity))
	out := OpenChoreoTargetAdapterAdmission{Authority: OpenChoreoTargetAdapterAdmissionAuthority, Capability: "application-platform.openchoreo", DistributionIdentity: distribution}
	switch distribution { case "rke2", "okd": default: out.Blockers = append(out.Blockers, "UNSUPPORTED_TARGET_DISTRIBUTION") }
	if !in.TargetAdmitted { out.Blockers = append(out.Blockers, "TARGET_NOT_ADMITTED") }
	if !in.TargetMutationReady { out.Blockers = append(out.Blockers, "TARGET_MUTATION_RBAC_NOT_READY") }
	if !in.ExecutorRBACReady { out.Blockers = append(out.Blockers, "OPENCHOREO_EXECUTOR_RBAC_NOT_READY") }
	if !in.CertificateManagerReady { out.Blockers = append(out.Blockers, "OPENCHOREO_CERT_MANAGER_CAPABILITY_PENDING") }
	if !in.CapabilityDiscoveryComplete { out.Blockers = append(out.Blockers, "CAPABILITY_DISCOVERY_INCOMPLETE") }
	if !in.DuplicateStackResolved { out.Blockers = append(out.Blockers, "DUPLICATE_STACK_RESOLUTION_INCOMPLETE") }
	if !in.ExactSourceAdmitted { out.Blockers = append(out.Blockers, "OPENCHOREO_EXACT_SOURCE_AUTHORITY_PENDING") }
	if in.Disconnected && !in.DisconnectedMirrorAdmitted { out.Blockers = append(out.Blockers, "OPENCHOREO_DISCONNECTED_MIRROR_PENDING") }
	if !in.DurableLifecycleReady { out.Blockers = append(out.Blockers, "OPENCHOREO_DURABLE_LIFECYCLE_CONTRACT_PENDING") }
	seen := map[string]bool{}
	for _, raw := range in.ObservedCapabilities {
		capability := strings.ToLower(strings.TrimSpace(raw)); suppression := ""
		switch {
		case strings.HasPrefix(capability, "networking.") || strings.Contains(capability, "ingress"): suppression = "networking-and-ingress-native"
		case strings.HasPrefix(capability, "monitoring.") || strings.HasPrefix(capability, "observability."): suppression = "observability-native"
		case strings.HasPrefix(capability, "operator-lifecycle.") || strings.Contains(capability, "olm"): suppression = "operator-lifecycle-native"
		case strings.HasPrefix(capability, "tenancy.") || strings.Contains(capability, "project"): suppression = "tenancy-native"
		}
		if suppression != "" && !seen[suppression] { seen[suppression] = true; out.NativeCapabilitySuppressions = append(out.NativeCapabilitySuppressions, suppression) }
	}
	sort.Strings(out.NativeCapabilitySuppressions); sort.Strings(out.Blockers); out.Eligible = len(out.Blockers)==0
	return out
}
