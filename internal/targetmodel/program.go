package targetmodel

import (
	"sort"
	"strings"
)

const (
	ProgramAuthorityMethod                = "PROGRAM_PHASE_MODEL_V73"
	ProgramProgressAuthority              = "PROGRAM_PROGRESS_MODEL_V2"
	CapabilityResolverAuthority           = "TARGET_CAPABILITY_RESOLVER_V1"
	FeatureCertificationRegistryAuthority = "FEATURE_CERTIFICATION_REGISTRY_V2"
	FeatureCertificationCoverageAuthority = "FEATURE_CERTIFICATION_CONTRACT_COVERAGE_V1"

	ProgramStatusSourceImplemented = "source-implemented"
	ProgramStatusBlocked           = "blocked"
	ProgramStatusNotEvaluated      = "not-evaluated"
	ProgramStatusDeferred          = "deferred-until-development-closure"

	ProgramSourceStatusImplemented = "source-implemented"
	ProgramSourceStatusOpen        = "source-open"
	ProgramClosureStatusReady      = "ready"
	ProgramClosureStatusBlocked    = "blocked"
	ProgramClosureStatusDeferred   = "deferred"
	ProgramClosureStatusPending    = "not-evaluated"

	ProgramTierCoreFreeze    = "core-freeze"
	ProgramTierExpansion     = "expansion"
	ProgramTierCertification = "certification"
	ProgramTierOptional      = "optional"

	ResolutionActionInclude     = "include"
	ResolutionActionSuppress    = "suppress"
	ResolutionActionConditional = "conditional"
)

type ProgramPhase struct {
	ID                       string   `json:"id"`
	Order                    int      `json:"order"`
	Status                   string   `json:"status"` // legacy compatibility alias; use sourceStatus/closureStatus for roadmap truth
	SourceStatus             string   `json:"sourceStatus"`
	ClosureStatus            string   `json:"closureStatus"`
	DeliveryTier             string   `json:"deliveryTier"`
	Objective                string   `json:"objective"`
	RequiredForFeatureFreeze bool     `json:"requiredForFeatureFreeze"`
	DependsOn                []string `json:"dependsOn,omitempty"`
	ParallelWith             []string `json:"parallelWith,omitempty"`
	Blockers                 []string `json:"blockers,omitempty"`
	Evidence                 []string `json:"evidence,omitempty"`
	ExitCriteria             []string `json:"exitCriteria,omitempty"`
}

type ProgramExecutionWave struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Objective   string   `json:"objective"`
	PhaseIDs    []string `json:"phaseIds"`
	MaxParallel int      `json:"maxParallel"`
}

type ProgramTrack struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Objective    string   `json:"objective"`
	Requirements []string `json:"requirements"`
}

type FeatureCertificationRequirement struct {
	Feature           string   `json:"feature"`
	OwnerPhases       []string `json:"ownerPhases"`
	RequiredLevels    []string `json:"requiredLevels"`
	PhysicalScenarios []string `json:"physicalScenarios,omitempty"`
	NegativeControls  []string `json:"negativeControls"`
}

type FeatureCertificationCoverage struct {
	Authority           string   `json:"authority"`
	RequiredOwnerPhases int      `json:"requiredOwnerPhases"`
	CoveredOwnerPhases  int      `json:"coveredOwnerPhases"`
	MissingOwnerPhases  []string `json:"missingOwnerPhases"`
	Complete            bool     `json:"complete"`
}

const (
	CertificationSourceSemantics         = "source-semantics"
	CertificationGeneratedRuntime        = "generated-installed-runtime"
	CertificationRuntimeRealism          = "runtime-realism-negative-controls"
	CertificationIntegrationLab          = "integration-lab"
	CertificationExactSHAPhysicalRuntime = "exact-sha-physical-runtime"
	CertificationChaosLoadSoak           = "chaos-load-soak"
)

type ProgramProgressSummary struct {
	Authority                         string         `json:"authority"`
	CoreRequiredPhases                int            `json:"coreRequiredPhases"`
	CoreSourceClosedPhases            int            `json:"coreSourceClosedPhases"`
	CoreSourceOpenPhases              int            `json:"coreSourceOpenPhases"`
	CorePhaseReady                    int            `json:"corePhaseReady"`
	CorePhaseBlocked                  int            `json:"corePhaseBlocked"`
	CoreSourceClosurePercent          int            `json:"coreSourceClosurePercent"`
	CorePhaseReadyPercent             int            `json:"corePhaseReadyPercent"`
	CoreSourceClosureComplete         bool           `json:"coreSourceClosureComplete"`
	FeatureFreezeReady                bool           `json:"featureFreezeReady"`
	PrePhysicalSoftwarePhases         int            `json:"prePhysicalSoftwarePhases"`
	PrePhysicalSoftwareClosedPhases   int            `json:"prePhysicalSoftwareClosedPhases"`
	PrePhysicalSoftwareOpenPhases     int            `json:"prePhysicalSoftwareOpenPhases"`
	PrePhysicalSoftwareClosurePercent int            `json:"prePhysicalSoftwareClosurePercent"`
	SourceOpenPhaseIDs                []string       `json:"sourceOpenPhaseIds"`
	ExternalClosureOnlyPhaseIDs       []string       `json:"externalClosureOnlyPhaseIds"`
	RemainingBlockerClasses           map[string]int `json:"remainingBlockerClasses"`
}

type ProgramRoadmap struct {
	Authority                      string                            `json:"authority"`
	CurrentPhase                   string                            `json:"currentPhase"`
	CurrentExecutionWave           string                            `json:"currentExecutionWave"`
	ExecutionWaves                 []ProgramExecutionWave            `json:"executionWaves"`
	GoalReady                      bool                              `json:"goalReady"`
	Positioning                    string                            `json:"positioning"`
	PrimaryBenchmarks              []string                          `json:"primaryBenchmarks"`
	CompetitiveDifferentiators     []string                          `json:"competitiveDifferentiators"`
	DeferredParity                 []string                          `json:"deferredParity"`
	Tracks                         []ProgramTrack                    `json:"tracks"`
	GlobalGuardrails               []string                          `json:"globalGuardrails"`
	CertificationRegistryAuthority string                            `json:"certificationRegistryAuthority"`
	CertificationRegistry          []FeatureCertificationRequirement `json:"certificationRegistry"`
	CertificationCoverage          FeatureCertificationCoverage      `json:"certificationCoverage"`
	Progress                       ProgramProgressSummary            `json:"progress"`
	Phases                         []ProgramPhase                    `json:"phases"`
}

type CapabilityResolverDescriptor struct {
	Authority       string   `json:"authority"`
	Status          string   `json:"status"`
	AdmittedTargets []string `json:"admittedTargets"`
	PreviewTargets  []string `json:"previewTargets"`
}

type CapabilityDecision struct {
	Component string `json:"component"`
	Action    string `json:"action"`
	Domain    string `json:"domain"`
	Authority string `json:"authority"`
	Reason    string `json:"reason"`
}

type CapabilityResolution struct {
	Authority             string               `json:"authority"`
	DistributionIdentity  string               `json:"distributionIdentity"`
	Status                string               `json:"status"`
	Admitted              bool                 `json:"admitted"`
	IntrinsicCapabilities []string             `json:"intrinsicCapabilities,omitempty"`
	Decisions             []CapabilityDecision `json:"decisions"`
	Blockers              []string             `json:"blockers,omitempty"`
}

func ProgramRoadmapModel() ProgramRoadmap {
	const dataScalePhase = "C2-console-data-scale-refresh-semantics"
	const actionPhase = "C3-console-action-workflow-evidence-convergence"
	const c4Phase = "C4-console-e2e-ux-certification"
	const c5Phase = "C5-installer-production-lifecycle-closure"
	const c7Phase = "C7-ai-mcp-delegated-operations"
	const c7OAuthPhase = "C7R-mcp-remote-oauth-human-delegation"
	const c7ParityPhase = "C7W-mcp-user-admin-write-parity"
	const c8Phase = "C8-console-operational-completion"
	const fPhase = "F-okd-import-capability-certification"
	const currentPhase = "S1-exact-supply-chain-acquisition-closure"
	const operatorScopePhase = "C1-operator-ia-scope-authority"
	positioning := "Enterprise / Sovereign Platform Factory: turn raw or existing infrastructure into certified, repeatable application platforms with deterministic supply chain, durable lifecycle operations, evidence and bounded AI assistance."
	primaryBenchmarks := []string{
		"Spectro Cloud Palette — primary product information-architecture, profile/template/workspace and lifecycle benchmark",
		"Rafay Platform — secondary benchmark for dense multi-cluster operations, self-service and usage visibility",
		"SUSE Rancher Prime — targeted benchmark for Kubernetes resource exploration and cluster ergonomics",
		"Mirantis k0rdent — targeted benchmark for template-driven platform engineering without adopting its control-plane authority model",
		"OpenChoreo v1.3 — reference implementation for workload/resource/project abstractions, immutable release bindings, multi-cluster agent/gateway transport, MCP authorization and AI/insight patterns; never a replacement for 4SO product authority",
		"shadcn/ui — implementation benchmark for open-code, product-owned UI primitives and accessible component composition; no React/Tailwind runtime migration is implied",
		"Novu — communication workflow/channel/agent benchmark; external communication systems remain adapters and never become 4SO control-plane authority",
		"LangChain OpenWiki — benchmark for source-grounded agent knowledge, durable refresh and stale-claim detection; generated knowledge is never product authority",
		"Archify — benchmark for typed deterministic architecture evidence and before/delta/after review; diagrams remain derived from 4SO authority",
		"Chrome DevTools MCP — benchmark for isolated browser triage and performance debugging in the developer Autopilot, never a production control-plane dependency",
		"OpenSearch — optional search/analytics projection benchmark for logs, traces and agent retrieval; PostgreSQL/evidence remain authoritative and projection rebuildability is mandatory",
		"Salsi — Persian editorial/normalization benchmark used only for safe localization QA with a 4SO-owned technical glossary; no external lexicon is shipped by default",
	}
	competitiveDifferentiators := []string{
		"Certified Platform Templates bind configuration, variables, lifecycle policy, supply-chain locks and runtime-certification requirements instead of treating templates as configuration-only objects.",
		"PostgreSQL product authority, Forgejo desired-state history, Argo reconciliation and zot registry authority remain explicit and non-overlapping.",
		"Every mutating workflow is a durable, fenced, retry/recovery-aware operation with impact preview, approval and evidence rather than an opaque imperative action.",
		"Exact source/byte locks, image digests, SBOM, license and provenance are product-owned supply-chain authority and feed release/runtime certification.",
		"The four-layer Release Gate keeps source, generated runtime, realism negative controls and Exact-SHA physical execution independent; Physical PASS is never inferred.",
		"Distribution capability ownership suppresses duplicate platform stacks and makes RKE2, OKD and imported Kubernetes target behavior explainable rather than hard-coded per product edition.",
		"AI is an evidence-linked Operator that diagnoses and proposes bounded actions but cannot become source of truth, bypass RBAC or directly execute arbitrary shell/kubectl mutations.",
		"Disconnected and sovereign operation are architecture constraints, not packaging afterthoughts.",
	}
	deferredParity := []string{
		"Hosted multi-tenant SaaS control plane is not a current product goal; self-contained private/sovereign deployment remains primary.",
		"AWS/Azure/GCP source adapters are active pre-physical expansion work; runtime support claims remain deferred until each provider has independent exact-runtime certification.",
		"Terraform remains the first external IaC implementation; Crossplane follows over the same Product API/SDK authority and may not become an independent lifecycle source of truth.",
		"VMware-to-KubeVirt migration is deferred until an optional VM workload plane itself is certified.",
		"GPU model serving / inference platform features are deferred until accelerator inventory, quota, placement and lifecycle primitives exist.",
		"Full MCP product-operation coverage is required for authorized users/admins, but arbitrary raw shell/SSH/SQL/database/secret authority remains explicitly rejected; delegated mutations must create the same deterministic product jobs used by UI/API.",
		"Generated wiki/diagram/search indexes are derived projections and are never canonical product state; losing them must not destroy or change PostgreSQL, durable operation or evidence authority.",
	}
	tracks := []ProgramTrack{
		{ID: "operator-experience", Title: "Operator Experience / UI / UX", Objective: "Make the console task-first and project-aware with Palette-inspired product information architecture, Rafay-level operational density and 4SO-owned workflow/evidence semantics.", Requirements: []string{"4SO Operator Horizon V3 remains product-owned; no competitor assets or runtime frameworks are copied", "open-code component ownership follows a shadcn-style principle: 4SO owns source, tokens, accessibility and behavior contracts instead of depending on a remote runtime UI framework", "primary navigation follows Overview -> Platforms -> Blueprints -> Fleet -> Operations -> Assurance -> Admin; Assurance owns runtime evidence, supply-chain release authority and physical certification while Workspaces remain the cross-cluster product object", "all new runtime capabilities expose truthful loading/empty/error/forbidden/blocked/stale states and complete keyboard/mobile/RTL paths", "mutations preserve Select -> Inspect -> Allowed Action -> Input -> Impact Preview -> Approval -> Execute -> Evidence", "Persian localization is checked with product-owned normalization/bidi/terminology rules and retains established technical terms instead of automatic pure-Persian rewriting"}},
		{ID: "platform-abstractions", Title: "Certified Platform Templates / Workspaces", Objective: "Compose blueprint releases, variables and policy sets into reusable certified platform templates, then give teams a cross-cluster workspace boundary above namespaces.", Requirements: []string{"PlatformTemplate references immutable BlueprintRelease plus VariableSchema and policy-set objects", "template certification state is evidence-backed and target-class aware", "Workspace groups project-authorized namespaces/environments across clusters without becoming a second Kubernetes or product SoT", "workspace quota/RBAC/backup/observability/cost are aggregate policy views over authoritative underlying resources", "WorkloadType plus composable CapabilityTrait intent prevents blueprint variant explosion while target capability resolution remains authoritative", "ManagedResourceType expresses database/cache/queue/object-store/external-service intent through Product API adapters and secret references only", "WorkspaceProfile composes shared quota/RBAC/network/security/backup/observability/catalog/virtual-cluster/cost policy without persisting runtime truth", "application promotion follows Desired -> Immutable Release -> Environment Binding -> Resolved Capabilities -> Rendered Runtime -> Observed Runtime"}},
		{ID: "application-platform-composition", Title: "Application Platform / IDP Composition", Objective: "Adapt proven IDP composition patterns without importing a second control plane, and optionally expose OpenChoreo as a capability-gated target application platform.", Requirements: []string{"OPENCHOREO_REFERENCE_ADOPTION_V1 is an executable decision boundary, not an upstream authority import", "Fleet transport is audited against outbound mTLS gateway/session patterns while existing 4SO certificate, task-fence and durable-operation authority remains canonical", "Cost, DORA/delivery and audit insights extend existing FinOps/Incident/Audit evidence as derived projections", "OpenChoreo target adapter is disabled by default, target-only and may not replace PostgreSQL, RKE2 management plane, Forgejo, zot, Keycloak, BuildKit or Operator Horizon"}},
		{ID: "infrastructure-providers", Title: "Infrastructure Provider Plane", Objective: "Grow infrastructure breadth through explicit provider adapters while runtime certification remains independent from pre-physical software development.", Requirements: []string{"Existing Kubernetes remains first-class import", "Bare Metal is the first managed provider target", "VMware is the first external virtualization provider", "AWS/Azure/GCP adapters may be developed before physical certification and must consume common Product API/provider execution contracts", "ambiguous external effects must never be auto-retried or promoted to success without authoritative readback evidence"}},
		{ID: "day2-resilience", Title: "Day-2 / Resilience", Objective: "Converge Kubernetes upgrades, OS patching, certificate renewal, node remediation and recovery on the same campaign/wave/fencing/evidence model.", Requirements: []string{"maintenance windows are policy objects reusable by templates", "OS patch/cert renewal/node restart/remediation use canary/wave controls where risk warrants", "rollback feasibility and recovery checkpoints are computed before disruptive execution", "long-running actions remain resumable/cancellable without replaying unsafe side effects"}},
		{ID: "security-governance", Title: "Security / Compliance / Identity", Objective: "Turn existing audit/evidence primitives into an enterprise governance center with runtime compliance scans and complete enterprise SSO.", Requirements: []string{"OIDC remains the application-facing authority; enterprise SAML is brokered through Keycloak into OIDC unless a customer-specific native SP requirement is separately admitted", "CIS/conformance/SBOM/vulnerability findings are normalized into evidence-backed ScanRun/Finding authority", "FIPS/hardened profiles are capability/evidence claims, never labels without certified dependency/runtime support", "security findings link to safe remediation proposals and exact affected platform/workspace scope"}},
		{ID: "usage-finops", Title: "Usage / Capacity / FinOps", Objective: "Give private-cloud operators measured showback/chargeback now and extend it with budget, forecast, anomaly and rightsizing intelligence before physical certification.", Requirements: []string{"rate-card model supports CPU, memory, storage and accelerator units", "cost/usage aggregates by cluster, project, workspace and namespace", "missing telemetry never renders as zero cost", "chargeback exports are derived from measured usage plus versioned rate cards", "FinOps v2 adds budget thresholds, forecast, anomaly and rightsizing as derived policy/advisory signals rather than new billing authority"}},
		{ID: "edge-sovereign", Title: "Edge / Sovereign Autonomy", Objective: "Develop bounded disconnected operation, site-local authority and secure-boot semantics before physical certification, then certify them later on exact artifacts.", Requirements: []string{"edge site can continue admitted local operations when central connectivity is lost", "local UI/action surface is explicitly smaller than central control plane and syncs durable evidence later", "TPM/Secure Boot/measured boot/disk encryption are modeled as discovered/certified capabilities", "central/edge conflict handling is deterministic and never silently last-write-wins", "lack of a physical disconnected lab never blocks source/API/UI/MCP development of these contracts"}},
		{ID: "agent-knowledge-evidence", Title: "Agent Knowledge / Architecture Evidence", Objective: "Give coding and operator agents compact source-grounded context without creating a documentation or architecture source of truth beside the product.", Requirements: []string{"knowledge claims carry exact file hashes and source authority references", "architecture views are deterministic projections of target/program authority and are reproducible", "stale claims are detectable after source changes and generated knowledge can be discarded/rebuilt", "external tools such as OpenWiki or Archify are optional developer adapters, not shipped control-plane dependencies"}},
		{ID: "automation-ecosystem", Title: "Automation / Integration Ecosystem", Objective: "Expose stable generated automation surfaces without multiplying control planes.", Requirements: []string{"PRODUCT_API_CONTRACT_AUTHORITY_V1 is generated from stable Product API routes before downstream clients", "the dependency-light Go SDK contains transport/route contracts only and never duplicates business logic, approvals or mutation retry policy", "Terraform provider consumes the Product API/SDK and is followed by a Crossplane provider over the same authority", "external OCI/Helm sources enter Discover -> Acquire -> Verify -> License/SBOM/Provenance -> Lock -> Admit before Catalog use", "Slack/Teams/ServiceNow/PagerDuty/Email remain notification adapters over one durable routing engine"}},
		{ID: "communication-automation", Title: "Communication / Notification Automation", Objective: "Give operators and authorized agents explainable communication routing without outsourcing product authority to a notification platform.", Requirements: []string{"notification event, route, delivery, retry and dead-letter state remain 4SO PostgreSQL/outbox authority", "routing preview is side-effect free and shows matched rules/destinations before policy changes or event delivery", "channel systems including Novu are optional adapters behind one provider contract and never become product SoT", "preferences/digest/inbox features are added only with organization/project-scoped product policy and deterministic delivery evidence"}},
		{ID: "ai-native", Title: "AI-Native Control Plane", Objective: "Make platform authority explainable and diagnosable through one provider-neutral AI runtime without allowing a model to become source of truth or release authority.", Requirements: []string{"mandatory pre-egress redaction and bounded structured output", "durable project-scoped ai_runs with prompt/context/output digests and usage/cost metadata", "cloud OpenAI-compatible and disconnected local provider profiles", "AI may diagnose/propose but execution always returns to deterministic RBAC/approval/durable-operation authority"}},
		{ID: "mcp-agent-surface", Title: "MCP / External Agent Surface", Objective: "Expose the full product operation surface to authorized human users/admins through remote MCP while Keycloak OAuth, product RBAC, revocable delegation grants, durable jobs, approval and evidence remain authoritative.", Requirements: []string{"MCP protocol 2026-07-28 is explicitly versioned and the remote resource server implements OAuth Protected Resource Metadata plus standards-compliant 401 discovery", "Keycloak is the single self-hosted OIDC/OAuth authorization authority; user passwords, session cookies, client secrets and administrator tokens never reach models or MCP tool payloads", "effective authority is the intersection of current product RBAC/membership, an active revocable MCP delegation grant, resource scope, tool/action policy and domain-specific approval/capability fences", "tools/list is authorization-filtered; users never need to understand OAuth scope strings, revision numbers or internal tool names", "every MCP write creates or advances a durable product Job/Operation with idempotency, request digest, actor/client/grant identity, audit and evidence; no arbitrary shell/SSH/kubectl/SQL escape hatch exists", "read, preview, request-change, approval, operation/evidence and identity/admin tools are separate families; high-impact requester self-approval remains impossible", "ChatGPT, Claude, Gemini and Grok are interoperability certification targets rather than separate product backends"}},
		{ID: "fleet-reliability", Title: "Fleet Reliability / Incident Intelligence", Objective: "Turn runtime signals into product-level service health, incidents, SLO/error-budget truth and evidence-linked remediation without creating a duplicate monitoring stack.", Requirements: []string{"existing Prometheus/OKD monitoring remains telemetry source rather than a second 4SO SoT", "service health and incident state are derived from bounded signals with explicit unknown/degraded states", "SLO/error budget never invents availability when telemetry is missing", "recommended remediation returns through approval/durable-operation/evidence authority"}},
		{ID: "lab-certification", Title: "Lab / Release Certification", Objective: "Use a deterministic server-driven runner for installation, matrices, evidence and exact-SHA certification; AI is failure-only.", Requirements: []string{"M00-M10 are Exact-SHA functional certification and M11-M13 are final chaos/load/soak certification; feature ownership and physical execution ownership are modeled separately", "exact artifact SHA and server inventory binding", "immutable dependency acquisition; missing authority is BLOCKED", "four-layer Release Gate remains independent and Physical PASS is never inferred"}},
		{ID: "supply-chain", Title: "Supply Chain / Disconnected", Objective: "Make every product-owned open-source input reproducible, license-aware, digest-locked and usable without hidden internet dependencies.", Requirements: []string{"no arbitrary latest downloads in certification", "Forgejo desired-state and zot registry boundaries remain canonical", "SBOM/provenance/license inventory is release evidence", "disconnected acquisition/install/upgrade is first-class"}},
		{ID: "developer-agent-experience", Title: "Developer / Agent Experience", Objective: "Keep source/release artifacts complete and cheap to validate with deterministic scripts before any agent spends tokens.", Requirements: []string{"downloadable exact-release source artifact contains full canonical source", "README contains install/lab/agent/MCP/AI/automation paths", "scripts own happy-path tests; AI sees bounded failure packets only", "repository validation prevents documentation/roadmap/test-source drift"}},
	}
	globalGuardrails := []string{
		"PostgreSQL remains the control-plane source of truth; Git/Forgejo remains desired-state history and Argo reconciliation does not become a second product SoT.",
		"OpenChoreo is a reference implementation and optional target application-platform adapter only; its CRD/Git authority model, Backstage portal, ThunderID/OpenBao choices, workflow plane and observability plane never replace 4SO PostgreSQL, Operator Horizon, Keycloak, BuildKit/zot or distribution-owned OKD capabilities.",
		"Certified Platform Templates and Workspaces compose existing authority; neither becomes a hidden alternate database or unrestricted templating engine.",
		"AI, MCP clients, UI and agents never bypass RBAC, approvals, idempotency, fencing, durable operations or evidence boundaries.",
		"The Operator Console never invents authority, percentages, health, cost or success from mock/static data; every status is API/authority backed.",
		"Release Gate has four independent layers: Source Semantics, Generated/Installed Runtime Semantics, Runtime-Realism Negative Controls and Exact-SHA Physical Runtime.",
		"Physical PASS is recorded only from direct execution evidence for the exact artifact SHA.",
		"Before C9 development/feature closure, Exact-SHA physical installation and certification are deferred states, never roadmap blockers for coding, feature hardening or non-physical verification.",
		"Physical/runtime evidence gates never serialize or pause expansion software work: SDK/IaC, virtual clusters, public-cloud providers, Fleet Reliability, FinOps v2 and Edge/Sovereign source development continue independently until their own runtime certification stage.",
		"Resource ownership scope is never inferred from route/table names; missing owner classification remains explicit UNCLASSIFIED/OWNER_REVIEW_REQUIRED until reviewed against source authority.",
		"New capabilities are incomplete until API/runtime, Operator Console, documentation, deterministic tests, negative controls and AI/MCP exposure where appropriate are aligned.",
		"Provider breadth follows certification depth: no provider is marketed as supported from source-only adapters or mocked infrastructure.",
		"Optional VM, accelerator and AI workload planes may not expand the core management appliance dependency set unless a product-owned consumer and independent lifecycle boundary justify them.",
		"External communication platforms are delivery adapters only; notification event/routing/delivery authority, RBAC, audit and evidence remain product-owned and provider-independent.",
		"Remote MCP OAuth tokens are identity/delegation carriers, never a second authorization database: current PostgreSQL product RBAC and MCP grant state are re-evaluated on every protected request so revocation is immediate.",
		"MCP user/admin parity means all product-supported operations have an explicit tool/action disposition; it never means raw SSH, shell, kubectl, SQL, database, secret-store or Keycloak-admin credentials are exposed to a model.",
		"MCP approval is a distinct durable action available only to an independently authorized principal when domain policy permits; a model acting for the requester cannot self-approve high-impact work.",
		"A phase marked source-implemented means only that its source-level authority/implementation contract is present; it is never equivalent to generated-runtime, integration, Exact-SHA physical or production readiness.",
		"Roadmap progress is quality-gated and evidence-dimensional; raw phase-count percentages must not be used as release readiness or to justify expanding breadth before core closure.",
		"Core Freeze scope is intentionally narrower than the long-term product roadmap: expansion features remain planned but cannot block closure and certification of the installable, recoverable, upgradeable sovereign Factory core.",
	}
	phases := []ProgramPhase{
		{ID: "A-architecture-authority-rebaseline", Order: 1, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Keep the self-contained RKE2 management appliance, PostgreSQL authority and target-distribution/provisioning/infrastructure boundaries explicit while eliminating duplicate control planes and documentation truths.", Evidence: []string{AuthorityMethod, "management-plane:rke2", "postgresql-control-plane-sot", "forgejo-desired-state", "zot-canonical-registry"}, ExitCriteria: []string{"management plane remains product-owned and self-contained", "distribution/provisioning/infrastructure identities are independent", "one canonical runtime/source authority exists for each product concern"}},
		{ID: "B-target-capability-supplychain-foundation", Order: 2, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Provide fail-closed target capability vocabulary plus reproducible catalog/supply-chain contracts without pretending preview distributions are runtime admitted.", DependsOn: []string{"A-architecture-authority-rebaseline"}, Evidence: []string{CapabilityResolverAuthority, "GET /api/v1/target-architecture-model", "catalog-source-locks", "SBOM/provenance"}, ExitCriteria: []string{"Kubernetes/RKE2/OKD admission boundaries remain explicit", "duplicate-stack decisions are capability/inventory driven", "source locks/digests/licenses are machine-readable"}},
		{ID: operatorScopePhase, Order: 3, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Converge the Operator Console information architecture and one authoritative Organization/Project scope before any workflow claims product completeness.", DependsOn: []string{"B-target-capability-supplychain-foundation"}, Evidence: []string{"4SO_OPERATOR_HORIZON_V3", "docs/OPERATOR_CONSOLE_DESIGN_FOUNDATION.md", "GET /api/v1/access/context"}},
		{ID: dataScalePhase, Order: 4, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Make console hot paths bounded and scope-aware so high-cardinality installations do not materialize canonical collections on each refresh.", DependsOn: []string{operatorScopePhase}, Evidence: []string{"GET /api/v1/control-plane/summary", "internal/api/operator_collection_page.go"}},
		{ID: actionPhase, Order: 5, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Converge every mutating console surface on one RBAC/state/impact/approval/durable-operation/evidence grammar.", DependsOn: []string{dataScalePhase}, Evidence: []string{"operator-console:durable-operation-impact-approval-evidence", "operator-console:central-action-state-guard"}},
		{ID: c4Phase, Order: 6, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Certify the implemented console foundation journeys and interaction quality after IA, scale and action semantics converge; final whole-product workflow certification is repeated after core backend closure.", DependsOn: []string{dataScalePhase, actionPhase}, Evidence: []string{"OPERATOR_EXPERIENCE_VIEWPORT_ACCESSIBILITY_V1", "C4_WORKFLOW_E2E_CERTIFICATION_PASS"}},
		{ID: "E-certified-platform-template-workspace-foundation", Order: 7, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Provide Certified Platform Templates and cross-cluster Workspaces as product abstractions between blueprints, fleets and tenant environments.", DependsOn: []string{c4Phase}, Evidence: []string{"VARIABLE_SCHEMA_AUTHORITY_V1", "PLATFORM_POLICY_SET_AUTHORITY_V1", "PLATFORM_TEMPLATE_AUTHORITY_V1", "WORKSPACE_AUTHORITY_V1"}},
		{ID: c5Phase, Order: 8, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Close the management-appliance install/upgrade/recovery source and generated-runtime lifecycle before the long physical campaign; Exact-SHA physical readiness remains independently unproven until D.", DependsOn: []string{"E-certified-platform-template-workspace-foundation"}, ParallelWith: []string{"C6-multi-agent-test-autopilot"}, Evidence: []string{"APPLIANCE_SIZING_AUTHORITY_V1", "INSTALLER_JOURNALED_RESET_AUTHORITY_V1", "INSTALLER_UPGRADE_INTERRUPTION_RECOVERY_MATRIX_V1"}},
		{ID: "C6-multi-agent-test-autopilot", Order: 9, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Provide deterministic checkpoint-safe testing orchestration with specialist triage/repair agents while preventing concurrent writers and premature physical campaigns.", DependsOn: []string{c4Phase}, ParallelWith: []string{c5Phase}, Evidence: []string{"AUTOPILOT_STAGE_SHARD_AUTHORITY_V2", "CHECKPOINT_SAFE_FULL_VERIFIER_V2", "AUTOPILOT_SINGLE_WRITER_REPAIR_AUTHORITY_V1"}},
		{ID: c7Phase, Order: 10, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Let authorized AI/MCP clients discover product state and request allow-listed product operations through the same authority as UI/API.", DependsOn: []string{"E-certified-platform-template-workspace-foundation"}, Evidence: []string{"MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1", "operation_cancel", "runtime_verification_request", "cluster_maintenance_request", "upgrade_campaign_request"}},
		{ID: c7OAuthPhase, Order: 11, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Turn the existing MCP endpoint into a standards-compliant remote OAuth resource server for human user/admin delegation without exposing passwords or creating a second identity authority.", DependsOn: []string{c7Phase, operatorScopePhase}, ParallelWith: []string{currentPhase, "G4-data-protection-productization", "G5-enterprise-identity-compliance"}, Evidence: []string{"MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1", "MCP_OAUTH_PROTECTED_RESOURCE_DISCOVERY_V1", "MCP_DEDICATED_AUDIENCE_VALIDATION_V1", "MCP_HUMAN_DELEGATION_AUTHORITY_V1", "MCP_CLIENT_TRUST_REGISTRY_V1", "MCP_TOKEN_REVOCATION_ENFORCEMENT_V1", "MCP_CONNECTION_CONSENT_UX_V1", "migrations/0062_mcp_human_delegation_authority.sql", "MCP 2026-07-28", "Keycloak OIDC/OAuth"}, ExitCriteria: []string{"/.well-known/oauth-protected-resource identifies Keycloak as the authorization server and protected MCP requests return standards-compliant 401 discovery", "access tokens validate issuer, audience/resource, subject, client, expiry and signing key and are short lived", "dynamic registration is disabled by default; trusted client metadata or explicit admin registration binds known remote MCP clients", "MCPDelegationGrant is durable, revocable and resource-bounded to platform/organization/project plus friendly access profile", "effective authorization always intersects current product RBAC with current grant state so token possession cannot preserve revoked product authority", "Console connection flow is Sign in -> Select organization/project -> Choose friendly access -> Review/Confirm -> Connected; scope/tool/revision internals remain advanced operator details"}},
		{ID: c7ParityPhase, Order: 12, Status: ProgramStatusBlocked, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Give authorized users and administrators complete read/write/operation parity over product-supported authority through typed MCP tools while every write remains a durable product Job/Operation.", DependsOn: []string{c7OAuthPhase, c7Phase}, ParallelWith: []string{currentPhase, "G4-data-protection-productization", "G5-enterprise-identity-compliance", "J1-automation-external-integrations"}, Blockers: []string{"MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING"}, Evidence: []string{"MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1", "MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1", "MCP_PRODUCT_ACTION_REGISTRY_V1", "MCP_EFFECTIVE_TOOL_FILTERING_V1", "MCP_ROUTE_PARITY_AUTHORITY_V1", "MCP_DURABLE_CONTROL_JOB_AUTHORITY_V1", "MCP_CONTROL_JOB_RECOVERY_AUTHORITY_V1", "IDENTITY_ADMIN_JOB_AUTHORITY_V1", "saml_broker_change_request", "saml_broker_delete_request", "identity_admin_job_approve", "cluster_maintenance_approve", "upgrade_campaign_approve", "MCP_INDEPENDENT_APPROVAL_TOOL_PARITY_V1", "MCP_TYPED_DATA_PROTECTION_COMPLIANCE_UPGRADE_PARITY_V2", "MCP_DURABLE_SUPPORT_BUNDLE_JOB_PARITY_V1", "support_bundle_request", "workspaces", "workspace", "workspace_create", "workspace_bindings", "workspace_binding_create", "workspace_binding_revoke", "projects", "project_create", "MCP_EXTERNAL_CLIENT_INTEROPERABILITY_MATRIX_V2", "lab/mcp-external-client-interop-matrix.json"}, ExitCriteria: []string{"every stable product read and mutation family has a machine-readable MCP disposition or an explicit security exclusion", "tools/list returns only actions currently authorized by RBAC, delegation grant and resource scope", "every write records actor, OAuth client, grant, resource scope, idempotency/request digest, Job/Operation ID, audit and result evidence", "indeterminate lost-response mutations enter RECOVERY_REQUIRED and only a human platform-admin can resolve them from revision-fenced authoritative readback plus evidence; the initiating MCP client cannot self-resolve or redispatch", "preview/plan and mutation tools remain distinct; dangerous changes stop at domain approval and maintenance-window gates", "approval is exposed as a separate tool only for principals with approval authority and requester self-approval remains fail-closed", "identity/administration operations use product jobs and server-held Keycloak credentials; no Keycloak admin token or user credential reaches the model", "black-box interoperability passes for ChatGPT custom MCP, Claude remote MCP, Gemini remote MCP and Grok custom MCP with allowed-tool restriction and revocation negative controls"}},
		{ID: c8Phase, Order: 13, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Complete current Operator Console surfaces around installation/recovery, AI/MCP access and Autopilot campaigns; final core workflow recertification occurs at C9 after blocked backend families close.", DependsOn: []string{c5Phase, "C6-multi-agent-test-autopilot", c7Phase}, Evidence: []string{"INSTALLER_RECOVERY_CONSOLE_AUTHORITY_V1", "AUTOPILOT_CAMPAIGN_CONSOLE_AUTHORITY_V1"}},
		{ID: fPhase, Order: 14, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Provide first-class existing OKD import/reconnect/revocation with inventory-bound capability ownership and health translation without claiming managed install or physical certification.", DependsOn: []string{"E-certified-platform-template-workspace-foundation"}, Evidence: []string{"OKD_CLUSTERVERSION_V1", "OKD_CLUSTER_OPERATOR_HEALTH_AUTHORITY_V1", "TARGET_DESIRED_OBSERVED_PROFILE_COMPILER_V1"}},

		{ID: "R0-release-authority-certification-rebaseline", Order: 15, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Make mandatory roadmap readiness, feature-freeze admission and certification ownership machine-readable release authority instead of advisory documentation.", DependsOn: []string{fPhase}, Evidence: []string{ProgramAuthorityMethod, FeatureCertificationRegistryAuthority, "LAB_CERTIFICATION_MATRIX_V2", "release-readiness:roadmapFeatureBlockers", "DOCUMENTATION_AUTHORITY_SYNC_V1"}, ExitCriteria: []string{"ProductReleaseReady is false while any mandatory feature-freeze phase is not ready", "roadmap blockers are counted separately and included in product readiness", "M00-M10 physical functional execution is owned by D and M11-M13 by M", "feature source ownership and certification execution ownership are distinct", "current architecture documents reference the executable roadmap authority"}},

		{ID: currentPhase, Order: 16, Status: ProgramStatusBlocked, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Acquire and exact-lock every mandatory upstream source and management workload byte early, in parallel with feature hardening, so disconnected and certification work do not build on moving inputs.", DependsOn: []string{"R0-release-authority-certification-rebaseline", "B-target-capability-supplychain-foundation"}, ParallelWith: []string{c7ParityPhase, "G4-data-protection-productization", "G5-enterprise-identity-compliance"}, Blockers: []string{"COMPONENT_SOURCE_ACQUISITION_PENDING", "SOURCE_LOCKS_PENDING", "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING", "MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING", "RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING"}, Evidence: []string{"LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8", "UPSTREAM_ACQUISITION_TOOLCHAIN_V3", "catalog/upstream-acquisition-toolchain.json", "scripts/upstream_acquisition_toolchain.py", "catalog/upstream-admission.json", "lab/release-build-toolchain-lock.json", "RELEASE_BUILD_TOOLCHAIN_AUTHORITY_V1", "scripts/verify_release_build_toolchain.py", "scripts/acquire_release_build_toolchain.py", "SUPPLY_CHAIN_HANDOFF_V1", "SUPPLY_CHAIN_HANDOFF_SEAL_V1", "RUNTIME_DEPENDENCY_TRANSITION_V1", "catalog/runtime-dependency-transition.json", "lab/supply-chain-handoff-plan.json", "scripts/supply_chain_handoff.py", "MANAGEMENT_WORKLOAD_STAGED_BATCH_V1", "scripts/acquire_management_workload_batch.py", "ARTIFACT-MANIFEST.json", "BUILD-PROVENANCE.json", "SBOM.spdx.json"}, ExitCriteria: []string{"all mandatory component versions are exact selected", "all source archives/manifests/images are byte locked with provenance/license evidence", "management workload OCI archive and exact image digests are complete", "disconnected rebuild uses only locked inputs"}},
		{ID: "S2-component-runtime-certification-authorities", Order: 17, Status: ProgramStatusBlocked, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Give every enabled catalog component an exact source-bound, owner-specific runtime certification lifecycle rather than treating render/apply or generic target harness evidence as component certification.", DependsOn: []string{currentPhase, fPhase}, Blockers: []string{"UPSTREAM_RUNTIME_SUITABILITY_HOLDS_PENDING", "COMPONENT_HISTORICAL_SOURCE_ACQUISITION_PENDING", "COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING"}, Evidence: []string{FeatureCertificationRegistryAuthority, "COMPONENT_UPGRADE_SOURCE_ADMISSION_V1", "CATALOG_HISTORICAL_SOURCE_IMPORT_V1", "COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1", "COMPONENT_RUNTIME_SOURCE_REBIND_TRANSACTION_V2", "COMPONENT_RUNTIME_SOURCE_GATED_EXECUTOR_PARITY_V1", "COMPONENT_RUNTIME_UPGRADE_MATRIX_V2", "COMPONENT_RUNTIME_UPGRADE_V1", "internal/runtimeupgrade", "catalog/component-runtime-upgrade-matrix.json", "scripts/component_runtime_upgrade_matrix.py", "HISTORICAL_UPGRADE_STAGED_BATCH_V1", "scripts/acquire_historical_upgrade_batch.py", "COMPONENT_RUNTIME_INSTALL_READINESS_DEPENDENCY_PARTIAL_V1", "COMPONENT_RUNTIME_DUPLICATE_CREATE_NEGATIVE_CONTROL_V1", "COMPONENT_RUNTIME_FAILURE_RECOVERY_SAFE_REMOVE_PARTIAL_V1", "COMPONENT_RUNTIME_CRD_LIVE_INSTANCE_DELETE_GUARD_V1", "COMPONENT_RUNTIME_V1", "migrations/0063_component_runtime_certification_identity.sql", "migrations/0064_component_runtime_failure_remove_lifecycle.sql", "GET /api/v1/catalog/runtime-certification-authority", "runtime-certification"}, ExitCriteria: []string{"every mandatory component has install/readiness/dependency/remove/failure evidence contracts bound to exact component release and source lock, and every upgrade-applicable component has an exact historical source pair; a first product release uses explicit install-only certification rather than fabricated history", "every lifecycle stage is executed by a component-owned executor instead of a catalog-wide capability harness", "stale source locks, wrong fence tokens, missing readiness, failed upgrade, partial remove and failure-recovery controls are exercised as negative controls", "runtime certification binds exact source/version, target capability evidence and component lifecycle evidence"}},
		{ID: "G1-operational-runtime-hardening", Order: 18, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Close remaining operational scale/observability debt without introducing new mutation authorities.", DependsOn: []string{"R0-release-authority-certification-rebaseline", fPhase}, Evidence: []string{"AGENT_SCHEDULER_V2", "OPERATIONS_QUEUE_CENTER_V1", "PRODUCT_LOG_CENTER_V1", "AGENT_TASK_QUEUE_OBSERVABILITY_V1", "TARGET_WORKLOAD_LOGS_V1", "NOTIFICATION_HEALTH_INCREMENTAL_V1", "SUPPORT_BUNDLE_ASYNC_JOB_V1", "CONSOLE_LOCALIZATION_RUNTIME_V1", "CONSOLE_LOCALIZATION_COVERAGE_V2", "CONSOLE_FULL_LOCALIZATION_V1"}, ExitCriteria: []string{"all Agent task families expose bounded queue age/lease/retry truth", "target workload log query/tail is capability-gated and bounded", "health recomputation is incremental", "support bundles are durable async jobs", "mandatory console localization coverage is complete"}},
		{ID: "G2-generalized-day2-campaign-engine", Order: 19, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Converge disruptive lifecycle work on one Plan -> Impact -> Window -> Approval -> Canary/Waves -> Fence -> Execute -> Verify -> Evidence -> Recovery engine.", DependsOn: []string{"G1-operational-runtime-hardening"}, Evidence: []string{"GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1", "GET /api/v1/day2-campaign-engine", "KUBERNETES_NODE_MAINTENANCE_V1", "fleet-upgrade-campaign", "memory/file/postgresql-store-boundary"}, ExitCriteria: []string{"maintenance and fleet-upgrade adapters share one machine-readable campaign contract", "independent approval is enforced at the durable store boundary", "maintenance windows and execution fences fail closed", "upgrade canary/wave topology and recovery baseline identity are immutable after planning", "REST and MCP normalize rollout bounds identically", "upgrade verification and recovery evidence are mandatory before successful disruptive rollout completion"}},
		{ID: "G3-target-node-maintenance-lifecycle", Order: 20, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Productize target node add/drain/remove/replace plus OS patch, certificate renewal, remediation, diagnostics and recovery on the generalized campaign engine.", DependsOn: []string{"G2-generalized-day2-campaign-engine"}, ParallelWith: []string{currentPhase, "S2-component-runtime-certification-authorities"}, Evidence: []string{"TARGET_NODE_LIFECYCLE_AUTHORITY_V1", "TARGET_NODE_PROVIDER_BINDING_AUTHORITY_V1", "TARGET_NODE_PROVIDER_MACHINE_LIFECYCLE_V1", "CAPI_EXACT_WORKER_MACHINE_REMOVE_REPLACE_V1", "RKE2_WORKER_CERTIFICATE_RENEWAL_BY_CAPI_REPLACEMENT_V1", "CAPI_WORKER_MACHINE_REMEDIATION_REPLACEMENT_V1", "TARGET_NODE_HOST_MAINTENANCE_EXECUTOR_V1", "GET /api/v1/clusters/{id}/node-lifecycle-authority", "POST /api/v1/clusters/{id}/node-lifecycle-plans", "POST /api/v1/clusters/{id}/provider-binding", "POST /api/v1/clusters/{id}/node-lifecycle-actions", "CAPI_TOPOLOGY_WORKER_ADD_V1", "KUBERNETES_NODE_MAINTENANCE_V1", "migrations/0060_target_node_os_patch_executor.sql", "migrations/0061_target_node_provider_machine_lifecycle.sql"}, ExitCriteria: []string{"add/drain/remove/replace are distribution/capability aware and have source-owned executors", "OS patch is fenced, resumable and evidence backed with reboot reported separately", "provider-managed Ready worker certificate renewal uses exact one-for-one CAPI Machine replacement and fresh join identity", "provider-managed NotReady worker remediation uses exact CAPI Machine replacement with persisted recovery evidence", "unsupported provider/control-plane/imported combinations remain fail-closed rather than being represented as implemented", "unsafe replay after crash is rejected"}},
		{ID: "G4-data-protection-productization", Order: 21, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Make backup, restore and restore-drill first-class durable product workflows with evidence-backed RPO/RTO semantics.", DependsOn: []string{"G2-generalized-day2-campaign-engine", "S2-component-runtime-certification-authorities"}, Evidence: []string{"TARGET_DATA_PROTECTION_AUTHORITY_V1", "TARGET_DATA_PROTECTION_SCHEDULER_V1", "TARGET_DATA_PROTECTION_OPERATOR_WORKFLOW_V1", "migrations/0065_target_data_protection_authority.sql", "POST /api/v1/backup-policies", "POST /api/v1/backup-runs", "POST /api/v1/restore-runs", "POST /api/v1/restore-drills"}, ExitCriteria: []string{"BackupPolicy/BackupRun/RestoreRun/RestoreDrill are durable authorities", "retention/schedule/credential references are scoped", "restore verification can produce recovery checkpoints"}},
		{ID: "G5-enterprise-identity-compliance", Order: 22, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Complete enterprise SSO and evidence-native compliance without creating a second application authentication authority.", DependsOn: []string{"G1-operational-runtime-hardening"}, Evidence: []string{"4SO_KUBERNETES_SECURITY_BASELINE_V1", "KEYCLOAK_SAML_BROKER_AUTHORITY_V1", "IDENTITY_ADMIN_JOB_AUTHORITY_V1", "migrations/0066_compliance_scan_center_authority.sql", "migrations/0067_identity_admin_saml_broker_authority.sql", "POST /api/v1/compliance/scans", "POST /api/v1/compliance/waivers", "POST /api/v1/identity/saml-brokers", "internal/identityadmin"}, ExitCriteria: []string{"enterprise SAML is brokered through Keycloak into product OIDC unless separately admitted", "compliance profiles/scans/findings/evidence/waivers/rechecks are durable and scoped"}},
		{ID: "H1-baremetal-connected-managed-okd", Order: 23, Status: ProgramStatusBlocked, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Make Bare Metal and connected Managed OKD Compact-3 an explicit first-class lifecycle instead of hiding Managed OKD behind a generic provider phase.", DependsOn: []string{"R0-release-authority-certification-rebaseline", currentPhase, fPhase}, Blockers: []string{"OKD_CONNECTED_MANAGED_INSTALL_PENDING"}, Evidence: []string{"BOOT_MEDIA_PROVIDER_AUTHORITY_V1", "REDFISH_BOOT_MEDIA_PROVIDER_V1", "BAREMETAL_MANAGED_INSTALL_AUTHORITY_V2", "BAREMETAL_MANAGED_INSTALL_EXECUTOR_V1", "DURABLE_OPERATION_REQUEST_PAYLOAD_AUTHORITY_V1", "migrations/0068_operation_request_payload_authority.sql", "POST /api/v1/managed-okd-installs", "GET /api/v1/managed-okd-installs/{id}", "POST /api/v1/managed-okd-installs/{id}/approve", "managed_okd_install_request", "managed_okd_install", "managed_okd_install_approve", "expired RUNNING operation reclaim with monotonic fence", "lease heartbeat with fenced revision refresh", "Compact-3 sealed request and independent approval", "REDFISH_FILE_CREDENTIAL_RESOLVER_V1", "MANAGED_OKD_CONTENT_ADDRESSED_MEDIA_V1", "MANAGED_OKD_EXACT_WORKSPACE_RUNTIME_V1", "MANAGED_OKD_INSTALL_WORKSPACE_V1", "MANAGED_OKD_CLUSTER_REGISTRATION_V1", "GET /api/v1/managed-okd-installs/runtime", "production cmd/platform-api managed OKD worker wiring", "exact ClusterVersion/Ready Node/ClusterOperator health verification"}, ExitCriteria: []string{"pinned openshift-install/FCOS/release payloads are acquired", "Agent ISO and BootMediaProvider attach/one-time-boot/power/observe workflow is durable", "installed cluster converges into normal imported OKD authority"}},
		{ID: "H2-vmware-provider", Order: 24, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Provide VMware vSphere as an independently admitted private-infrastructure identity through the existing Cluster API topology lifecycle without delaying sovereign Core certification.", DependsOn: []string{"R0-release-authority-certification-rebaseline"}, ParallelWith: []string{"H1-baremetal-connected-managed-okd", "J1-automation-external-integrations"}, Evidence: []string{"VMWARE_PROVIDER_AUTHORITY_V1", "migrations/0071_vmware_provider_authority.sql", "POST /api/v1/provider-profiles", "VSphereClusterTemplate", "VSphereMachineTemplate", "external-secret://4so-provider-system/<name>", "operator-console:vmware-provider-profile"}, ExitCriteria: []string{"VMware provider profiles require an HTTPS vCenter origin without embedded credentials and an external-secret reference", "VMware admission is currently amd64-only and propagates infrastructureProvider=vmware into provider-cluster desired state", "management agents verify the admitted ClusterClass is backed by CAPV VSphereClusterTemplate and VSphereMachineTemplate references", "raw vCenter credentials and arbitrary infrastructure manifests are never product authority", "real vCenter/CAPV provisioning remains independently runtime/physical certification-gated"}},
		{ID: "I1-disconnected-okd-core", Order: 25, Status: ProgramStatusBlocked, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Certify disconnected OKD acquisition/install/upgrade using the connected managed OKD and exact supply-chain authorities.", DependsOn: []string{"H1-baremetal-connected-managed-okd", currentPhase}, Blockers: []string{"OKD_OC_MIRROR_V2_ACQUISITION_PENDING"}, Evidence: []string{"DISCONNECTED_OKD_MIRROR_RUNTIME_V1", "DISCONNECTED_OKD_MIRROR_INVENTORY_V1", "BAREMETAL_MANAGED_INSTALL_EXECUTOR_V1", "POST /api/v1/managed-okd-installs", "GET /api/v1/managed-okd-installs/runtime", "managed_okd_install_request", "exact oc-mirror v2 disk-to-mirror runtime boundary", "sealed ImageSetConfiguration and mirror inventory digests", "offline archive rejects symlinks and unsealed files", "mode-specific Operator Console readiness"}},
		{ID: "I2-edge-sovereign-extension", Order: 26, Status: ProgramStatusBlocked, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Develop bounded site-local authority, UI, boot-attestation semantics and disconnected local AI in parallel before physical certification; exact disconnected runtime evidence is a later independent certification gate.", DependsOn: []string{"B-target-capability-supplychain-foundation", "E-certified-platform-template-workspace-foundation"}, ParallelWith: []string{"I1-disconnected-okd-core", "J3-virtual-cluster-profile"}, Blockers: []string{"EDGE_LOCAL_AUTHORITY_PENDING", "EDGE_LOCAL_UI_PENDING", "BOOT_SECURITY_ATTESTATION_PENDING", "LOCAL_AI_DISCONNECTED_PROFILE_PENDING"}},
		{ID: "J1-automation-external-integrations", Order: 27, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Expose SDK/Terraform/Crossplane/external-registry/notification integrations as adapters in parallel with Core evidence closure and without creating a second lifecycle authority.", DependsOn: []string{"R0-release-authority-certification-rebaseline", "B-target-capability-supplychain-foundation"}, ParallelWith: []string{currentPhase, "H2-vmware-provider", "J3-virtual-cluster-profile"}, Evidence: []string{"PRODUCT_API_CONTRACT_AUTHORITY_V1", "sdk/product-api-contract.json", "sdk/go", "sdk/go/mutation.go", "providers/terraform", "providers/terraform/internal/provider/saml_broker_resource.go", ".github/workflows/repository-integrity.yml:terraform-provider", "providers/crossplane", "providers/crossplane/internal/controller/samlbroker/controller.go", "providers/crossplane/package/crossplane.yaml", "providers/crossplane/package/crds", ".github/workflows/repository-integrity.yml:crossplane-provider", "EXTERNAL_REGISTRY_ADMISSION_AUTHORITY_V1", "NOTIFICATION_PROVIDER_ADAPTER_CONTRACT_V1", "NOTIFICATION_PREFERENCE_DIGEST_POLICY_V1", "POST /api/v1/external-registry/admission", "GET /api/v1/notification-provider-contracts", "GET /api/v1/notification-routes/{id}/policy-digest", "MCP_ROUTE_PARITY_AUTHORITY_V1", "operator-console:external-registry-admission-preview", "operator-console:notification-provider-contracts"}, ExitCriteria: []string{"Product API route contract and Go client are reproducible and contain no business-logic or mutation-retry bypass", "external registry candidates are HTTPS-only, digest-pinned and never replace zot as managed registry authority", "notification providers declare transport/auth/HMAC/egress capability without exposing raw secret material", "notification routing policy has deterministic revision-independent digest evidence", "a real Terraform provider and a Crossplane provider consume stable product APIs without bypassing RBAC, durable operations or approval"}},
		{ID: "J2-finops-usage", Order: 28, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Provide measured private-cloud usage/capacity/rate-card authority without representing missing telemetry as zero cost.", DependsOn: []string{"G1-operational-runtime-hardening", "E-certified-platform-template-workspace-foundation"}, ParallelWith: []string{"J1-automation-external-integrations"}, Evidence: []string{"FINOPS_RATE_CARD_AUTHORITY_V1", "FINOPS_USAGE_MEASUREMENT_AUTHORITY_V1", "FINOPS_CAPACITY_OBSERVATION_AUTHORITY_V1", "FINOPS_CHARGEBACK_AUTHORITY_V1", "migrations/0070_finops_usage_ratecard_authority.sql", "POST /api/v1/finops/rate-cards", "POST /api/v1/finops/usage-measurements", "POST /api/v1/finops/capacity-observations", "GET /api/v1/finops/showback", "GET /api/v1/finops/chargeback-export", "MCP_ROUTE_PARITY_AUTHORITY_V1", "operator-console:finops-chargeback"}, ExitCriteria: []string{"rate cards cover CPU, memory, storage and accelerator usage with integer micro-currency arithmetic", "measured usage and capacity observations are immutable, idempotent and organization/project scoped", "missing telemetry or missing rate coverage never becomes a numeric total cost", "chargeback export is deterministic and derived only from measured usage plus versioned rate cards"}},
		{ID: "J3-virtual-cluster-profile", Order: 29, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Provide workspace-bound virtual-cluster desired state, exact offline runtime execution, lifecycle fencing, bounded diagnostics and measured FinOps attribution while keeping Exact-SHA Physical certification independent.", DependsOn: []string{"E-certified-platform-template-workspace-foundation", "G2-generalized-day2-campaign-engine"}, ParallelWith: []string{"J1-automation-external-integrations", "J2-finops-usage", "I2-edge-sovereign-extension", "J8-application-platform-abstraction-composition"}, Evidence: []string{"VIRTUAL_CLUSTER_PROFILE_AUTHORITY_V1", "VIRTUAL_CLUSTER_LIFECYCLE_AUTHORITY_V1", "VIRTUAL_CLUSTER_DURABLE_AUTHORITY_V1", "VIRTUAL_CLUSTER_DIAGNOSTICS_AUTHORITY_V1", "internal/virtualcluster", "cmd/platform-agent/virtual_cluster_runtime.go", "migrations/0078_virtual_cluster_authority.sql", "migrations/0079_virtual_cluster_runtime_fence.sql", "migrations/0080_virtual_cluster_lifecycle_journal.sql", "migrations/0081_finops_virtual_cluster_attribution.sql", "WORKSPACE_AUTHORITY_V1", "WorkspaceBinding revision fence", "POST /api/v1/workspaces/{id}/virtual-clusters", "POST /api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/suspend", "POST /api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/resume", "POST /api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/delete", "GET /agent/v1/clusters/{id}/virtual-cluster-tasks/next", "POST /agent/v1/clusters/{id}/virtual-cluster-tasks/{virtualClusterId}/dispatch", "POST /agent/v1/clusters/{id}/virtual-cluster-tasks/{virtualClusterId}/result", "GET virtual-cluster includeDiagnostics=true", "MCP_ROUTE_PARITY_AUTHORITY_V1", "POSTGRES_BEHAVIORAL_INTEGRATION_V1", "operator-console:virtual-cluster-lifecycle"}, ExitCriteria: []string{"runtime creation and lifecycle use immutable vCluster chart/image authority and internal mirrors with no hidden internet dependency", "WorkspaceBinding revision, desired digest, task lease/fence and dispatch acknowledgement bind every runtime mutation", "ambiguous or expired dispatched mutations enter RECOVERY_REQUIRED rather than unsafe automatic replay", "suspend/resume/delete terminal states require authoritative runtime readback", "diagnostics is a bounded read-only projection over lifecycle journal and exact-resource audit evidence", "FinOps virtual-cluster attribution extends measured usage authority without synthesizing missing telemetry", "source closure never implies Exact-SHA Physical Runtime PASS"}},
		{ID: "J4-product-api-contract-recovery-foundation", Order: 30, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Make Product API automation and ambiguous MCP mutation recovery explicit reusable authorities before Terraform/Crossplane breadth expands.", DependsOn: []string{"C7-ai-mcp-delegated-operations", "R0-release-authority-certification-rebaseline"}, ParallelWith: []string{"J1-automation-external-integrations", "J3-virtual-cluster-profile"}, Evidence: []string{"PRODUCT_API_CONTRACT_AUTHORITY_V1", "RESOURCE_SCOPE_REGISTRY_V1", "MCP_CONTROL_JOB_RECOVERY_AUTHORITY_V1", "OPERATOR_COLLECTION_CURSOR_V1", "POSTGRES_BEHAVIORAL_INTEGRATION_V1", "migrations/0072_mcp_control_job_recovery_resolution.sql", "GET /api/v1/access/resource-scopes", "POST /api/v1/ai/control-jobs/{id}/resolve-recovery", "sdk/product-api-contract.json", "sdk/go", ".github/workflows/repository-integrity.yml"}, ExitCriteria: []string{"every stable Product API route appears in a reproducible route contract", "bounded operator collections use a deterministic opaque cursor with continuation metadata and adapters apply scope/cursor before LIMIT", "production PostgreSQL authority has a real service-container behavioral integration gate for migrations, idempotency, tenant scope and lease fencing", "Go SDK transport never auto-retries mutations or embeds approval/business logic", "RECOVERY_REQUIRED MCP jobs can only be terminally resolved by a human platform-admin from authoritative readback plus evidence", "resource scope audit defaults missing classifications to UNCLASSIFIED instead of guessing"}},
		{ID: "J5-resource-scope-owner-closure", Order: 31, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Classify every Product API resource family against explicit platform/organization/project/dynamic ownership and use the registry to audit SDK, MCP, Terraform, Crossplane and Console scope behavior.", DependsOn: []string{"J4-product-api-contract-recovery-foundation"}, ParallelWith: []string{"J1-automation-external-integrations", "J3-virtual-cluster-profile"}, Evidence: []string{"RESOURCE_SCOPE_REGISTRY_V1", "RESOURCE_SCOPE_OWNER_CLASSIFICATIONS_V1", "RESOURCE_SCOPE_CONSUMER_AUDIT_V1", "PRODUCT_API_RESOURCE_SCOPE_PROPAGATION_V1", "CONSOLE_RESOURCE_SCOPE_FAIL_CLOSED_V1", "GET /api/v1/access/resource-scopes", "sdk/product-api-contract.json", "sdk/go/routes_gen.go", "internal/api/mcp_route_parity_registry.json", "scripts/validate_repository.py", "webconsole/static/app.js"}, ExitCriteria: []string{"every stable API family is OWNER_CLASSIFIED from source evidence", "no SDK/MCP/IaC client widens an unclassified resource to global scope", "RLS/authorization audits consume the same ownership registry"}},
		{ID: "H3-public-cloud-provider-adapters", Order: 32, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Develop AWS, Azure and GCP infrastructure provider adapters over common Product API/provider lifecycle contracts without waiting for physical certification of VMware or bare metal.", DependsOn: []string{"H2-vmware-provider", "J4-product-api-contract-recovery-foundation"}, ParallelWith: []string{"J1-automation-external-integrations", "J3-virtual-cluster-profile"}, Evidence: []string{"PUBLIC_CLOUD_PROVIDER_EXECUTION_AUTHORITY_V1", "internal/providerexec", "ProviderClusterRecoveryRequired", "migrations/0077_provider_cluster_recovery_required.sql", "AWSClusterTemplate", "AWSMachineTemplate", "AzureClusterTemplate", "AzureMachineTemplate", "GCPClusterTemplate", "GCPMachineTemplate", "external-secret://4so-provider-system/<name>", "operator-console:aws-azure-gcp-provider-profile", "cmd/platform-agent:clusterAPIProviderAdapter"}, ExitCriteria: []string{"provider identity, credential-reference, plan/apply/readback/error semantics share one product contract", "unknown external outcome never triggers unsafe automatic replay", "provider-specific credentials remain external-secret references"}},
		{ID: "J6-fleet-reliability-incident-intelligence", Order: 33, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Provide product-level Service Health, Incident, SLO/Error Budget and evidence-linked remediation views over existing telemetry without deploying a duplicate monitoring authority.", DependsOn: []string{"G1-operational-runtime-hardening", "G2-generalized-day2-campaign-engine", "J4-product-api-contract-recovery-foundation"}, ParallelWith: []string{"J7-finops-v2-budget-forecast-rightsizing"}, Evidence: []string{"SERVICE_HEALTH_AUTHORITY_V1", "INCIDENT_AUTHORITY_V1", "SLO_ERROR_BUDGET_AUTHORITY_V1", "HEALTH_OBSERVATION_AUTHORITY_V1", "migrations/0074_fleet_reliability_incident_slo.sql", "migrations/0075_slo_cluster_scope.sql", "migrations/0076_incident_operation_evidence_link.sql", "MCP_ROUTE_PARITY_AUTHORITY_V1", "operator-console:fleet-reliability"}, ExitCriteria: []string{"service health preserves unknown/degraded truth when observations are incomplete", "incident lifecycle is durable, revision-fenced and optionally bound to same-project durable operations/evidence", "SLO/error-budget projections require complete observation coverage before emitting numeric budget truth", "REST, Console and MCP expose the same scoped authority without raw evidence payload disclosure"}},
		{ID: "J7-finops-v2-budget-forecast-rightsizing", Order: 34, Status: ProgramStatusSourceImplemented, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Extend measured FinOps authority with immutable budget thresholds, deterministic forecast/anomaly views and evidence-backed review-only rightsizing while preserving missing-telemetry fail-closed semantics.", DependsOn: []string{"J2-finops-usage", "J4-product-api-contract-recovery-foundation"}, ParallelWith: []string{"J6-fleet-reliability-incident-intelligence"}, Evidence: []string{"FINOPS_BUDGET_POLICY_AUTHORITY_V1", "FINOPS_FORECAST_ANOMALY_RIGHTSIZING_AUTHORITY_V1", "migrations/0073_finops_budget_policy_authority.sql", "POST /api/v1/finops/budget-policies", "GET /api/v1/finops/budget-policies", "GET /api/v1/finops/budget-policies/{id}", "GET /api/v1/finops/insights", "MCP_ROUTE_PARITY_AUTHORITY_V1", "operator-console:finops-budget-forecast-rightsizing"}, ExitCriteria: []string{"budget policies are immutable, organization/project scoped and PostgreSQL-backed in production", "forecast and budget projections remain UNKNOWN when measured cost or rate coverage is incomplete", "spend anomaly is derived deterministically from complete measured baseline and recent cost windows", "rightsizing requires fresh project-aggregate capacity plus complete measured demand and is always review-only with automatable=false"}},
		{ID: "J8-application-platform-abstraction-composition", Order: 35, Status: ProgramStatusBlocked, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Complete the remaining exact-source durable OpenChoreo target adapter around the persisted Application Platform authorities; Fleet gateway runtime transport and release/deployment evidence ingestion are source-implemented without importing a second control plane.", DependsOn: []string{"E-certified-platform-template-workspace-foundation", "J4-product-api-contract-recovery-foundation", "J5-resource-scope-owner-closure"}, ParallelWith: []string{"J3-virtual-cluster-profile", "J6-fleet-reliability-incident-intelligence", "J7-finops-v2-budget-forecast-rightsizing", "I2-edge-sovereign-extension"}, Blockers: []string{"OPENCHOREO_EXACT_SOURCE_LIFECYCLE_ADAPTER_PENDING"}, Evidence: []string{OpenChoreoReferenceAuthority, "TARGET_ARCHITECTURE_MODEL_V1", "PLATFORM_TEMPLATE_AUTHORITY_V1", "WORKSPACE_AUTHORITY_V1", "WORKLOAD_TYPE_AUTHORITY_V1", "CAPABILITY_TRAIT_AUTHORITY_V1", "WORKLOAD_COMPOSITION_AUTHORITY_V1", "MANAGED_RESOURCE_TYPE_AUTHORITY_V1", "WORKSPACE_PROFILE_AUTHORITY_V1", "APPLICATION_RELEASE_AUTHORITY_V1", "ENVIRONMENT_BINDING_AUTHORITY_V1", "internal/controlplane/application_platform_composition.go", "internal/controlplane/application_platform_store.go", "internal/persistence/postgres_application_platform.go", "migrations/0082_application_platform_authority.sql", "POST /api/v1/application-platform/workload-types", "POST /api/v1/application-platform/resource-types", "POST /api/v1/application-platform/workspace-profiles", "POST /api/v1/application-platform/releases", "POST /api/v1/application-platform/environment-bindings", "POST /api/v1/application-platform/environment-bindings/{id}/promote", "FLEET_AGENT_GATEWAY_SESSION_AUTHORITY_V1", "migrations/0083_fleet_gateway_session_authority.sql", "POST /agent/v1/clusters/{id}/gateway-sessions/admit", "POST /agent/v1/clusters/{id}/gateway-sessions/{sessionId}/heartbeat", "GET /agent/v1/clusters/{id}/gateway-session-head", "GET /agent/v1/clusters/{id}/gateway-stream", "cmd/platform-agent/fleet_gateway.go", "internal/api/fleet_gateway_stream.go", "internal/api/fleet_gateway_stream_test.go", "POST /api/v1/clusters/{id}/gateway-session/drain", "DELIVERY_INSIGHTS_AUTHORITY_V1", "internal/api/reliability_delivery_projection.go", "internal/api/reliability_delivery_projection_test.go", "APPLICATION_RELEASE_SOURCE_PROVENANCE", "application.deploy durable terminal operations", "GET /api/v1/reliability/delivery-insights", "POST /api/v1/application-platform/openchoreo/assessment", "TARGET_CAPABILITY_RESOLVER_V1", "MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1", "FINOPS_USAGE_MEASUREMENT_AUTHORITY_V1", "INCIDENT_AUTHORITY_V1", "PRODUCT_API_CONTRACT_AUTHORITY_V1", "MCP_ROUTE_PARITY_AUTHORITY_V1"}, ExitCriteria: []string{"WorkloadType/CapabilityTrait composition is typed, immutable/versioned and capability-resolved without blueprint variant explosion", "ManagedResourceType outputs and secrets are typed references; target CRDs/operators/Crossplane never become product SoT", "WorkspaceProfile and immutable EnvironmentBinding promotion are explicit and preserve desired/rendered/observed authority separation", "Fleet streaming transport has outbound mTLS identity, heartbeat, reconnect/backoff, session epoch, duplicate-session and gateway-drain semantics without bypassing task fences", "delivery/DORA and AI insights are bounded derived projections over exact releases, operations, incidents, audit and measured telemetry", "optional OpenChoreo target adapter is disabled by default, target-only, exact-source/disconnected-capable and duplicate-stack aware"}},
		{ID: "C9-pre-certification-feature-freeze-exact-bundle", Order: 36, Status: ProgramStatusBlocked, DeliveryTier: ProgramTierCoreFreeze, RequiredForFeatureFreeze: true, Objective: "Freeze required product scope and assemble one exact immutable release only after every mandatory DAG branch and certification contract is ready.", DependsOn: []string{c5Phase, "C6-multi-agent-test-autopilot", c7Phase, c7OAuthPhase, c7ParityPhase, c8Phase, fPhase, "S2-component-runtime-certification-authorities", "G3-target-node-maintenance-lifecycle", "G4-data-protection-productization", "G5-enterprise-identity-compliance", "H1-baremetal-connected-managed-okd", "I1-disconnected-okd-core"}, Blockers: []string{"PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN", "LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING"}, Evidence: []string{"FEATURE_FREEZE_AUTHORITY_V1", FeatureCertificationRegistryAuthority, "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8", "ARTIFACT-MANIFEST.json", "BUILD-PROVENANCE.json", "SBOM.spdx.json"}},
		{ID: "D-exact-artifact-lab-ai-certification", Order: 37, Status: ProgramStatusDeferred, DeliveryTier: ProgramTierCertification, Objective: "Execute Exact-SHA physical functional certification M00-M10 only after C9 development closure; until then this phase is deferred and never blocks coding, feature hardening or source/runtime-realism validation.", DependsOn: []string{"C9-pre-certification-feature-freeze-exact-bundle"}, Evidence: []string{"LAB_CERTIFICATION_MATRIX_V2", "scripts/lab_runner.py", "LAB_EXACT_RELEASE_EXECUTION_AUTHORITY_V1", "PHYSICAL_CERTIFICATION_DEFERRED_UNTIL_DEVELOPMENT_CLOSURE_V1"}, ExitCriteria: []string{"same exact release executes M00-M10 and all feature contracts requiring physical/integration evidence", "Physical PASS is recorded only from direct exact-SHA evidence"}},
		{ID: "K-optional-vm-workload-plane", Order: 38, Status: ProgramStatusNotEvaluated, DeliveryTier: ProgramTierOptional, Objective: "Evaluate an optional KubeVirt VM workload plane without blocking required feature freeze.", DependsOn: []string{"J3-virtual-cluster-profile"}, Blockers: []string{"VM_WORKLOAD_PLANE_PRODUCT_DECISION_PENDING"}},
		{ID: "L-optional-accelerator-ai-infrastructure", Order: 39, Status: ProgramStatusNotEvaluated, DeliveryTier: ProgramTierOptional, Objective: "Evaluate accelerator inventory/pooling/quota/placement as an optional infrastructure capability without blocking required feature freeze.", DependsOn: []string{"J2-finops-usage"}, ParallelWith: []string{"K-optional-vm-workload-plane"}, Blockers: []string{"ACCELERATOR_INFRASTRUCTURE_PRODUCT_DECISION_PENDING"}},
		{ID: "M-full-product-certification-chaos-soak-ux-ai-evals", Order: 40, Status: ProgramStatusDeferred, DeliveryTier: ProgramTierCertification, Objective: "Run M11-M13 chaos/load/soak/two-cluster plus final security/UI/AI/MCP certification only after Exact-SHA functional D; it is deferred during development and is not a coding blocker.", DependsOn: []string{"D-exact-artifact-lab-ai-certification"}, Evidence: []string{"PHYSICAL_CERTIFICATION_DEFERRED_UNTIL_DEVELOPMENT_CLOSURE_V1"}, ExitCriteria: []string{"M11 failure controls pass", "M12 high-load soak passes", "M13 two-cluster isolation passes", "Operator Console and AI/MCP adversarial certification pass"}},
	}

	// V68 separates source/software completion from release/runtime closure. Legacy Status remains
	// for mixed-version consumers, but progress and feature-freeze truth use the independent fields.
	for i := range phases {
		switch phases[i].Status {
		case ProgramStatusSourceImplemented:
			phases[i].SourceStatus = ProgramSourceStatusImplemented
			phases[i].ClosureStatus = ProgramClosureStatusReady
		case ProgramStatusBlocked:
			phases[i].SourceStatus = ProgramSourceStatusOpen
			phases[i].ClosureStatus = ProgramClosureStatusBlocked
		case ProgramStatusDeferred:
			phases[i].SourceStatus = ProgramSourceStatusOpen
			phases[i].ClosureStatus = ProgramClosureStatusDeferred
		default:
			phases[i].SourceStatus = ProgramSourceStatusOpen
			phases[i].ClosureStatus = ProgramClosureStatusPending
		}
	}
	// These phases have complete source/software contracts but remain blocked on external/runtime evidence.
	for _, id := range []string{c7ParityPhase, currentPhase, "S2-component-runtime-certification-authorities", "H1-baremetal-connected-managed-okd", "I1-disconnected-okd-core", "C9-pre-certification-feature-freeze-exact-bundle"} {
		for i := range phases {
			if phases[i].ID == id {
				phases[i].SourceStatus = ProgramSourceStatusImplemented
				break
			}
		}
	}

	executionWaves := []ProgramExecutionWave{
		{ID: "W0-truth-rebaseline", Title: "Truth rebaseline", Objective: "Keep executable roadmap/source truth synchronized with canonical main and close stale phase blockers before scheduling new work.", PhaseIDs: []string{"J6-fleet-reliability-incident-intelligence"}, MaxParallel: 1},
		{ID: "W1-core-closure-blitz", Title: "Core closure blitz", Objective: "Stream exact acquisition into component certification while management images, base/product images, manifest resolution and toolchain locks advance independently.", PhaseIDs: []string{currentPhase, "S2-component-runtime-certification-authorities"}, MaxParallel: 6},
		{ID: "W2-core-evidence-parallel", Title: "Core evidence parallel", Objective: "Close external MCP interoperability, connected Managed OKD and disconnected OKD evidence without serializing software work behind physical certification.", PhaseIDs: []string{c7ParityPhase, "H1-baremetal-connected-managed-okd", "I1-disconnected-okd-core"}, MaxParallel: 3},
		{ID: "W3-expansion-mega-wave", Title: "Expansion mega-wave", Objective: "Develop Terraform/Crossplane, public-cloud provider adapters, Virtual Cluster, Edge/Sovereign and application-platform composition software in parallel over stable product authorities.", PhaseIDs: []string{"J1-automation-external-integrations", "H3-public-cloud-provider-adapters", "J3-virtual-cluster-profile", "I2-edge-sovereign-extension", "J8-application-platform-abstraction-composition"}, MaxParallel: 5},
		{ID: "W4-convergence", Title: "Cross-surface convergence", Objective: "Converge API, SDK, MCP, Console, PostgreSQL, durable operations, evidence and negative controls for all newly closed capabilities, including application-platform composition.", PhaseIDs: []string{"J1-automation-external-integrations", "H3-public-cloud-provider-adapters", "J3-virtual-cluster-profile", "I2-edge-sovereign-extension", "J8-application-platform-abstraction-composition"}, MaxParallel: 5},
		{ID: "W5-feature-freeze", Title: "Feature freeze and exact bundle", Objective: "Freeze mandatory scope and produce one immutable exact release only after required closure states are ready.", PhaseIDs: []string{"C9-pre-certification-feature-freeze-exact-bundle"}, MaxParallel: 1},
	}

	certificationRegistry := []FeatureCertificationRequirement{
		{Feature: "architecture-authority", OwnerPhases: []string{"A-architecture-authority-rebaseline"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationRuntimeRealism}, NegativeControls: []string{"management-plane-target-role-conflation-rejected", "distribution-provisioning-infrastructure-conflation-rejected"}},
		{Feature: "target-capability-supply-chain", OwnerPhases: []string{"B-target-capability-supplychain-foundation"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism}, NegativeControls: []string{"unobserved-okd-capability-admission-rejected", "mutable-or-unlocked-source-admission-rejected"}},
		{Feature: "operator-scope-authority", OwnerPhases: []string{"C1-operator-ia-scope-authority"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism}, NegativeControls: []string{"cross-organization-context-leak-rejected", "ambiguous-scope-mutation-rejected"}},
		{Feature: "console-data-scale-refresh", OwnerPhases: []string{"C2-console-data-scale-refresh-semantics"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism}, NegativeControls: []string{"unbounded-hot-path-materialization-rejected", "stale-refresh-overwrite-rejected"}},
		{Feature: "console-action-workflow", OwnerPhases: []string{"C3-console-action-workflow-evidence-convergence"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"forbidden-action-hidden-and-rejected", "self-approval-or-unfenced-mutation-rejected"}},
		{Feature: "console-e2e-ux", OwnerPhases: []string{"C4-console-e2e-ux-certification"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationIntegrationLab}, NegativeControls: []string{"responsive-overflow-regression-detected", "unlabeled-or-keyboard-inaccessible-control-detected"}},
		{Feature: "certified-platform-template-workspace", OwnerPhases: []string{"E-certified-platform-template-workspace-foundation"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"cross-project-workspace-binding-rejected", "uncertified-template-admission-rejected"}},
		{Feature: "management-appliance-installer", OwnerPhases: []string{"C5-installer-production-lifecycle-closure"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationExactSHAPhysicalRuntime}, PhysicalScenarios: []string{"M00", "M01", "M02", "M03"}, NegativeControls: []string{"interrupted-install-resume-does-not-duplicate-runtime", "wrong-release-or-stale-journal-rejected"}},
		{Feature: "multi-agent-test-autopilot", OwnerPhases: []string{"C6-multi-agent-test-autopilot"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"concurrent-repair-writers-rejected", "checkpoint-without-evidence-not-promoted"}},
		{Feature: "ai-mcp-delegated-operations", OwnerPhases: []string{"C7-ai-mcp-delegated-operations"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"arbitrary-shell-ssh-sql-authority-rejected", "model-release-pass-override-rejected"}},
		{Feature: "remote-mcp-oauth-user-admin-delegation", OwnerPhases: []string{"C7R-mcp-remote-oauth-human-delegation"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"wrong-audience-or-revoked-delegation-rejected", "requester-self-approval-rejected"}},
		{Feature: "mcp-user-admin-parity", OwnerPhases: []string{"C7W-mcp-user-admin-write-parity"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"read-only-client-mutation-tool-hidden", "lost-response-idempotent-replay-does-not-repeat-mutation"}},
		{Feature: "console-operational-completion", OwnerPhases: []string{"C8-console-operational-completion"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"loading-error-forbidden-state-truth-preserved", "operation-success-not-inferred-from-request-creation"}},
		{Feature: "existing-kubernetes-okd-import", OwnerPhases: []string{"F-okd-import-capability-certification"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab, CertificationExactSHAPhysicalRuntime}, PhysicalScenarios: []string{"M04", "M05", "M06"}, NegativeControls: []string{"revoked-enrollment-cannot-reconnect", "unhealthy-or-ambiguous-okd-capabilities-not-admitted"}},
		{Feature: "release-authority-rebaseline", OwnerPhases: []string{"R0-release-authority-certification-rebaseline"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationRuntimeRealism}, NegativeControls: []string{"physical-pass-never-inferred-from-source-gates", "blocked-required-phase-keeps-product-release-not-ready"}},
		{Feature: "exact-supply-chain-acquisition", OwnerPhases: []string{"S1-exact-supply-chain-acquisition-closure"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"missing-or-mutable-source-lock-fails-closed", "forged-ready-acquisition-lock-rejected"}},
		{Feature: "component-runtime-certification", OwnerPhases: []string{"S2-component-runtime-certification-authorities"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"stale-source-lock-or-wrong-fence-rejected", "failed-upgrade-or-live-crd-delete-not-certified"}},
		{Feature: "operational-runtime-hardening", OwnerPhases: []string{"G1-operational-runtime-hardening"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"unknown-runtime-state-not-rendered-as-healthy", "localization-or-runtime-observability-gap-detected"}},
		{Feature: "generalized-day2-campaign-engine", OwnerPhases: []string{"G2-generalized-day2-campaign-engine"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"stale-campaign-fence-rejected", "partial-wave-failure-preserves-recovery-state"}},
		{Feature: "target-node-day2-lifecycle", OwnerPhases: []string{"G3-target-node-maintenance-lifecycle"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab, CertificationExactSHAPhysicalRuntime}, PhysicalScenarios: []string{"M07"}, NegativeControls: []string{"unsupported-provider-or-control-plane-mutation-rejected", "unsafe-replay-after-crash-rejected"}},
		{Feature: "data-protection", OwnerPhases: []string{"G4-data-protection-productization"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab, CertificationChaosLoadSoak}, PhysicalScenarios: []string{"M11"}, NegativeControls: []string{"restore-without-verified-backup-evidence-rejected", "cross-project-backup-credential-use-rejected"}},
		{Feature: "enterprise-identity-compliance", OwnerPhases: []string{"G5-enterprise-identity-compliance"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"raw-idp-admin-secret-never-enters-model-context", "expired-waiver-or-broker-scope-mismatch-rejected"}},
		{Feature: "connected-managed-okd-compact3", OwnerPhases: []string{"H1-baremetal-connected-managed-okd"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab, CertificationExactSHAPhysicalRuntime}, PhysicalScenarios: []string{"M08"}, NegativeControls: []string{"agent-iso-digest-or-redfish-scope-mismatch-rejected", "duplicate-or-foreign-cluster-import-ownership-rejected"}},
		{Feature: "disconnected-okd", OwnerPhases: []string{"I1-disconnected-okd-core"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab, CertificationExactSHAPhysicalRuntime}, PhysicalScenarios: []string{"M09", "M10"}, NegativeControls: []string{"unsealed-or-symlinked-mirror-content-rejected", "mirror-success-never-implies-disconnected-install-pass"}},
		{Feature: "final-chaos-load-soak", OwnerPhases: []string{"M-full-product-certification-chaos-soak-ux-ai-evals"}, RequiredLevels: []string{CertificationChaosLoadSoak}, PhysicalScenarios: []string{"M11", "M12", "M13"}, NegativeControls: []string{"cross-cluster-isolation-failure-detected", "soak-or-chaos-failure-never-promoted-to-pass"}},
	}
	certificationCoverage := featureCertificationCoverage(phases, certificationRegistry)

	goalReady := true
	for _, phase := range phases {
		if phase.RequiredForFeatureFreeze && phase.ClosureStatus != ProgramClosureStatusReady {
			goalReady = false
			break
		}
	}

	progress := programProgressSummary(phases, goalReady)
	return ProgramRoadmap{Authority: ProgramAuthorityMethod, CurrentPhase: currentPhase, CurrentExecutionWave: "W1-core-closure-blitz", ExecutionWaves: executionWaves, GoalReady: goalReady, Positioning: positioning, PrimaryBenchmarks: primaryBenchmarks, CompetitiveDifferentiators: competitiveDifferentiators, DeferredParity: deferredParity, Tracks: tracks, GlobalGuardrails: globalGuardrails, CertificationRegistryAuthority: FeatureCertificationRegistryAuthority, CertificationRegistry: certificationRegistry, CertificationCoverage: certificationCoverage, Progress: progress, Phases: phases}
}

func blockerClosureClass(blocker string) string {
	classes := map[string]string{
		"MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING":      "external-client-evidence",
		"COMPONENT_SOURCE_ACQUISITION_PENDING":            "external-byte-acquisition",
		"SOURCE_LOCKS_PENDING":                            "external-byte-acquisition",
		"MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING":         "external-byte-acquisition",
		"MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING":           "external-byte-acquisition",
		"RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING":            "external-byte-acquisition",
		"UPSTREAM_RUNTIME_SUITABILITY_HOLDS_PENDING":      "runtime-certification-evidence",
		"COMPONENT_HISTORICAL_SOURCE_ACQUISITION_PENDING": "external-byte-acquisition",
		"COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING":        "runtime-certification-evidence",
		"OKD_CONNECTED_MANAGED_INSTALL_PENDING":           "physical-runtime-evidence",
		"OKD_OC_MIRROR_V2_ACQUISITION_PENDING":            "external-byte-acquisition",
		"PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN":        "aggregate-release-closure",
		"LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING":       "external-byte-acquisition",
	}
	return classes[blocker]
}

func programProgressSummary(phases []ProgramPhase, goalReady bool) ProgramProgressSummary {
	out := ProgramProgressSummary{Authority: ProgramProgressAuthority, FeatureFreezeReady: goalReady, RemainingBlockerClasses: map[string]int{}}
	for _, phase := range phases {
		if !phase.RequiredForFeatureFreeze || phase.DeliveryTier != ProgramTierCoreFreeze {
			continue
		}
		out.CoreRequiredPhases++
		if phase.SourceStatus == ProgramSourceStatusImplemented {
			out.CoreSourceClosedPhases++
		} else {
			out.CoreSourceOpenPhases++
			out.SourceOpenPhaseIDs = append(out.SourceOpenPhaseIDs, phase.ID)
		}
		if phase.ClosureStatus == ProgramClosureStatusReady {
			out.CorePhaseReady++
		} else {
			out.CorePhaseBlocked++
			if phase.SourceStatus == ProgramSourceStatusImplemented {
				out.ExternalClosureOnlyPhaseIDs = append(out.ExternalClosureOnlyPhaseIDs, phase.ID)
			}
			if len(phase.Blockers) == 0 {
				out.RemainingBlockerClasses["source-software-closure"]++
			}
			for _, blocker := range phase.Blockers {
				class := blockerClosureClass(blocker)
				if class == "" {
					class = "source-software-closure"
				}
				out.RemainingBlockerClasses[class]++
			}
		}
	}
	if out.CoreRequiredPhases > 0 {
		out.CoreSourceClosurePercent = out.CoreSourceClosedPhases * 100 / out.CoreRequiredPhases
		out.CorePhaseReadyPercent = out.CorePhaseReady * 100 / out.CoreRequiredPhases
	}
	out.CoreSourceClosureComplete = out.CoreSourceOpenPhases == 0 && out.CoreRequiredPhases > 0
	for _, phase := range phases {
		if phase.DeliveryTier != ProgramTierCoreFreeze && phase.DeliveryTier != ProgramTierExpansion {
			continue
		}
		out.PrePhysicalSoftwarePhases++
		if phase.SourceStatus == ProgramSourceStatusImplemented {
			out.PrePhysicalSoftwareClosedPhases++
		} else {
			out.PrePhysicalSoftwareOpenPhases++
		}
	}
	if out.PrePhysicalSoftwarePhases > 0 {
		out.PrePhysicalSoftwareClosurePercent = out.PrePhysicalSoftwareClosedPhases * 100 / out.PrePhysicalSoftwarePhases
	}
	sort.Strings(out.SourceOpenPhaseIDs)
	sort.Strings(out.ExternalClosureOnlyPhaseIDs)
	return out
}

func featureCertificationCoverage(phases []ProgramPhase, registry []FeatureCertificationRequirement) FeatureCertificationCoverage {
	required := map[string]bool{}
	for _, phase := range phases {
		if phase.RequiredForFeatureFreeze && phase.ID != "C9-pre-certification-feature-freeze-exact-bundle" {
			required[phase.ID] = true
		}
	}
	covered := map[string]bool{}
	for _, contract := range registry {
		for _, owner := range contract.OwnerPhases {
			if required[owner] {
				covered[owner] = true
			}
		}
	}
	missing := make([]string, 0)
	for owner := range required {
		if !covered[owner] {
			missing = append(missing, owner)
		}
	}
	sort.Strings(missing)
	return FeatureCertificationCoverage{Authority: FeatureCertificationCoverageAuthority, RequiredOwnerPhases: len(required), CoveredOwnerPhases: len(covered), MissingOwnerPhases: missing, Complete: len(missing) == 0}
}

func ValidateFeatureCertificationRegistry(roadmap ProgramRoadmap) []string {
	issues := []string{}
	phaseByID := map[string]ProgramPhase{}
	for _, phase := range roadmap.Phases {
		phaseByID[phase.ID] = phase
	}
	seenFeature := map[string]bool{}
	allowedLevels := map[string]bool{
		CertificationSourceSemantics: true, CertificationGeneratedRuntime: true,
		CertificationRuntimeRealism: true, CertificationIntegrationLab: true,
		CertificationExactSHAPhysicalRuntime: true, CertificationChaosLoadSoak: true,
	}
	for _, contract := range roadmap.CertificationRegistry {
		if strings.TrimSpace(contract.Feature) == "" {
			issues = append(issues, "feature-name-empty")
			continue
		}
		if seenFeature[contract.Feature] {
			issues = append(issues, "duplicate-feature:"+contract.Feature)
		}
		seenFeature[contract.Feature] = true
		if len(contract.OwnerPhases) == 0 {
			issues = append(issues, "owner-phase-missing:"+contract.Feature)
		}
		for _, owner := range contract.OwnerPhases {
			if _, ok := phaseByID[owner]; !ok {
				issues = append(issues, "unknown-owner-phase:"+contract.Feature+":"+owner)
			}
		}
		if len(contract.RequiredLevels) == 0 {
			issues = append(issues, "required-levels-missing:"+contract.Feature)
		}
		needsScenario := false
		for _, level := range contract.RequiredLevels {
			if !allowedLevels[level] {
				issues = append(issues, "unknown-level:"+contract.Feature+":"+level)
			}
			if level == CertificationExactSHAPhysicalRuntime || level == CertificationChaosLoadSoak {
				needsScenario = true
			}
		}
		if needsScenario && len(contract.PhysicalScenarios) == 0 {
			issues = append(issues, "physical-scenario-missing:"+contract.Feature)
		}
		if len(contract.NegativeControls) == 0 {
			issues = append(issues, "negative-controls-missing:"+contract.Feature)
		}
	}
	coverage := featureCertificationCoverage(roadmap.Phases, roadmap.CertificationRegistry)
	if !coverage.Complete {
		for _, owner := range coverage.MissingOwnerPhases {
			issues = append(issues, "required-owner-uncovered:"+owner)
		}
	}
	sort.Strings(issues)
	return issues
}

func FeatureFreezeBlockerCounts(roadmap ProgramRoadmap) map[string]int {
	out := map[string]int{}
	for _, phase := range roadmap.Phases {
		if !phase.RequiredForFeatureFreeze || phase.ClosureStatus == ProgramClosureStatusReady {
			continue
		}
		if len(phase.Blockers) == 0 {
			out["ROADMAP_PHASE_NOT_READY"]++
			continue
		}
		for _, blocker := range phase.Blockers {
			blocker = strings.TrimSpace(blocker)
			if blocker != "" {
				out[blocker]++
			}
		}
	}
	return out
}

func CapabilityResolverModel() CapabilityResolverDescriptor {
	return CapabilityResolverDescriptor{
		Authority:       CapabilityResolverAuthority,
		Status:          "OKD_IMPORT_ADMISSION_SOURCE_READY",
		AdmittedTargets: []string{DistributionKubernetes, DistributionRKE2, DistributionOKD},
		PreviewTargets:  nil,
	}
}

func ResolveTargetComponents(distribution string, requested []string, observedCapabilities []string) CapabilityResolution {
	identity := CanonicalDistribution(distribution)
	requested = uniqueSorted(requested)
	observed := make(map[string]bool, len(observedCapabilities))
	for _, capability := range observedCapabilities {
		capability = strings.ToLower(strings.TrimSpace(capability))
		if capability != "" {
			observed[capability] = true
		}
	}

	out := CapabilityResolution{Authority: CapabilityResolverAuthority, DistributionIdentity: identity}
	switch identity {
	case DistributionKubernetes, DistributionRKE2:
		out.Status = "ADMITTED"
		out.Admitted = true
	case DistributionOKD:
		out.IntrinsicCapabilities = []string{
			"networking.ovn-kubernetes",
			"network-policy.native",
			"monitoring.cluster",
			"operator-lifecycle.olm",
			"security.scc",
			"tenancy.projects",
		}
		required := []string{"okd-import-admitted", "networking.ovn-kubernetes", "monitoring.cluster", "operator-lifecycle.olm", "security.scc", "tenancy.projects"}
		missing := []string{}
		for _, capability := range required {
			if !observed[capability] {
				missing = append(missing, capability)
			}
		}
		if len(missing) == 0 {
			out.Status = "ADMITTED"
			out.Admitted = true
		} else {
			out.Status = "DISCOVERED_BLOCKED"
			out.Admitted = false
			for _, capability := range missing {
				out.Blockers = append(out.Blockers, "OKD_CAPABILITY_MISSING:"+capability)
			}
		}
	default:
		out.Status = "UNSUPPORTED"
		out.Admitted = false
		out.Blockers = []string{"TARGET_DISTRIBUTION_NOT_ADMITTED"}
	}

	for _, component := range requested {
		decision := CapabilityDecision{Component: component, Action: ResolutionActionInclude, Domain: "product-addon", Authority: CapabilityResolverAuthority, Reason: "no distribution-owned replacement is asserted by the current resolver contract"}
		if identity == DistributionOKD {
			switch component {
			case "cilium":
				if observed["networking.ovn-kubernetes"] {
					decision.Action, decision.Domain, decision.Reason = ResolutionActionSuppress, "networking", "observed OKD inventory proves OVN-Kubernetes owns the primary cluster network; installing Cilium would duplicate distribution-owned networking"
				} else {
					decision.Action, decision.Domain, decision.Reason = ResolutionActionConditional, "networking", "OKD identity alone is insufficient to suppress Cilium until OVN-Kubernetes ownership is observed"
				}
			case "capsule":
				if observed["tenancy.projects"] {
					decision.Action, decision.Domain, decision.Reason = ResolutionActionSuppress, "tenancy", "observed OKD Project API owns the tenant namespace boundary; the default Capsule controller would duplicate distribution-owned tenancy"
				} else {
					decision.Action, decision.Domain, decision.Reason = ResolutionActionConditional, "tenancy", "OKD Project ownership must be observed before Capsule is suppressed"
				}
			case "victoria-metrics":
				if observed["monitoring.cluster"] {
					decision.Action, decision.Domain, decision.Reason = ResolutionActionSuppress, "monitoring", "observed OKD cluster monitoring owns platform metrics; installing the default Factory metrics backend would duplicate the distribution stack"
				} else {
					decision.Action, decision.Domain, decision.Reason = ResolutionActionConditional, "monitoring", "cluster-monitoring ownership must be observed before the default metrics backend is suppressed"
				}
			case "kyverno":
				decision.Action, decision.Domain, decision.Reason = ResolutionActionConditional, "policy", "OKD provides SCC/RBAC/admission controls; Kyverno is selected only when target inventory and product policy require capabilities not satisfied natively"
			case "metallb":
				decision.Action, decision.Domain, decision.Reason = ResolutionActionConditional, "load-balancer", "load-balancer ownership is infrastructure/capability dependent on OKD; MetalLB is not a distribution-wide default"
			case "snapshot-controller":
				decision.Action, decision.Domain, decision.Reason = ResolutionActionConditional, "snapshot", "snapshot-controller is selected only when target discovery proves the capability is absent"
			case "tetragon":
				decision.Action, decision.Domain, decision.Reason = ResolutionActionConditional, "runtime-security", "the current catalog binds Tetragon to Cilium; an OKD runtime-security profile must resolve that dependency before selection"
			}
		}
		if component == "snapshot-controller" && observed["volume-snapshot-controller"] {
			decision.Action, decision.Domain, decision.Reason = ResolutionActionSuppress, "snapshot", "target inventory already reports a volume snapshot controller"
		}
		out.Decisions = append(out.Decisions, decision)
	}
	sort.Slice(out.Decisions, func(i, j int) bool { return out.Decisions[i].Component < out.Decisions[j].Component })
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
