package targetmodel

import (
	"sort"
	"strings"
)

const (
	ProgramAuthorityMethod      = "PROGRAM_PHASE_MODEL_V3"
	CapabilityResolverAuthority = "TARGET_CAPABILITY_RESOLVER_V1"

	ProgramStatusSourceImplemented = "source-implemented"
	ProgramStatusBlocked           = "blocked"
	ProgramStatusNotEvaluated      = "not-evaluated"

	ResolutionActionInclude     = "include"
	ResolutionActionSuppress    = "suppress"
	ResolutionActionConditional = "conditional"
)

type ProgramPhase struct {
	ID           string   `json:"id"`
	Order        int      `json:"order"`
	Status       string   `json:"status"`
	Objective    string   `json:"objective"`
	DependsOn    []string `json:"dependsOn,omitempty"`
	ParallelWith []string `json:"parallelWith,omitempty"`
	Blockers     []string `json:"blockers,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
	ExitCriteria []string `json:"exitCriteria,omitempty"`
}

type ProgramTrack struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Objective    string   `json:"objective"`
	Requirements []string `json:"requirements"`
}

type ProgramRoadmap struct {
	Authority        string         `json:"authority"`
	CurrentPhase     string         `json:"currentPhase"`
	GoalReady        bool           `json:"goalReady"`
	Tracks           []ProgramTrack `json:"tracks"`
	GlobalGuardrails []string       `json:"globalGuardrails"`
	Phases           []ProgramPhase `json:"phases"`
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
	const currentPhase = "C-ai-native-operator-experience-lab-mcp-foundation"
	tracks := []ProgramTrack{
		{ID: "operator-experience", Title: "Operator Experience / UI / UX", Objective: "Keep every operator-visible capability task-first, authority-backed, responsive, accessible and consistent with the 4SO design system rather than a generic admin template.", Requirements: []string{"4SO Operator Horizon theme and design tokens remain product-owned", "TailAdmin Community patterns are reference-only; CoreUI accessibility practices are adopted where useful without importing framework lock-in", "all new runtime capabilities expose truthful loading/empty/error/forbidden/blocked states and complete keyboard/mobile/RTL paths", "mutations preserve Select -> Inspect -> Allowed Action -> Input -> Impact Preview -> Approval -> Execute -> Evidence"}},
		{ID: "ai-native", Title: "AI-Native Control Plane", Objective: "Make platform authority explainable and diagnosable through one provider-neutral AI runtime without allowing a model to become source of truth or release authority.", Requirements: []string{"mandatory pre-egress redaction and bounded structured output", "durable project-scoped ai_runs with prompt/context/output digests and usage/cost metadata", "cloud OpenAI-compatible and disconnected local provider profiles", "AI may diagnose/propose but execution always returns to deterministic RBAC/approval/durable-operation authority"}},
		{ID: "mcp-agent-surface", Title: "MCP / External Agent Surface", Objective: "Expose safe product context to Codex, Claude, Antigravity and other clients through scoped, auditable, project-authorized MCP contracts.", Requirements: []string{"MCP protocol 2026-07-28 or later explicitly versioned", "tool-level mcp.read/ai.diagnose authorization and project checks", "read-only by default; future mutations create existing durable product operations rather than direct shell/kubectl actions", "external-client interoperability and negative authorization tests are release evidence"}},
		{ID: "lab-certification", Title: "Lab / Release Certification", Objective: "Use a deterministic DBaaS-style server-driven runner for installation, matrices, evidence and exact-SHA certification; AI is failure-only.", Requirements: []string{"M00-M13 machine-readable authority", "exact artifact SHA and server inventory binding", "immutable dependency acquisition; missing authority is BLOCKED", "four-layer Release Gate remains independent and Physical PASS is never inferred"}},
		{ID: "security-evidence", Title: "Security / RBAC / Evidence", Objective: "Preserve tenant isolation, least privilege, fencing, durable audit and evidence truth across UI, API, MCP and AI surfaces.", Requirements: []string{"project/org scope is re-applied at every external context boundary", "secrets never become prompt/audit/UI state", "destructive operations remain confirmation/approval/fencing bound", "evidence identifies source, authority, freshness, digest and exact release context"}},
		{ID: "supply-chain", Title: "Supply Chain / Disconnected", Objective: "Make every product-owned open-source input reproducible, license-aware, digest-locked and usable without hidden internet dependencies.", Requirements: []string{"no arbitrary latest downloads in certification", "Forgejo desired-state and zot registry boundaries remain canonical", "SBOM/provenance/license inventory is release evidence", "disconnected acquisition/install/upgrade is first-class"}},
		{ID: "developer-agent-experience", Title: "Developer / Agent Experience", Objective: "Keep the canonical GitHub repository cloneable, fully documented and cheap to test with deterministic scripts before any agent spends tokens.", Requirements: []string{"full source on canonical main branch; generated runtime/release evidence stays out of source history", "README contains fresh install, lab sizing/matrix, Codex/Claude/Antigravity, MCP and AI-provider paths", "scripts own happy-path tests; AI sees bounded failure packets only", "repository validation prevents documentation/roadmap/test-source drift"}},
	}
	globalGuardrails := []string{
		"PostgreSQL remains the control-plane source of truth; Git/Forgejo remains desired-state history and Argo reconciliation does not become a second product SoT.",
		"AI, MCP clients, UI and agents never bypass RBAC, approvals, idempotency, fencing, durable operations or evidence boundaries.",
		"The Operator Console never invents authority, percentages, health or success from mock/static data; every status is API/authority backed.",
		"Release Gate has four independent layers: Source Semantics, Generated/Installed Runtime Semantics, Runtime-Realism Negative Controls and Exact-SHA Physical Runtime.",
		"Physical PASS is recorded only from direct execution evidence for the exact artifact SHA.",
		"New capabilities are incomplete until API/runtime, Operator Console, AI/MCP exposure where appropriate, documentation, deterministic tests and negative controls are aligned.",
	}
	phases := []ProgramPhase{
		{ID: "A-architecture-authority-rebaseline", Order: 1, Status: ProgramStatusSourceImplemented, Objective: "Keep the self-contained RKE2 management appliance, PostgreSQL authority and target-distribution/provisioning/infrastructure boundaries explicit while eliminating duplicate control planes and documentation truths.", Evidence: []string{AuthorityMethod, "management-plane:rke2", "postgresql-control-plane-sot", "forgejo-desired-state", "zot-canonical-registry"}, ExitCriteria: []string{"management plane remains product-owned and self-contained", "distribution/provisioning/infrastructure identities are independent", "one canonical runtime/source authority exists for each product concern"}},
		{ID: "B-target-capability-supplychain-foundation", Order: 2, Status: ProgramStatusSourceImplemented, Objective: "Provide fail-closed target capability vocabulary plus reproducible catalog/supply-chain contracts without pretending preview distributions are runtime admitted.", DependsOn: []string{"A-architecture-authority-rebaseline"}, Evidence: []string{CapabilityResolverAuthority, "GET /api/v1/target-architecture-model", "catalog-source-locks", "SBOM/provenance"}, ExitCriteria: []string{"Kubernetes/RKE2 admission and OKD preview boundaries remain explicit", "duplicate-stack decisions are capability/inventory driven", "source locks/digests/licenses are machine-readable"}},
		{ID: currentPhase, Order: 3, Status: ProgramStatusBlocked, Objective: "Close the shared AI-native operator experience, deterministic Lab and MCP/agent foundation before expanding OKD runtime scope: custom 4SO design system, truthful workflow UX, unified AI runtime, scoped MCP, full-source developer onboarding and M00-M03 server-driven certification.", DependsOn: []string{"B-target-capability-supplychain-foundation"}, Blockers: []string{"LAB_SERVER_DRIVEN_INSTALL_RUNTIME_CERTIFICATION_PENDING", "LAB_PHASE_C_MATRIX_M00_M03_AUTOMATION_PENDING", "LAB_IMMUTABLE_BUNDLE_AUTO_ACQUISITION_CLOSURE_PENDING", "AI_UNIFIED_RUNTIME_EXTERNAL_PROVIDER_CERTIFICATION_PENDING", "AI_RUN_POSTGRES_DURABILITY_RUNTIME_CERTIFICATION_PENDING", "AI_MCP_SCOPED_EXTERNAL_CLIENT_INTEROPERABILITY_PENDING", "OPERATOR_EXPERIENCE_FULL_VIEWPORT_ACCESSIBILITY_CERTIFICATION_PENDING", "CANONICAL_GITHUB_FULL_SOURCE_PARITY_PENDING"}, Evidence: []string{"LAB_CERTIFICATION_MATRIX_V1", "4SO_OPERATOR_HORIZON_V1", "docs/OPERATOR_CONSOLE_DESIGN_FOUNDATION.md", "internal/airuntime:provider-neutral-redaction-budget-runtime", "migration-0053-durable-ai-run-authority", "GET /api/v1/ai/policy", "POST /api/v1/ai/diagnose:advisory-only", "GET /api/v1/ai/runs", "GET /api/v1/lab/guide", "POST /mcp:2026-07-28:mcp.read:project-scoped-read-only", "platformctl ai policy|redact|diagnose", "scripts/lab_runner.py", "scripts/codex_autopilot.py", "operator-console:command-palette-dark-rtl-responsive-ai-lab-evidence"}, ExitCriteria: []string{"full canonical source and current install/lab/agent documentation are present on GitHub main and reproduce repository validation from a clean clone", "4SO Operator Horizon shell and workflow components pass desktop/mobile, RTL/LTR, keyboard, dark/light, accessibility and truthful state tests without importing a template runtime dependency", "Marketplace/operator/lab diagnosis consume one provider-neutral AI runtime with mandatory redaction, budgets, structured output and durable project-scoped audit", "MCP is authenticated, capability-scoped, project-authorized, modern-protocol and externally interoperable with no direct mutating tool", "an operator supplies exact release plus server inventory and deterministic runner owns M00-M03 execution/evidence while AI sees only bounded failures", "open-source dependencies are automatically acquired only from immutable product-shipped locks or the run is BLOCKED"}},
		{ID: "D-okd-import-identity-security-certification", Order: 4, Status: ProgramStatusBlocked, Objective: "Physically certify OKD import/reconnect, identity continuity, observation freshness, RBAC revocation and same-UID re-enrollment while exposing the same evidence and diagnostics through Operator/AI/MCP read surfaces.", DependsOn: []string{currentPhase}, Blockers: []string{"OKD_IMPORT_RUNTIME_CERTIFICATION_PENDING"}, Evidence: []string{"OKD_CLUSTERVERSION_V1", "target-cluster-uid-attested", "target-rbac-revocation-fence-digest-acknowledgement", "inventoryObservedAt-target-observation-epoch"}, ExitCriteria: []string{"real exact-SHA OKD import/reconnect/revocation is physically evidenced", "same-UID re-enrollment is fenced until exact RBAC revocation acknowledgement", "Operator Console/AI/MCP show the same project-scoped identity and blocker evidence without mutation shortcuts"}},
		{ID: "E-capability-catalog-blueprint-ai-explainability", Order: 5, Status: ProgramStatusBlocked, Objective: "Compile exact observed target capabilities into one catalog/profile/blueprint model and make every include/suppress/conditional decision explainable in API, Operator Console and advisory AI surfaces.", DependsOn: []string{"D-okd-import-identity-security-certification"}, Blockers: []string{"OKD_INVENTORY_BOUND_CAPABILITY_RESOLUTION_PENDING", "OKD_CLUSTER_OPERATOR_HEALTH_TRANSLATION_PENDING", "OKD_DESIRED_OBSERVED_PROFILE_COMPILER_PENDING", "OKD_CATALOG_EXECUTION_PLAN_PENDING"}, ExitCriteria: []string{"native OKD ownership suppresses duplicate defaults from stored inventory", "desired/observed profile compiler is shared across install/import", "catalog/health decisions are inspectable and AI can explain but not override them"}},
		{ID: "F-day2-managed-compact3-workflow-convergence", Order: 6, Status: ProgramStatusBlocked, Objective: "Deliver imported Day-2 and managed Compact-3 with one durable operation model and complete operator workflows, impact previews, recovery evidence and bounded AI remediation proposals.", DependsOn: []string{"E-capability-catalog-blueprint-ai-explainability"}, Blockers: []string{"OKD_DAY2_ACTION_ROUTING_PENDING", "OKD_ADD_REMOVE_REPLACE_RUNTIME_PENDING", "OKD_DAY2_RUNTIME_CERTIFICATION_PENDING", "OKD_INSTALLER_ACQUISITION_AUTHORITY_PENDING", "OKD_BOOT_MEDIA_PROVIDER_PENDING", "OKD_COMPACT3_INSTALL_RUNTIME_CERTIFICATION_PENDING"}, ExitCriteria: []string{"drain/add/remove/replace/install are durable/fenced/retryable", "every mutation has complete Operator Console journey and evidence", "AI proposes bounded remediation through existing plan/approval/operation contracts only"}},
		{ID: "G-disconnected-upgrade-recovery-local-ai", Order: 7, Status: ProgramStatusBlocked, Objective: "Certify disconnected acquisition/install plus CVO-native upgrade/recovery while keeping Operator Console, MCP and AI usable in zero-cloud mode with local inference optional rather than required.", DependsOn: []string{"F-day2-managed-compact3-workflow-convergence"}, Blockers: []string{"OKD_OC_MIRROR_V2_ACQUISITION_PENDING", "OKD_DISCONNECTED_INSTALL_CERTIFICATION_PENDING", "OKD_CVO_UPDATE_GRAPH_AUTHORITY_PENDING", "OKD_CVO_UPGRADE_CERTIFICATION_PENDING", "LOCAL_AI_DISCONNECTED_PROFILE_CERTIFICATION_PENDING"}, ExitCriteria: []string{"oc-mirror v2/zot path works with internet denied", "upgrade/recovery states come from CVO/runtime evidence without fake rollback", "core product remains functional with AI unavailable and optional local AI/MCP diagnostics work without cloud egress"}},
		{ID: "H-full-product-certification-chaos-soak-ux-ai-evals", Order: 8, Status: ProgramStatusNotEvaluated, Objective: "Run complete exact-SHA physical certification across HA, two target clusters, destructive controls, load/24h soak, security, UI/accessibility/performance and AI/MCP evals before declaring the product ready.", DependsOn: []string{"G-disconnected-upgrade-recovery-local-ai"}, Blockers: []string{"PHYSICAL_RUNTIME_NOT_EVALUATED"}, ExitCriteria: []string{"M00-M13 exact-SHA matrix passes on real infrastructure", "management/target failure injection, load and 24h soak keep bounded resources and complete evidence", "Operator Console passes supported desktop/mobile RTL/LTR accessibility/performance workflows", "AI evals cover secret leakage, prompt injection, unsupported claims, provider outage, cross-tenant context and unsafe remediation", "MCP authorization/interoperability negative controls pass", "Physical PASS is recorded only from exact artifact evidence"}},
	}
	return ProgramRoadmap{Authority: ProgramAuthorityMethod, CurrentPhase: currentPhase, GoalReady: false, Tracks: tracks, GlobalGuardrails: globalGuardrails, Phases: phases}
}

func CapabilityResolverModel() CapabilityResolverDescriptor {
	return CapabilityResolverDescriptor{
		Authority:       CapabilityResolverAuthority,
		Status:          "FOUNDATION_READY_OKD_PREVIEW_ONLY",
		AdmittedTargets: []string{DistributionKubernetes, DistributionRKE2},
		PreviewTargets:  []string{DistributionOKD},
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
		out.Status = "PREVIEW_ONLY"
		out.Admitted = false
		out.IntrinsicCapabilities = []string{
			"networking.ovn-kubernetes",
			"network-policy.native",
			"monitoring.cluster",
			"operator-lifecycle.olm",
			"security.scc",
			"tenancy.projects",
		}
		out.Blockers = []string{"OKD_TARGET_NOT_ADMITTED"}
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
				decision.Action, decision.Domain, decision.Reason = ResolutionActionSuppress, "networking", "OKD owns the primary cluster network through OVN-Kubernetes; installing the default Cilium stack would duplicate distribution-owned networking"
			case "capsule":
				decision.Action, decision.Domain, decision.Reason = ResolutionActionSuppress, "tenancy", "OKD Projects/namespaces are the first-class tenant boundary; the default Capsule tenant controller is not selected for the OKD profile"
			case "victoria-metrics":
				decision.Action, decision.Domain, decision.Reason = ResolutionActionSuppress, "monitoring", "OKD ships cluster monitoring; the default Factory metrics backend must not be installed as a duplicate platform monitoring stack"
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
