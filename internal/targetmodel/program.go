package targetmodel

import (
	"sort"
	"strings"
)

const (
	ProgramAuthorityMethod                = "PROGRAM_PHASE_MODEL_V75"
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
	const s1Phase = "S1-exact-supply-chain-acquisition-closure"
	const currentPhase = c7ParityPhase
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
	tracks := programTracksV75()
	globalGuardrails := programGlobalGuardrailsV75()
	phases := programPhasesV75(dataScalePhase, actionPhase, c4Phase, c5Phase, c7Phase, c7OAuthPhase, c7ParityPhase, c8Phase, fPhase, s1Phase, operatorScopePhase)

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
	for _, id := range []string{c7ParityPhase, "J8-application-platform-abstraction-composition", "C9-pre-certification-feature-freeze-exact-bundle"} {
		for i := range phases {
			if phases[i].ID == id {
				phases[i].SourceStatus = ProgramSourceStatusImplemented
				break
			}
		}
	}

	executionWaves := programExecutionWavesV75(c7ParityPhase, s1Phase)
	certificationRegistry := programCertificationRegistryV75()
	certificationCoverage := featureCertificationCoverage(phases, certificationRegistry)

	goalReady := true
	for _, phase := range phases {
		if phase.RequiredForFeatureFreeze && phase.ClosureStatus != ProgramClosureStatusReady {
			goalReady = false
			break
		}
	}

	progress := programProgressSummary(phases, goalReady)
	roadmap := ProgramRoadmap{Authority: ProgramAuthorityMethod, CurrentPhase: currentPhase, CurrentExecutionWave: "W2-core-evidence-parallel", ExecutionWaves: executionWaves, GoalReady: goalReady, Positioning: positioning, PrimaryBenchmarks: primaryBenchmarks, CompetitiveDifferentiators: competitiveDifferentiators, DeferredParity: deferredParity, Tracks: tracks, GlobalGuardrails: globalGuardrails, CertificationRegistryAuthority: FeatureCertificationRegistryAuthority, CertificationRegistry: certificationRegistry, CertificationCoverage: certificationCoverage, Progress: progress, Phases: phases}
	return competitiveProofRoadmapRebaseline(roadmap)
}

func blockerClosureClass(blocker string) string {
	classes := map[string]string{
		"MCP_EXTERNAL_CLIENT_INTEROP_EVIDENCE_PENDING":        "external-client-evidence",
		"COMPONENT_SOURCE_ACQUISITION_PENDING":                "external-byte-acquisition",
		"SOURCE_LOCKS_PENDING":                                "external-byte-acquisition",
		"APPLIANCE_INPUT_PACK_DISTRIBUTION_PENDING":           "external-distribution-evidence",
		"MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING":               "external-byte-acquisition",
		"RELEASE_BUILD_TOOLCHAIN_LOCK_PENDING":                "external-byte-acquisition",
		"UPSTREAM_RUNTIME_SUITABILITY_HOLDS_PENDING":          "runtime-certification-evidence",
		"COMPONENT_HISTORICAL_SOURCE_ACQUISITION_PENDING":     "external-byte-acquisition",
		"COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING":            "runtime-certification-evidence",
		"OKD_CONNECTED_MANAGED_INSTALL_PENDING":               "physical-runtime-evidence",
		"OKD_DISCONNECTED_RUNTIME_CERTIFICATION_PENDING":      "runtime-certification-evidence",
		"OPENCHOREO_PRODUCTION_ZOT_SEAL_PENDING":              "external-byte-acquisition",
		"FINAL_EXACT_RELEASE_SEAL_PENDING":                    "aggregate-release-closure",
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
