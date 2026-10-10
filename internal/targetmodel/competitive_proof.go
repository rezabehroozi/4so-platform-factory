package targetmodel

const (
	CompetitiveProofAuthority              = "COMPETITIVE_PROOF_PHASE_MODEL_V1"
	CompetitiveTierExpansion               = "competitive-expansion"
	CompetitiveTierCertification           = "competitive-certification"
	CompetitiveStatusSourceOpen            = "source-open"
	CompetitiveStatusSourceImplemented     = "source-implemented"
	CompetitiveStatusCertificationPending  = "certification-pending"
)

type CompetitiveProofPhase struct {
	ID                string   `json:"id"`
	Order             int      `json:"order"`
	DeliveryTier      string   `json:"deliveryTier"`
	SourceStatus      string   `json:"sourceStatus"`
	Objective         string   `json:"objective"`
	CoreFreezeBlocker bool     `json:"coreFreezeBlocker"`
	DependsOn         []string `json:"dependsOn,omitempty"`
	ParallelWith      []string `json:"parallelWith,omitempty"`
	Blockers          []string `json:"blockers,omitempty"`
	Benchmarks        []string `json:"benchmarks,omitempty"`
	Evidence          []string `json:"evidence,omitempty"`
	ExitCriteria      []string `json:"exitCriteria,omitempty"`
}

type CompetitiveProofProgram struct {
	Authority                    string                  `json:"authority"`
	BaselineProgramAuthority     string                  `json:"baselineProgramAuthority"`
	Status                       string                  `json:"status"`
	CoreReleasePathUnchanged     bool                    `json:"coreReleasePathUnchanged"`
	RequiredCoreClosurePhases    []string                `json:"requiredCoreClosurePhases"`
	PhysicalCertificationPhases []string                `json:"physicalCertificationPhases"`
	Benchmarks                   []string                `json:"benchmarks"`
	CanonicalMutationGrammar     []string                `json:"canonicalMutationGrammar"`
	Guardrails                   []string                `json:"guardrails"`
	PhysicalProofTargets         []string                `json:"physicalProofTargets"`
	SourceExpansionPhases        int                     `json:"sourceExpansionPhases"`
	SourceClosedExpansionPhases  int                     `json:"sourceClosedExpansionPhases"`
	SourceOpenExpansionPhases    int                     `json:"sourceOpenExpansionPhases"`
	Phases                       []CompetitiveProofPhase `json:"phases"`
}

func CompetitiveProofProgramModel() CompetitiveProofProgram {
	phases := []CompetitiveProofPhase{
		{
			ID:                "CP1-virtual-cluster-lifecycle-automation",
			Order:             1,
			DeliveryTier:      CompetitiveTierExpansion,
			SourceStatus:      CompetitiveStatusSourceOpen,
			CoreFreezeBlocker: false,
			Objective:         "Close the virtual-cluster lifecycle convenience gap with workspace-scoped IdlePolicy/AutoSleep, wake-on-authorized-activity, SnapshotPolicy and TTL/AutoDelete while reusing existing durable fencing, exact runtime readback and FinOps attribution.",
			DependsOn:         []string{"J3-virtual-cluster-profile", "J2-finops-usage"},
			ParallelWith:      []string{"CP2-managed-resource-instance-graph", "CP4-fleet-signal-correlation-durable-remediation"},
			Blockers:          []string{"VIRTUAL_CLUSTER_AUTOMATION_SOURCE_PENDING"},
			Benchmarks:        []string{"vCluster Platform", "Spectro Cloud Palette"},
			Evidence:          []string{"VIRTUAL_CLUSTER_IDLE_POLICY_AUTHORITY_V1", "VIRTUAL_CLUSTER_SNAPSHOT_POLICY_AUTHORITY_V1", "VIRTUAL_CLUSTER_TTL_AUTHORITY_V1"},
			ExitCriteria: []string{
				"idle detection is telemetry-complete or UNKNOWN and missing telemetry never triggers AutoSleep",
				"AutoSleep and wake use the existing fenced virtual-cluster lifecycle operation rather than direct runtime mutation",
				"snapshots bind exact virtual-cluster identity/revision and restore produces observed evidence",
				"TTL/AutoDelete requires explicit policy and cannot bypass backup, retention, approval or recovery fences",
				"Console/API/MCP expose identical policy and lifecycle truth without inferring Runtime or Physical PASS",
			},
		},
		{
			ID:                "CP2-managed-resource-instance-graph",
			Order:             2,
			DeliveryTier:      CompetitiveTierExpansion,
			SourceStatus:      CompetitiveStatusSourceOpen,
			CoreFreezeBlocker: false,
			Objective:         "Extend ManagedResourceType into a PostgreSQL-authoritative resource graph: ResourceRequest -> deterministic ResourcePlan -> independent approval -> durable ProvisionOperation -> ResourceInstance -> typed Outputs -> Binding -> Evidence.",
			DependsOn:         []string{"J8-application-platform-abstraction-composition", "J4-product-api-contract-recovery-foundation", "J5-resource-scope-owner-closure"},
			ParallelWith:      []string{"CP1-virtual-cluster-lifecycle-automation", "CP3-application-promotion-verification"},
			Blockers:          []string{"MANAGED_RESOURCE_INSTANCE_GRAPH_SOURCE_PENDING"},
			Benchmarks:        []string{"Humanitec", "OpenChoreo"},
			Evidence:          []string{"MANAGED_RESOURCE_INSTANCE_AUTHORITY_V1", "RESOURCE_REQUEST_PLAN_AUTHORITY_V1", "RESOURCE_DEPENDENCY_GRAPH_AUTHORITY_V1", "RESOURCE_OUTPUT_BINDING_AUTHORITY_V1"},
			ExitCriteria: []string{
				"ResourceInstance identity and lifecycle are product-owned durable PostgreSQL authority rather than inferred target objects",
				"dependency edges are acyclic, project-scoped and revision/digest bound",
				"providers, Crossplane and target CRDs remain executors or observed projections and never become a second product source of truth",
				"secrets are references only and typed outputs never expose raw secret material",
				"ambiguous provision/delete outcomes enter RECOVERY_REQUIRED and resolve by authoritative readback without blind replay",
			},
		},
		{
			ID:                "CP3-application-promotion-verification",
			Order:             3,
			DeliveryTier:      CompetitiveTierExpansion,
			SourceStatus:      CompetitiveStatusSourceOpen,
			CoreFreezeBlocker: false,
			Objective:         "Productize multi-stage application promotion with exact ApplicationRelease provenance, ordered stages, verification/health gates, independent approval, immutable history and recovery while keeping Argo CD as reconciliation only.",
			DependsOn:         []string{"J8-application-platform-abstraction-composition", "CP2-managed-resource-instance-graph"},
			ParallelWith:      []string{"CP4-fleet-signal-correlation-durable-remediation"},
			Blockers:          []string{"APPLICATION_PROMOTION_VERIFICATION_SOURCE_PENDING"},
			Benchmarks:        []string{"Akuity / Kargo"},
			Evidence:          []string{"APPLICATION_PROMOTION_POLICY_AUTHORITY_V1", "APPLICATION_PROMOTION_RUN_AUTHORITY_V1", "PROMOTION_VERIFICATION_EVIDENCE_V1"},
			ExitCriteria: []string{
				"every promotion binds one exact ApplicationRelease and source EnvironmentBinding revision",
				"ordered stage transitions require configured health/verification gates and a failed verification cannot advance a later stage",
				"high-impact promotion approval is independent and requester self-approval remains fail-closed",
				"failed or ambiguous promotion preserves durable recovery state and never silently advances",
				"promotion history is immutable evidence while Forgejo remains desired-state history and Argo CD remains the reconciler",
			},
		},
		{
			ID:                "CP4-fleet-signal-correlation-durable-remediation",
			Order:             4,
			DeliveryTier:      CompetitiveTierExpansion,
			SourceStatus:      CompetitiveStatusSourceOpen,
			CoreFreezeBlocker: false,
			Objective:         "Correlate bounded runtime signals, recent changes, service health and incidents into impacted-resource hypotheses and evidence-linked remediation plans that return through approval and durable repair rather than creating a duplicate monitoring or AI mutation plane.",
			DependsOn:         []string{"J6-fleet-reliability-incident-intelligence", "G2-generalized-day2-campaign-engine"},
			ParallelWith:      []string{"CP1-virtual-cluster-lifecycle-automation", "CP3-application-promotion-verification", "CP5-bounded-resource-explorer-persona-ux"},
			Blockers:          []string{"FLEET_SIGNAL_CORRELATION_SOURCE_PENDING"},
			Benchmarks:        []string{"Red Hat Advanced Cluster Management / OpenShift", "Akuity"},
			Evidence:          []string{"FLEET_SIGNAL_CORRELATION_AUTHORITY_V1", "INCIDENT_CHANGE_CORRELATION_AUTHORITY_V1", "DURABLE_REMEDIATION_PLAN_AUTHORITY_V1"},
			ExitCriteria: []string{
				"metrics/log/trace/network/change inputs remain bounded projections over existing telemetry authorities rather than a duplicate monitoring source of truth",
				"missing signal families produce UNKNOWN confidence instead of invented correlation",
				"impacted resources and contributing changes are evidence-linked and organization/project scoped",
				"AI may rank and explain remediation proposals but execution requires normal plan, approval and durable-operation authority",
				"repair completion requires observed verification and Incident -> Operation -> Evidence linkage",
			},
		},
		{
			ID:                "CP5-bounded-resource-explorer-persona-ux",
			Order:             5,
			DeliveryTier:      CompetitiveTierExpansion,
			SourceStatus:      CompetitiveStatusSourceOpen,
			CoreFreezeBlocker: false,
			Objective:         "Provide Rancher-grade bounded resource exploration and explicit Operator, Platform Engineer and Developer journeys without turning Operator Horizon into a second unrestricted Kubernetes control plane.",
			DependsOn:         []string{"J5-resource-scope-owner-closure", "G1-operational-runtime-hardening", "C8-console-operational-completion"},
			ParallelWith:      []string{"CP4-fleet-signal-correlation-durable-remediation", "CP6-release-attestation-set"},
			Blockers:          []string{"RESOURCE_EXPLORER_PERSONA_UX_SOURCE_PENDING"},
			Benchmarks:        []string{"SUSE Rancher Prime", "Rafay Platform", "Spectro Cloud Palette"},
			Evidence:          []string{"BOUNDED_RESOURCE_EXPLORER_AUTHORITY_V1", "RESOURCE_EXPLORER_OWNER_CONTINUATION_V1", "PERSONA_TASK_JOURNEY_AUTHORITY_V1"},
			ExitCriteria: []string{
				"resource collections are bounded/paginated and target, organization and project scope are explicit",
				"resource details preserve UNKNOWN, FORBIDDEN and STALE truth and expose related events/owners without raw secret disclosure",
				"Resource Explorer authority is read-only by default and cannot issue arbitrary patch/delete or unrestricted kubectl",
				"supported mutations deep-link or dispatch existing typed Product API operations with impact preview, approval, progress and evidence",
				"Operator, Platform Engineer and Developer journeys expose task language first while revision/fence/digest internals remain advanced evidence details unless operator action requires them",
				"mobile, keyboard, accessibility and RTL/LTR behavior remain part of the same Operator Horizon quality gates",
			},
		},
		{
			ID:                "CP6-release-attestation-set",
			Order:             6,
			DeliveryTier:      CompetitiveTierExpansion,
			SourceStatus:      CompetitiveStatusSourceOpen,
			CoreFreezeBlocker: false,
			Objective:         "Productize exact-SHA release assurance as one inspectable attestation set: SBOM + VEX + SLSA/build provenance + 4SO Exact Runtime Evidence, with each evidence layer remaining independently truthful.",
			DependsOn:         []string{"S1-exact-supply-chain-acquisition-closure", "R0-release-authority-certification-rebaseline", "G5-enterprise-identity-compliance"},
			ParallelWith:      []string{"CP5-bounded-resource-explorer-persona-ux", "CP7-accelerator-lifecycle-foundation"},
			Blockers:          []string{"RELEASE_ATTESTATION_PRODUCTIZATION_SOURCE_PENDING"},
			Benchmarks:        []string{"SUSE Rancher Prime supply-chain assurance"},
			Evidence:          []string{"RELEASE_ATTESTATION_SET_AUTHORITY_V1", "VEX_RELEASE_EVIDENCE_V1", "SLSA_BUILD_PROVENANCE_BINDING_V1", "EXACT_RUNTIME_EVIDENCE_BINDING_V1"},
			ExitCriteria: []string{
				"SBOM, VEX and build provenance bind one exact source/release artifact identity",
				"4SO Exact Runtime Evidence remains independent and absent until its runtime/physical layer actually executes",
				"attestation publication is immutable or content-addressed and rejects cross-release evidence mixing",
				"Assurance UI/API/MCP expose artifact identity, certification layer and missing evidence without promoting source-only claims",
				"disconnected verification requires no external online authority beyond product-shipped trust material",
			},
		},
		{
			ID:                "CP7-accelerator-lifecycle-foundation",
			Order:             7,
			DeliveryTier:      CompetitiveTierExpansion,
			SourceStatus:      CompetitiveStatusSourceOpen,
			CoreFreezeBlocker: false,
			Objective:         "Build accelerator infrastructure authority from discovered inventory through GPUClass, quota, placement, MIG/vGPU partitioning, health, drain/replace and evidence before any inference/model-serving product plane is admitted.",
			DependsOn:         []string{"J2-finops-usage", "G2-generalized-day2-campaign-engine", "B-target-capability-supplychain-foundation"},
			ParallelWith:      []string{"CP6-release-attestation-set"},
			Blockers:          []string{"ACCELERATOR_LIFECYCLE_FOUNDATION_SOURCE_PENDING"},
			Benchmarks:        []string{"SUSE Rancher Prime", "Rafay Platform", "Spectro Cloud Palette"},
			Evidence:          []string{"ACCELERATOR_INVENTORY_AUTHORITY_V1", "GPU_CLASS_AUTHORITY_V1", "ACCELERATOR_QUOTA_PLACEMENT_AUTHORITY_V1", "ACCELERATOR_PARTITION_LIFECYCLE_AUTHORITY_V1"},
			ExitCriteria: []string{
				"accelerator inventory is target-observed and never inferred from static labels",
				"GPUClass and quota are organization/project scoped and capacity aware",
				"placement binds exact device/class capability and cannot oversubscribe unknown capacity",
				"MIG/vGPU partition create/assign/drain/replace lifecycle has authoritative readback and evidence",
				"device health degradation and replacement use durable operation/recovery semantics",
				"model serving remains deferred and cannot bypass this infrastructure lifecycle authority",
			},
		},
		{
			ID:                "CP8-fleet-scale-chaos-certification",
			Order:             8,
			DeliveryTier:      CompetitiveTierCertification,
			SourceStatus:      CompetitiveStatusCertificationPending,
			CoreFreezeBlocker: false,
			Objective:         "Certify competitive fleet, durability and failure envelopes against one exact release after Core Exact-SHA closure and the competitive expansion contracts are source-ready; scale evidence never substitutes for Exact-SHA Physical certification.",
			DependsOn: []string{
				"C9-pre-certification-feature-freeze-exact-bundle",
				"D-exact-artifact-lab-ai-certification",
				"M-full-product-certification-chaos-soak-ux-ai-evals",
				"CP1-virtual-cluster-lifecycle-automation",
				"CP2-managed-resource-instance-graph",
				"CP3-application-promotion-verification",
				"CP4-fleet-signal-correlation-durable-remediation",
				"CP5-bounded-resource-explorer-persona-ux",
				"CP6-release-attestation-set",
				"CP7-accelerator-lifecycle-foundation",
			},
			Blockers:   []string{"COMPETITIVE_SCALE_EXACT_RUNTIME_EVIDENCE_PENDING"},
			Benchmarks: []string{"Rafay Platform", "Red Hat Advanced Cluster Management / OpenShift", "SUSE Rancher Prime", "Spectro Cloud Palette"},
			Evidence:   []string{"COMPETITIVE_FLEET_SCALE_CERTIFICATION_V1", "SCALE_ENVELOPE_EVIDENCE_V1", "M12", "M13"},
			ExitCriteria: []string{
				"100/500/1000-cluster fleet envelopes are characterized with explicit supported, degraded and unsupported bounds rather than inferred from source tests",
				"10000-node inventory, health, pagination and bounded operator read paths remain within declared latency/resource envelopes",
				"100 concurrent maintenance or upgrade campaigns preserve lease, fence, approval and recovery identity without duplicate target mutation",
				"reconnect storm testing proves gateway/session epoch fencing and task ownership do not create duplicate dispatch or false healthy state",
				"1,000,000 durable operation/evidence records retain bounded query, pagination, retention and incident-correlation behavior without fabricating missing history",
				"an exceeded scale envelope is recorded as degraded/unsupported and is never promoted to PASS",
				"security, UI, AI/MCP adversarial and failure/chaos evidence remains bound to the exact certified artifact identity",
			},
		},
	}

	program := CompetitiveProofProgram{
		Authority:                CompetitiveProofAuthority,
		BaselineProgramAuthority: ProgramAuthorityMethod,
		Status:                   "COMPETITIVE_PROOF_EXPANSION_OPEN",
		CoreReleasePathUnchanged: true,
		RequiredCoreClosurePhases: []string{
			"C7W-mcp-user-admin-write-parity",
			"C9-pre-certification-feature-freeze-exact-bundle",
		},
		PhysicalCertificationPhases: []string{
			"D-exact-artifact-lab-ai-certification",
			"M-full-product-certification-chaos-soak-ux-ai-evals",
		},
		Benchmarks: []string{
			"Spectro Cloud Palette",
			"Rafay Platform",
			"SUSE Rancher Prime",
			"Mirantis k0rdent",
			"Red Hat Advanced Cluster Management / OpenShift",
			"Humanitec",
			"Akuity / Kargo",
			"Talos Omni",
			"vCluster Platform",
			"OpenChoreo",
		},
		CanonicalMutationGrammar: []string{"Plan", "Impact", "Approval", "Durable Operation", "Fence", "Execute", "Observe", "Evidence", "Recovery"},
		Guardrails: []string{
			"Core C7W/C9 closure and Exact-SHA release path remain independent; competitive expansion cannot silently become a Core Freeze blocker.",
			"AI/MCP, UI, API, SDK, Terraform and Crossplane mutations use the same product-owned durable operation, approval, recovery and evidence authority; no model-only mutation side door exists.",
			"Resource Explorer is read-only by default and cannot expose unrestricted kubectl, arbitrary patch/delete or raw-secret authority.",
			"Promotion composes Product API ApplicationRelease/EnvironmentBinding authority with Forgejo desired state and Argo reconciliation; Argo or Kargo patterns never become a second 4SO source of truth.",
			"GPU model serving is deferred until accelerator inventory, quota, placement, MIG/vGPU partitioning, health and lifecycle authority close independently.",
			"source-only implementation never establishes runtime, disconnected, scale, Physical or competitive-superiority claims; each claim requires evidence at the exact claimed layer.",
			"PostgreSQL remains product authority; projections, providers, target CRDs, GitOps and external tools remain adapters or observed state.",
		},
		PhysicalProofTargets: []string{
			"C7W named-client 4/4 external interoperability evidence",
			"C9 final Exact-SHA release seal",
			"connected Managed OKD Compact-3 Exact-SHA physical execution",
			"disconnected Managed OKD install/upgrade Exact-SHA physical execution",
			"fleet scale/chaos exact-artifact evidence",
		},
		Phases: phases,
	}
	for _, phase := range phases {
		if phase.DeliveryTier != CompetitiveTierExpansion {
			continue
		}
		program.SourceExpansionPhases++
		if phase.SourceStatus == CompetitiveStatusSourceImplemented {
			program.SourceClosedExpansionPhases++
		} else {
			program.SourceOpenExpansionPhases++
		}
	}
	return program
}
