package targetmodel

import "strings"

const CompetitiveProgramAuthorityMethod = "PROGRAM_PHASE_MODEL_V76"

var competitiveExpansionPhaseIDs = []string{
	"J9-virtual-cluster-lifecycle-automation",
	"J10-managed-resource-instance-graph",
	"J11-application-promotion-verification",
	"J12-fleet-signal-correlation-durable-remediation",
	"J13-bounded-operational-resource-explorer",
	"J14-release-attestation-competitive-proof",
	"L-optional-accelerator-ai-infrastructure",
}

func competitiveProofRoadmapRebaseline(roadmap ProgramRoadmap) ProgramRoadmap {
	roadmap.Authority = CompetitiveProgramAuthorityMethod
	roadmap.PrimaryBenchmarks = append(roadmap.PrimaryBenchmarks,
		"Red Hat Advanced Cluster Management / OpenShift — production governance, lifecycle and integrated observability benchmark",
		"Humanitec — resource graph, dynamic resource provisioning and developer self-service benchmark without importing an alternate product authority",
		"Akuity / Kargo — GitOps promotion, verification, audit and MCP guardrail benchmark while Argo remains reconciliation rather than 4SO product authority",
		"Talos Omni — focused machine, node, upgrade, backup and recovery lifecycle ergonomics benchmark",
		"vCluster Platform — virtual-cluster isolation, auto-sleep, snapshot, TTL and air-gapped lifecycle benchmark",
	)
	roadmap.CompetitiveDifferentiators = append(roadmap.CompetitiveDifferentiators,
		"One product mutation grammar is canonical across UI, API, SDK, Terraform, Crossplane and MCP: Plan -> Impact -> Approval -> Durable Operation -> Fence -> Execute -> Observe -> Evidence -> Recovery.",
		"AI/MCP never receives a privileged mutation side door: an AI-originated write is the same approval-aware, idempotent, recoverable and evidence-producing operation used by UI/API.",
		"Competitive claims require exact runtime, scale or physical evidence for the claimed layer; source breadth alone is never marketed as production superiority.",
	)
	for i, item := range roadmap.DeferredParity {
		if strings.HasPrefix(item, "GPU model serving / inference platform features are deferred") {
			roadmap.DeferredParity[i] = "GPU model serving / inference platform features remain deferred until the accelerator lifecycle foundation closes inventory, GPUClass, quota, placement, MIG/vGPU partitioning, health and replacement semantics; model serving is not allowed to shortcut infrastructure authority."
		}
	}
	for i := range roadmap.Tracks {
		switch roadmap.Tracks[i].ID {
		case "operator-experience":
			roadmap.Tracks[i].Requirements = append(roadmap.Tracks[i].Requirements,
				"Operator, Platform Engineer and Developer journeys are explicit persona surfaces over the same authority; fence/revision/digest internals stay behind advanced evidence views unless an operator must act on them",
				"bounded Kubernetes resource exploration is read-only by default and any mutation continues through existing Product API durable-operation authority rather than becoming a generic kubectl console",
			)
		case "platform-abstractions":
			roadmap.Tracks[i].Requirements = append(roadmap.Tracks[i].Requirements,
				"ManagedResourceType grows a concrete ResourceRequest -> ResourcePlan -> approval -> durable ProvisionOperation -> ResourceInstance -> typed Outputs -> Binding -> Evidence graph without making target CRDs or Crossplane a second SoT",
			)
		case "application-platform-composition":
			roadmap.Tracks[i].Requirements = append(roadmap.Tracks[i].Requirements,
				"PromotionPolicy owns ordered environment stages, exact ApplicationRelease provenance, verification/health gates, independent approval, promotion history and failure recovery while Argo remains the reconciler",
			)
		case "fleet-reliability":
			roadmap.Tracks[i].Requirements = append(roadmap.Tracks[i].Requirements,
				"bounded metrics/log/trace/network/change signals correlate into impacted resources and incidents before any remediation proposal is created",
				"incident remediation follows plan -> approval -> durable repair -> observed verification -> evidence and never lets an AI or signal processor mutate a target directly",
			)
		case "lab-certification":
			roadmap.Tracks[i].Requirements = append(roadmap.Tracks[i].Requirements,
				"competitive scale certification characterizes 100/500/1000-cluster fleet envelopes, 10000-node inventory, reconnect storms, concurrent maintenance/upgrade campaigns and million-record operation/evidence history without converting an exceeded envelope into PASS",
			)
		case "supply-chain":
			roadmap.Tracks[i].Requirements = append(roadmap.Tracks[i].Requirements,
				"release assurance productizes SBOM + VEX + SLSA/build provenance + 4SO Exact Runtime Evidence as distinct artifacts bound to one exact release SHA",
			)
		case "ai-native", "mcp-agent-surface":
			roadmap.Tracks[i].Requirements = append(roadmap.Tracks[i].Requirements,
				"AI/MCP writes must enter the same durable product operation path as UI/API and can never receive a model-only mutation, recovery or approval bypass",
			)
		}
	}
	roadmap.GlobalGuardrails = append(roadmap.GlobalGuardrails,
		"Competitive expansion may honestly reopen pre-physical software closure, but it never reopens completed Core source closure or becomes an implicit C9 feature-freeze dependency unless explicitly promoted by a future authority revision.",
		"Promotion orchestration composes ApplicationRelease, EnvironmentBinding, verification, approval and Argo reconciliation; it may not create a second GitOps source of truth.",
		"Resource Explorer is bounded and read-only by default; mutating controls must dispatch existing product-owned durable operations and may not expose unrestricted kubectl/raw object mutation.",
		"Accelerator support becomes marketable only after inventory, quota, placement, partitioning, health and lifecycle evidence close; model serving cannot substitute for missing GPU infrastructure authority.",
		"Scale, disconnected, runtime and Physical superiority claims require direct evidence at the exact claimed layer and artifact identity; source/test completion cannot be promoted into those claims.",
	)

	var finalCertification ProgramPhase
	phases := make([]ProgramPhase, 0, len(roadmap.Phases)+6)
	for _, phase := range roadmap.Phases {
		switch phase.ID {
		case "R0-release-authority-certification-rebaseline":
			phase.Evidence = appendUniqueString(phase.Evidence, CompetitiveProgramAuthorityMethod)
		case "L-optional-accelerator-ai-infrastructure":
			phase.Status = ProgramStatusBlocked
			phase.SourceStatus = ProgramSourceStatusOpen
			phase.ClosureStatus = ProgramClosureStatusBlocked
			phase.DeliveryTier = ProgramTierExpansion
			phase.Objective = "Build the accelerator lifecycle foundation from discovered accelerator inventory through GPUClass, quota, placement, MIG/vGPU partitioning, health, drain/replace and evidence before any inference/model-serving product plane is admitted."
			phase.Blockers = []string{"ACCELERATOR_LIFECYCLE_FOUNDATION_SOURCE_PENDING"}
			phase.Evidence = []string{"ACCELERATOR_INVENTORY_AUTHORITY_V1", "GPU_CLASS_AUTHORITY_V1", "ACCELERATOR_QUOTA_PLACEMENT_AUTHORITY_V1", "ACCELERATOR_PARTITION_LIFECYCLE_AUTHORITY_V1"}
			phase.ExitCriteria = []string{"accelerator inventory is target-observed and never inferred from static labels", "GPUClass and quota are organization/project scoped and capacity aware", "placement binds exact device/class capability and cannot oversubscribe unknown capacity", "MIG/vGPU partition lifecycle has explicit create/assign/drain/replace/readback evidence", "health degradation and replacement preserve durable operation/recovery semantics", "model serving remains deferred until this infrastructure foundation is source-closed and independently runtime-certified"}
		case "M-full-product-certification-chaos-soak-ux-ai-evals":
			phase.Order = 46
			phase.ExitCriteria = append(phase.ExitCriteria,
				"100/500/1000-cluster fleet envelopes are characterized with explicit supported/degraded/unsupported bounds rather than inferred from unit tests",
				"10000-node inventory, health, pagination and bounded operator read paths remain within declared resource and latency envelopes",
				"100 concurrent maintenance or upgrade campaigns preserve leases, fences, approvals and recovery without duplicate target mutation",
				"reconnect storm testing proves gateway/session identity, epoch fencing and task ownership do not create duplicate dispatch or false healthy state",
				"1,000,000 durable operation/evidence records retain bounded query, pagination, retention and incident-correlation behavior without fabricating missing history",
			)
			finalCertification = phase
			continue
		}
		phases = append(phases, phase)
	}

	newPhases := []ProgramPhase{
		{ID: "J9-virtual-cluster-lifecycle-automation", Order: 40, Status: ProgramStatusBlocked, SourceStatus: ProgramSourceStatusOpen, ClosureStatus: ProgramClosureStatusBlocked, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Close the virtual-cluster convenience gap with workspace-scoped IdlePolicy/AutoSleep, SnapshotPolicy, wake-on-authorized-activity and TTL/AutoDelete while preserving durable fencing, cost attribution and exact runtime readback.", DependsOn: []string{"J3-virtual-cluster-profile", "J2-finops-usage"}, ParallelWith: []string{"J10-managed-resource-instance-graph", "J12-fleet-signal-correlation-durable-remediation"}, Blockers: []string{"VIRTUAL_CLUSTER_AUTOMATION_SOURCE_PENDING"}, Evidence: []string{"VIRTUAL_CLUSTER_IDLE_POLICY_AUTHORITY_V1", "VIRTUAL_CLUSTER_SNAPSHOT_POLICY_AUTHORITY_V1", "VIRTUAL_CLUSTER_TTL_AUTHORITY_V1"}, ExitCriteria: []string{"idle detection is telemetry-complete or UNKNOWN and never sleeps from missing signals", "AutoSleep and wake use the existing fenced virtual-cluster lifecycle operation rather than direct runtime mutation", "snapshots bind exact virtual-cluster identity/revision and restore evidence", "TTL/AutoDelete requires explicit policy and cannot bypass retention/backup/recovery fences", "Console/API/MCP expose the same policy/status without inferring Physical PASS"}},
		{ID: "J10-managed-resource-instance-graph", Order: 41, Status: ProgramStatusBlocked, SourceStatus: ProgramSourceStatusOpen, ClosureStatus: ProgramClosureStatusBlocked, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Extend ManagedResourceType into a concrete, PostgreSQL-authoritative resource graph with ResourceRequest, deterministic ResourcePlan, approval-gated ProvisionOperation, ResourceInstance, typed Outputs, dependency Binding and observed Evidence.", DependsOn: []string{"J8-application-platform-abstraction-composition", "J4-product-api-contract-recovery-foundation", "J5-resource-scope-owner-closure"}, ParallelWith: []string{"J9-virtual-cluster-lifecycle-automation", "J11-application-promotion-verification"}, Blockers: []string{"MANAGED_RESOURCE_INSTANCE_GRAPH_SOURCE_PENDING"}, Evidence: []string{"MANAGED_RESOURCE_INSTANCE_AUTHORITY_V1", "RESOURCE_REQUEST_PLAN_AUTHORITY_V1", "RESOURCE_DEPENDENCY_GRAPH_AUTHORITY_V1", "RESOURCE_OUTPUT_BINDING_AUTHORITY_V1"}, ExitCriteria: []string{"resource instances are product-owned durable identities rather than inferred target objects", "dependencies are acyclic, project-scoped and revision/digest bound", "provider/Crossplane/target resources remain executors or observed projections rather than product SoT", "secrets are references only and typed outputs never expose raw secret values", "ambiguous provision/delete outcomes enter RECOVERY_REQUIRED and resolve by authoritative readback without blind replay"}},
		{ID: "J11-application-promotion-verification", Order: 42, Status: ProgramStatusBlocked, SourceStatus: ProgramSourceStatusOpen, ClosureStatus: ProgramClosureStatusBlocked, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Productize multi-stage application promotion with exact artifact provenance, PromotionPolicy, ordered environments, verification/health gates, independent approval, immutable history and recovery while keeping Argo CD as reconciliation only.", DependsOn: []string{"J8-application-platform-abstraction-composition", "J10-managed-resource-instance-graph"}, ParallelWith: []string{"J12-fleet-signal-correlation-durable-remediation"}, Blockers: []string{"APPLICATION_PROMOTION_VERIFICATION_SOURCE_PENDING"}, Evidence: []string{"APPLICATION_PROMOTION_POLICY_AUTHORITY_V1", "APPLICATION_PROMOTION_RUN_AUTHORITY_V1", "PROMOTION_VERIFICATION_EVIDENCE_V1"}, ExitCriteria: []string{"promotion binds one exact ApplicationRelease and source EnvironmentBinding revision", "ordered stage transitions require configured health/verification gates before later stages", "high-impact promotion approval is independent and requester self-approval remains fail-closed", "failed or ambiguous promotion preserves durable recovery state and never silently advances the next stage", "promotion history is immutable evidence while Forgejo/Argo retain desired-state/reconciliation roles"}},
		{ID: "J12-fleet-signal-correlation-durable-remediation", Order: 43, Status: ProgramStatusBlocked, SourceStatus: ProgramSourceStatusOpen, ClosureStatus: ProgramClosureStatusBlocked, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Correlate bounded runtime signals, recent changes, service health and incidents into impacted-resource hypotheses and evidence-linked remediation plans that return through approval and durable repair rather than creating a duplicate monitoring or AI mutation plane.", DependsOn: []string{"J6-fleet-reliability-incident-intelligence", "G2-generalized-day2-campaign-engine"}, ParallelWith: []string{"J9-virtual-cluster-lifecycle-automation", "J11-application-promotion-verification"}, Blockers: []string{"FLEET_SIGNAL_CORRELATION_SOURCE_PENDING"}, Evidence: []string{"FLEET_SIGNAL_CORRELATION_AUTHORITY_V1", "INCIDENT_CHANGE_CORRELATION_AUTHORITY_V1", "DURABLE_REMEDIATION_PLAN_AUTHORITY_V1"}, ExitCriteria: []string{"metrics/log/trace/network/change inputs remain bounded projections over existing telemetry authorities", "missing signal families produce UNKNOWN confidence instead of invented correlation", "impacted resources and contributing changes are evidence-linked and scope-safe", "AI may rank/explain remediation proposals but execution requires normal plan/approval/durable-operation authority", "repair completion requires observed verification and incident/evidence linkage"}},
		{ID: "J13-bounded-operational-resource-explorer", Order: 44, Status: ProgramStatusBlocked, SourceStatus: ProgramSourceStatusOpen, ClosureStatus: ProgramClosureStatusBlocked, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Provide Rancher-grade operational resource exploration with bounded discovery, scope-aware filters, YAML/details/events/relationships and owner navigation without turning the Console into a second unrestricted Kubernetes control plane.", DependsOn: []string{"J5-resource-scope-owner-closure", "G1-operational-runtime-hardening", "C8-console-operational-completion"}, ParallelWith: []string{"J12-fleet-signal-correlation-durable-remediation"}, Blockers: []string{"RESOURCE_EXPLORER_SOURCE_PENDING"}, Evidence: []string{"BOUNDED_RESOURCE_EXPLORER_AUTHORITY_V1", "RESOURCE_EXPLORER_OWNER_CONTINUATION_V1"}, ExitCriteria: []string{"collection reads are bounded/paginated and target/project scope is explicit", "resource details preserve unknown/forbidden/stale truth and expose related events/owners without raw secret disclosure", "default explorer authority is read-only", "supported mutations deep-link or dispatch existing typed Product API operations with preview/approval/evidence rather than arbitrary patch/delete", "mobile/keyboard/RTL behavior remains part of Operator Horizon quality gates"}},
		{ID: "J14-release-attestation-competitive-proof", Order: 45, Status: ProgramStatusBlocked, SourceStatus: ProgramSourceStatusOpen, ClosureStatus: ProgramClosureStatusBlocked, DeliveryTier: ProgramTierExpansion, RequiredForFeatureFreeze: false, Objective: "Productize release assurance as an exact-SHA attestation set combining SBOM, VEX, SLSA/build provenance and 4SO Exact Runtime Evidence without allowing any artifact to imply a certification layer it did not execute.", DependsOn: []string{"S1-exact-supply-chain-acquisition-closure", "R0-release-authority-certification-rebaseline", "G5-enterprise-identity-compliance"}, ParallelWith: []string{"J13-bounded-operational-resource-explorer"}, Blockers: []string{"RELEASE_ATTESTATION_PRODUCTIZATION_SOURCE_PENDING"}, Evidence: []string{"RELEASE_ATTESTATION_SET_AUTHORITY_V1", "VEX_RELEASE_EVIDENCE_V1", "SLSA_BUILD_PROVENANCE_BINDING_V1", "EXACT_RUNTIME_EVIDENCE_BINDING_V1"}, ExitCriteria: []string{"SBOM, VEX and build provenance bind the exact release artifact/source identities", "Exact Runtime Evidence remains independent and absent until its runtime/physical layer actually executes", "attestation publication is immutable/content-addressed and rejects cross-release evidence mixing", "Assurance UI/API/MCP expose artifact identity, certification layer and missing evidence without promoting source-only claims", "disconnected verification requires no external authority beyond shipped trust material"}},
	}
	phases = append(phases, newPhases...)
	if finalCertification.ID != "" {
		phases = append(phases, finalCertification)
	}
	roadmap.Phases = phases

	for i := range roadmap.ExecutionWaves {
		switch roadmap.ExecutionWaves[i].ID {
		case "W3-expansion-mega-wave":
			roadmap.ExecutionWaves[i].Objective = "Close competitive-depth expansion software in parallel: automation/providers, virtual-cluster lifecycle automation, resource-instance graph, promotion verification, signal correlation/remediation, bounded resource exploration, release attestations and accelerator lifecycle foundation."
			roadmap.ExecutionWaves[i].PhaseIDs = appendUniqueStrings(roadmap.ExecutionWaves[i].PhaseIDs, competitiveExpansionPhaseIDs...)
			roadmap.ExecutionWaves[i].MaxParallel = 8
		case "W4-convergence":
			roadmap.ExecutionWaves[i].Objective = "Converge API, SDK, MCP, Console, PostgreSQL, durable operations, evidence, UX and negative controls across both existing expansion capabilities and the competitive-proof depth phases."
			roadmap.ExecutionWaves[i].PhaseIDs = appendUniqueStrings(roadmap.ExecutionWaves[i].PhaseIDs, competitiveExpansionPhaseIDs...)
			roadmap.ExecutionWaves[i].MaxParallel = 8
		}
	}

	roadmap.CertificationRegistry = append(roadmap.CertificationRegistry,
		FeatureCertificationRequirement{Feature: "virtual-cluster-lifecycle-automation", OwnerPhases: []string{"J9-virtual-cluster-lifecycle-automation"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"missing-telemetry-never-triggers-autosleep", "ttl-delete-cannot-bypass-backup-or-fence"}},
		FeatureCertificationRequirement{Feature: "managed-resource-instance-graph", OwnerPhases: []string{"J10-managed-resource-instance-graph"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"cross-project-resource-binding-rejected", "ambiguous-provider-effect-never-auto-replayed"}},
		FeatureCertificationRequirement{Feature: "application-promotion-verification", OwnerPhases: []string{"J11-application-promotion-verification"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"failed-verification-cannot-advance-stage", "requester-self-approval-rejected"}},
		FeatureCertificationRequirement{Feature: "fleet-signal-correlation-remediation", OwnerPhases: []string{"J12-fleet-signal-correlation-durable-remediation"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"missing-signals-never-become-high-confidence-correlation", "ai-recommendation-cannot-mutate-target-directly"}},
		FeatureCertificationRequirement{Feature: "bounded-operational-resource-explorer", OwnerPhases: []string{"J13-bounded-operational-resource-explorer"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism}, NegativeControls: []string{"unbounded-resource-list-rejected", "arbitrary-resource-mutation-path-rejected"}},
		FeatureCertificationRequirement{Feature: "release-attestation-competitive-proof", OwnerPhases: []string{"J14-release-attestation-competitive-proof"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism}, NegativeControls: []string{"cross-release-attestation-mixing-rejected", "missing-runtime-evidence-never-inferred-from-sbom-or-provenance"}},
		FeatureCertificationRequirement{Feature: "accelerator-lifecycle-foundation", OwnerPhases: []string{"L-optional-accelerator-ai-infrastructure"}, RequiredLevels: []string{CertificationSourceSemantics, CertificationGeneratedRuntime, CertificationRuntimeRealism, CertificationIntegrationLab}, NegativeControls: []string{"unknown-accelerator-capacity-not-schedulable", "model-serving-cannot-bypass-accelerator-lifecycle-authority"}},
		FeatureCertificationRequirement{Feature: "competitive-fleet-scale-envelope", OwnerPhases: []string{"M-full-product-certification-chaos-soak-ux-ai-evals"}, RequiredLevels: []string{CertificationChaosLoadSoak}, PhysicalScenarios: []string{"M12", "M13"}, NegativeControls: []string{"exceeded-scale-envelope-never-promoted-to-pass", "reconnect-storm-duplicate-dispatch-detected", "million-record-history-unbounded-query-detected"}},
	)
	roadmap.CertificationCoverage = featureCertificationCoverage(roadmap.Phases, roadmap.CertificationRegistry)
	roadmap.Progress = programProgressSummary(roadmap.Phases, roadmap.GoalReady)
	return roadmap
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueStrings(values []string, additions ...string) []string {
	out := append([]string(nil), values...)
	for _, value := range additions {
		out = appendUniqueString(out, value)
	}
	return out
}
