package targetmodel

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestLegacyDistributionIdentityDoesNotEncodeProvisioner(t *testing.T) {
	for legacy, want := range map[string]string{
		"generic-imported": DistributionKubernetes,
		"kubespray":        DistributionKubernetes,
		"Kubespray v2.28":  DistributionKubernetes,
		"rke2":             DistributionRKE2,
		"v1.34.9+rke2r1":   DistributionRKE2,
		"OKD":              DistributionOKD,
		"OpenShift 4.19":   DistributionOpenShift,
	} {
		if got := CanonicalDistribution(legacy); got != want {
			t.Fatalf("CanonicalDistribution(%q)=%q want %q", legacy, got, want)
		}
	}
	if got := ProvisioningModeFromAdapter("cluster-api-topology-v1beta2"); got != ProvisioningClusterAPI {
		t.Fatalf("cluster-api adapter classified as %q", got)
	}
	if got := ProvisioningModeFromAdapter("imported"); got != ProvisioningImportExisting {
		t.Fatalf("imported adapter classified as %q", got)
	}
}

func TestArchitectureModelKeepsManagementPlaneSeparateFromTargets(t *testing.T) {
	model := ArchitectureModel()
	if model.Authority != AuthorityMethod {
		t.Fatalf("authority=%q", model.Authority)
	}
	if model.ManagementPlane.DistributionIdentity != DistributionRKE2 || model.ManagementPlane.ProvisioningMode != ProvisioningManagedInstall {
		t.Fatalf("unexpected management-plane boundary: %#v", model.ManagementPlane)
	}
	storage := model.ManagementPlaneStorage
	if storage.Authority != "MANAGEMENT_PLANE_STORAGE_AUTHORITY_V1" || storage.Provider != "longhorn" || storage.Version != "v1.12.1" || storage.DataEngine != "v1" || storage.ReplicaCount != 3 {
		t.Fatalf("unexpected management-plane storage authority: %#v", storage)
	}
	if storage.Scope != "management-plane-rke2-production-ha-only" || storage.Status != "SOURCE_LOCKED_RUNTIME_CERTIFICATION_PENDING" || storage.SourceLockID != "replicated-storage-install-manifest" || storage.TargetDefault {
		t.Fatalf("management-plane storage must remain internal/non-target-default: %#v", storage)
	}
	if len(storage.HostPrerequisites) != 2 || storage.HostPrerequisites[0] != "iscsiadm" || storage.HostPrerequisites[1] != "iscsid" {
		t.Fatalf("management-plane storage prerequisites drifted: %#v", storage.HostPrerequisites)
	}
	if SupportedDistribution(DistributionOKD) {
		t.Fatal("OKD must not be treated as generally runtime-certified while connected managed-install certification is still pending")
	}
	if !ManagedInstallSourceSupported(DistributionOKD, InfrastructureBareMetal) {
		t.Fatal("OKD on bare metal must expose source-level managed-install support after H1 orchestration closure")
	}
	if ManagedInstallSourceSupported(DistributionOpenShift, InfrastructureBareMetal) || ManagedInstallSourceSupported(DistributionOKD, InfrastructureVMware) {
		t.Fatal("managed-install source support must remain narrowly scoped to OKD + bare metal")
	}
	var okd, managedInstall, bareMetal *VocabularyEntry
	for i := range model.Distributions {
		if model.Distributions[i].ID == DistributionOKD {
			okd = &model.Distributions[i]
		}
	}
	for i := range model.ProvisioningModes {
		if model.ProvisioningModes[i].ID == ProvisioningManagedInstall {
			managedInstall = &model.ProvisioningModes[i]
		}
	}
	for i := range model.InfrastructureProviders {
		if model.InfrastructureProviders[i].ID == InfrastructureBareMetal {
			bareMetal = &model.InfrastructureProviders[i]
		}
	}
	if okd == nil || managedInstall == nil || bareMetal == nil || !okd.ManagedInstallSupport || !managedInstall.ManagedInstallSupport || !bareMetal.ManagedInstallSupport {
		t.Fatalf("managed OKD target-model source support is incomplete: okd=%#v mode=%#v baremetal=%#v", okd, managedInstall, bareMetal)
	}
	if !strings.Contains(okd.Status, "RUNTIME_CERTIFICATION_PENDING") || !strings.Contains(bareMetal.Status, "RUNTIME_CERTIFICATION_PENDING") {
		t.Fatalf("source support must not be confused with runtime certification: okd=%#v baremetal=%#v", okd, bareMetal)
	}
	if SupportedDistribution(DistributionOpenShift) {
		t.Fatal("Red Hat OpenShift must not be silently admitted through the OKD target path")
	}
	mcp := model.MCPRemoteOAuth
	if mcp.Authority != "MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1" || mcp.ProtocolVersion != "2026-07-28" || mcp.AuthorizationAuthority != "self-hosted-keycloak-oidc-oauth" || mcp.PasswordOrSecretToModel || !mcp.EveryWriteCreatesDurableJob {
		t.Fatalf("unexpected MCP remote OAuth authority: %#v", mcp)
	}
	if len(mcp.ExternalInteropTargets) != 4 || len(mcp.EffectiveAuthorization) < 5 || len(mcp.ForbiddenDirectAuthorities) < 5 {
		t.Fatalf("MCP delegated access architecture incomplete: %#v", mcp)
	}
	search := model.SearchProjection
	if search.Authority != "SEARCH_PROJECTION_AUTHORITY_V2" || search.DefaultBackend != "postgresql-bounded" || search.Status != "DECIDED_OPTIONAL_OPENSEARCH_SCALE_PROJECTION" || search.RebuildAuthority != "SEARCH_PROJECTION_REBUILD_CONTRACT_V1" || !search.RebuildRequired {
		t.Fatalf("unexpected search projection authority: %#v", search)
	}
	if len(search.OptionalBackends) != 1 || search.OptionalBackends[0] != "opensearch" {
		t.Fatalf("OpenSearch must remain an optional projection backend: %#v", search.OptionalBackends)
	}
	if !strings.Contains(search.Role, "not-source-of-truth") || !strings.Contains(search.MCPBoundary, "4SO") {
		t.Fatalf("search projection boundary is not explicit: %#v", search)
	}
}

func TestManagementPlaneStorageAuthorityMatchesAcquisitionSourceLock(t *testing.T) {
	body, err := os.ReadFile("../../lab/appliance-bundle-acquisition-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Authority           string `json:"authority"`
		SchemaVersion       int    `json:"schemaVersion"`
		ResolvedAuthorities []struct {
			ID        string `json:"id"`
			Provider  string `json:"provider"`
			Version   string `json:"version"`
			Scope     string `json:"scope"`
			Artifacts []struct {
				Name        string   `json:"name"`
				URLs        []string `json:"urls"`
				SHA256      string   `json:"sha256"`
				Size        int64    `json:"sizeBytes"`
				StagingPath string   `json:"stagingPath"`
			} `json:"artifacts"`
		} `json:"resolvedAuthorities"`
	}
	if err := json.Unmarshal(body, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Authority != "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8" || lock.SchemaVersion != 8 {
		t.Fatalf("unexpected acquisition lock authority: %#v", lock)
	}
	storage := ArchitectureModel().ManagementPlaneStorage
	for _, authority := range lock.ResolvedAuthorities {
		if authority.ID != storage.SourceLockID {
			continue
		}
		if authority.Provider != storage.Provider || authority.Version != storage.Version || authority.Scope != storage.Scope {
			t.Fatalf("storage model/source-lock drift: storage=%#v lock=%#v", storage, authority)
		}
		if len(authority.Artifacts) != 1 || len(authority.Artifacts[0].URLs) != 1 || authority.Artifacts[0].URLs[0] != "https://github.com/longhorn/longhorn/releases/download/v1.12.1/longhorn.yaml" || authority.Artifacts[0].SHA256 != "41648963af867ac1d0c85755fb53cf61cacd57c9bb22e1942e3fb0439eeb04fd" || authority.Artifacts[0].Size != 207054 || authority.Artifacts[0].StagingPath != "manifests/replicated-storage-install.yaml" {
			t.Fatalf("unexpected immutable Longhorn source authority: %#v", authority)
		}
		return
	}
	t.Fatalf("storage source lock %q is not resolved: %#v", storage.SourceLockID, lock.ResolvedAuthorities)
}

func TestProgramRoadmapDefersPhysicalCertificationUntilFeatureFreeze(t *testing.T) {
	roadmap := ArchitectureModel().ProgramRoadmap
	if roadmap.Authority != "PROGRAM_PHASE_MODEL_V75" || roadmap.CurrentPhase != "C7W-mcp-user-admin-write-parity" || roadmap.GoalReady {
		t.Fatalf("unexpected roadmap authority: %#v", roadmap)
	}
	if len(roadmap.Phases) != 40 {
		t.Fatalf("phase count=%d", len(roadmap.Phases))
	}
	progress := roadmap.Progress
	if progress.Authority != ProgramProgressAuthority || progress.CoreRequiredPhases != 25 || progress.CoreSourceClosedPhases != 25 || progress.CoreSourceOpenPhases != 0 || progress.CorePhaseReady != 23 || progress.CorePhaseBlocked != 2 || progress.CoreSourceClosurePercent != 100 || progress.CorePhaseReadyPercent != 92 || !progress.CoreSourceClosureComplete || progress.FeatureFreezeReady {
		t.Fatalf("program progress truth drift: %#v", progress)
	}
	if progress.PrePhysicalSoftwarePhases != 36 || progress.PrePhysicalSoftwareClosedPhases != 36 || progress.PrePhysicalSoftwareOpenPhases != 0 || progress.PrePhysicalSoftwareClosurePercent != 100 || len(progress.SourceOpenPhaseIDs) != 0 {
		t.Fatalf("pre-physical software progress truth drift: %#v", progress)
	}
	for _, id := range []string{"C7W-mcp-user-admin-write-parity", "C9-pre-certification-feature-freeze-exact-bundle"} {
		if !containsString(progress.ExternalClosureOnlyPhaseIDs, id) {
			t.Fatalf("external-only closure phase missing %s: %#v", id, progress.ExternalClosureOnlyPhaseIDs)
		}
	}
	if progress.RemainingBlockerClasses["source-software-closure"] != 0 || progress.RemainingBlockerClasses["external-distribution-evidence"] != 0 || progress.RemainingBlockerClasses["physical-runtime-evidence"] != 0 || progress.RemainingBlockerClasses["external-client-evidence"] < 1 || progress.RemainingBlockerClasses["runtime-certification-evidence"] != 0 {
		t.Fatalf("remaining blocker classification drift: %#v", progress.RemainingBlockerClasses)
	}
	if len(roadmap.Tracks) != 17 || len(roadmap.GlobalGuardrails) < 8 || len(roadmap.CertificationRegistry) < 10 {
		t.Fatalf("program cross-cutting authority incomplete: tracks=%d guardrails=%d certification=%d", len(roadmap.Tracks), len(roadmap.GlobalGuardrails), len(roadmap.CertificationRegistry))
	}
	for i, phase := range roadmap.Phases {
		if phase.Order != i+1 {
			t.Fatalf("phase order drift at %s: %d", phase.ID, phase.Order)
		}
	}
	byID := map[string]ProgramPhase{}
	for _, phase := range roadmap.Phases {
		if phase.SourceStatus == "" || phase.ClosureStatus == "" {
			t.Fatalf("phase must expose independent source and closure status: %#v", phase)
		}
		byID[phase.ID] = phase
	}
	if roadmap.CurrentExecutionWave != "W2-core-evidence-parallel" || len(roadmap.ExecutionWaves) != 6 {
		t.Fatalf("execution-wave authority drift: current=%q waves=%#v", roadmap.CurrentExecutionWave, roadmap.ExecutionWaves)
	}
	w2 := roadmap.ExecutionWaves[2]
	if w2.ID != "W2-core-evidence-parallel" || w2.MaxParallel != 1 || len(w2.PhaseIDs) != 1 || w2.PhaseIDs[0] != "C7W-mcp-user-admin-write-parity" || w2.PhaseIDs[0] != roadmap.CurrentPhase {
		t.Fatalf("W2 must target only remaining external pre-freeze closure: %#v", w2)
	}
	for _, id := range []string{"A-architecture-authority-rebaseline", "B-target-capability-supplychain-foundation", "C1-operator-ia-scope-authority", "C2-console-data-scale-refresh-semantics", "C3-console-action-workflow-evidence-convergence", "C4-console-e2e-ux-certification", "E-certified-platform-template-workspace-foundation", "C5-installer-production-lifecycle-closure", "C6-multi-agent-test-autopilot", "C7-ai-mcp-delegated-operations", "C8-console-operational-completion", "F-okd-import-capability-certification", "R0-release-authority-certification-rebaseline", "G1-operational-runtime-hardening", "G2-generalized-day2-campaign-engine", "G3-target-node-maintenance-lifecycle"} {
		phase, ok := byID[id]
		if !ok || phase.Status != ProgramStatusSourceImplemented || phase.DeliveryTier != ProgramTierCoreFreeze || !phase.RequiredForFeatureFreeze || len(phase.Blockers) != 0 {
			t.Fatalf("source-implemented mandatory phase drift %s: %#v", id, phase)
		}
	}
	c4 := byID["C4-console-e2e-ux-certification"]
	for _, evidence := range []string{"OPERATOR_EXPERIENCE_VIEWPORT_ACCESSIBILITY_V1", "OPERATOR_EXPERIENCE_DISCLOSURE_EXPANDED_MATRIX_V1", "FORM_VALIDATION_FEEDBACK_V1", "APPLICATION_COMPOSITION_TASK_MATRIX_V1", "RUNTIME_GENERATED_LOCALIZATION_PARITY_V1", "PROGRAMMATIC_REDUCED_MOTION_V1", "ROUTE_JOURNEY_FRAMING_V1", "NAVIGATION_ROUTE_OWNERSHIP_PARITY_V1", "DIRECTIONAL_AFFORDANCE_RTL_PARITY_V1"} {
		if !containsString(c4.Evidence, evidence) {
			t.Fatalf("C4 deep RTL/LTR evidence %q missing: %#v", evidence, c4)
		}
	}
	if len(c4.ExitCriteria) < 12 || !containsString(c4.ExitCriteria, "320/390/768/1024/1440 viewport checks cover LTR and RTL with workflow disclosures collapsed and expanded") || !containsString(c4.ExitCriteria, "invalid required/pattern/range inputs expose persistent localized field errors, aria-describedby, a form summary and first-error focus in both Console and Installer") || !containsString(c4.ExitCriteria, "runtime-generated Console/Installer controls round-trip English -> Persian/RTL -> English without hardcoded locale residue") || !containsString(c4.ExitCriteria, "workflow copy and comparison labels remain position-independent across responsive LTR/RTL layouts rather than relying on left/right/above/below instructions") || !containsString(c4.ExitCriteria, "workflow guidance remains input-method independent and never requires mouse/touch assumptions or desktop-only modifier-key instructions for ordinary form completion") || !containsString(c4.ExitCriteria, "programmatic scrolling respects prefers-reduced-motion and cannot bypass the same reduced-motion contract enforced by CSS") || !containsString(c4.ExitCriteria, "every Console route exposes one clear page heading, one Outcome/Done framing strip, at least one meaningful operational surface and the correct active navigation context") || !containsString(c4.ExitCriteria, "every rendered route belongs to exactly one runtime navigation domain, every primary domain home belongs to that domain, secondary-navigation DOM order exactly matches runtime sectionNavigation, and English/Persian breadcrumb groups match the same primary domain without orphan, duplicate or cross-domain title drift") || !containsString(c4.ExitCriteria, "semantic directional affordances including CSS pseudo-content reverse with document direction while technical identifiers remain isolated LTR") || !containsString(c4.ExitCriteria, "Application Composition hidden task variants are each activated and audited for overflow, labels, target size, bidi and contrast across the same supported viewport/direction matrix") {
		t.Fatalf("C4 expanded workflow viewport criteria drift: %#v", c4.ExitCriteria)
	}
	c5 := byID["C5-installer-production-lifecycle-closure"]
	for _, evidence := range []string{"INSTALLER_GUIDED_MANUAL_WORKFLOW_V1", "INSTALLER_MANUAL_EXACT_RELEASE_BINDING_V1", "INSTALLER_MANUAL_REMOTE_HANDOFF_V1", "INSTALLER_MANUAL_ENTRYPOINT_V1", "INSTALLER_MANUAL_CONTINUATION_ENTRYPOINT_V1", "INSTALLER_MANUAL_DOCTOR_V1", "INSTALLER_MANUAL_INPUT_DISCOVERY_V1", "INSTALLER_MANUAL_ACTIONABLE_ENTRYPOINT_V1", "INSTALLER_MANUAL_PREFLIGHT_GUIDANCE_V1", "INSTALLER_MANUAL_BOOTSTRAP_RESUME_V1", "INSTALLER_BOOTSTRAP_RUNTIME_STATUS_V1", "INSTALLER_MANUAL_BOOTSTRAP_RESET_V1", "INSTALLER_HA_STORAGE_HOST_PREREQUISITE_V1", "INSTALLER_EXAMPLE_VERSION_PARITY_V1", "INSTALLER_RECOVERY_STATUS_FIRST_UI_V1", "INSTALLER_RECOVERY_POLL_BOUNDED_V1", "INSTALLER_BROWSER_TOKEN_STALE_CLEAR_V1"} {
		if !containsString(c5.Evidence, evidence) {
			t.Fatalf("C5 guided manual installer evidence %q missing: %#v", evidence, c5)
		}
	}
	for _, criterion := range []string{
		"platformctl installer-manual preflight/plan/install composes the canonical hostdeployment owner and does not create a second installer engine",
		"the common manual path never requires an operator to hand-author Installer deployment JSON, edit systemd units, or manually assemble PLATFORM_INSTALLER_* environment files",
		"the release ships a thin install.sh entrypoint that delegates to installer-manual, safely auto-discovers only explicit/standard real bundle directories plus an exact adjacent/source-specified release ZIP, never downloads moving upstream content and never drives systemd outside the canonical hostdeployment owner",
		"bash install.sh doctor is non-mutating and non-root: it reports packaged binary, bundle and exact-release input readiness before installation without claiming bundle admission",
		"the normal install.sh install path fails before host mutation unless --enable-execution and explicit --confirmation DEPLOY are present, preventing a successful host deployment that leaves the Browser Installer unexpectedly non-actionable",
		"manual preflight preserves top-level host admission fields while adding exact-release binding and an explicit nextAction to plan, so human operators and existing automation share one truthful first step",
		"the same install.sh entrypoint owns host status/verify/recovery/rollback plus bootstrap-status, bootstrap resume, journaled reset and reset-resume after deployment without requiring the original bundle/release ZIP again; every mutating continuation preserves an explicit confirmation fence",
		"advanced installer-host examples are pinned to the current VERSION by repository validation so documented copy/paste paths cannot silently become version-rejected stale examples",
		"browser Installer owns supported profile selection, infrastructure/HA access and pinned host trust, dedicated HA storage, endpoint/TLS, managed/external service inputs, plan, host preflight and explicit INSTALL confirmation",
		"production-standard-ha preflight verifies iscsiadm/iscsid plus an iscsid service/socket on the local node and every peer before runtime mutation; explicit INSTALL/RESUME enables the existing service locally/remotely without package download",
		"loopback remains the safe default; the guided result exposes a workstation URL plus an explicit SSH local-forward command for remote operators instead of requiring them to expose the Installer service",
		"failed/interrupted bootstrap runs resume from durable owner-classified state; clean reinstall uses journaled reset; host-deployment interruption requires explicit recovery and never overwrites unrelated host state",
		"manual bootstrap resume reads authenticated durable Installer status before mutation, defaults to the local loopback/token-file handoff, supports explicit URL/token/CA for custom transport, and resolves a lost resume response by readback without automatic replay",
		"manual clean reinstall exposes read-only bootstrap-status plus journaled reset/reset-resume through authenticated Installer authority; reset confirmation is derived from the exact source run/reset run ID and lost responses are resolved by readback without automatic replay",
		"the browser recovery surface renders durable installer status and Resume/Reset authority before ancillary health, preflight or access-security enrichment so partial endpoint failure cannot hide recovery controls",
		"Installer status polling has a bounded request deadline and resumes scheduling after timeout/visibility changes without overlapping mutation requests",
		"HTTP 401 clears the tab-scoped bootstrap token from memory and sessionStorage so a rejected credential cannot survive reload into a reconnect loop",
	} {
		if !containsString(c5.ExitCriteria, criterion) {
			t.Fatalf("C5 manual installer criterion %q missing: %#v", criterion, c5.ExitCriteria)
		}
	}
	c6 := byID["C6-multi-agent-test-autopilot"]
	for _, evidence := range []string{"AUTOPILOT_FAILURE_CAPSULE_V1", "AUTOPILOT_OWNER_SCOPED_CONVERGENCE_V1", "AUTOPILOT_REPAIR_SCOPE_FENCE_V1", "AUTOPILOT_STRUCTURED_TRIAGE_V1", "AUTOPILOT_REPAIR_GIT_BOUNDARY_V1", "AUTOPILOT_DIRTY_DELTA_V1", "AUTOPILOT_GIT_WORKSPACE_FINGERPRINT_V1", "AUTOPILOT_AGENT_CONTEXT_V1", "AUTOPILOT_INSTALLER_OWNER_STAGE_V1", "AUTOPILOT_INSTALLER_OWNER_CONTRACT_STAGE_V1", "AUTOPILOT_AGENT_FAILURE_CAPSULE_V2", "AUTOPILOT_AGENT_OWNER_PROOF_V1", "AUTOPILOT_ENVIRONMENT_PREFLIGHT_HANDOFF_V1", "AUTOPILOT_AGENT_ENTRYPOINT_V1", "AUTOPILOT_OWNER_CONTEXT_PATHS_V1", "AUTOPILOT_PROMPT_BUDGET_V1", "AUTOPILOT_AGENT_REPAIR_BUDGET_V1", "AUTOPILOT_FAILURE_PATH_HINTS_V1"} {
		if !containsString(c6.Evidence, evidence) {
			t.Fatalf("C6 token-efficient autopilot evidence %q missing: %#v", evidence, c6)
		}
	}
	for _, criterion := range []string{
		"environment preflight never emits raw custom Codex argv or secret-bearing wrapper arguments; a blocked preflight writes a compact fingerprinted handoff naming only missing prerequisites so the next agent fixes environment rather than product source",
		"the first failure sends agents a bounded secret-redacted high-signal failure capsule rather than replaying a large raw log; read-only triage emits one unambiguous CODE_DEFECT/TEST_DEFECT/ENVIRONMENT/SUPPLY_CHAIN/UNKNOWN classification before the single workspace-write repair",
		"the repair writer opens only for CODE_DEFECT or TEST_DEFECT; environment, supply-chain, missing/conflicting triage and unavailable-agent outcomes remain mutation-free",
		"a timed-out deterministic stage is process-tree cleaned and, in repair mode, receives the same structured read-only diagnosis so a proven code/test hang may be repaired while an untriaged timeout remains environment-blocked",
		"repair reruns only the failing owner stage immediately; final convergence is selected from the repaired specialist dependency family instead of automatically replaying the entire graph",
		"workspace deltas around every repair are digested; no-change, unreadable, unknown or cross-owner modifications force full convergence, and that decision survives crash/resume",
		"repair agents may edit only the working tree and may not commit/reset/checkout/stash/rebase/merge or mutate Git refs/index/history; any observed HEAD mutation stops automatic repair and requires operator reconciliation",
		"checkpoint workspace identity combines the immutable Git HEAD with exact hashes of only dirty/untracked product inputs, falling back to the full-tree digest when local Git enumeration is unavailable",
		"make autopilot-agent is the single normal agent entrypoint and composes durable project-runtime execution with prerequisite checking, exact checkpoint/resume, bounded repair and owner-scoped convergence so agents do not need to reconstruct orchestration flags or replay green stages",
		"repair prompts and compact agent handoffs expose the failing specialist owner-path set before broad repository search, and the same owner-path map drives cross-owner convergence escalation",
		"triage and repair prompts use explicit compact character budgets for failure and triage capsules so agent token usage stays bounded without reducing deterministic test coverage",
		"make autopilot-context emits a compact non-authoritative continuation capsule containing run/stage/failure fingerprint/resume metadata, source-context pointers and at most one bounded secret-redacted failure capsule, never raw stage logs or unredacted secrets",
		"the continuation capsule includes the exact current owner proof command and bounded stage timeout so a new agent can reproduce the smallest failing proof without rereading the full orchestration source or replaying earlier green stages",
		"the continuation capsule extracts at most eight existing repository-relative failure-path hints and keeps only paths inside the failing specialist owner surface so a new agent starts from exact evidence before broad owner-directory reads",
		"Installer entrypoint Python contracts, Installer Go owner packages, core smoke, host-deployment smoke and remote-bootstrap smoke are independent checkpoint stages; Installer repair convergence reruns this narrow owner family before package verification so a late failure never requires replaying the unrelated Python/Go graph",
		"same-stage same-fingerprint repetition stops as NO_PROGRESS before another repair is spent; normal repair keeps a conservative three-repair campaign budget while make autopilot-agent defaults to eight independent repairs so distinct defects can converge without turning the campaign into an unbounded token loop",
	} {
		if !containsString(c6.ExitCriteria, criterion) {
			t.Fatalf("C6 autopilot criterion %q missing: %#v", criterion, c6.ExitCriteria)
		}
	}
	c8 := byID["C8-console-operational-completion"]
	for _, evidence := range []string{"CONSOLE_JOURNEY_RTL_LTR_HARDENING_V1", "APPLICATION_DELIVERY_JOURNEY_V1", "APPLICATION_COMPOSITION_CONSOLE_PARITY_V1", "ACTION_AVAILABILITY_RAIL_V1", "ACTIONABLE_EMPTY_STATE_RECOVERY_V1", "TRUTHFUL_NON_ACTIONABLE_BLOCKER_V1", "HARD_PAGE_STALE_FAILURE_V1", "APPLICATION_PROGRESSIVE_STEP_ADMISSION_V1", "APPLICATION_DELIVERY_LOCALIZATION_PARITY_V1", "CRITICAL_INTERACTION_LOCALIZATION_GRAMMAR_V1", "DISCLOSURE_SAFE_LIVE_PROGRESS_REFRESH_V1", "DAPR_RUNTIME_JOURNEY_V1", "DAPR_DURABLE_UI_RESUME_V1", "DAPR_TASK_DISCLOSURE_V1", "APPLICATION_COMPOSITION_TASK_PICKER_V1", "APPLICATION_GUIDED_PREREQUISITE_DISCLOSURE_V1", "OPERATIONS_SEARCH_IA_PLACEMENT_V1", "OPERATIONS_SEARCH_CONTINUATION_V1", "FLEET_INCIDENT_PROGRESSIVE_DISCLOSURE_V1"} {
		if !containsString(c8.Evidence, evidence) {
			t.Fatalf("C8 task-first journey evidence %q missing: %#v", evidence, c8)
		}
	}
	for _, criterion := range []string{
		"core workflows expose prerequisite -> input -> preview -> approval -> progress -> evidence/recovery without hidden dead ends",
		"Platform Templates and Application Delivery are separate navigation destinations rather than one overloaded page",
		"Global Operations Search lives under Operations and is loaded/scoped there rather than occupying Fleet or inheriting Fleet project state",
		"every Global Operations Search result carries a derived ownerRef and offers an exact read-only continuation to its owning Operation, Cluster or Project; evidence never becomes an independent source of truth",
		"Fleet keeps Reliability incident state visible while incident creation is an explicit disclosure; successful creation collapses the mutation form and returns focus to the updated incident results",
		"optional Dapr runtime lifecycle and workload admission live on a separate Delivery route so the primary Application Delivery journey is not overloaded",
		"Application Delivery exposes UI creation paths for WorkloadType, CapabilityTrait, ManagedResourceType and WorkspaceProfile before Release -> EnvironmentBinding -> Plan/Request -> Observed Evidence",
		"Application Composition presents one authority-creation task at a time and prerequisite actions open the exact Workload/Profile/Trait/Resource owner task instead of exposing all forms together",
		"Application Delivery keeps downstream journey steps focusable but aria-disabled with a localized prerequisite reason until the previous authoritative step exists",
		"Application Delivery opens the actionable owner disclosure on load and closes release/binding/deployment forms when Project, WorkloadType, WorkspaceProfile, Workspace or the selected Workspace active namespace binding is missing so empty selectors are never the primary task",
		"Application Delivery critical form labels, help and actions round-trip English -> Persian/RTL -> English without leaving mixed-language workflow controls",
		"critical toast/confirm/detail action grammar localizes approval, revoke, delete, cancel, retry and recovery flows including dynamic resource identifiers instead of falling back to English interaction sentences",
		"application collection reads and mutation forms follow the selected global project scope and backend RBAC instead of cross-project dropdown aggregation",
		"Dapr assessment and workload-plan remain viewer-safe project reads while lifecycle mutation and independent approval remain project-scoped and fail-closed",
		"Dapr keeps assessment as the primary visible task while lifecycle mutation and workload admission are separate disclosures; resumed durable lifecycle/admission state automatically opens its owner disclosure without redispatch",
		"Dapr route reload or scope change rediscovers the latest durable lifecycle operation from bounded owner history and resumes it read-only without redispatch",
		"disabled mutation controls expose visible page-level role/scope/prerequisite/state reasons while remaining fail-closed, including intrinsically disabled controls whose owner supplies a blocker title",
		"empty and prerequisite states expose a direct in-product next action when an owner UI exists, but do not render a fake CTA for blockers without an operator-owned recovery surface; runtime-generated guidance is re-rendered correctly after locale changes, and a hard page refresh failure marks any retained visible data as stale with an explicit retry instead of silently preserving current-looking state",
		"durable application deployment progress is refreshed read-only without requiring mutation replay or a manual page refresh",
		"live status pages keep refreshing while read-only disclosures are open, but focused or dirty form input still fences background refresh; Workspace virtual-cluster and Platform maintenance RUNNING/RESTORING lifecycles are included",
		"LTR and RTL use the same semantic ordering with logical layout properties and isolated technical identifiers",
	} {
		if !containsString(c8.ExitCriteria, criterion) {
			t.Fatalf("C8 user-flow criterion %q missing: %#v", criterion, c8.ExitCriteria)
		}
	}
	r0 := byID["R0-release-authority-certification-rebaseline"]
	for _, evidence := range []string{"PROGRAM_PHASE_MODEL_V75", "FEATURE_CERTIFICATION_REGISTRY_V2", "LAB_CERTIFICATION_MATRIX_V2", "DOCUMENTATION_AUTHORITY_SYNC_V1"} {
		if !containsString(r0.Evidence, evidence) {
			t.Fatalf("R0 evidence %q missing: %#v", evidence, r0)
		}
	}
	s1 := byID["S1-exact-supply-chain-acquisition-closure"]
	if s1.Status != ProgramStatusSourceImplemented || s1.ClosureStatus != ProgramClosureStatusReady || len(s1.Blockers) != 0 || !s1.RequiredForFeatureFreeze || !containsString(s1.ParallelWith, "C7W-mcp-user-admin-write-parity") || !containsString(s1.ParallelWith, "G4-data-protection-productization") || !containsString(s1.ParallelWith, "G5-enterprise-identity-compliance") || containsString(s1.ParallelWith, "H2-vmware-provider") || containsString(s1.ParallelWith, "J1-automation-external-integrations") {
		t.Fatalf("supply-chain phase is not an immediate parallel critical path: %#v", s1)
	}
	for _, evidence := range []string{"LAB_APPLIANCE_INPUT_PACK_BUILD_V1", "scripts/build_appliance_input_pack.py", "lab/appliance-input-pack-receipt.json", "scripts/seal_appliance_bundle_distribution.py", "APPLIANCE_MULTIPART_DISTRIBUTION_AUTHORITY_V1"} {
		if !containsString(s1.Evidence, evidence) {
			t.Fatalf("S1 distribution closure evidence missing %q: %#v", evidence, s1.Evidence)
		}
	}
	c7r := byID["C7R-mcp-remote-oauth-human-delegation"]
	if c7r.Status != ProgramStatusSourceImplemented || !c7r.RequiredForFeatureFreeze || len(c7r.Blockers) != 0 || !containsString(c7r.Evidence, "MCP_OAUTH_PROTECTED_RESOURCE_DISCOVERY_V1") || !containsString(c7r.Evidence, "MCP_DEDICATED_AUDIENCE_VALIDATION_V1") || !containsString(c7r.Evidence, "MCP_HUMAN_DELEGATION_AUTHORITY_V1") || !containsString(c7r.Evidence, "MCP_CLIENT_TRUST_REGISTRY_V1") || !containsString(c7r.Evidence, "MCP_TOKEN_REVOCATION_ENFORCEMENT_V1") {
		t.Fatalf("remote OAuth MCP phase drift: %#v", c7r)
	}
	c7w := byID["C7W-mcp-user-admin-write-parity"]
	for _, evidence := range []string{"MCP_EXTERNAL_CLIENT_INTEROP_CAMPAIGN_V1", "scripts/prepare_mcp_external_interop_campaign.py", "MCP_EXTERNAL_CLIENT_INTEROP_BINDING_V1", "MCP_EXTERNAL_CLIENT_OAUTH_BINDINGS_V1", "scripts/prepare_mcp_external_client_execution.py", "scripts/finalize_mcp_external_client_receipt.py", "scripts/fetch_mcp_external_audit_window.py", "migrations/0084_security_audit_mcp_interop_binding.sql", "migrations/0085_security_audit_oauth_client_identity.sql"} {
		if !containsString(c7w.Evidence, evidence) {
			t.Fatalf("C7W Git/source evidence missing %q: %#v", evidence, c7w.Evidence)
		}
	}
	for _, forbidden := range []string{".github/workflows/mcp-external-interop-campaign.yml", ".github/workflows/mcp-external-interop-seal.yml", ".github/workflows/mcp-external-receipt-admission.yml"} {
		if containsString(c7w.Evidence, forbidden) {
			t.Fatalf("C7W execution authority must not depend on GitHub workflow evidence %q: %#v", forbidden, c7w.Evidence)
		}
	}
	if c7w.Status != ProgramStatusBlocked || !c7w.RequiredForFeatureFreeze || !containsString(c7w.DependsOn, c7r.ID) || containsString(c7w.Blockers, "MCP_ACTION_REGISTRY_ENFORCEMENT_PENDING") || containsString(c7w.Blockers, "MCP_EFFECTIVE_TOOL_FILTERING_PENDING") || containsString(c7w.Blockers, "MCP_WRITE_JOB_COVERAGE_PENDING") || !containsString(c7w.Blockers, "MCP_EXTERNAL_CLIENT_INTEROP_EVIDENCE_PENDING") || !containsString(c7w.Evidence, "MCP_PRODUCT_ACTION_REGISTRY_V1") || !containsString(c7w.Evidence, "MCP_EFFECTIVE_TOOL_FILTERING_V1") {
		t.Fatalf("MCP write parity phase drift: %#v", c7w)
	}
	s2 := byID["S2-component-runtime-certification-authorities"]
	if s2.Status != ProgramStatusSourceImplemented || s2.ClosureStatus != ProgramClosureStatusReady || len(s2.Blockers) != 0 || containsString(s2.Blockers, "UPSTREAM_RUNTIME_SUITABILITY_HOLDS_PENDING") || containsString(s2.Blockers, "COMPONENT_HISTORICAL_SOURCE_ACQUISITION_PENDING") || containsString(s2.Blockers, "COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING") || !containsString(s2.Evidence, "COMPONENT_UPGRADE_SOURCE_ADMISSION_V1") || !containsString(s2.Evidence, "CATALOG_HISTORICAL_SOURCE_IMPORT_V1") || !containsString(s2.Evidence, "COMPONENT_RUNTIME_UPGRADE_EVIDENCE_REGISTRY_V1") || !containsString(s2.Evidence, "GATEWAY_API_RUNTIME_UPGRADE_MATRIX_V1") {
		t.Fatalf("component runtime S2 admission drift: %#v", s2)
	}
	g1 := byID["G1-operational-runtime-hardening"]
	if g1.Status != ProgramStatusSourceImplemented || len(g1.Blockers) != 0 || !containsString(g1.Evidence, "CONSOLE_LOCALIZATION_COVERAGE_V2") || !containsString(g1.Evidence, "CONSOLE_FULL_LOCALIZATION_V1") {
		t.Fatalf("G1 localization/operational closure drift: %#v", g1)
	}
	g2 := byID["G2-generalized-day2-campaign-engine"]
	if g2.Status != ProgramStatusSourceImplemented || len(g2.Blockers) != 0 || !containsString(g2.DependsOn, g1.ID) || !containsString(g2.Evidence, "GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1") || !containsString(g2.Evidence, "GET /api/v1/day2-campaign-engine") {
		t.Fatalf("G2 generalized campaign closure drift: %#v", g2)
	}
	h1 := byID["H1-baremetal-connected-managed-okd"]
	if h1.Status != ProgramStatusSourceImplemented || h1.ClosureStatus != ProgramClosureStatusReady || len(h1.Blockers) != 0 || containsString(h1.DependsOn, "H2-vmware-provider") {
		t.Fatalf("connected managed OKD authority drift: %#v", h1)
	}
	i1 := byID["I1-disconnected-okd-core"]
	if i1.Status != ProgramStatusSourceImplemented || i1.ClosureStatus != ProgramClosureStatusReady || len(i1.Blockers) != 0 || containsString(i1.Blockers, "OKD_DISCONNECTED_RUNTIME_CERTIFICATION_PENDING") || containsString(i1.Blockers, "OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING") || !containsString(i1.Evidence, "DISCONNECTED_OKD_MIRROR_RUNTIME_V1") || !containsString(i1.Evidence, "DISCONNECTED_OKD_MIRROR_INVENTORY_V1") || !containsString(i1.Evidence, "OC_MIRROR_DISCONNECTED_TRANSPORT_REALISM_V1") || !containsString(i1.Evidence, "mode-specific Operator Console readiness") {
		t.Fatalf("disconnected managed OKD source-workflow drift: %#v", i1)
	}
	h2 := byID["H2-vmware-provider"]
	if containsString(h2.DependsOn, "I1-disconnected-okd-core") || containsString(h2.DependsOn, "I2-edge-sovereign-extension") {
		t.Fatalf("VMware was incorrectly serialized behind disconnected work: %#v", h2)
	}
	if h2.Status != ProgramStatusSourceImplemented || len(h2.Blockers) != 0 {
		t.Fatalf("VMware source authority should be implemented without claiming runtime certification: %#v", h2)
	}
	for _, evidence := range []string{"VMWARE_PROVIDER_AUTHORITY_V1", "migrations/0071_vmware_provider_authority.sql", "VSphereClusterTemplate", "VSphereMachineTemplate", "operator-console:vmware-provider-profile"} {
		if !containsString(h2.Evidence, evidence) {
			t.Fatalf("VMware evidence missing %q: %#v", evidence, h2)
		}
	}
	j1 := byID["J1-automation-external-integrations"]
	if containsString(j1.DependsOn, "I1-disconnected-okd-core") || containsString(j1.DependsOn, "I2-edge-sovereign-extension") {
		t.Fatalf("automation integrations were incorrectly serialized behind disconnected work: %#v", j1)
	}
	if j1.Status != ProgramStatusSourceImplemented || len(j1.Blockers) != 0 {
		t.Fatalf("J1 automation integrations must be source-implemented after Terraform and Crossplane closure: %#v", j1)
	}
	for _, evidence := range []string{"providers/terraform", "providers/terraform/internal/provider/saml_broker_resource.go", "providers/crossplane", "providers/crossplane/internal/controller/samlbroker/controller.go", "providers/crossplane/package/crossplane.yaml", "providers/crossplane/package/crds", "EXTERNAL_REGISTRY_ADMISSION_AUTHORITY_V1", "NOTIFICATION_PROVIDER_ADAPTER_CONTRACT_V1", "NOTIFICATION_PREFERENCE_DIGEST_POLICY_V1", "POST /api/v1/external-registry/admission", "GET /api/v1/notification-provider-contracts", "GET /api/v1/notification-routes/{id}/policy-digest"} {
		if !containsString(j1.Evidence, evidence) {
			t.Fatalf("J1 evidence %q missing: %#v", evidence, j1)
		}
	}
	for _, phase := range roadmap.Phases {
		for _, evidence := range phase.Evidence {
			if strings.HasPrefix(evidence, ".github/workflows/") {
				t.Fatalf("roadmap evidence must be source/runtime authority, not CI workflow %s: %#v", phase.ID, evidence)
			}
		}
	}
	j2 := byID["J2-finops-usage"]
	if j2.Status != ProgramStatusSourceImplemented || len(j2.Blockers) != 0 {
		t.Fatalf("J2 FinOps source closure drift: %#v", j2)
	}
	for _, evidence := range []string{"FINOPS_RATE_CARD_AUTHORITY_V1", "FINOPS_USAGE_MEASUREMENT_AUTHORITY_V1", "FINOPS_CAPACITY_OBSERVATION_AUTHORITY_V1", "FINOPS_CHARGEBACK_AUTHORITY_V1", "migrations/0070_finops_usage_ratecard_authority.sql", "GET /api/v1/finops/showback", "GET /api/v1/finops/chargeback-export", "MCP_ROUTE_PARITY_AUTHORITY_V1", "operator-console:finops-chargeback"} {
		if !containsString(j2.Evidence, evidence) {
			t.Fatalf("J2 evidence %q missing: %#v", evidence, j2)
		}
	}
	g3 := byID["G3-target-node-maintenance-lifecycle"]
	if g3.Status != ProgramStatusSourceImplemented || len(g3.Blockers) != 0 || !containsString(g3.Evidence, "TARGET_NODE_LIFECYCLE_AUTHORITY_V1") || !containsString(g3.Evidence, "TARGET_NODE_PROVIDER_BINDING_AUTHORITY_V1") || !containsString(g3.Evidence, "TARGET_NODE_PROVIDER_MACHINE_LIFECYCLE_V1") || !containsString(g3.Evidence, "CAPI_EXACT_WORKER_MACHINE_REMOVE_REPLACE_V1") || !containsString(g3.Evidence, "RKE2_WORKER_CERTIFICATE_RENEWAL_BY_CAPI_REPLACEMENT_V1") || !containsString(g3.Evidence, "CAPI_WORKER_MACHINE_REMEDIATION_REPLACEMENT_V1") || !containsString(g3.Evidence, "migrations/0061_target_node_provider_machine_lifecycle.sql") || !containsString(g3.Evidence, "CAPI_TOPOLOGY_WORKER_ADD_V1") || !containsString(g3.Evidence, "POST /api/v1/clusters/{id}/provider-binding") || !containsString(g3.Evidence, "POST /api/v1/clusters/{id}/node-lifecycle-actions") || !containsString(g3.Evidence, "TARGET_NODE_HOST_MAINTENANCE_EXECUTOR_V1") || !containsString(g3.ParallelWith, "S1-exact-supply-chain-acquisition-closure") || !containsString(g3.ParallelWith, "S2-component-runtime-certification-authorities") {
		t.Fatalf("node lifecycle source closure drift: %#v", g3)
	}
	g4 := byID["G4-data-protection-productization"]
	if g4.Status != ProgramStatusSourceImplemented || len(g4.Blockers) != 0 || !containsString(g4.Evidence, "TARGET_DATA_PROTECTION_AUTHORITY_V1") || !containsString(g4.Evidence, "TARGET_DATA_PROTECTION_SCHEDULER_V1") || !containsString(g4.Evidence, "TARGET_DATA_PROTECTION_OPERATOR_WORKFLOW_V1") || !containsString(g4.Evidence, "migrations/0065_target_data_protection_authority.sql") {
		t.Fatalf("data protection source closure drift: %#v", g4)
	}
	c9 := byID["C9-pre-certification-feature-freeze-exact-bundle"]
	if len(c9.Blockers) != 1 || !containsString(c9.Blockers, "FINAL_EXACT_RELEASE_SEAL_PENDING") {
		t.Fatalf("C9 independent exact-release seal blocker drift: %#v", c9)
	}
	for _, evidence := range []string{"FINAL_EXACT_RELEASE_ADMISSION_V1", "scripts/final_exact_release_admission.py", "FINAL_EXACT_RELEASE_SEAL_V1", "scripts/seal_final_exact_release.py", "LOCAL_EXACT_RELEASE_SEAL_V1", "GIT_DETACHED_EXACT_SHA_WORKTREE_V1", "scripts/build_release.py", "lab/final-exact-release-evidence.json"} {
		if !containsString(c9.Evidence, evidence) {
			t.Fatalf("C9 exact-release finalizer evidence missing %q: %#v", evidence, c9.Evidence)
		}
	}
	if containsString(c9.Evidence, ".github/workflows/final-exact-release-seal.yml") {
		t.Fatalf("C9 exact release authority must not depend on GitHub workflow evidence: %#v", c9.Evidence)
	}
	for _, dependency := range []string{"C7R-mcp-remote-oauth-human-delegation", "C7W-mcp-user-admin-write-parity", "S2-component-runtime-certification-authorities", "G3-target-node-maintenance-lifecycle", "G4-data-protection-productization", "G5-enterprise-identity-compliance", "H1-baremetal-connected-managed-okd", "I1-disconnected-okd-core"} {
		if !containsString(c9.DependsOn, dependency) {
			t.Fatalf("feature freeze dependency %q missing: %#v", dependency, c9.DependsOn)
		}
	}

	for _, id := range []string{"H2-vmware-provider", "I2-edge-sovereign-extension", "J1-automation-external-integrations", "J2-finops-usage", "J3-virtual-cluster-profile", "J4-product-api-contract-recovery-foundation", "J5-resource-scope-owner-closure", "H3-public-cloud-provider-adapters", "J6-fleet-reliability-incident-intelligence", "J7-finops-v2-budget-forecast-rightsizing", "J8-application-platform-abstraction-composition"} {
		phase := byID[id]
		if phase.RequiredForFeatureFreeze || phase.DeliveryTier != ProgramTierExpansion {
			t.Fatalf("expansion phase must not block core freeze %s: %#v", id, phase)
		}
		if containsString(c9.DependsOn, id) {
			t.Fatalf("core feature freeze must not depend on expansion phase %s: %#v", id, c9.DependsOn)
		}
	}
	i2 := byID["I2-edge-sovereign-extension"]
	if i2.Status != ProgramStatusSourceImplemented || i2.SourceStatus != ProgramSourceStatusImplemented || len(i2.Blockers) != 0 {
		t.Fatalf("I2 edge/sovereign source closure drift: %#v", i2)
	}
	for _, evidence := range []string{"EDGE_LOCAL_AUTHORITY_V1", "BOOT_SECURITY_ATTESTATION_AUTHORITY_V1", "LOCAL_AI_DISCONNECTED_PROFILE_AUTHORITY_V1", "POST /api/v1/edge/local-authority/policies/compile", "POST /api/v1/edge/local-authority/mutations/admit", "POST /api/v1/edge/local-authority/reconnect/resolve", "POST /api/v1/edge/boot-attestations/assess", "POST /api/v1/edge/local-ai/profiles/validate", "MCP_ROUTE_PARITY_AUTHORITY_V1", "MCP_PRODUCT_ACTION_REGISTRY_V1", "operator-console:edge-sovereign", "CONSOLE_LOCALIZATION_COVERAGE_V2"} {
		if !containsString(i2.Evidence, evidence) {
			t.Fatalf("I2 edge/sovereign evidence missing %s: %#v", evidence, i2)
		}
	}
	if !strings.Contains(strings.Join(i2.ExitCriteria, "\n"), "never infers Physical") || !strings.Contains(strings.Join(i2.ExitCriteria, "\n"), "never starts a runtime") {
		t.Fatalf("I2 source/physical truth boundary drift: %#v", i2.ExitCriteria)
	}

	h3 := byID["H3-public-cloud-provider-adapters"]
	if h3.Status != ProgramStatusSourceImplemented || h3.SourceStatus != ProgramSourceStatusImplemented || len(h3.Blockers) != 0 {
		t.Fatalf("H3 public-cloud provider source closure drift: %#v", h3)
	}
	for _, evidence := range []string{"PUBLIC_CLOUD_PROVIDER_EXECUTION_AUTHORITY_V1", "internal/providerexec", "ProviderClusterRecoveryRequired", "migrations/0077_provider_cluster_recovery_required.sql", "AWSClusterTemplate", "AzureClusterTemplate", "GCPClusterTemplate", "cmd/platform-agent:clusterAPIProviderAdapter"} {
		if !containsString(h3.Evidence, evidence) {
			t.Fatalf("H3 public-cloud provider evidence missing %s: %#v", evidence, h3)
		}
	}

	j3 := byID["J3-virtual-cluster-profile"]
	if j3.Status != ProgramStatusSourceImplemented || j3.SourceStatus != ProgramSourceStatusImplemented || len(j3.Blockers) != 0 {
		t.Fatalf("J3 virtual-cluster source closure drift: %#v", j3)
	}
	for _, evidence := range []string{"VIRTUAL_CLUSTER_PROFILE_AUTHORITY_V1", "VIRTUAL_CLUSTER_LIFECYCLE_AUTHORITY_V1", "VIRTUAL_CLUSTER_DURABLE_AUTHORITY_V1", "VIRTUAL_CLUSTER_DIAGNOSTICS_AUTHORITY_V1", "internal/virtualcluster", "cmd/platform-agent/virtual_cluster_runtime.go", "migrations/0078_virtual_cluster_authority.sql", "migrations/0080_virtual_cluster_lifecycle_journal.sql", "migrations/0081_finops_virtual_cluster_attribution.sql", "POST /api/v1/workspaces/{id}/virtual-clusters", "POST /api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/suspend", "MCP_ROUTE_PARITY_AUTHORITY_V1", "POSTGRES_BEHAVIORAL_INTEGRATION_V1", "operator-console:virtual-cluster-lifecycle", "WORKSPACE_AUTHORITY_V1"} {
		if !containsString(j3.Evidence, evidence) {
			t.Fatalf("J3 virtual-cluster source evidence missing %s: %#v", evidence, j3)
		}
	}

	phaseD := byID["D-exact-artifact-lab-ai-certification"]
	if phaseD.RequiredForFeatureFreeze || phaseD.Status != ProgramStatusDeferred || phaseD.DeliveryTier != ProgramTierCertification || len(phaseD.DependsOn) != 1 || phaseD.DependsOn[0] != c9.ID || len(phaseD.Blockers) != 0 || !containsString(phaseD.Evidence, "LAB_CERTIFICATION_MATRIX_V2") || !strings.Contains(phaseD.Objective, "M00-M10") {
		t.Fatalf("physical functional phase authority drift: %#v", phaseD)
	}
	phaseM := byID["M-full-product-certification-chaos-soak-ux-ai-evals"]
	if phaseM.RequiredForFeatureFreeze || phaseM.Status != ProgramStatusDeferred || phaseM.DeliveryTier != ProgramTierCertification || len(phaseM.Blockers) != 0 || len(phaseM.DependsOn) != 1 || phaseM.DependsOn[0] != phaseD.ID || !strings.Contains(phaseM.Objective, "M11-M13") {
		t.Fatalf("final chaos/soak phase authority drift: %#v", phaseM)
	}
	blockers := FeatureFreezeBlockerCounts(roadmap)
	for _, code := range []string{"MCP_EXTERNAL_CLIENT_INTEROP_EVIDENCE_PENDING"} {
		if blockers[code] == 0 {
			t.Fatalf("mandatory feature-freeze blocker %q missing: %#v", code, blockers)
		}
	}
	if blockers["PRE_CERTIFICATION_REQUIRED_FEATURES_OPEN"] != 0 || blockers["LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING"] != 0 {
		t.Fatalf("retired C9 aggregate blockers must not remain: %#v", blockers)
	}
	if blockers["APPLIANCE_INPUT_PACK_DISTRIBUTION_PENDING"] != 0 {
		t.Fatalf("closed S1 distribution blocker remained in feature-freeze authority: %#v", blockers)
	}
	if blockers["FINAL_EXACT_RELEASE_SEAL_PENDING"] != 1 {
		t.Fatalf("C9 must expose exactly one independent final exact-release seal blocker: %#v", blockers)
	}
	for _, code := range []string{"COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING", "OKD_CONNECTED_MANAGED_INSTALL_PENDING", "OKD_DISCONNECTED_RUNTIME_CERTIFICATION_PENDING"} {
		if blockers[code] != 0 {
			t.Fatalf("Phase-D or closed pre-certification blocker %q leaked into feature-freeze authority: %#v", code, blockers)
		}
	}
	if blockers["TARGET_DATA_PROTECTION_WORKFLOW_PENDING"] != 0 {
		t.Fatalf("closed G4 blocker must not remain in feature-freeze authority: %#v", blockers)
	}
	if blockers["CERTIFICATE_RENEWAL_EXECUTOR_PENDING"] != 0 || blockers["NODE_REMEDIATION_EXECUTOR_PENDING"] != 0 {
		t.Fatalf("closed G3 blockers must not remain in feature-freeze authority: %#v", blockers)
	}
	if blockers["PHYSICAL_RUNTIME_NOT_EVALUATED"] != 0 {
		t.Fatalf("physical runtime blockers must not be counted as pre-freeze product blockers: %#v", blockers)
	}
	if blockers["FEATURE_CERTIFICATION_CONTRACTS_INCOMPLETE"] != 0 {
		t.Fatalf("closed certification-contract blocker must not remain: %#v", blockers)
	}
	if roadmap.CertificationRegistryAuthority != FeatureCertificationRegistryAuthority || roadmap.CertificationCoverage.Authority != FeatureCertificationCoverageAuthority || !roadmap.CertificationCoverage.Complete || roadmap.CertificationCoverage.RequiredOwnerPhases != 24 || roadmap.CertificationCoverage.CoveredOwnerPhases != 24 || len(roadmap.CertificationCoverage.MissingOwnerPhases) != 0 {
		t.Fatalf("feature certification coverage incomplete: %#v", roadmap.CertificationCoverage)
	}
	if issues := ValidateFeatureCertificationRegistry(roadmap); len(issues) != 0 {
		t.Fatalf("feature certification registry validation issues: %#v", issues)
	}
	foundManagedOKD := false
	foundChaos := false
	for _, requirement := range roadmap.CertificationRegistry {
		if requirement.Feature == "connected-managed-okd-compact3" && containsString(requirement.PhysicalScenarios, "M08") && containsString(requirement.RequiredLevels, CertificationExactSHAPhysicalRuntime) {
			foundManagedOKD = true
		}
		if requirement.Feature == "final-chaos-load-soak" && containsString(requirement.PhysicalScenarios, "M11") && containsString(requirement.PhysicalScenarios, "M13") && containsString(requirement.RequiredLevels, CertificationChaosLoadSoak) {
			foundChaos = true
		}
	}
	if !foundManagedOKD || !foundChaos {
		t.Fatalf("feature certification registry is incomplete: %#v", roadmap.CertificationRegistry)
	}
	if roadmap.Positioning == "" || len(roadmap.PrimaryBenchmarks) < 3 || len(roadmap.CompetitiveDifferentiators) < 6 || len(roadmap.DeferredParity) < 4 {
		t.Fatalf("competitive product authority is incomplete: %#v", roadmap)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestOKDCapabilityResolverRequiresObservedAdmissionEvidence(t *testing.T) {
	resolution := ResolveTargetComponents("OKD", []string{"cilium", "capsule", "victoria-metrics", "snapshot-controller", "argocd"}, nil)
	if resolution.Authority != CapabilityResolverAuthority || resolution.Admitted || resolution.Status != "DISCOVERED_BLOCKED" {
		t.Fatalf("OKD without inventory evidence was incorrectly admitted: %#v", resolution)
	}
	if len(resolution.Blockers) < 5 {
		t.Fatalf("missing inventory-bound OKD blockers: %#v", resolution.Blockers)
	}
	actions := map[string]string{}
	for _, decision := range resolution.Decisions {
		actions[decision.Component] = decision.Action
	}
	for _, component := range []string{"cilium", "capsule", "victoria-metrics"} {
		if actions[component] != ResolutionActionConditional {
			t.Fatalf("%s action=%q without observed ownership", component, actions[component])
		}
	}
}

func TestOKDCapabilityResolverAdmitsHealthyInventoryAndSuppressesObservedNativeOwnership(t *testing.T) {
	observed := []string{"okd-import-admitted", "networking.ovn-kubernetes", "network-policy.native", "monitoring.cluster", "operator-lifecycle.olm", "security.scc", "tenancy.projects", "volume-snapshot-controller"}
	resolution := ResolveTargetComponents("OKD", []string{"cilium", "capsule", "victoria-metrics", "snapshot-controller", "argocd"}, observed)
	if !resolution.Admitted || resolution.Status != "ADMITTED" || len(resolution.Blockers) != 0 {
		t.Fatalf("healthy OKD inventory not admitted: %#v", resolution)
	}
	actions := map[string]string{}
	for _, decision := range resolution.Decisions {
		actions[decision.Component] = decision.Action
	}
	for _, component := range []string{"cilium", "capsule", "victoria-metrics", "snapshot-controller"} {
		if actions[component] != ResolutionActionSuppress {
			t.Fatalf("%s action=%q", component, actions[component])
		}
	}
	if actions["argocd"] != ResolutionActionInclude {
		t.Fatalf("argocd action=%q", actions["argocd"])
	}
}

func TestAdmittedKubernetesResolverDoesNotInventDistributionOwnedSuppression(t *testing.T) {
	resolution := ResolveTargetComponents("rke2", []string{"cilium", "argocd"}, nil)
	if !resolution.Admitted || resolution.Status != "ADMITTED" {
		t.Fatalf("rke2 unexpectedly not admitted: %#v", resolution)
	}
	for _, decision := range resolution.Decisions {
		if decision.Action != ResolutionActionInclude {
			t.Fatalf("unexpected suppression for admitted rke2 target: %#v", decision)
		}
	}
}

func TestFeatureCertificationRegistryFailsClosedOnMissingOwnerAndNegativeControls(t *testing.T) {
	roadmap := ProgramRoadmapModel()
	if len(roadmap.CertificationRegistry) < 2 {
		t.Fatal("certification registry unexpectedly small")
	}
	broken := roadmap
	broken.CertificationRegistry = append([]FeatureCertificationRequirement(nil), roadmap.CertificationRegistry...)
	broken.CertificationRegistry[0].OwnerPhases = nil
	broken.CertificationRegistry[1].NegativeControls = nil
	issues := ValidateFeatureCertificationRegistry(broken)
	if !containsString(issues, "owner-phase-missing:"+broken.CertificationRegistry[0].Feature) {
		t.Fatalf("missing owner phase was not rejected: %#v", issues)
	}
	if !containsString(issues, "negative-controls-missing:"+broken.CertificationRegistry[1].Feature) {
		t.Fatalf("missing negative controls were not rejected: %#v", issues)
	}
}

func TestFeatureCertificationRegistryFailsClosedWhenMandatoryCorePhaseIsUncovered(t *testing.T) {
	roadmap := ProgramRoadmapModel()
	filtered := make([]FeatureCertificationRequirement, 0, len(roadmap.CertificationRegistry))
	for _, contract := range roadmap.CertificationRegistry {
		if containsString(contract.OwnerPhases, "C7W-mcp-user-admin-write-parity") {
			continue
		}
		filtered = append(filtered, contract)
	}
	roadmap.CertificationRegistry = filtered
	issues := ValidateFeatureCertificationRegistry(roadmap)
	if !containsString(issues, "required-owner-uncovered:C7W-mcp-user-admin-write-parity") {
		t.Fatalf("uncovered mandatory phase was not rejected: %#v", issues)
	}
}

func TestProgramProgressUnknownBlockerReopensSourceClosure(t *testing.T) {
	phases := []ProgramPhase{{
		ID:                       "future-core-phase",
		Order:                    1,
		Status:                   ProgramStatusBlocked,
		DeliveryTier:             ProgramTierCoreFreeze,
		RequiredForFeatureFreeze: true,
		Blockers:                 []string{"FUTURE_UNCLASSIFIED_IMPLEMENTATION_GAP"},
	}}
	progress := programProgressSummary(phases, false)
	if progress.CoreSourceClosureComplete || progress.CoreSourceClosedPhases != 0 || progress.CoreSourceOpenPhases != 1 || progress.RemainingBlockerClasses["source-software-closure"] != 1 || !containsString(progress.SourceOpenPhaseIDs, "future-core-phase") {
		t.Fatalf("unknown blocker must fail closed into source/software debt: %#v", progress)
	}
}

func TestCompetitivePrePhysicalRoadmapKeepsSoftwareExpansionRunnable(t *testing.T) {
	roadmap := ProgramRoadmapModel()
	if roadmap.Authority != "PROGRAM_PHASE_MODEL_V75" {
		t.Fatalf("authority=%s", roadmap.Authority)
	}
	byID := map[string]ProgramPhase{}
	for _, phase := range roadmap.Phases {
		byID[phase.ID] = phase
	}
	foundation := byID["J4-product-api-contract-recovery-foundation"]
	if foundation.Status != ProgramStatusSourceImplemented || foundation.RequiredForFeatureFreeze {
		t.Fatalf("contract/recovery foundation=%+v", foundation)
	}
	for _, evidence := range []string{"PRODUCT_API_CONTRACT_AUTHORITY_V1", "RESOURCE_SCOPE_REGISTRY_V1", "MCP_CONTROL_JOB_RECOVERY_AUTHORITY_V1"} {
		if !containsString(foundation.Evidence, evidence) {
			t.Fatalf("foundation evidence missing %s: %+v", evidence, foundation)
		}
	}
	scopeClosure := byID["J5-resource-scope-owner-closure"]
	if scopeClosure.Status != ProgramStatusSourceImplemented || len(scopeClosure.Blockers) != 0 {
		t.Fatalf("scope closure=%+v", scopeClosure)
	}
	for _, evidence := range []string{"RESOURCE_SCOPE_OWNER_CLASSIFICATIONS_V1", "RESOURCE_SCOPE_CONSUMER_AUDIT_V1", "PRODUCT_API_RESOURCE_SCOPE_PROPAGATION_V1", "CONSOLE_RESOURCE_SCOPE_FAIL_CLOSED_V1"} {
		if !containsString(scopeClosure.Evidence, evidence) {
			t.Fatalf("scope closure evidence missing %s: %+v", evidence, scopeClosure)
		}
	}
	j1 := byID["J1-automation-external-integrations"]
	if j1.Status != ProgramStatusSourceImplemented || j1.SourceStatus != ProgramSourceStatusImplemented || len(j1.Blockers) != 0 {
		t.Fatalf("automation integration source closure drift: %+v", j1)
	}
	i2 := byID["I2-edge-sovereign-extension"]
	if containsString(i2.DependsOn, "I1-disconnected-okd-core") || i2.RequiredForFeatureFreeze {
		t.Fatalf("edge software work is incorrectly physically serialized: %+v", i2)
	}
	j6 := byID["J6-fleet-reliability-incident-intelligence"]
	if j6.Status != ProgramStatusSourceImplemented || j6.SourceStatus != ProgramSourceStatusImplemented || len(j6.Blockers) != 0 || !containsString(j6.Evidence, "SERVICE_HEALTH_AUTHORITY_V1") || !containsString(j6.Evidence, "INCIDENT_AUTHORITY_V1") || !containsString(j6.Evidence, "SLO_ERROR_BUDGET_AUTHORITY_V1") || !containsString(j6.Evidence, "migrations/0076_incident_operation_evidence_link.sql") {
		t.Fatalf("J6 source closure drift: %#v", j6)
	}
	j7 := byID["J7-finops-v2-budget-forecast-rightsizing"]
	if j7.Status != ProgramStatusSourceImplemented || len(j7.Blockers) != 0 {
		t.Fatalf("FinOps v2 phase must be source-implemented after durable budget/insight closure: %+v", j7)
	}
	for _, evidence := range []string{"FINOPS_BUDGET_POLICY_AUTHORITY_V1", "FINOPS_FORECAST_ANOMALY_RIGHTSIZING_AUTHORITY_V1", "migrations/0073_finops_budget_policy_authority.sql", "POST /api/v1/finops/budget-policies", "GET /api/v1/finops/insights", "operator-console:finops-budget-forecast-rightsizing"} {
		if !containsString(j7.Evidence, evidence) {
			t.Fatalf("FinOps v2 evidence missing %s: %+v", evidence, j7)
		}
	}

	j8 := byID["J8-application-platform-abstraction-composition"]
	if j8.Status != ProgramStatusBlocked || j8.SourceStatus != ProgramSourceStatusImplemented || j8.RequiredForFeatureFreeze || !containsString(j8.Evidence, OpenChoreoReferenceAuthority) || !containsString(j8.Evidence, DaprApplicationRuntimeAuthority) || !containsString(j8.Evidence, DaprRuntimeSourcePlanAuthority) || !containsString(j8.Evidence, DaprRuntimeSupplyChainAuthority) || !containsString(j8.Evidence, DaprTargetAdmissionAuthority) || !containsString(j8.Evidence, "DAPR_TARGET_LIFECYCLE_AUTHORITY_V1") || !containsString(j8.Evidence, "DAPR_TARGET_EXECUTOR_RUNTIME_V1") || !containsString(j8.Evidence, "DAPR_TARGET_EXECUTOR_JOB_AUTHORITY_V1") || !containsString(j8.Evidence, "DAPR_TARGET_OBSERVED_RECEIPT_V1") || !containsString(j8.Evidence, "DAPR_TARGET_MIRROR_PULL_EVIDENCE_V1") || !containsString(j8.Evidence, "DAPR_WORKLOAD_ADMISSION_AUTHORITY_V1") || !containsString(j8.Evidence, "DAPR_WORKLOAD_ADMISSION_EVIDENCE_V1") || !containsString(j8.Evidence, "DAPR_WORKLOAD_POLICY_PROJECTION_V1") || !containsString(j8.Evidence, "DAPR_WORKLOAD_ADMISSION_EXECUTOR_JOB_V1") || !containsString(j8.Evidence, "DAPR_EXECUTOR_IMAGE_EVIDENCE_V1") || !containsString(j8.Evidence, "dapr-workload-admission-rbac-active") || !containsString(j8.Evidence, "4so-dapr-workload-admitter") || !containsString(j8.Evidence, "application-runtime.dapr") || !containsString(j8.Evidence, "internal/targetmodel/dapr.go") || !containsString(j8.Evidence, "internal/dapr/executor_authority.go") || !containsString(j8.Evidence, "internal/dapr/workload_admission.go") || !containsString(j8.Evidence, "internal/dapr/workload_policy.go") || !containsString(j8.Evidence, "internal/api/dapr_lifecycle.go") || !containsString(j8.Evidence, "internal/api/dapr_workload_admission.go") || !containsString(j8.Evidence, "cmd/platform-agent/dapr_runtime.go") || !containsString(j8.Evidence, "cmd/platform-agent/dapr_workload_admission.go") || !containsString(j8.Evidence, "POST /api/v1/application-platform/dapr/assessment") || !containsString(j8.Evidence, "POST /api/v1/application-platform/dapr/workload-admissions") || !containsString(j8.Evidence, "GET /api/v1/application-platform/dapr/workload-admissions/{id}") || !containsString(j8.Evidence, "POST /api/v1/application-platform/dapr/lifecycle") || !containsString(j8.Evidence, "GET /agent/v1/clusters/{id}/dapr-recovery/next") {
		t.Fatalf("application-platform composition phase drift: %+v", j8)
	}
	for _, evidence := range []string{
		"APPLICATION_DEPLOYMENT_PLAN_V1",
		"APPLICATION_DEPLOYMENT_REQUEST_V1",
		"APPLICATION_DEPLOYMENT_EVIDENCE_V1",
		"application-deployment-rbac-active",
		"4so-platform-application-manager",
		"internal/controlplane/application_deployment.go",
		"internal/controlplane/application_deployment_runtime.go",
		"internal/api/application_deployment_runtime.go",
		"cmd/platform-agent/application_deployment.go",
		"POST /api/v1/application-platform/environment-bindings/{id}/deployment-plan",
		"POST /api/v1/application-platform/environment-bindings/{id}/deployments",
		"GET /api/v1/application-platform/deployments/{id}",
		"POST /api/v1/application-platform/deployments/{id}/approve",
		"GET /agent/v1/clusters/{id}/application-deployment-tasks/next",
		"POST /agent/v1/clusters/{id}/application-deployment-tasks/{operationId}/result",
		"GET /agent/v1/clusters/{id}/application-deployment-recovery/next",
		"POST /agent/v1/clusters/{id}/application-deployment-recovery/{operationId}/result",
		"OPERATION_UNKNOWN_OUTCOME_RECOVERY_V1",
	} {
		if !containsString(j8.Evidence, evidence) {
			t.Fatalf("J8 application deployment authority evidence missing %s: %#v", evidence, j8)
		}
	}
	if len(j8.Blockers) != 1 || !containsString(j8.Blockers, "OPENCHOREO_PRODUCTION_ZOT_SEAL_PENDING") || containsString(j8.Blockers, "DAPR_RUNTIME_PENDING") {
		t.Fatalf("J8 must retain only the OpenChoreo production zot seal blocker; optional Dapr may not become a release blocker: %+v", j8)
	}
	if containsString(j8.Blockers, "FLEET_GATEWAY_RUNTIME_TRANSPORT_PENDING") {
		t.Fatalf("Fleet gateway source blocker remained after reconnect/runtime closure: %+v", j8)
	}

	if containsString(j8.Blockers, "DELIVERY_DEPLOYMENT_EVIDENCE_INGESTION_PENDING") {
		t.Fatalf("delivery evidence blocker remained after durable deployment projection closure: %+v", j8)
	}

	for _, id := range []string{"H3-public-cloud-provider-adapters", "J3-virtual-cluster-profile", "J6-fleet-reliability-incident-intelligence", "J7-finops-v2-budget-forecast-rightsizing", "J8-application-platform-abstraction-composition"} {
		phase := byID[id]
		if phase.ID == "" || phase.RequiredForFeatureFreeze || phase.DeliveryTier != ProgramTierExpansion {
			t.Fatalf("pre-physical expansion phase %s=%+v", id, phase)
		}
		for _, dep := range phase.DependsOn {
			if dep == "D-exact-artifact-lab-ai-certification" || dep == "M-full-product-certification-chaos-soak-ux-ai-evals" {
				t.Fatalf("software phase %s depends on physical certification: %+v", id, phase)
			}
		}
	}
}
