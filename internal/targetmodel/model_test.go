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
	if roadmap.Authority != "PROGRAM_PHASE_MODEL_V68" || roadmap.CurrentPhase != "S1-exact-supply-chain-acquisition-closure" || roadmap.GoalReady {
		t.Fatalf("unexpected roadmap authority: %#v", roadmap)
	}
	if len(roadmap.Phases) != 39 {
		t.Fatalf("phase count=%d", len(roadmap.Phases))
	}
	progress := roadmap.Progress
	if progress.Authority != ProgramProgressAuthority || progress.CoreRequiredPhases != 25 || progress.CoreSourceClosedPhases != 25 || progress.CoreSourceOpenPhases != 0 || progress.CorePhaseReady != 19 || progress.CorePhaseBlocked != 6 || progress.CoreSourceClosurePercent != 100 || progress.CorePhaseReadyPercent != 76 || !progress.CoreSourceClosureComplete || progress.FeatureFreezeReady {
		t.Fatalf("program progress truth drift: %#v", progress)
	}
	if progress.PrePhysicalSoftwarePhases != 35 || progress.PrePhysicalSoftwareClosedPhases != 31 || progress.PrePhysicalSoftwareOpenPhases != 4 || progress.PrePhysicalSoftwareClosurePercent != 88 {
		t.Fatalf("pre-physical software progress truth drift: %#v", progress)
	}
	for _, id := range []string{"C7W-mcp-user-admin-write-parity", "S1-exact-supply-chain-acquisition-closure", "S2-component-runtime-certification-authorities", "H1-baremetal-connected-managed-okd", "I1-disconnected-okd-core", "C9-pre-certification-feature-freeze-exact-bundle"} {
		if !containsString(progress.ExternalClosureOnlyPhaseIDs, id) {
			t.Fatalf("external-only closure phase missing %s: %#v", id, progress.ExternalClosureOnlyPhaseIDs)
		}
	}
	if progress.RemainingBlockerClasses["source-software-closure"] != 0 || progress.RemainingBlockerClasses["external-byte-acquisition"] < 1 || progress.RemainingBlockerClasses["physical-runtime-evidence"] < 1 || progress.RemainingBlockerClasses["external-client-evidence"] < 1 || progress.RemainingBlockerClasses["runtime-certification-evidence"] < 1 {
		t.Fatalf("remaining blocker classification drift: %#v", progress.RemainingBlockerClasses)
	}
	if len(roadmap.Tracks) != 16 || len(roadmap.GlobalGuardrails) < 8 || len(roadmap.CertificationRegistry) < 10 {
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
	if roadmap.CurrentExecutionWave != "W1-core-closure-blitz" || len(roadmap.ExecutionWaves) != 6 {
		t.Fatalf("execution-wave authority drift: current=%q waves=%#v", roadmap.CurrentExecutionWave, roadmap.ExecutionWaves)
	}
	for _, id := range []string{"A-architecture-authority-rebaseline", "B-target-capability-supplychain-foundation", "C1-operator-ia-scope-authority", "C2-console-data-scale-refresh-semantics", "C3-console-action-workflow-evidence-convergence", "C4-console-e2e-ux-certification", "E-certified-platform-template-workspace-foundation", "C5-installer-production-lifecycle-closure", "C6-multi-agent-test-autopilot", "C7-ai-mcp-delegated-operations", "C8-console-operational-completion", "F-okd-import-capability-certification", "R0-release-authority-certification-rebaseline", "G1-operational-runtime-hardening", "G2-generalized-day2-campaign-engine", "G3-target-node-maintenance-lifecycle"} {
		phase, ok := byID[id]
		if !ok || phase.Status != ProgramStatusSourceImplemented || phase.DeliveryTier != ProgramTierCoreFreeze || !phase.RequiredForFeatureFreeze || len(phase.Blockers) != 0 {
			t.Fatalf("source-implemented mandatory phase drift %s: %#v", id, phase)
		}
	}
	r0 := byID["R0-release-authority-certification-rebaseline"]
	for _, evidence := range []string{"PROGRAM_PHASE_MODEL_V68", "FEATURE_CERTIFICATION_REGISTRY_V2", "LAB_CERTIFICATION_MATRIX_V2", "DOCUMENTATION_AUTHORITY_SYNC_V1"} {
		if !containsString(r0.Evidence, evidence) {
			t.Fatalf("R0 evidence %q missing: %#v", evidence, r0)
		}
	}
	s1 := byID[roadmap.CurrentPhase]
	if s1.Status != ProgramStatusBlocked || !s1.RequiredForFeatureFreeze || !containsString(s1.ParallelWith, "C7W-mcp-user-admin-write-parity") || !containsString(s1.ParallelWith, "G4-data-protection-productization") || !containsString(s1.ParallelWith, "G5-enterprise-identity-compliance") || containsString(s1.ParallelWith, "H2-vmware-provider") || containsString(s1.ParallelWith, "J1-automation-external-integrations") {
		t.Fatalf("supply-chain phase is not an immediate parallel critical path: %#v", s1)
	}
	for _, blocker := range []string{"COMPONENT_SOURCE_ACQUISITION_PENDING", "SOURCE_LOCKS_PENDING", "MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING", "MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING"} {
		if !containsString(s1.Blockers, blocker) {
			t.Fatalf("supply-chain blocker %q missing: %#v", blocker, s1)
		}
	}
	c7r := byID["C7R-mcp-remote-oauth-human-delegation"]
	if c7r.Status != ProgramStatusSourceImplemented || !c7r.RequiredForFeatureFreeze || len(c7r.Blockers) != 0 || !containsString(c7r.Evidence, "MCP_OAUTH_PROTECTED_RESOURCE_DISCOVERY_V1") || !containsString(c7r.Evidence, "MCP_DEDICATED_AUDIENCE_VALIDATION_V1") || !containsString(c7r.Evidence, "MCP_HUMAN_DELEGATION_AUTHORITY_V1") || !containsString(c7r.Evidence, "MCP_CLIENT_TRUST_REGISTRY_V1") || !containsString(c7r.Evidence, "MCP_TOKEN_REVOCATION_ENFORCEMENT_V1") {
		t.Fatalf("remote OAuth MCP phase drift: %#v", c7r)
	}
	c7w := byID["C7W-mcp-user-admin-write-parity"]
	if c7w.Status != ProgramStatusBlocked || !c7w.RequiredForFeatureFreeze || !containsString(c7w.DependsOn, c7r.ID) || containsString(c7w.Blockers, "MCP_ACTION_REGISTRY_ENFORCEMENT_PENDING") || containsString(c7w.Blockers, "MCP_EFFECTIVE_TOOL_FILTERING_PENDING") || containsString(c7w.Blockers, "MCP_WRITE_JOB_COVERAGE_PENDING") || !containsString(c7w.Blockers, "MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING") || !containsString(c7w.Evidence, "MCP_PRODUCT_ACTION_REGISTRY_V1") || !containsString(c7w.Evidence, "MCP_EFFECTIVE_TOOL_FILTERING_V1") {
		t.Fatalf("MCP write parity phase drift: %#v", c7w)
	}
	s2 := byID["S2-component-runtime-certification-authorities"]
	if s2.Status != ProgramStatusBlocked || !containsString(s2.Blockers, "UPSTREAM_RUNTIME_SUITABILITY_HOLDS_PENDING") || !containsString(s2.Blockers, "COMPONENT_HISTORICAL_SOURCE_ACQUISITION_PENDING") || !containsString(s2.Blockers, "COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING") || !containsString(s2.Evidence, "COMPONENT_UPGRADE_SOURCE_ADMISSION_V1") || !containsString(s2.Evidence, "CATALOG_HISTORICAL_SOURCE_IMPORT_V1") {
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
	if !containsString(h1.Blockers, "OKD_CONNECTED_MANAGED_INSTALL_PENDING") || containsString(h1.DependsOn, "H2-vmware-provider") {
		t.Fatalf("connected managed OKD authority drift: %#v", h1)
	}
	i1 := byID["I1-disconnected-okd-core"]
	if i1.Status != ProgramStatusBlocked || len(i1.Blockers) != 1 || !containsString(i1.Blockers, "OKD_OC_MIRROR_V2_ACQUISITION_PENDING") || containsString(i1.Blockers, "OKD_DISCONNECTED_INSTALL_WORKFLOW_PENDING") || !containsString(i1.Evidence, "DISCONNECTED_OKD_MIRROR_RUNTIME_V1") || !containsString(i1.Evidence, "DISCONNECTED_OKD_MIRROR_INVENTORY_V1") || !containsString(i1.Evidence, "mode-specific Operator Console readiness") {
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
	if j1.Status != ProgramStatusBlocked || len(j1.Blockers) != 1 || !containsString(j1.Blockers, "CROSSPLANE_PROVIDER_PENDING") || containsString(j1.Blockers, "TERRAFORM_PROVIDER_PENDING") {
		t.Fatalf("J1 should retain only the real Crossplane provider blocker after Terraform source closure: %#v", j1)
	}
	for _, evidence := range []string{"providers/terraform", "providers/terraform/internal/provider/saml_broker_resource.go", ".github/workflows/repository-integrity.yml:terraform-provider", "EXTERNAL_REGISTRY_ADMISSION_AUTHORITY_V1", "NOTIFICATION_PROVIDER_ADAPTER_CONTRACT_V1", "NOTIFICATION_PREFERENCE_DIGEST_POLICY_V1", "POST /api/v1/external-registry/admission", "GET /api/v1/notification-provider-contracts", "GET /api/v1/notification-routes/{id}/policy-digest"} {
		if !containsString(j1.Evidence, evidence) {
			t.Fatalf("J1 evidence %q missing: %#v", evidence, j1)
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
	if g3.Status != ProgramStatusSourceImplemented || len(g3.Blockers) != 0 || !containsString(g3.Evidence, "TARGET_NODE_LIFECYCLE_AUTHORITY_V1") || !containsString(g3.Evidence, "TARGET_NODE_PROVIDER_BINDING_AUTHORITY_V1") || !containsString(g3.Evidence, "TARGET_NODE_PROVIDER_MACHINE_LIFECYCLE_V1") || !containsString(g3.Evidence, "CAPI_EXACT_WORKER_MACHINE_REMOVE_REPLACE_V1") || !containsString(g3.Evidence, "RKE2_WORKER_CERTIFICATE_RENEWAL_BY_CAPI_REPLACEMENT_V1") || !containsString(g3.Evidence, "CAPI_WORKER_MACHINE_REMEDIATION_REPLACEMENT_V1") || !containsString(g3.Evidence, "migrations/0061_target_node_provider_machine_lifecycle.sql") || !containsString(g3.Evidence, "CAPI_TOPOLOGY_WORKER_ADD_V1") || !containsString(g3.Evidence, "POST /api/v1/clusters/{id}/provider-binding") || !containsString(g3.Evidence, "POST /api/v1/clusters/{id}/node-lifecycle-actions") || !containsString(g3.Evidence, "TARGET_NODE_HOST_MAINTENANCE_EXECUTOR_V1") || !containsString(g3.ParallelWith, roadmap.CurrentPhase) || !containsString(g3.ParallelWith, "S2-component-runtime-certification-authorities") {
		t.Fatalf("node lifecycle source closure drift: %#v", g3)
	}
	g4 := byID["G4-data-protection-productization"]
	if g4.Status != ProgramStatusSourceImplemented || len(g4.Blockers) != 0 || !containsString(g4.Evidence, "TARGET_DATA_PROTECTION_AUTHORITY_V1") || !containsString(g4.Evidence, "TARGET_DATA_PROTECTION_SCHEDULER_V1") || !containsString(g4.Evidence, "TARGET_DATA_PROTECTION_OPERATOR_WORKFLOW_V1") || !containsString(g4.Evidence, "migrations/0065_target_data_protection_authority.sql") {
		t.Fatalf("data protection source closure drift: %#v", g4)
	}
	c9 := byID["C9-pre-certification-feature-freeze-exact-bundle"]
	for _, dependency := range []string{"C7R-mcp-remote-oauth-human-delegation", "C7W-mcp-user-admin-write-parity", "S2-component-runtime-certification-authorities", "G3-target-node-maintenance-lifecycle", "G4-data-protection-productization", "G5-enterprise-identity-compliance", "H1-baremetal-connected-managed-okd", "I1-disconnected-okd-core"} {
		if !containsString(c9.DependsOn, dependency) {
			t.Fatalf("feature freeze dependency %q missing: %#v", dependency, c9.DependsOn)
		}
	}

	for _, id := range []string{"H2-vmware-provider", "I2-edge-sovereign-extension", "J1-automation-external-integrations", "J2-finops-usage", "J3-virtual-cluster-profile", "J4-product-api-contract-recovery-foundation", "J5-resource-scope-owner-closure", "H3-public-cloud-provider-adapters", "J6-fleet-reliability-incident-intelligence", "J7-finops-v2-budget-forecast-rightsizing"} {
		phase := byID[id]
		if phase.RequiredForFeatureFreeze || phase.DeliveryTier != ProgramTierExpansion {
			t.Fatalf("expansion phase must not block core freeze %s: %#v", id, phase)
		}
		if containsString(c9.DependsOn, id) {
			t.Fatalf("core feature freeze must not depend on expansion phase %s: %#v", id, c9.DependsOn)
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
	for _, code := range []string{"MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING", "COMPONENT_RUNTIME_UPGRADE_MATRIX_PENDING", "OKD_CONNECTED_MANAGED_INSTALL_PENDING"} {
		if blockers[code] == 0 {
			t.Fatalf("mandatory feature-freeze blocker %q missing: %#v", code, blockers)
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
	if roadmap.Authority != "PROGRAM_PHASE_MODEL_V68" {
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
	if len(j1.Blockers) != 1 || !containsString(j1.Blockers, "CROSSPLANE_PROVIDER_PENDING") || containsString(j1.Blockers, "TERRAFORM_PROVIDER_PENDING") {
		t.Fatalf("automation blockers must retain only Crossplane after Terraform source closure: %+v", j1)
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

	for _, id := range []string{"H3-public-cloud-provider-adapters", "J3-virtual-cluster-profile", "J6-fleet-reliability-incident-intelligence", "J7-finops-v2-budget-forecast-rightsizing"} {
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
