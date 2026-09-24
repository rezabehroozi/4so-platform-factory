package targetmodel

import "testing"

func TestOpenChoreoReferenceAdoptionPreservesFactoryAuthorities(t *testing.T) {
	model := OpenChoreoAdoptionModel()
	if issues := ValidateOpenChoreoAdoption(model); len(issues) != 0 {
		t.Fatalf("OpenChoreo adoption model invalid: %#v", issues)
	}
	if model.Authority != OpenChoreoReferenceAuthority || model.DocsBaseline != "v1.3.x" || model.ReviewedUpstreamCommit != "178dfbde3e3343e5ac151b88a2f203f523f97480" {
		t.Fatalf("review identity drift: %#v", model)
	}
	if !model.PostgreSQLSoTPreserved || !model.ManagementPlaneRemainsRKE2 || !model.BuildKitZotCanonical || !model.KeycloakCanonical || !model.OperatorConsoleProductOwned {
		t.Fatalf("canonical authority regression: %#v", model)
	}
	if model.OptionalAdapter.DefaultEnabled || !model.OptionalAdapter.TargetOnly || model.OptionalAdapter.Status != "PLANNED_SOURCE_ADAPTER_NOT_RUNTIME_ADMITTED" {
		t.Fatalf("optional target adapter was over-admitted: %#v", model.OptionalAdapter)
	}
}

func TestOpenChoreoPatternsMapToExistingAuthoritiesWithoutSecondSoT(t *testing.T) {
	model := OpenChoreoAdoptionModel()
	byID := map[string]OpenChoreoReferencePattern{}
	for _, pattern := range model.Patterns {
		byID[pattern.ID] = pattern
	}
	for _, id := range []string{"component-type-trait", "resource-type", "project-type", "immutable-release-binding"} {
		pattern, ok := byID[id]
		if !ok || pattern.Decision != OpenChoreoAdaptPattern || !containsString(pattern.OwnerPhases, "J8-application-platform-abstraction-composition") {
			t.Fatalf("platform abstraction pattern %s invalid: %#v", id, pattern)
		}
	}
	if byID["cluster-agent-gateway"].Decision != OpenChoreoAuditSelectiveReuse {
		t.Fatalf("cluster transport must remain selective audit/reuse: %#v", byID["cluster-agent-gateway"])
	}
	if byID["cost-insights"].Decision != OpenChoreoExtendExistingAuthority || byID["delivery-insights"].UpstreamMaturity != "ALPHA_REFERENCE" || byID["audit-logging"].UpstreamMaturity != "BETA_REFERENCE" {
		t.Fatalf("insight maturity/authority mapping drift: %#v", byID)
	}
	if byID["optional-openchoreo-target"].Decision != OpenChoreoOptionalTargetAdapter {
		t.Fatalf("OpenChoreo runtime may only enter as optional target adapter: %#v", byID["optional-openchoreo-target"])
	}
}

func TestOpenChoreoReferencePhaseIsExpansionOnlyAndDoesNotBlockCoreFreeze(t *testing.T) {
	roadmap := ProgramRoadmapModel()
	byID := map[string]ProgramPhase{}
	for _, phase := range roadmap.Phases {
		byID[phase.ID] = phase
	}
	phase := byID["J8-application-platform-abstraction-composition"]
	if phase.ID == "" || phase.RequiredForFeatureFreeze || phase.DeliveryTier != ProgramTierExpansion || phase.Status != ProgramStatusBlocked || phase.SourceStatus != ProgramSourceStatusOpen {
		t.Fatalf("J8 phase boundary invalid: %#v", phase)
	}
	if len(phase.Blockers) != 1 || !containsString(phase.Blockers, "OPENCHOREO_EXACT_SOURCE_LIFECYCLE_ADAPTER_PENDING") {
		t.Fatalf("J8 must retain only the exact-source OpenChoreo blocker after Fleet transport closure: %#v", phase.Blockers)
	}
	if containsString(phase.Blockers, "FLEET_GATEWAY_RUNTIME_TRANSPORT_PENDING") {
		t.Fatalf("Fleet gateway runtime blocker remained after exact-SHA CI-green source closure: %#v", phase.Blockers)
	}
	if containsString(phase.Blockers, "DELIVERY_DEPLOYMENT_EVIDENCE_INGESTION_PENDING") {
		t.Fatalf("delivery deployment evidence ingestion blocker remained after durable projection closure: %#v", phase.Blockers)
	}
	c9 := byID["C9-pre-certification-feature-freeze-exact-bundle"]
	if containsString(c9.DependsOn, phase.ID) {
		t.Fatalf("optional expansion phase must not gate Core feature freeze: %#v", c9.DependsOn)
	}
}
