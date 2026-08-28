package releasereadiness

import (
	"testing"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/domain"
)

func admissionPolicy(admission *catalog.UpstreamAdmission) {
	admission.APIVersion = "platform.4so.io/v1alpha1"
	admission.Kind = "CatalogUpstreamAdmission"
	admission.Metadata.Name = "test"
	admission.Spec.Policy = map[string]any{
		"sourceAuthority":            "official-upstream-only",
		"versionSelection":           "exact-semver-no-prerelease",
		"sourceResolution":           "separate-immutable-acquisition-required",
		"runtimeCertification":       "separate-runtime-evidence-required",
		"autoWidenCatalogConstraint": false,
		"allowLatestResolution":      false,
	}
}

func unresolvedHelmComponent(name, release, versionPolicy, chart string) catalog.Component {
	var component catalog.Component
	component.Metadata.Name = name
	component.Spec.Release = release
	component.Spec.VersionPolicy = versionPolicy
	component.Spec.Delivery.Type = "helm"
	component.Spec.Delivery.Chart = chart
	component.Spec.Source.Type = "helm-chart"
	component.Spec.Source.Resolved = false
	return component
}

func strptr(value string) *string { return &value }

func TestBuildSeparatesProductDeploymentAndPhysicalAuthority(t *testing.T) {
	plan := domain.DeploymentPlan{
		ID: "plan-test", Blueprint: "test", BlueprintVersion: "1.0.0",
		Status: "planning-only", Executable: false,
		Steps: []domain.PlanStep{
			{Component: "external", ReleaseConstraint: "1.2.3", SourceResolved: false},
			{Component: "resolved", ReleaseConstraint: "1.0.0", SourceResolved: true, SourceLockDigest: "sha256:lock", CertificationStatus: "target-runtime-certified", CertificationEvidence: "sha256:evidence"},
		},
		Blockers: []domain.Finding{
			{Code: "COMPONENT_VERSION_NOT_PINNED"},
			{Code: "COMPONENT_SOURCE_UNRESOLVED"},
			{Code: "SOURCE_LOCK_MISSING"},
			{Code: "COMPONENT_NOT_RUNTIME_CERTIFIED"},
			{Code: "CERTIFICATION_EVIDENCE_MISSING"},
			{Code: "GIT_REVISION_NOT_IMMUTABLE"},
			{Code: "FUTURE_FAIL_CLOSED_BLOCKER"},
		},
	}
	var admission catalog.UpstreamAdmission
	admissionPolicy(&admission)
	admission.Spec.Components = []catalog.UpstreamAdmissionComponent{{
		Component: "external", CatalogConstraint: "1.2.x", Chart: "external", Source: "https://example.test/charts",
		Rationale: "test authority", Status: "ready-for-acquisition", SelectedVersion: strptr("1.2.3"), UpstreamVersion: strptr("v1.2.3"),
	}}
	components := map[string]catalog.Component{
		"external": unresolvedHelmComponent("external", "1.2.3", "exact-upstream-admitted-pending-source-acquisition", "external"),
	}

	report, err := Build(plan, admission, components)
	if err != nil {
		t.Fatal(err)
	}
	if report.ProductReleaseReady || report.DeploymentExecutable {
		t.Fatalf("blocked plan became ready: %+v", report)
	}
	if report.ProductReleaseBlockers != 6 || report.DeploymentContextBlockers != 1 || report.UnclassifiedProductBlockers != 1 {
		t.Fatalf("unexpected blocker split: %+v", report)
	}
	if report.PhysicalRuntimeStatus != StatusNotEvaluated {
		t.Fatalf("physical runtime status was manufactured: %q", report.PhysicalRuntimeStatus)
	}
	if report.ProductBlockerCodes["FUTURE_FAIL_CLOSED_BLOCKER"] != 1 {
		t.Fatalf("unknown blocker did not fail closed as a product blocker: %+v", report.ProductBlockerCodes)
	}
	if report.DeploymentContextBlockerCodes["GIT_REVISION_NOT_IMMUTABLE"] != 1 {
		t.Fatalf("deployment-context blocker classification drifted: %+v", report.DeploymentContextBlockerCodes)
	}
}

func TestBuildFailsClosedWhenUnresolvedComponentHasNoAdmissionAuthority(t *testing.T) {
	plan := domain.DeploymentPlan{
		ID: "plan-test", Blueprint: "test", BlueprintVersion: "1.0.0",
		Steps: []domain.PlanStep{{Component: "missing", ReleaseConstraint: "1.0.x", SourceResolved: false}},
	}
	var admission catalog.UpstreamAdmission
	admissionPolicy(&admission)
	components := map[string]catalog.Component{
		"missing": unresolvedHelmComponent("missing", "1.0.x", "resolve-verify-and-pin-before-execution", "missing"),
	}
	if _, err := Build(plan, admission, components); err == nil {
		t.Fatal("missing upstream admission authority was accepted")
	}
}

func TestAdmissionReviewIsSeparateFromImmutableAcquisition(t *testing.T) {
	plan := domain.DeploymentPlan{
		ID: "plan-test", Blueprint: "test", BlueprintVersion: "1.0.0",
		Steps:    []domain.PlanStep{{Component: "external", ReleaseConstraint: "1.2.3", SourceResolved: false}},
		Blockers: []domain.Finding{{Code: "COMPONENT_SOURCE_UNRESOLVED"}, {Code: "SOURCE_LOCK_MISSING"}},
	}
	var admission catalog.UpstreamAdmission
	admissionPolicy(&admission)
	admission.Spec.Components = []catalog.UpstreamAdmissionComponent{{
		Component: "external", CatalogConstraint: "1.2.3", Chart: "external", Source: "https://example.test/charts",
		Rationale: "test authority", Status: "dependency-review-required", SelectedVersion: strptr("1.2.3"), UpstreamVersion: strptr("1.2.3"),
	}}
	components := map[string]catalog.Component{
		"external": unresolvedHelmComponent("external", "1.2.3", "resolve-verify-and-pin-before-execution", "external"),
	}
	report, err := Build(plan, admission, components)
	if err != nil {
		t.Fatal(err)
	}
	if report.UpstreamAdmission.ReviewRequired != 1 || report.UpstreamAdmission.Ready != 0 {
		t.Fatalf("admission metrics are wrong: %+v", report.UpstreamAdmission)
	}
	if report.Phases[0].ID != "upstream-admission" || report.Phases[0].Status != StatusBlocked {
		t.Fatalf("review-required admission did not block its own phase: %+v", report.Phases[0])
	}
	if report.Phases[1].ID != "immutable-source-acquisition" || report.Phases[1].BlockerCount != 2 {
		t.Fatalf("source acquisition blockers were not kept separate: %+v", report.Phases[1])
	}
}

func TestBuildRejectsAdmissionConstraintDriftInsteadOfReportingComplete(t *testing.T) {
	plan := domain.DeploymentPlan{
		ID: "plan-test", Blueprint: "test", BlueprintVersion: "1.0.0",
		Steps: []domain.PlanStep{{Component: "external", ReleaseConstraint: "2.0.x", SourceResolved: false}},
	}
	var admission catalog.UpstreamAdmission
	admissionPolicy(&admission)
	admission.Spec.Components = []catalog.UpstreamAdmissionComponent{{
		Component: "external", CatalogConstraint: "1.2.x", Chart: "external", Source: "https://example.test/charts",
		Rationale: "stale authority", Status: "dependency-review-required",
	}}
	components := map[string]catalog.Component{
		"external": unresolvedHelmComponent("external", "2.0.x", "resolve-verify-and-pin-before-execution", "external"),
	}
	if _, err := Build(plan, admission, components); err == nil {
		t.Fatal("stale upstream admission authority was accepted")
	}
}

func TestBuildIncludesCanonicalProgramRoadmapWithoutConflatingPhysicalRuntime(t *testing.T) {
	plan := domain.DeploymentPlan{ID: "plan-roadmap", Blueprint: "test", BlueprintVersion: "1.0.0"}
	var admission catalog.UpstreamAdmission
	admissionPolicy(&admission)
	report, err := Build(plan, admission, map[string]catalog.Component{})
	if err != nil {
		t.Fatal(err)
	}
	if report.ProgramRoadmap.Authority != "PROGRAM_PHASE_MODEL_V3" || report.ProgramRoadmap.CurrentPhase != "C-ai-native-operator-experience-lab-mcp-foundation" {
		t.Fatalf("unexpected program roadmap: %#v", report.ProgramRoadmap)
	}
	if report.ProgramRoadmap.GoalReady {
		t.Fatal("program goal was reported ready while OKD target phases remain blocked")
	}
	if report.PhysicalRuntimeStatus != StatusNotEvaluated || report.ProgramRoadmap.Phases[len(report.ProgramRoadmap.Phases)-1].Status != "not-evaluated" {
		t.Fatalf("physical runtime was inferred from source readiness: report=%q roadmap=%#v", report.PhysicalRuntimeStatus, report.ProgramRoadmap.Phases[len(report.ProgramRoadmap.Phases)-1])
	}
}
