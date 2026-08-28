package targetmodel

import "testing"

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
	if SupportedDistribution(DistributionOKD) {
		t.Fatal("OKD must remain recognized but not admitted until its target-adapter phase")
	}
	if SupportedDistribution(DistributionOpenShift) {
		t.Fatal("Red Hat OpenShift must not be silently admitted through the OKD target path")
	}
}

func TestProgramRoadmapUsesLargeLabFirstPhasesAndKeepsPhysicalCertificationSeparate(t *testing.T) {
	roadmap := ArchitectureModel().ProgramRoadmap
	if roadmap.Authority != ProgramAuthorityMethod || roadmap.CurrentPhase != "C-ai-native-operator-experience-lab-mcp-foundation" || roadmap.GoalReady {
		t.Fatalf("unexpected roadmap authority: %#v", roadmap)
	}
	if len(roadmap.Phases) != 8 {
		t.Fatalf("phase count=%d", len(roadmap.Phases))
	}
	if len(roadmap.Tracks) != 7 || len(roadmap.GlobalGuardrails) < 6 {
		t.Fatalf("program cross-cutting authority incomplete: tracks=%d guardrails=%d", len(roadmap.Tracks), len(roadmap.GlobalGuardrails))
	}
	for _, trackID := range []string{"operator-experience", "ai-native", "mcp-agent-surface", "lab-certification", "security-evidence", "supply-chain", "developer-agent-experience"} {
		found := false
		for _, track := range roadmap.Tracks {
			if track.ID == trackID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing cross-cutting track %q", trackID)
		}
	}
	for i, phase := range roadmap.Phases {
		if phase.Order != i+1 {
			t.Fatalf("phase order drift at %s: %d", phase.ID, phase.Order)
		}
	}
	current := roadmap.Phases[2]
	if current.ID != "C-ai-native-operator-experience-lab-mcp-foundation" || current.Status != ProgramStatusBlocked {
		t.Fatalf("lab foundation is not current blocked phase: %#v", current)
	}
	for _, evidence := range []string{"LAB_CERTIFICATION_MATRIX_V1", "GET /api/v1/lab/guide", "POST /mcp:2026-07-28:mcp.read:project-scoped-read-only", "scripts/lab_runner.py"} {
		if !containsString(current.Evidence, evidence) {
			t.Fatalf("missing lab evidence %q: %#v", evidence, current)
		}
	}
	if roadmap.Phases[3].ID != "D-okd-import-identity-security-certification" || roadmap.Phases[3].DependsOn[0] != current.ID {
		t.Fatalf("OKD physical import certification not sequenced after lab authority: %#v", roadmap.Phases[3])
	}
	if roadmap.Phases[4].ID != "E-capability-catalog-blueprint-ai-explainability" || roadmap.Phases[5].ID != "F-day2-managed-compact3-workflow-convergence" || roadmap.Phases[6].ID != "G-disconnected-upgrade-recovery-local-ai" {
		t.Fatalf("large-phase consolidation drifted: %#v", roadmap.Phases)
	}
	final := roadmap.Phases[7]
	if final.ID != "H-full-product-certification-chaos-soak-ux-ai-evals" || final.Status != ProgramStatusNotEvaluated || !containsString(final.Blockers, "PHYSICAL_RUNTIME_NOT_EVALUATED") {
		t.Fatalf("physical certification must remain independent and not evaluated: %#v", final)
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

func TestOKDCapabilityResolverSuppressesDuplicateDefaultsButDoesNotAdmitOKD(t *testing.T) {
	resolution := ResolveTargetComponents("OKD", []string{"cilium", "capsule", "victoria-metrics", "kyverno", "metallb", "snapshot-controller", "tetragon", "argocd"}, nil)
	if resolution.Authority != CapabilityResolverAuthority || resolution.Admitted || resolution.Status != "PREVIEW_ONLY" {
		t.Fatalf("OKD preview incorrectly admitted: %#v", resolution)
	}
	if len(resolution.Blockers) != 1 || resolution.Blockers[0] != "OKD_TARGET_NOT_ADMITTED" {
		t.Fatalf("missing OKD admission blocker: %#v", resolution.Blockers)
	}
	actions := map[string]string{}
	for _, decision := range resolution.Decisions {
		actions[decision.Component] = decision.Action
	}
	for _, component := range []string{"cilium", "capsule", "victoria-metrics"} {
		if actions[component] != ResolutionActionSuppress {
			t.Fatalf("%s action=%q", component, actions[component])
		}
	}
	for _, component := range []string{"kyverno", "metallb", "snapshot-controller", "tetragon"} {
		if actions[component] != ResolutionActionConditional {
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
