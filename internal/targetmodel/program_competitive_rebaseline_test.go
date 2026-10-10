package targetmodel

import (
	"strings"
	"testing"
)

func TestCompetitiveProofRoadmapRebaselineV76(t *testing.T) {
	roadmap := ProgramRoadmapModel()
	if roadmap.Authority != "PROGRAM_PHASE_MODEL_V76" {
		t.Fatalf("authority=%q", roadmap.Authority)
	}
	if len(roadmap.Phases) != 46 {
		t.Fatalf("phase count=%d", len(roadmap.Phases))
	}
	progress := roadmap.Progress
	if progress.CoreRequiredPhases != 25 || progress.CoreSourceClosedPhases != 25 || progress.CorePhaseReady != 23 || progress.CorePhaseBlocked != 2 {
		t.Fatalf("competitive rebaseline must not dilute Core truth: %#v", progress)
	}
	if progress.PrePhysicalSoftwarePhases != 43 || progress.PrePhysicalSoftwareClosedPhases != 36 || progress.PrePhysicalSoftwareOpenPhases != 7 || progress.PrePhysicalSoftwareClosurePercent != 83 {
		t.Fatalf("competitive pre-physical work must reopen honestly: %#v", progress)
	}

	byID := map[string]ProgramPhase{}
	for _, phase := range roadmap.Phases {
		byID[phase.ID] = phase
	}
	for _, id := range []string{
		"J9-virtual-cluster-lifecycle-automation",
		"J10-managed-resource-instance-graph",
		"J11-application-promotion-verification",
		"J12-fleet-signal-correlation-durable-remediation",
		"J13-bounded-operational-resource-explorer",
		"J14-release-attestation-competitive-proof",
	} {
		phase, ok := byID[id]
		if !ok {
			t.Fatalf("competitive phase missing %s", id)
		}
		if phase.RequiredForFeatureFreeze || phase.DeliveryTier != ProgramTierExpansion || phase.SourceStatus != ProgramSourceStatusOpen || phase.ClosureStatus != ProgramClosureStatusBlocked || len(phase.Blockers) == 0 {
			t.Fatalf("competitive phase truth drift %s: %#v", id, phase)
		}
	}
	accelerator := byID["L-optional-accelerator-ai-infrastructure"]
	if accelerator.RequiredForFeatureFreeze || accelerator.DeliveryTier != ProgramTierExpansion || accelerator.SourceStatus != ProgramSourceStatusOpen || accelerator.ClosureStatus != ProgramClosureStatusBlocked || !strings.Contains(accelerator.Objective, "MIG/vGPU") || !strings.Contains(accelerator.Objective, "GPUClass") {
		t.Fatalf("accelerator foundation must be explicit expansion work: %#v", accelerator)
	}

	for _, benchmark := range []string{"Red Hat Advanced Cluster Management", "Humanitec", "Akuity / Kargo", "Talos Omni", "vCluster Platform"} {
		found := false
		for _, actual := range roadmap.PrimaryBenchmarks {
			if strings.Contains(actual, benchmark) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("competitive benchmark missing %q: %#v", benchmark, roadmap.PrimaryBenchmarks)
		}
	}

	var w3, w4 ProgramExecutionWave
	for _, wave := range roadmap.ExecutionWaves {
		switch wave.ID {
		case "W3-expansion-mega-wave":
			w3 = wave
		case "W4-convergence":
			w4 = wave
		}
	}
	for _, id := range []string{
		"J9-virtual-cluster-lifecycle-automation",
		"J10-managed-resource-instance-graph",
		"J11-application-promotion-verification",
		"J12-fleet-signal-correlation-durable-remediation",
		"J13-bounded-operational-resource-explorer",
		"J14-release-attestation-competitive-proof",
		"L-optional-accelerator-ai-infrastructure",
	} {
		if !containsString(w3.PhaseIDs, id) || !containsString(w4.PhaseIDs, id) {
			t.Fatalf("competitive phase %s must participate in expansion and convergence waves: W3=%#v W4=%#v", id, w3, w4)
		}
	}

	m := byID["M-full-product-certification-chaos-soak-ux-ai-evals"]
	for _, criterion := range []string{
		"100/500/1000-cluster",
		"10000-node",
		"100 concurrent",
		"reconnect storm",
		"1,000,000 durable operation/evidence",
	} {
		found := false
		for _, actual := range m.ExitCriteria {
			if strings.Contains(actual, criterion) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("scale certification criterion missing %q: %#v", criterion, m.ExitCriteria)
		}
	}
}
