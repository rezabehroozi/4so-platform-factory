package targetmodel

import (
	"strings"
	"testing"
)

func TestCompetitiveProofExpansionAuthority(t *testing.T) {
	model := ArchitectureModel()
	proof := model.CompetitiveProof
	if proof.Authority != CompetitiveProofAuthority || proof.BaselineProgramAuthority != ProgramAuthorityMethod || !proof.CoreReleasePathUnchanged {
		t.Fatalf("competitive proof authority drift: %#v", proof)
	}
	if len(proof.RequiredCoreClosurePhases) != 2 || proof.RequiredCoreClosurePhases[0] != "C7W-mcp-user-admin-write-parity" || proof.RequiredCoreClosurePhases[1] != "C9-pre-certification-feature-freeze-exact-bundle" {
		t.Fatalf("core proof closure references drift: %#v", proof.RequiredCoreClosurePhases)
	}
	if len(proof.Phases) != 8 || proof.SourceExpansionPhases != 7 || proof.SourceClosedExpansionPhases != 0 || proof.SourceOpenExpansionPhases != 7 {
		t.Fatalf("competitive phase truth drift: %#v", proof)
	}

	byID := map[string]CompetitiveProofPhase{}
	for i, phase := range proof.Phases {
		if phase.Order != i+1 {
			t.Fatalf("competitive phase order drift: %#v", proof.Phases)
		}
		byID[phase.ID] = phase
	}
	for _, id := range []string{
		"CP1-virtual-cluster-lifecycle-automation",
		"CP2-managed-resource-instance-graph",
		"CP3-application-promotion-verification",
		"CP4-fleet-signal-correlation-durable-remediation",
		"CP5-bounded-resource-explorer-persona-ux",
		"CP6-release-attestation-set",
		"CP7-accelerator-lifecycle-foundation",
	} {
		phase, ok := byID[id]
		if !ok || phase.DeliveryTier != CompetitiveTierExpansion || phase.SourceStatus != CompetitiveStatusSourceOpen || phase.CoreFreezeBlocker || len(phase.Blockers) == 0 || len(phase.ExitCriteria) < 4 {
			t.Fatalf("competitive expansion phase drift %s: %#v", id, phase)
		}
	}
	cert := byID["CP8-fleet-scale-chaos-certification"]
	if cert.DeliveryTier != CompetitiveTierCertification || cert.SourceStatus != CompetitiveStatusCertificationPending || cert.CoreFreezeBlocker {
		t.Fatalf("scale certification phase drift: %#v", cert)
	}
	for _, marker := range []string{"100/500/1000-cluster", "10000-node", "100 concurrent", "reconnect storm", "1,000,000 durable operation/evidence"} {
		if !sliceContainsFragment(cert.ExitCriteria, marker) {
			t.Fatalf("scale proof %q missing: %#v", marker, cert.ExitCriteria)
		}
	}

	for _, benchmark := range []string{"Spectro Cloud Palette", "Rafay Platform", "SUSE Rancher Prime", "Red Hat Advanced Cluster Management", "Humanitec", "Akuity / Kargo", "Talos Omni", "vCluster Platform", "OpenChoreo"} {
		if !sliceContainsFragment(proof.Benchmarks, benchmark) {
			t.Fatalf("benchmark %q missing: %#v", benchmark, proof.Benchmarks)
		}
	}
	if got := strings.Join(proof.CanonicalMutationGrammar, " -> "); got != "Plan -> Impact -> Approval -> Durable Operation -> Fence -> Execute -> Observe -> Evidence -> Recovery" {
		t.Fatalf("canonical mutation grammar drift: %s", got)
	}
	for _, guard := range []string{"AI/MCP", "Resource Explorer", "Argo", "model serving", "source-only"} {
		if !sliceContainsFragment(proof.Guardrails, guard) {
			t.Fatalf("guardrail %q missing: %#v", guard, proof.Guardrails)
		}
	}
	if !sliceContainsFragment(proof.PhysicalProofTargets, "connected Managed OKD") || !sliceContainsFragment(proof.PhysicalProofTargets, "disconnected Managed OKD") || !sliceContainsFragment(proof.PhysicalProofTargets, "Exact-SHA") {
		t.Fatalf("physical competitive proof targets incomplete: %#v", proof.PhysicalProofTargets)
	}
}

func sliceContainsFragment(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}
