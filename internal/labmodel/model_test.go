package labmodel

import (
	"fmt"
	"testing"
)

func TestModelIsCanonicalAndLargePhaseMatrix(t *testing.T) {
	guide := Model()
	if guide.Authority != "LAB_CERTIFICATION_MATRIX_V2" || guide.SchemaVersion != 3 {
		t.Fatalf("unexpected guide authority: %#v", guide)
	}
	if len(guide.ServerTiers) != 4 || len(guide.Matrix) != 14 {
		t.Fatalf("unexpected guide dimensions tiers=%d matrix=%d", len(guide.ServerTiers), len(guide.Matrix))
	}
	if guide.AIPolicy.DefaultMode != "failure-only" || guide.AIPolicy.DefaultFailurePacketBytes > guide.AIPolicy.MaxFailurePacketBytes || guide.AIPolicy.MaxFailurePacketBytes > 16384 || guide.AIPolicy.DefaultOutputTokens > guide.AIPolicy.MaxOutputTokens || guide.AIPolicy.MaxOutputTokens > 1200 || guide.AIPolicy.MaxDiagnosisCallsPerFailureRun != 1 {
		t.Fatalf("AI policy is not bounded: %#v", guide.AIPolicy)
	}
	if guide.AIPolicy.RuntimeAuthority != "UNIFIED_AI_RUNTIME_V1" || guide.AIPolicy.EgressPolicy == "" || guide.AIPolicy.DurableAudit == "" || guide.AIPolicy.ExecutionAuthority == "" {
		t.Fatalf("AI-native authority contract is incomplete: %#v", guide.AIPolicy)
	}
	if guide.Runner.Command != "python3 scripts/lab_runner.py" || len(guide.Runner.CurrentFullyAutomatedRows) != 4 || guide.Runner.CurrentFullyAutomatedRows[0] != "M00" || guide.Runner.CurrentFullyAutomatedRows[1] != "M01" || guide.Runner.CurrentFullyAutomatedRows[2] != "M02" || guide.Runner.CurrentFullyAutomatedRows[3] != "M03" || len(guide.Runner.CurrentPartiallyAutomatedRows) != 0 {
		t.Fatalf("runner coverage is not explicit: %#v", guide.Runner)
	}
	expectedOwner := map[string]string{
		"M00": "C5-installer-production-lifecycle-closure", "M01": "C5-installer-production-lifecycle-closure", "M02": "C5-installer-production-lifecycle-closure", "M03": "C5-installer-production-lifecycle-closure",
		"M04": "F-okd-import-capability-certification", "M05": "F-okd-import-capability-certification", "M06": "F-okd-import-capability-certification",
		"M07": "G3-target-node-maintenance-lifecycle", "M08": "H1-baremetal-connected-managed-okd",
		"M09": "I1-disconnected-okd-core", "M10": "I1-disconnected-okd-core",
		"M11": "M-full-product-certification-chaos-soak-ux-ai-evals", "M12": "M-full-product-certification-chaos-soak-ux-ai-evals", "M13": "M-full-product-certification-chaos-soak-ux-ai-evals",
	}
	expectedExecution := map[string]string{}
	for i := 0; i <= 10; i++ {
		expectedExecution[fmt.Sprintf("M%02d", i)] = "D-exact-artifact-lab-ai-certification"
	}
	for i := 11; i <= 13; i++ {
		expectedExecution[fmt.Sprintf("M%02d", i)] = "M-full-product-certification-chaos-soak-ux-ai-evals"
	}
	m03Found := false
	for _, row := range guide.Matrix {
		if want := expectedOwner[row.ID]; row.FeatureOwnerPhase != want {
			t.Fatalf("matrix row %s feature owner=%q want=%q", row.ID, row.FeatureOwnerPhase, want)
		}
		if want := expectedExecution[row.ID]; row.ExecutionPhase != want || row.Phase != want {
			t.Fatalf("matrix row %s execution=%q phase=%q want=%q", row.ID, row.ExecutionPhase, row.Phase, want)
		}
		if row.AutomationStatus == "" || row.AutomationDetail == "" {
			t.Fatalf("matrix row lacks automation truth: %#v", row)
		}
		if row.ID == "M03" {
			m03Found = true
			if row.ServerTier != "production-ha" || row.AutomationStatus != "IMPLEMENTED" {
				t.Fatalf("M03 must be bound to the production HA runtime: %#v", row)
			}
			hasPostgresRestart := false
			for _, action := range row.Actions {
				if action == "PostgreSQL primary restart/failover" {
					hasPostgresRestart = true
				}
			}
			if !hasPostgresRestart {
				t.Fatalf("M03 matrix must describe the PostgreSQL restart it actually certifies: %#v", row.Actions)
			}
		}
	}
	if !m03Found {
		t.Fatal("M03 matrix row is missing")
	}
	if guide.MCP.Protocol != "2026-07-28" || guide.MCP.Transport != "streamable-http" || guide.MCP.Path != "/mcp" || guide.MCP.Permission != "mcp.read" || guide.MCP.OperationPermission != "mcp.operate" || guide.MCP.DelegatedOperationAuthority != "MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1" || guide.MCP.Authorization == "" || guide.MCP.ConformanceAuthority != "MCP_EXTERNAL_CLIENT_INTEROPERABILITY_V1" || guide.MCP.ExternalClient == "" || len(guide.MCP.Tools) < 10 || len(guide.MCP.MutatingTools) != 27 {
		t.Fatalf("unexpected MCP contract: %#v", guide.MCP)
	}
}
