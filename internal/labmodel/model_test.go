package labmodel

import "testing"

func TestModelIsCanonicalAndLargePhaseMatrix(t *testing.T) {
	guide := Model()
	if guide.Authority != "LAB_CERTIFICATION_MATRIX_V1" || guide.SchemaVersion != 2 {
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
	if guide.Runner.Command != "python3 scripts/lab_runner.py" || len(guide.Runner.CurrentFullyAutomatedRows) != 1 || len(guide.Runner.CurrentPartiallyAutomatedRows) != 2 {
		t.Fatalf("runner coverage is not explicit: %#v", guide.Runner)
	}
	for _, row := range guide.Matrix {
		if row.AutomationStatus == "" || row.AutomationDetail == "" {
			t.Fatalf("matrix row lacks automation truth: %#v", row)
		}
	}
	if guide.MCP.Protocol != "2026-07-28" || guide.MCP.Transport != "streamable-http" || guide.MCP.Path != "/mcp" || guide.MCP.Permission != "mcp.read" || guide.MCP.Authorization == "" || len(guide.MCP.Tools) < 6 || len(guide.MCP.MutatingTools) != 0 {
		t.Fatalf("unexpected MCP contract: %#v", guide.MCP)
	}
}
