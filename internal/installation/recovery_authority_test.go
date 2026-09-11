package installation

import "testing"

func TestRecoveryConsoleModelMatchesInstallerRecoveryBoundary(t *testing.T) {
	model := RecoveryConsoleModel()
	if model.Authority != RecoveryConsoleAuthority || !model.SeparateBootstrapPlane {
		t.Fatalf("unexpected model: %+v", model)
	}
	want := map[string]bool{"/api/v1/resume": false, "/api/v1/reset/start": false, "/api/v1/reset/resume": false, "/api/v1/diagnostics/report": false, "/api/v1/disaster-recovery/backup": false, "/api/v1/disaster-recovery/restore": false, "/api/v1/lifecycle/upgrade-recovery": false}
	for _, action := range model.Actions {
		if _, ok := want[action.Path]; ok {
			want[action.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Fatalf("missing recovery action %s", path)
		}
	}
	if model.CredentialBoundary == "" {
		t.Fatal("credential boundary must be explicit")
	}
}
