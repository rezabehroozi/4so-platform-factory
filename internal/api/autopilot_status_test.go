package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutopilotStatusIsAdminOnlyAndSanitized(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLATFORM_FACTORY_AUTOPILOT_STATE_DIR", dir)
	report := `{"authority":"AUTOPILOT_CAMPAIGN_REPORT_V1","status":"REPAIRING","phase":"deterministic","stageCount":21,"nextIndex":4,"currentStage":"smoke-ui-live","currentSpecialist":"operator-console","repairCount":2,"resumeEligible":true,"updatedAt":"2026-09-03T00:00:00Z","stageResults":[{"name":"go-tests","specialist":"backend","status":"PASS","returncode":0,"elapsedSeconds":1.2,"fingerprint":"abc","output_tail":"SECRET"}],"lastFailure":{"stage":"smoke-ui-live","specialist":"operator-console","status":"FAIL","fingerprint":"def","reason":"console regression","raw":"SECRET"}}`
	if err := os.WriteFile(filepath.Join(dir, "codex-autopilot-report.json"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "codex-autopilot-run.json"), []byte(`{"activeProcess":{"pid":991,"label":"codex-triage:smoke-ui-live"},"workspace":"/secret/path"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := New("test", nil, slog.Default()).Handler()

	viewer := httptest.NewRequest(http.MethodGet, "/api/v1/autopilot/status", nil)
	viewer.Header.Set("X-Actor-Role", "platform-viewer")
	vw := httptest.NewRecorder()
	h.ServeHTTP(vw, viewer)
	if vw.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d body=%s", vw.Code, vw.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/autopilot/status", nil)
	req.Header.Set("X-Actor-Role", "platform-admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "SECRET") || strings.Contains(w.Body.String(), "/secret/path") || strings.Contains(w.Body.String(), "991") {
		t.Fatalf("sensitive report detail leaked: %s", w.Body.String())
	}
	var got autopilotConsoleStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Available || got.Authority != autopilotConsoleAuthority || got.CurrentSpecialist != "operator-console" || got.ActiveProcess != "codex-triage:smoke-ui-live" {
		t.Fatalf("unexpected status: %+v", got)
	}
	if got.LastFailure == nil || got.LastFailure.Reason != "console regression" {
		t.Fatalf("missing failure summary: %+v", got.LastFailure)
	}
}

func TestAutopilotStatusRejectsSymlinkReport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLATFORM_FACTORY_AUTOPILOT_STATE_DIR", dir)
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(`{"authority":"AUTOPILOT_CAMPAIGN_REPORT_V1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "codex-autopilot-report.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/autopilot/status", nil)
	req.Header.Set("X-Actor-Role", "platform-admin")
	w := httptest.NewRecorder()
	New("test", nil, slog.Default()).Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
