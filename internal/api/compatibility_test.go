package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/domain"
)

func TestCompatibilityEvaluateUsesProviderDimension(t *testing.T) {
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("test", components, slog.Default())
	raw, err := os.ReadFile("../../blueprints/enterprise-private-cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	var blueprint domain.Blueprint
	if err = json.Unmarshal(raw, &blueprint); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"blueprint": blueprint, "target": map[string]any{"kubernetesVersion": "v1.35.2", "architecture": "amd64", "distribution": "rke2", "provider": "imported"}})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/compatibility/evaluate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body, _ = json.Marshal(map[string]any{"blueprint": blueprint, "target": map[string]any{"kubernetesVersion": "v1.36.0", "architecture": "amd64", "distribution": "rke2", "provider": "imported"}})
	r = httptest.NewRequest(http.MethodPost, "/api/v1/compatibility/evaluate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported Kubernetes 1.36 accepted: %d %s", w.Code, w.Body.String())
	}

	body, _ = json.Marshal(map[string]any{"blueprint": blueprint, "target": map[string]any{"kubernetesVersion": "v1.35.2", "architecture": "amd64", "distribution": "rke2", "provider": "unsupported-provider"}})
	r = httptest.NewRequest(http.MethodPost, "/api/v1/compatibility/evaluate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("provider mismatch accepted: %d %s", w.Code, w.Body.String())
	}
}
