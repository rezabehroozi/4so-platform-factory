package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestFinOpsAPIKeepsMissingTelemetryDistinctAndScopesFinancialWrites(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "finops-api", DisplayName: "FinOps API"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	h := New("test", nil, nil, store).Handler()
	admin := map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin"}
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	card := fmt.Sprintf(`{"organizationId":%q,"name":"standard","version":"1","currency":"EUR","effectiveFrom":%q,"rates":{"CPU_CORE_HOUR":1000000,"MEMORY_GIB_HOUR":100000,"STORAGE_GIB_HOUR":10000,"ACCELERATOR_HOUR":5000000}}`, org.ID, start.Format(time.RFC3339))
	w := apiRequest(t, h, http.MethodPost, "/api/v1/finops/rate-cards", card, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("rate card status=%d body=%s", w.Code, w.Body.String())
	}
	metrics := `"CPU_CORE_HOUR":{"available":true,"quantityMicros":1000000},"MEMORY_GIB_HOUR":{"available":false,"quantityMicros":0},"STORAGE_GIB_HOUR":{"available":true,"quantityMicros":0},"ACCELERATOR_HOUR":{"available":true,"quantityMicros":0}`
	usage := fmt.Sprintf(`{"organizationId":%q,"projectId":%q,"source":"meter","sourceEventId":"evt-1","windowStart":%q,"windowEnd":%q,"metrics":{%s}}`, org.ID, project.ID, start.Format(time.RFC3339), start.Add(time.Hour).Format(time.RFC3339), metrics)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/finops/usage-measurements", usage, map[string]string{"X-Actor-ID": "viewer", "X-Actor-Role": "platform-viewer"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("untrusted telemetry write status=%d", w.Code)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/finops/usage-measurements", usage, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("usage status=%d body=%s", w.Code, w.Body.String())
	}
	showbackURL := fmt.Sprintf("/api/v1/finops/showback?organizationId=%s&projectId=%s&currency=EUR&groupBy=PROJECT&from=%s&to=%s", org.ID, project.ID, start.Format(time.RFC3339), start.Add(time.Hour).Format(time.RFC3339))
	w = apiRequest(t, h, http.MethodGet, showbackURL, "", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("showback status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["complete"] != false {
		t.Fatalf("missing telemetry was not preserved: %s", w.Body.String())
	}
	if _, ok := got["totalCostMicros"]; ok {
		t.Fatalf("incomplete showback exposed total cost: %s", w.Body.String())
	}
	if got["knownCostMicros"].(float64) != 1_000_000 {
		t.Fatalf("known cost mismatch: %s", w.Body.String())
	}
	exportURL := fmt.Sprintf("/api/v1/finops/chargeback-export?organizationId=%s&projectId=%s&currency=EUR&groupBy=PROJECT&from=%s&to=%s", org.ID, project.ID, start.Format(time.RFC3339), start.Add(time.Hour).Format(time.RFC3339))
	w = apiRequest(t, h, http.MethodGet, exportURL, "", admin)
	if w.Code != http.StatusOK || w.Header().Get("X-FinOps-Export-Digest") == "" {
		t.Fatalf("export status=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}
	if gotType := w.Header().Get("Content-Type"); gotType != "text/csv; charset=utf-8" {
		t.Fatalf("content-type=%q", gotType)
	}
}
