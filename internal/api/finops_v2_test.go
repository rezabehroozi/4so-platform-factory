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

func TestFinOpsBudgetAndInsightsAPIAreScopedAndFailClosed(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "finops-v2", DisplayName: "FinOps v2"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	h := New("test", nil, nil, store).Handler()
	admin := map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin"}
	viewer := map[string]string{"X-Actor-ID": "viewer", "X-Actor-Role": "platform-viewer"}
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	body := fmt.Sprintf(`{"organizationId":%q,"projectId":%q,"name":"monthly","version":"1","currency":"EUR","effectiveFrom":%q,"limitMicros":250000000,"warningBasisPoints":8000,"criticalBasisPoints":10000}`, org.ID, project.ID, start.Format(time.RFC3339))
	w := apiRequest(t, h, http.MethodPost, "/api/v1/finops/budget-policies", body, viewer)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer budget write status=%d body=%s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/finops/budget-policies", body, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("budget create status=%d body=%s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodGet, fmt.Sprintf("/api/v1/finops/budget-policies?organizationId=%s&projectId=%s", org.ID, project.ID), "", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("budget list status=%d body=%s", w.Code, w.Body.String())
	}
	var policies []controlplane.FinOpsBudgetPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &policies); err != nil || len(policies) != 1 {
		t.Fatalf("budget list decode=%v values=%#v", err, policies)
	}

	insightURL := fmt.Sprintf("/api/v1/finops/insights?organizationId=%s&projectId=%s&currency=EUR&windowStart=%s&observedThrough=%s&forecastEnd=%s", org.ID, project.ID, start.Format(time.RFC3339), start.Add(48*time.Hour).Format(time.RFC3339), start.Add(30*24*time.Hour).Format(time.RFC3339))
	w = apiRequest(t, h, http.MethodGet, insightURL, "", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("insight status=%d body=%s", w.Code, w.Body.String())
	}
	var insight controlplane.FinOpsInsights
	if err := json.Unmarshal(w.Body.Bytes(), &insight); err != nil {
		t.Fatal(err)
	}
	if insight.Forecast.Status != controlplane.FinOpsInsightUnknown || insight.Forecast.ProjectedCostMicros != nil {
		t.Fatalf("empty telemetry must stay unknown: %#v", insight.Forecast)
	}
	if len(insight.Budgets) != 1 || insight.Budgets[0].Status != controlplane.FinOpsInsightUnknown {
		t.Fatalf("budget must preserve unknown forecast: %#v", insight.Budgets)
	}
}
