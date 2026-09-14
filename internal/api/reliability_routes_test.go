package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

func TestReliabilityRoutesAreRegisteredOnProductHandler(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-routes", DisplayName: "Reliability Routes"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	incident, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: project.ID, Severity: "CRITICAL"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	srv := New("test", nil, nil, store)

	tests := []struct{ method, target, body string }{
		{http.MethodGet, "/api/v1/reliability/service-health", ""},
		{http.MethodGet, "/api/v1/reliability/incidents", ""},
		{http.MethodPost, "/api/v1/reliability/incidents", `{}`},
		{http.MethodGet, "/api/v1/reliability/incidents/" + incident.ID, ""},
		{http.MethodPost, "/api/v1/reliability/incidents/" + incident.ID + "/acknowledge", ""},
		{http.MethodPost, "/api/v1/reliability/incidents/" + incident.ID + "/resolve", `{}`},
		{http.MethodGet, "/api/v1/reliability/slo-policies", ""},
		{http.MethodPost, "/api/v1/reliability/slo-policies", `{}`},
		{http.MethodGet, "/api/v1/reliability/error-budgets", ""},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Actor-ID", "owner")
			if strings.Contains(tc.target, "/incidents/"+incident.ID+"/") {
				req.Header.Set("If-Match", fmt.Sprint(incident.Revision))
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			if w.Code == http.StatusNotFound && strings.Contains(w.Body.String(), "404 page not found") {
				t.Fatalf("route is not registered: %s %s", tc.method, tc.target)
			}
		})
	}
}
