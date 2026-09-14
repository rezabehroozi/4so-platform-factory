package api

import (
	"context"
	"net/http"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestReliabilityIncidentListRejectsCursorUntilStorePagingIsAuthoritative(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-cursor-inc", DisplayName: "Reliability"}, "owner")
	if err != nil { t.Fatal(err) }
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "p", DisplayName: "P"}, "owner")
	if err != nil { t.Fatal(err) }
	srv := New("test", nil, nil, store)
	r, w := reliabilityHandlerRequest(http.MethodGet, "/api/v1/reliability/incidents?projectId="+project.ID+"&cursor=not-yet-supported", "", "operator-a")
	srv.listReliabilityIncidents(w, r)
	if w.Code != http.StatusUnprocessableEntity { t.Fatalf("cursor must fail closed, got %d body=%s", w.Code, w.Body.String()) }
}

func TestReliabilitySLOListRejectsCursorUntilStorePagingIsAuthoritative(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "rel-cursor-slo", DisplayName: "Reliability"}, "owner")
	if err != nil { t.Fatal(err) }
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "p", DisplayName: "P"}, "owner")
	if err != nil { t.Fatal(err) }
	srv := New("test", nil, nil, store)
	r, w := sloRequest(http.MethodGet, "/api/v1/reliability/slo-policies?projectId="+project.ID+"&cursor=not-yet-supported", "", "operator-a")
	srv.listReliabilitySLOPolicies(w, r)
	if w.Code != http.StatusUnprocessableEntity { t.Fatalf("cursor must fail closed, got %d body=%s", w.Code, w.Body.String()) }
}
