package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func TestDirectProjectRoleDoesNotExpandToSiblingProjectsInOperationList(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "scope-isolation", DisplayName: "Scope Isolation"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "a", DisplayName: "A"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "b", DisplayName: "B"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	own, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: projectA.ID, Kind: "read", TargetRef: "a", DesiredRevision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Risk: "low"}, "own", "admin", "own")
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: projectB.ID, Kind: "read", TargetRef: "b", DesiredRevision: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Risk: "low"}, "foreign", "admin", "foreign")
	if err != nil {
		t.Fatal(err)
	}

	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "project-only-user", Authentication: "oidc", Roles: []string{"platform-viewer"},
		ProjectRoles: map[string]string{projectA.ID: "project-viewer"}, Expires: time.Now().Add(time.Hour).Unix(),
	}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var ops []controlplane.Operation
	if err := json.Unmarshal(w.Body.Bytes(), &ops); err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].ID != own.ID {
		t.Fatalf("project-only principal saw wrong operations: own=%s foreign=%s response=%s", own.ID, foreign.ID, w.Body.String())
	}
}

func TestDirectProjectRoleDoesNotListSiblingProjectMetadata(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "project-list-scope", DisplayName: "Project List Scope"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "a", DisplayName: "A"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "b", DisplayName: "B"}, "admin")
	if err != nil {
		t.Fatal(err)
	}

	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "project-only-user", Authentication: "oidc", Roles: []string{"platform-viewer"},
		ProjectRoles: map[string]string{projectA.ID: "project-viewer"}, Expires: time.Now().Add(time.Hour).Unix(),
	}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var projects []controlplane.Project
	if err := json.Unmarshal(w.Body.Bytes(), &projects); err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 || projects[0].ID != projectA.ID {
		t.Fatalf("project-only principal saw sibling metadata: own=%s sibling=%s response=%s", projectA.ID, projectB.ID, w.Body.String())
	}
}

type scopedOperationPagerProbe struct {
	controlplane.Store
	globalPage  []controlplane.Operation
	scopedPage  []controlplane.Operation
	globalCalls int
	scopedCalls int
}

func (s *scopedOperationPagerProbe) ListOperationsPage(context.Context, string, int) ([]controlplane.Operation, error) {
	s.globalCalls++
	return append([]controlplane.Operation(nil), s.globalPage...), nil
}

func (s *scopedOperationPagerProbe) ListOperationsPageByProjects(context.Context, []string, int) ([]controlplane.Operation, error) {
	s.scopedCalls++
	return append([]controlplane.Operation(nil), s.scopedPage...), nil
}

func TestScopedOperationsLimitAppliesAuthorizationBeforePagination(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "page-scope", DisplayName: "Page Scope"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "a", DisplayName: "A"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "b", DisplayName: "B"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	own, _, err := base.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: projectA.ID, Kind: "read", TargetRef: "a", DesiredRevision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Risk: "low"}, "page-own", "admin", "own")
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := base.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: projectB.ID, Kind: "read", TargetRef: "b", DesiredRevision: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Risk: "low"}, "page-foreign", "admin", "foreign")
	if err != nil {
		t.Fatal(err)
	}
	store := &scopedOperationPagerProbe{Store: base, globalPage: []controlplane.Operation{foreign}, scopedPage: []controlplane.Operation{own}}
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations?limit=1", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "project-token", Authentication: "api-token", Roles: []string{"platform-viewer"},
		OrganizationID: org.ID, ProjectID: projectA.ID, Expires: time.Now().Add(time.Hour).Unix(),
	}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var ops []controlplane.Operation
	if err := json.Unmarshal(w.Body.Bytes(), &ops); err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].ID != own.ID {
		t.Fatalf("authorization was applied after global pagination: own=%s foreign=%s response=%s", own.ID, foreign.ID, w.Body.String())
	}
	if store.scopedCalls != 1 || store.globalCalls != 0 {
		t.Fatalf("pager calls scoped=%d global=%d want scoped=1 global=0", store.scopedCalls, store.globalCalls)
	}
}

func TestDirectProjectRoleDoesNotGainOrganizationResourceVisibility(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "org-resource-scope", DisplayName: "Org Resource Scope"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "project", DisplayName: "Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertEntitlement(ctx, controlplane.Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateNotificationDestination(ctx, controlplane.NotificationDestination{OrganizationID: org.ID, Name: "org-console", Kind: controlplane.NotificationDestinationConsole}, "admin"); err != nil {
		t.Fatal(err)
	}

	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	principal := auth.Principal{
		Subject: "project-only-user", Authentication: "oidc", Roles: []string{"platform-viewer"},
		ProjectRoles: map[string]string{project.ID: "project-viewer"}, Expires: time.Now().Add(time.Hour).Unix(),
	}
	do := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}

	w := do("/api/v1/notification-destinations")
	if w.Code != http.StatusOK {
		t.Fatalf("destinations status=%d body=%s", w.Code, w.Body.String())
	}
	var destinations []controlplane.NotificationDestination
	if err := json.Unmarshal(w.Body.Bytes(), &destinations); err != nil {
		t.Fatal(err)
	}
	if len(destinations) != 0 {
		t.Fatalf("direct project role leaked organization notification destinations: %s", w.Body.String())
	}

	w = do("/api/v1/control-plane/summary")
	if w.Code != http.StatusOK {
		t.Fatalf("summary status=%d body=%s", w.Code, w.Body.String())
	}
	var summary map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["projects"] != float64(1) || summary["entitlements"] != float64(0) || summary["oemProfiles"] != float64(0) {
		t.Fatalf("direct project role leaked organization summary resources: %s", w.Body.String())
	}

	w = do("/api/v1/audit-events?limit=100")
	if w.Code != http.StatusOK {
		t.Fatalf("audit status=%d body=%s", w.Code, w.Body.String())
	}
	var audit []controlplane.AuditEvent
	if err := json.Unmarshal(w.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	for _, event := range audit {
		if event.ResourceType == "organization_entitlement" || event.ResourceType == "notificationDestination" || event.ResourceType == "notification_destination" {
			t.Fatalf("direct project role leaked organization audit event: %#v", event)
		}
	}
}
