package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

type aggregateSummaryStore struct {
	controlplane.Store
	counts controlplane.ControlPlaneSummaryCounts
	calls  int
}

func (s *aggregateSummaryStore) Snapshot(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{}, errors.New("summary hot path must not materialize canonical snapshot")
}
func (s *aggregateSummaryStore) ControlPlaneSummaryCounts(context.Context, []string, []string, []string, bool, bool) (controlplane.ControlPlaneSummaryCounts, error) {
	s.calls++
	return s.counts, nil
}

func TestControlPlaneSummaryUsesBoundedAggregateAuthority(t *testing.T) {
	base := controlplane.NewMemoryStore()
	store := &aggregateSummaryStore{Store: base, counts: controlplane.ControlPlaneSummaryCounts{
		Organizations: 2, Projects: 3, Operations: 7, Evidence: 11,
		OperationStates: map[controlplane.OperationState]int{controlplane.OperationQueued: 2},
	}}
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control-plane/summary", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if store.calls != 1 {
		t.Fatalf("aggregate calls=%d want=1", store.calls)
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := int(body["operations"].(float64)); got != 7 {
		t.Fatalf("operations=%d want=7", got)
	}
}

type operationPagerStore struct {
	controlplane.Store
	pageCalls int
}

func (s *operationPagerStore) ListOperationsPage(context.Context, string, int) ([]controlplane.Operation, error) {
	s.pageCalls++
	return []controlplane.Operation{{ResourceMeta: controlplane.ResourceMeta{ID: "op-recent"}, ProjectID: "project-1"}}, nil
}

func TestOperationsLimitUsesBoundedStorePath(t *testing.T) {
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(context.Background(), controlplane.Organization{Name: "org", DisplayName: "Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := base.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "project", DisplayName: "Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	store := &operationPagerStore{Store: base}
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations?projectId="+project.ID+"&limit=200", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if store.pageCalls != 1 {
		t.Fatalf("paged calls=%d want=1", store.pageCalls)
	}
	if got := res.Header().Get("X-Result-Limit"); got != "200" {
		t.Fatalf("X-Result-Limit=%q", got)
	}
}

func TestOperationsRejectsUnboundedRequestedLimit(t *testing.T) {
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), controlplane.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations?limit=5000", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
}

type projectScopeScanGuardStore struct {
	controlplane.Store
	globalProjectScans int
}

func (s *projectScopeScanGuardStore) ListProjects(ctx context.Context, organizationID string) ([]controlplane.Project, error) {
	if organizationID == "" {
		s.globalProjectScans++
		return nil, errors.New("global project scan forbidden in scoped hot path")
	}
	return s.Store.ListProjects(ctx, organizationID)
}

func TestProjectScopedAPITokenAvoidsGlobalProjectScan(t *testing.T) {
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(context.Background(), controlplane.Organization{Name: "org-scope", DisplayName: "Org Scope"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := base.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "project-scope", DisplayName: "Project Scope"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	store := &projectScopeScanGuardStore{Store: base}
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations?limit=10", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "service-account", Roles: []string{"platform-viewer"}, Authentication: "api-token",
		OrganizationID: org.ID, ProjectID: project.ID,
	}))
	projects, all, err := s.accessibleProjectSet(req)
	if err != nil {
		t.Fatal(err)
	}
	if all || len(projects) != 1 || !projects[project.ID] {
		t.Fatalf("unexpected project scope: all=%v projects=%v", all, projects)
	}
	if store.globalProjectScans != 0 {
		t.Fatalf("global project scans=%d want=0", store.globalProjectScans)
	}
}

func TestOperationsBoundedOrderingIsNewestFirstAcrossDevelopmentStore(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "ordering-org", DisplayName: "Ordering Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "ordering-project", DisplayName: "Ordering Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	older, _, err := base.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "TEST", TargetRef: "target/older", DesiredRevision: "rev-older", Risk: "low", Class: controlplane.OperationClassReadOnly}, "ordering-older", "operator", "req-older")
	if err != nil {
		t.Fatal(err)
	}
	newer, _, err := base.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "TEST", TargetRef: "target/newer", DesiredRevision: "rev-newer", Risk: "low", Class: controlplane.OperationClassReadOnly}, "ordering-newer", "operator", "req-newer")
	if err != nil {
		t.Fatal(err)
	}

	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), base)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations?projectId="+project.ID+"&limit=2", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	var got []controlplane.Operation
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("operations=%d want=2 body=%s", len(got), res.Body.String())
	}
	if got[0].ID != newer.ID || got[1].ID != older.ID {
		t.Fatalf("bounded operation ordering=%v want newest-first [%s %s]", []string{got[0].ID, got[1].ID}, newer.ID, older.ID)
	}
}
