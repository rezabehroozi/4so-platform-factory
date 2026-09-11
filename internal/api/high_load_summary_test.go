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
	counts                   controlplane.ControlPlaneSummaryCounts
	calls                    int
	organizationIDs          []string
	projectIDs               []string
	resourceOrganizationIDs  []string
	allScope                 bool
	allResourceOrganizations bool
}

func (s *aggregateSummaryStore) Snapshot(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{}, errors.New("summary hot path must not materialize canonical snapshot")
}
func (s *aggregateSummaryStore) ControlPlaneSummaryCounts(_ context.Context, organizationIDs, projectIDs, resourceOrganizationIDs []string, allScope, allResourceOrganizations bool) (controlplane.ControlPlaneSummaryCounts, error) {
	s.calls++
	s.organizationIDs = append([]string(nil), organizationIDs...)
	s.projectIDs = append([]string(nil), projectIDs...)
	s.resourceOrganizationIDs = append([]string(nil), resourceOrganizationIDs...)
	s.allScope = allScope
	s.allResourceOrganizations = allResourceOrganizations
	return s.counts, nil
}

func TestControlPlaneSummaryUsesBoundedAggregateAuthority(t *testing.T) {
	base := controlplane.NewMemoryStore()
	store := &aggregateSummaryStore{Store: base, counts: controlplane.ControlPlaneSummaryCounts{
		Organizations: 2, Projects: 3, Operations: 7, Evidence: 11, ManagedClusters: 8, ConnectedClusters: 6,
		BaselineDeployments: 9, SuccessfulBaselineDeployments: 7, RuntimeVerifications: 6, SuccessfulRuntimeVerifications: 5,
		RuntimeClosureCampaigns: 4, SuccessfulRuntimeClosureCampaigns: 3, FailedProductWorkflows: 2,
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
	for key, want := range map[string]int{"connectedClusters": 6, "successfulBaselineDeployments": 7, "successfulRuntimeVerifications": 5, "successfulRuntimeClosureCampaigns": 3, "failedProductWorkflows": 2} {
		if got := int(body[key].(float64)); got != want {
			t.Fatalf("%s=%d want=%d", key, got, want)
		}
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

func TestControlPlaneSummaryHonorsExplicitProjectScope(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "summary-org", DisplayName: "Summary Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "summary-project", DisplayName: "Summary Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	other, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "summary-other", DisplayName: "Summary Other"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_ = other
	store := &aggregateSummaryStore{Store: base, counts: controlplane.ControlPlaneSummaryCounts{Organizations: 1, Projects: 1}}
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control-plane/summary?organizationId="+org.ID+"&projectId="+project.ID, nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if store.calls != 1 {
		t.Fatalf("aggregate calls=%d want=1", store.calls)
	}
	if store.allScope || store.allResourceOrganizations {
		t.Fatalf("explicit project scope widened: allScope=%v allResources=%v", store.allScope, store.allResourceOrganizations)
	}
	if len(store.organizationIDs) != 1 || store.organizationIDs[0] != org.ID {
		t.Fatalf("organization scope=%v want=%s", store.organizationIDs, org.ID)
	}
	if len(store.projectIDs) != 1 || store.projectIDs[0] != project.ID {
		t.Fatalf("project scope=%v want=%s", store.projectIDs, project.ID)
	}
	if len(store.resourceOrganizationIDs) != 0 {
		t.Fatalf("project scope must not include organization-wide resources: %v", store.resourceOrganizationIDs)
	}
}

func TestControlPlaneSummaryHonorsExplicitOrganizationScope(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	orgA, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "summary-a", DisplayName: "Summary A"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "summary-b", DisplayName: "Summary B"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA1, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: orgA.ID, Name: "a1", DisplayName: "A1"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA2, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: orgA.ID, Name: "a2", DisplayName: "A2"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = base.CreateProject(ctx, controlplane.Project{OrganizationID: orgB.ID, Name: "b1", DisplayName: "B1"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	store := &aggregateSummaryStore{Store: base, counts: controlplane.ControlPlaneSummaryCounts{Organizations: 1, Projects: 2}}
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control-plane/summary?organizationId="+orgA.ID, nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	gotProjects := map[string]bool{}
	for _, id := range store.projectIDs {
		gotProjects[id] = true
	}
	if len(gotProjects) != 2 || !gotProjects[projectA1.ID] || !gotProjects[projectA2.ID] {
		t.Fatalf("organization-scoped project set=%v", store.projectIDs)
	}
	if len(store.organizationIDs) != 1 || store.organizationIDs[0] != orgA.ID {
		t.Fatalf("organization scope=%v", store.organizationIDs)
	}
	if len(store.resourceOrganizationIDs) != 1 || store.resourceOrganizationIDs[0] != orgA.ID {
		t.Fatalf("organization resource scope=%v", store.resourceOrganizationIDs)
	}
}

func TestControlPlaneSummaryRejectsMismatchedOrganizationProjectSelection(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	orgA, _ := base.CreateOrganization(ctx, controlplane.Organization{Name: "scope-a", DisplayName: "Scope A"}, "admin")
	orgB, _ := base.CreateOrganization(ctx, controlplane.Organization{Name: "scope-b", DisplayName: "Scope B"}, "admin")
	projectB, _ := base.CreateProject(ctx, controlplane.Project{OrganizationID: orgB.ID, Name: "project-b", DisplayName: "Project B"}, "admin")
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), base)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control-plane/summary?organizationId="+orgA.ID+"&projectId="+projectB.ID, nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
}

type attentionStoreProbe struct {
	controlplane.Store
	calls       int
	projectIDs  []string
	allProjects bool
	limit       int
}

func (s *attentionStoreProbe) ControlPlaneAttention(_ context.Context, projectIDs []string, allProjects bool, limit int) ([]controlplane.OperatorAttentionItem, error) {
	s.calls++
	s.projectIDs = append([]string(nil), projectIDs...)
	s.allProjects = allProjects
	s.limit = limit
	return []controlplane.OperatorAttentionItem{{Kind: "tenant", ID: "tenant-failed", ProjectID: "project-1", DisplayName: "Tenant Failed", State: "FAILED", Message: "failed", Page: "tenants"}}, nil
}

func TestControlPlaneAttentionUsesBoundedScopeBeforeLimit(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "attention-org", DisplayName: "Attention Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "attention-project", DisplayName: "Attention Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	store := &attentionStoreProbe{Store: base}
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control-plane/attention?organizationId="+org.ID+"&projectId="+project.ID+"&limit=7", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if store.calls != 1 || store.limit != 7 || store.allProjects {
		t.Fatalf("unexpected attention call: calls=%d limit=%d all=%v", store.calls, store.limit, store.allProjects)
	}
	if len(store.projectIDs) != 1 || store.projectIDs[0] != project.ID {
		t.Fatalf("attention project scope=%v want=%s", store.projectIDs, project.ID)
	}
	if got := res.Header().Get("X-Result-Limit"); got != "7" {
		t.Fatalf("X-Result-Limit=%q", got)
	}
}

func TestControlPlaneAttentionRejectsUnboundedLimit(t *testing.T) {
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), controlplane.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/control-plane/attention?limit=5000", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
}
