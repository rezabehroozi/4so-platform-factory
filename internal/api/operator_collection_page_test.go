package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

type operatorCollectionPagerProbe struct {
	controlplane.Store
	clusterPageCalls          int
	marketplaceInstallCalls   int
	marketplaceRecommendCalls int
	lastProjects              []string
	lastAll                   bool
	lastLimit                 int
	lastCursor                *controlplane.CollectionCursor
	clusters                  []controlplane.ManagedCluster
	installations             []controlplane.BaselineDeployment
	recommendations           []controlplane.MarketplaceRecommendation
}

func (s *operatorCollectionPagerProbe) capture(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) {
	s.lastProjects = append([]string(nil), ids...)
	s.lastAll = all
	s.lastLimit = limit
	if cursor == nil {
		s.lastCursor = nil
	} else {
		copy := *cursor
		s.lastCursor = &copy
	}
}
func (s *operatorCollectionPagerProbe) ListManagedClustersPage(_ context.Context, ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ManagedCluster, error) {
	s.clusterPageCalls++
	s.capture(ids, all, cursor, limit)
	return boundedCollectionWindow(s.clusters, cursor, limit, func(v controlplane.ManagedCluster) controlplane.ResourceMeta { return v.ResourceMeta }), nil
}
func (s *operatorCollectionPagerProbe) ListMarketplaceInstallationsPage(_ context.Context, ids []string, all bool, _ string, _ *controlplane.CollectionCursor, limit int) ([]controlplane.BaselineDeployment, error) {
	s.marketplaceInstallCalls++
	s.capture(ids, all, nil, limit)
	return append([]controlplane.BaselineDeployment(nil), s.installations...), nil
}
func (s *operatorCollectionPagerProbe) ListMarketplaceRecommendationsPage(_ context.Context, ids []string, all bool, _ string, _ *controlplane.CollectionCursor, limit int) ([]controlplane.MarketplaceRecommendation, error) {
	s.marketplaceRecommendCalls++
	s.capture(ids, all, nil, limit)
	return append([]controlplane.MarketplaceRecommendation(nil), s.recommendations...), nil
}

func operatorCollectionScopedServer(t *testing.T) (*Server, *operatorCollectionPagerProbe, controlplane.Organization, controlplane.Project, controlplane.Project) {
	t.Helper()
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "bounded-org", DisplayName: "Bounded Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	own, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "own", DisplayName: "Own"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "foreign", DisplayName: "Foreign"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	probe := &operatorCollectionPagerProbe{Store: base}
	server := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), probe)
	return server, probe, org, own, foreign
}

func projectScopedCollectionRequest(server *Server, method, path string, org controlplane.Organization, project controlplane.Project) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "bounded-project-token", Authentication: "api-token", Roles: []string{"platform-viewer"},
		OrganizationID: org.ID, ProjectID: project.ID, Expires: time.Now().Add(time.Hour).Unix(),
	}))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	return w
}

func TestSpecialistCollectionLimitScopesBeforePager(t *testing.T) {
	server, probe, org, own, foreign := operatorCollectionScopedServer(t)
	probe.clusters = []controlplane.ManagedCluster{{ResourceMeta: controlplane.ResourceMeta{ID: "own-cluster"}, ProjectID: own.ID}}
	w := projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/clusters?limit=1", org, own)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if probe.clusterPageCalls != 1 || probe.lastAll || len(probe.lastProjects) != 1 || probe.lastProjects[0] != own.ID {
		t.Fatalf("pager scope calls=%d all=%v projects=%v; foreign=%s", probe.clusterPageCalls, probe.lastAll, probe.lastProjects, foreign.ID)
	}
	if probe.lastLimit != 2 {
		t.Fatalf("fetch limit=%d want=2 (requested+1)", probe.lastLimit)
	}
	if got := w.Header().Get("X-4SO-Result-Limit"); got != "1" {
		t.Fatalf("X-4SO-Result-Limit=%q", got)
	}
	if got := w.Header().Get("X-4SO-Result-Order"); got != "updatedAt:desc,id:desc" {
		t.Fatalf("X-4SO-Result-Order=%q", got)
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d body=%s", len(rows), w.Body.String())
	}
}

func TestSpecialistCollectionRejectsOversizedLimit(t *testing.T) {
	server, probe, org, own, _ := operatorCollectionScopedServer(t)
	w := projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/clusters?limit=201", org, own)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if probe.clusterPageCalls != 0 {
		t.Fatalf("pager called %d times for invalid limit", probe.clusterPageCalls)
	}
}

func TestMarketplaceCollectionsUseBoundedProjectPager(t *testing.T) {
	server, probe, org, own, _ := operatorCollectionScopedServer(t)
	probe.installations = []controlplane.BaselineDeployment{{ResourceMeta: controlplane.ResourceMeta{ID: "market-install"}, ProjectID: own.ID, SourceType: controlplane.BaselineSourceMarketplace}}
	probe.recommendations = []controlplane.MarketplaceRecommendation{{ResourceMeta: controlplane.ResourceMeta{ID: "market-rec"}, ProjectID: own.ID}}

	w := projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/marketplace/installations?limit=2", org, own)
	if w.Code != http.StatusOK {
		t.Fatalf("install status=%d body=%s", w.Code, w.Body.String())
	}
	if probe.marketplaceInstallCalls != 1 || probe.lastLimit != 3 || len(probe.lastProjects) != 1 || probe.lastProjects[0] != own.ID {
		t.Fatalf("installation pager calls=%d projects=%v limit=%d", probe.marketplaceInstallCalls, probe.lastProjects, probe.lastLimit)
	}

	w = projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/marketplace/recommendations?limit=3", org, own)
	if w.Code != http.StatusOK {
		t.Fatalf("recommend status=%d body=%s", w.Code, w.Body.String())
	}
	if probe.marketplaceRecommendCalls != 1 || probe.lastLimit != 4 || len(probe.lastProjects) != 1 || probe.lastProjects[0] != own.ID {
		t.Fatalf("recommendation pager calls=%d projects=%v limit=%d", probe.marketplaceRecommendCalls, probe.lastProjects, probe.lastLimit)
	}
}

func TestSpecialistCollectionNilPagerResponseIsEmptyArray(t *testing.T) {
	server, probe, org, own, _ := operatorCollectionScopedServer(t)
	probe.clusters = nil
	w := projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/clusters?limit=5", org, own)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Fatalf("nil pager response must encode as [] not null; body=%s", got)
	}
}

func TestOperatorCollectionLimitDefaultsToBoundedWindow(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
	got, err := operatorCollectionLimit(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != operatorCollectionDefaultLimit {
		t.Fatalf("default limit=%d want=%d", got, operatorCollectionDefaultLimit)
	}
}

func TestSpecialistCollectionUsesDefaultBoundedPager(t *testing.T) {
	server, probe, org, own, _ := operatorCollectionScopedServer(t)
	probe.clusters = []controlplane.ManagedCluster{{ResourceMeta: controlplane.ResourceMeta{ID: "own-cluster"}, ProjectID: own.ID}}
	w := projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/clusters", org, own)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if probe.clusterPageCalls != 1 {
		t.Fatalf("default collection must use bounded pager; calls=%d", probe.clusterPageCalls)
	}
	if probe.lastLimit != operatorCollectionDefaultLimit+1 {
		t.Fatalf("pager fetch limit=%d want=%d", probe.lastLimit, operatorCollectionDefaultLimit+1)
	}
	if got := w.Header().Get("X-4SO-Result-Limit"); got != "100" {
		t.Fatalf("X-4SO-Result-Limit=%q want=100", got)
	}
	if got := w.Header().Get("X-4SO-Pagination-Authority"); got != "OPERATOR_COLLECTION_CURSOR_V1" {
		t.Fatalf("X-4SO-Pagination-Authority=%q", got)
	}
}

func TestOperatorCollectionCursorRoundTrip(t *testing.T) {
	want := controlplane.CollectionCursor{UpdatedAt: time.Date(2026, 9, 10, 12, 34, 56, 789123000, time.UTC), ID: "cls_cursor"}
	token, err := encodeOperatorCollectionCursor(want)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters?cursor="+token, nil)
	got, err := operatorCollectionCursor(req)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.UpdatedAt.Equal(want.UpdatedAt) || got.ID != want.ID {
		t.Fatalf("cursor=%+v want=%+v", got, want)
	}
}

func TestOperatorCollectionCursorRejectsMalformedToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters?cursor=not-a-valid-cursor", nil)
	if _, err := operatorCollectionCursor(req); err == nil {
		t.Fatal("malformed cursor must fail closed")
	}
}

func TestBoundedCollectionWindowUsesStableCursorBoundary(t *testing.T) {
	base := time.Date(2026, 9, 10, 13, 0, 0, 0, time.UTC)
	items := []controlplane.ManagedCluster{
		{ResourceMeta: controlplane.ResourceMeta{ID: "c3", UpdatedAt: base.Add(3 * time.Minute)}},
		{ResourceMeta: controlplane.ResourceMeta{ID: "c2b", UpdatedAt: base.Add(2 * time.Minute)}},
		{ResourceMeta: controlplane.ResourceMeta{ID: "c2a", UpdatedAt: base.Add(2 * time.Minute)}},
		{ResourceMeta: controlplane.ResourceMeta{ID: "c1", UpdatedAt: base.Add(time.Minute)}},
	}
	cursor := &controlplane.CollectionCursor{UpdatedAt: base.Add(2 * time.Minute), ID: "c2b"}
	got := boundedCollectionWindow(items, cursor, 2, func(v controlplane.ManagedCluster) controlplane.ResourceMeta { return v.ResourceMeta })
	if len(got) != 2 || got[0].ID != "c2a" || got[1].ID != "c1" {
		t.Fatalf("window=%v want=[c2a c1]", []string{got[0].ID, got[1].ID})
	}
}

func TestSpecialistCollectionCursorContinuationHasNoOverlap(t *testing.T) {
	server, probe, org, own, _ := operatorCollectionScopedServer(t)
	base := time.Date(2026, 9, 10, 14, 0, 0, 0, time.UTC)
	probe.clusters = []controlplane.ManagedCluster{
		{ResourceMeta: controlplane.ResourceMeta{ID: "c3", UpdatedAt: base.Add(3 * time.Minute)}, ProjectID: own.ID},
		{ResourceMeta: controlplane.ResourceMeta{ID: "c2", UpdatedAt: base.Add(2 * time.Minute)}, ProjectID: own.ID},
		{ResourceMeta: controlplane.ResourceMeta{ID: "c1", UpdatedAt: base.Add(time.Minute)}, ProjectID: own.ID},
	}
	first := projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/clusters?limit=2", org, own)
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	cursor := first.Header().Get("X-4SO-Next-Cursor")
	if cursor == "" {
		t.Fatal("first page must emit continuation cursor")
	}
	if link := first.Header().Get("Link"); !strings.Contains(link, "rel=\"next\"") || !strings.Contains(link, "cursor=") {
		t.Fatalf("next link=%q", link)
	}
	var firstRows []map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &firstRows); err != nil {
		t.Fatal(err)
	}
	if len(firstRows) != 2 {
		t.Fatalf("first rows=%d", len(firstRows))
	}

	second := projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/clusters?limit=2&cursor="+cursor, org, own)
	if second.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}
	if probe.lastCursor == nil || probe.lastCursor.ID != "c2" {
		t.Fatalf("pager cursor=%+v want boundary c2", probe.lastCursor)
	}
	if second.Header().Get("X-4SO-Next-Cursor") != "" {
		t.Fatalf("terminal page emitted unexpected cursor=%q", second.Header().Get("X-4SO-Next-Cursor"))
	}
	var secondRows []map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &secondRows); err != nil {
		t.Fatal(err)
	}
	if len(secondRows) != 1 {
		t.Fatalf("second rows=%d body=%s", len(secondRows), second.Body.String())
	}
}

func TestSpecialistCollectionRejectsMalformedCursorBeforePager(t *testing.T) {
	server, probe, org, own, _ := operatorCollectionScopedServer(t)
	w := projectScopedCollectionRequest(server, http.MethodGet, "/api/v1/clusters?cursor=malformed", org, own)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if probe.clusterPageCalls != 0 {
		t.Fatalf("pager called %d times for malformed cursor", probe.clusterPageCalls)
	}
}
