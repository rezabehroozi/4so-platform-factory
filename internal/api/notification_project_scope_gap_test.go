package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func projectTokenRequest(t *testing.T, s *Server, method, path string, principal auth.Principal) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestProjectScopedTokenCannotReadOtherProjectNotificationEvents(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "notif-scope", DisplayName: "Notification Scope"}, "admin")
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
	own, _, _, err := store.RouteNotificationEvent(ctx, controlplane.NotificationEvent{OrganizationID: org.ID, ProjectID: projectA.ID, SourceEventID: "evt-own", EventType: "operation.failed", Severity: controlplane.NotificationCritical, Title: "Own", OccurredAt: time.Now().Add(-time.Minute)}, "system")
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, _, err := store.RouteNotificationEvent(ctx, controlplane.NotificationEvent{OrganizationID: org.ID, ProjectID: projectB.ID, SourceEventID: "evt-foreign", EventType: "operation.failed", Severity: controlplane.NotificationCritical, Title: "Foreign", OccurredAt: time.Now()}, "system")
	if err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	principal := auth.Principal{Subject: "sa-a", Roles: []string{"platform-viewer"}, Authentication: "api-token", OrganizationID: org.ID, ProjectID: projectA.ID, Expires: time.Now().Add(time.Hour).Unix()}

	w := projectTokenRequest(t, s, http.MethodGet, "/api/v1/notification-events?limit=100", principal)
	if w.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	var events []controlplane.NotificationEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != own.ID {
		t.Fatalf("project token notification leak: own=%s foreign=%s got=%#v", own.ID, foreign.ID, events)
	}

	w = projectTokenRequest(t, s, http.MethodGet, "/api/v1/notification-events/"+foreign.ID, principal)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign event direct read status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestNotificationEventLimitIsAppliedAfterTenantScope(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	orgA, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "notif-limit-a", DisplayName: "A"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgA.ID, Name: "a", DisplayName: "A"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertOrganizationMembership(ctx, controlplane.OrganizationMembership{OrganizationID: orgA.ID, Subject: "viewer-a", Role: controlplane.OrganizationViewer}, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	own, _, _, err := store.RouteNotificationEvent(ctx, controlplane.NotificationEvent{OrganizationID: orgA.ID, ProjectID: projectA.ID, SourceEventID: "limit-own", EventType: "operation.failed", Severity: controlplane.NotificationCritical, Title: "Own", OccurredAt: time.Now().Add(-time.Hour)}, "system")
	if err != nil {
		t.Fatal(err)
	}

	orgB, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "notif-limit-b", DisplayName: "B"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgB.ID, Name: "b", DisplayName: "B"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, _, err := store.RouteNotificationEvent(ctx, controlplane.NotificationEvent{OrganizationID: orgB.ID, ProjectID: projectB.ID, SourceEventID: "limit-foreign-" + string(rune('a'+i)), EventType: "operation.failed", Severity: controlplane.NotificationCritical, Title: "Foreign", OccurredAt: time.Now().Add(time.Duration(i) * time.Minute)}, "system"); err != nil {
			t.Fatal(err)
		}
	}
	s := scopedServer(t, store)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/notification-events?limit=1", "", "viewer-a", "platform-viewer")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var events []controlplane.NotificationEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != own.ID {
		t.Fatalf("tenant-scoped notification limit was applied before scope: own=%s got=%#v", own.ID, events)
	}
}

func TestProjectScopedTokenCannotReadOtherProjectNotificationRoutesOrDeliveries(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "notif-chain", DisplayName: "Notification Chain"}, "admin")
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
	destination, err := store.CreateNotificationDestination(ctx, controlplane.NotificationDestination{OrganizationID: org.ID, Name: "console", Kind: controlplane.NotificationDestinationConsole, TimeoutSeconds: 5}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	routeA, err := store.CreateNotificationRoute(ctx, controlplane.NotificationRoute{OrganizationID: org.ID, ProjectID: projectA.ID, Name: "route-a", Enabled: true, EventPatterns: []string{"operation.*"}, MinimumSeverity: controlplane.NotificationInfo, DestinationIDs: []string{destination.ID}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	routeB, err := store.CreateNotificationRoute(ctx, controlplane.NotificationRoute{OrganizationID: org.ID, ProjectID: projectB.ID, Name: "route-b", Enabled: true, EventPatterns: []string{"operation.*"}, MinimumSeverity: controlplane.NotificationInfo, DestinationIDs: []string{destination.ID}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, deliveriesA, _, err := store.RouteNotificationEvent(ctx, controlplane.NotificationEvent{OrganizationID: org.ID, ProjectID: projectA.ID, SourceEventID: "chain-a", EventType: "operation.failed", Severity: controlplane.NotificationCritical, Title: "A"}, "system")
	if err != nil || len(deliveriesA) != 1 {
		t.Fatalf("own deliveries=%d err=%v", len(deliveriesA), err)
	}
	_, deliveriesB, _, err := store.RouteNotificationEvent(ctx, controlplane.NotificationEvent{OrganizationID: org.ID, ProjectID: projectB.ID, SourceEventID: "chain-b", EventType: "operation.failed", Severity: controlplane.NotificationCritical, Title: "B"}, "system")
	if err != nil || len(deliveriesB) != 1 {
		t.Fatalf("foreign deliveries=%d err=%v", len(deliveriesB), err)
	}

	s := scopedServer(t, store)
	principal := auth.Principal{Subject: "sa-a", Roles: []string{"platform-viewer"}, Authentication: "api-token", OrganizationID: org.ID, ProjectID: projectA.ID, Expires: time.Now().Add(time.Hour).Unix()}

	w := projectTokenRequest(t, s, http.MethodGet, "/api/v1/notification-routes", principal)
	if w.Code != http.StatusOK {
		t.Fatalf("route list status=%d body=%s", w.Code, w.Body.String())
	}
	var routes []controlplane.NotificationRoute
	if err := json.Unmarshal(w.Body.Bytes(), &routes); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].ID != routeA.ID {
		t.Fatalf("project token route leak: own=%s foreign=%s got=%#v", routeA.ID, routeB.ID, routes)
	}
	w = projectTokenRequest(t, s, http.MethodGet, "/api/v1/notification-routes/"+routeB.ID, principal)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign route direct read status=%d body=%s", w.Code, w.Body.String())
	}

	w = projectTokenRequest(t, s, http.MethodGet, "/api/v1/notification-deliveries", principal)
	if w.Code != http.StatusOK {
		t.Fatalf("delivery list status=%d body=%s", w.Code, w.Body.String())
	}
	var deliveries []controlplane.NotificationDelivery
	if err := json.Unmarshal(w.Body.Bytes(), &deliveries); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].ID != deliveriesA[0].ID {
		t.Fatalf("project token delivery leak: own=%s foreign=%s got=%#v", deliveriesA[0].ID, deliveriesB[0].ID, deliveries)
	}
	w = projectTokenRequest(t, s, http.MethodGet, "/api/v1/notification-deliveries/"+deliveriesB[0].ID, principal)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign delivery direct read status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestProjectScopedOperateTokenCanManageOwnProjectNotificationRouteOnly(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "notif-write", DisplayName: "Notification Write"}, "admin")
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
	destination, err := store.CreateNotificationDestination(ctx, controlplane.NotificationDestination{OrganizationID: org.ID, Name: "console", Kind: controlplane.NotificationDestinationConsole, TimeoutSeconds: 5}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	principal := auth.Principal{Subject: "sa-a", Roles: []string{"platform-operator"}, Authentication: "api-token", OrganizationID: org.ID, ProjectID: projectA.ID, Expires: time.Now().Add(time.Hour).Unix()}
	body := `{"organizationId":"` + org.ID + `","projectId":"` + projectA.ID + `","name":"route-a","enabled":true,"eventPatterns":["operation.*"],"minimumSeverity":"INFO","destinationIds":["` + destination.ID + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notification-routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("own project route create status=%d body=%s", w.Code, w.Body.String())
	}
	var route controlplane.NotificationRoute
	if err := json.Unmarshal(w.Body.Bytes(), &route); err != nil {
		t.Fatal(err)
	}

	move := `{"organizationId":"` + org.ID + `","projectId":"` + projectB.ID + `","name":"route-a","enabled":true,"eventPatterns":["operation.*"],"minimumSeverity":"INFO","destinationIds":["` + destination.ID + `"]}`
	req = httptest.NewRequest(http.MethodPut, "/api/v1/notification-routes/"+route.ID, strings.NewReader(move))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `"1"`)
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-project route move status=%d body=%s", w.Code, w.Body.String())
	}
}

type scopedNotificationPagerProbe struct {
	controlplane.Store
	events                []controlplane.NotificationEvent
	deliveries            []controlplane.NotificationDelivery
	globalEventCalls      int
	scopedEventCalls      int
	globalDeliveryCalls   int
	scopedDeliveryCalls   int
	getNotificationEvents int
}

func (s *scopedNotificationPagerProbe) ListNotificationEvents(ctx context.Context, organizationID, projectID string, limit int) ([]controlplane.NotificationEvent, error) {
	if organizationID == "" && projectID == "" {
		s.globalEventCalls++
	}
	return s.Store.ListNotificationEvents(ctx, organizationID, projectID, limit)
}

func (s *scopedNotificationPagerProbe) ListNotificationEventsPageByScopes(context.Context, []string, []string, int) ([]controlplane.NotificationEvent, error) {
	s.scopedEventCalls++
	return append([]controlplane.NotificationEvent(nil), s.events...), nil
}

func (s *scopedNotificationPagerProbe) ListNotificationDeliveries(ctx context.Context, organizationID, projectID string, state controlplane.NotificationDeliveryState, limit int) ([]controlplane.NotificationDelivery, error) {
	if organizationID == "" && projectID == "" {
		s.globalDeliveryCalls++
	}
	return s.Store.ListNotificationDeliveries(ctx, organizationID, projectID, state, limit)
}

func (s *scopedNotificationPagerProbe) ListNotificationDeliveriesPageByScopes(context.Context, []string, []string, controlplane.NotificationDeliveryState, int) ([]controlplane.NotificationDelivery, error) {
	s.scopedDeliveryCalls++
	return append([]controlplane.NotificationDelivery(nil), s.deliveries...), nil
}

func (s *scopedNotificationPagerProbe) GetNotificationEvent(ctx context.Context, id string) (controlplane.NotificationEvent, error) {
	s.getNotificationEvents++
	return s.Store.GetNotificationEvent(ctx, id)
}

func TestScopedNotificationCollectionsUseBoundedAuthorizationAwareQueries(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "notif-bounded", DisplayName: "Notification Bounded"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "project", DisplayName: "Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	own, deliveries, _, err := func() (controlplane.NotificationEvent, []controlplane.NotificationDelivery, bool, error) {
		destination, e := base.CreateNotificationDestination(ctx, controlplane.NotificationDestination{OrganizationID: org.ID, Name: "console", Kind: controlplane.NotificationDestinationConsole, TimeoutSeconds: 5}, "admin")
		if e != nil {
			return controlplane.NotificationEvent{}, nil, false, e
		}
		if _, e = base.CreateNotificationRoute(ctx, controlplane.NotificationRoute{OrganizationID: org.ID, ProjectID: project.ID, Name: "route", Enabled: true, EventPatterns: []string{"operation.*"}, MinimumSeverity: controlplane.NotificationInfo, DestinationIDs: []string{destination.ID}}, "admin"); e != nil {
			return controlplane.NotificationEvent{}, nil, false, e
		}
		return base.RouteNotificationEvent(ctx, controlplane.NotificationEvent{OrganizationID: org.ID, ProjectID: project.ID, SourceEventID: "bounded-own", EventType: "operation.failed", Severity: controlplane.NotificationCritical, Title: "Own", OccurredAt: time.Now()}, "system")
	}()
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("seed notification err=%v deliveries=%d", err, len(deliveries))
	}
	store := &scopedNotificationPagerProbe{Store: base, events: []controlplane.NotificationEvent{own}, deliveries: deliveries}
	s := scopedServer(t, store)
	principal := auth.Principal{Subject: "project-only", Authentication: "oidc", Roles: []string{"platform-viewer"}, ProjectRoles: map[string]string{project.ID: "project-viewer"}, Expires: time.Now().Add(time.Hour).Unix()}

	w := projectTokenRequest(t, s, http.MethodGet, "/api/v1/notification-events?limit=1", principal)
	if w.Code != http.StatusOK {
		t.Fatalf("event list status=%d body=%s", w.Code, w.Body.String())
	}
	if store.scopedEventCalls != 1 || store.globalEventCalls != 0 {
		t.Fatalf("event paging scoped=%d global=%d want scoped=1 global=0", store.scopedEventCalls, store.globalEventCalls)
	}

	w = projectTokenRequest(t, s, http.MethodGet, "/api/v1/notification-deliveries?limit=1", principal)
	if w.Code != http.StatusOK {
		t.Fatalf("delivery list status=%d body=%s", w.Code, w.Body.String())
	}
	if store.scopedDeliveryCalls != 1 || store.globalDeliveryCalls != 0 {
		t.Fatalf("delivery paging scoped=%d global=%d want scoped=1 global=0", store.scopedDeliveryCalls, store.globalDeliveryCalls)
	}
	if store.getNotificationEvents != 0 {
		t.Fatalf("delivery list performed %d per-row event lookups; want 0", store.getNotificationEvents)
	}
}

func TestNotificationRoutingPreviewIsProjectScopedAndSideEffectFree(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "notif-preview", DisplayName: "Notification Preview"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "a-preview", DisplayName: "A Preview"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "b-preview", DisplayName: "B Preview"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := store.CreateNotificationDestination(ctx, controlplane.NotificationDestination{OrganizationID: org.ID, Name: "console-preview", Kind: controlplane.NotificationDestinationConsole, TimeoutSeconds: 5}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	orgRoute, err := store.CreateNotificationRoute(ctx, controlplane.NotificationRoute{OrganizationID: org.ID, Name: "org-critical", Enabled: true, EventPatterns: []string{"operation.*"}, MinimumSeverity: controlplane.NotificationWarning, DestinationIDs: []string{destination.ID}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectRoute, err := store.CreateNotificationRoute(ctx, controlplane.NotificationRoute{OrganizationID: org.ID, ProjectID: projectA.ID, Name: "project-cluster", Enabled: true, EventPatterns: []string{"cluster.*"}, MinimumSeverity: controlplane.NotificationInfo, DestinationIDs: []string{destination.ID}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateNotificationRoute(ctx, controlplane.NotificationRoute{OrganizationID: org.ID, ProjectID: projectB.ID, Name: "foreign-route", Enabled: true, EventPatterns: []string{"operation.*"}, MinimumSeverity: controlplane.NotificationInfo, DestinationIDs: []string{destination.ID}}, "admin"); err != nil {
		t.Fatal(err)
	}

	s := scopedServer(t, store)
	principal := auth.Principal{Subject: "preview-reader", Roles: []string{"platform-viewer"}, Authentication: "api-token", OrganizationID: org.ID, ProjectID: projectA.ID, Expires: time.Now().Add(time.Hour).Unix()}
	preview := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/notification-routing/preview", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}

	w := preview(`{"projectId":"` + projectA.ID + `","eventType":"operation.failed","severity":"CRITICAL"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("operation preview status=%d body=%s", w.Code, w.Body.String())
	}
	var operationResult notificationRoutingPreviewResult
	if err := json.Unmarshal(w.Body.Bytes(), &operationResult); err != nil {
		t.Fatal(err)
	}
	if operationResult.Authority != "NOTIFICATION_ROUTING_PREVIEW_AUTHORITY_V1" || operationResult.SideEffects || operationResult.DeliveryCreated || operationResult.RouteCount != 1 || len(operationResult.MatchedRoutes) != 1 || operationResult.MatchedRoutes[0].ID != orgRoute.ID {
		t.Fatalf("unexpected operation preview: %#v", operationResult)
	}

	w = preview(`{"projectId":"` + projectA.ID + `","eventType":"cluster.offline","severity":"INFO"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("cluster preview status=%d body=%s", w.Code, w.Body.String())
	}
	var clusterResult notificationRoutingPreviewResult
	if err := json.Unmarshal(w.Body.Bytes(), &clusterResult); err != nil {
		t.Fatal(err)
	}
	if clusterResult.RouteCount != 1 || len(clusterResult.MatchedRoutes) != 1 || clusterResult.MatchedRoutes[0].ID != projectRoute.ID {
		t.Fatalf("unexpected cluster preview: %#v", clusterResult)
	}

	w = preview(`{"projectId":"` + projectB.ID + `","eventType":"operation.failed","severity":"CRITICAL"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign project preview status=%d body=%s", w.Code, w.Body.String())
	}

	events, err := store.ListNotificationEvents(ctx, org.ID, projectA.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := store.ListNotificationDeliveries(ctx, org.ID, projectA.ID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 || len(deliveries) != 0 {
		t.Fatalf("routing preview created side effects: events=%d deliveries=%d", len(events), len(deliveries))
	}
}
