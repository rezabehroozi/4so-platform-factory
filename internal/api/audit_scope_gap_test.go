package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestScopedAuditIncludesNotificationDestinationUpdates(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, _, _, _ := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: org.ID, Subject: "audit-admin", Role: controlplane.OrganizationAdmin}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	destination, err := store.CreateNotificationDestination(context.Background(), controlplane.NotificationDestination{OrganizationID: org.ID, Name: "ops", Kind: controlplane.NotificationDestinationWebhook, Endpoint: "https://example.invalid/hook", TimeoutSeconds: 5}, "audit-admin")
	if err != nil {
		t.Fatal(err)
	}
	destination.Name = "ops-updated"
	updated, err := store.UpdateNotificationDestination(context.Background(), destination.ID, destination.Revision, destination, "audit-admin")
	if err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/audit-events?limit=100", "", "audit-admin", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var events []controlplane.AuditEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == "notification_destination.updated" && event.ResourceID == updated.ID {
			return
		}
	}
	t.Fatalf("notification destination update audit missing from scoped view: %#v", events)
}

func TestScopedAuditAppliesLimitAfterScopeFiltering(t *testing.T) {
	store := controlplane.NewMemoryStore()
	orgA, _, _, opA := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgA.ID, Subject: "audit-user-a", Role: controlplane.OrganizationOperator}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	// Seed another organization after A so its audit activity occupies the global tail.
	_, _, _, _ = seedOrganizationScope(t, store)
	s := scopedServer(t, store)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/audit-events?limit=1", "", "audit-user-a", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var events []controlplane.AuditEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("scoped limit starved by foreign audit activity: got=%d events=%#v", len(events), events)
	}
	// The exact latest own event can vary with membership creation, but it must be in A's scope.
	foundOwn := false
	for _, event := range events {
		if event.ResourceID == orgA.ID || event.ResourceID == opA.ID || metadataString(event.Metadata, "organizationId") == orgA.ID {
			foundOwn = true
		}
	}
	if !foundOwn {
		t.Fatalf("limit returned no event from caller scope: %#v", events)
	}
}

func TestBuildScopeIndexCoversScopedAuditResourceFamiliesWithoutCrossTenantLeak(t *testing.T) {
	orgs := map[string]bool{"org-own": true}
	projects := map[string]bool{"prj-own": true}
	snap := controlplane.Snapshot{
		OIDCGroupMappings:          []controlplane.OIDCGroupMapping{{ResourceMeta: controlplane.ResourceMeta{ID: "oidc-own"}, OrganizationID: "org-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "oidc-foreign"}, OrganizationID: "org-foreign"}},
		BlueprintOverlays:          []controlplane.BlueprintOverlay{{ResourceMeta: controlplane.ResourceMeta{ID: "overlay-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "overlay-foreign"}, ProjectID: "prj-foreign"}},
		BlueprintReleases:          []controlplane.BlueprintRelease{{ResourceMeta: controlplane.ResourceMeta{ID: "bpr-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "bpr-foreign"}, ProjectID: "prj-foreign"}},
		CatalogTrustKeys:           []controlplane.CatalogTrustKey{{ResourceMeta: controlplane.ResourceMeta{ID: "ctk-own"}, OrganizationID: "org-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "ctk-foreign"}, OrganizationID: "org-foreign"}},
		CatalogRevisions:           []controlplane.CatalogRevision{{ResourceMeta: controlplane.ResourceMeta{ID: "crv-own"}, OrganizationID: "org-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "crv-foreign"}, OrganizationID: "org-foreign"}},
		CatalogReleases:            []controlplane.CatalogRelease{{ResourceMeta: controlplane.ResourceMeta{ID: "crl-own"}, OrganizationID: "org-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "crl-foreign"}, OrganizationID: "org-foreign"}},
		Operations:                 []controlplane.Operation{{ResourceMeta: controlplane.ResourceMeta{ID: "op-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "op-foreign"}, ProjectID: "prj-foreign"}},
		StepTraces:                 []controlplane.OperationStepTrace{{ResourceMeta: controlplane.ResourceMeta{ID: "trace-own"}, OperationID: "op-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "trace-foreign"}, OperationID: "op-foreign"}},
		CompensationSteps:          []controlplane.OperationCompensationStep{{ResourceMeta: controlplane.ResourceMeta{ID: "comp-own"}, OperationID: "op-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "comp-foreign"}, OperationID: "op-foreign"}},
		NotificationDestinations:   []controlplane.NotificationDestination{{ResourceMeta: controlplane.ResourceMeta{ID: "dest-own"}, OrganizationID: "org-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "dest-foreign"}, OrganizationID: "org-foreign"}},
		NotificationRoutes:         []controlplane.NotificationRoute{{ResourceMeta: controlplane.ResourceMeta{ID: "route-own"}, OrganizationID: "org-own", ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "route-foreign"}, OrganizationID: "org-foreign", ProjectID: "prj-foreign"}},
		NotificationEvents:         []controlplane.NotificationEvent{{ResourceMeta: controlplane.ResourceMeta{ID: "evt-own"}, OrganizationID: "org-own", ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "evt-foreign"}, OrganizationID: "org-foreign", ProjectID: "prj-foreign"}},
		NotificationDeliveries:     []controlplane.NotificationDelivery{{ResourceMeta: controlplane.ResourceMeta{ID: "del-own"}, EventID: "evt-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "del-foreign"}, EventID: "evt-foreign"}},
		NotificationAttempts:       []controlplane.NotificationDeliveryAttempt{{ResourceMeta: controlplane.ResourceMeta{ID: "att-own"}, DeliveryID: "del-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "att-foreign"}, DeliveryID: "del-foreign"}},
		ManagedClusters:            []controlplane.ManagedCluster{{ResourceMeta: controlplane.ResourceMeta{ID: "cluster-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "cluster-foreign"}, ProjectID: "prj-foreign"}},
		ClusterMaintenanceProfiles: []controlplane.ClusterMaintenanceProfile{{ResourceMeta: controlplane.ResourceMeta{ID: "maint-profile-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "maint-profile-foreign"}, ProjectID: "prj-foreign"}},
		ClusterMaintenanceWindows:  []controlplane.ClusterMaintenanceWindow{{ResourceMeta: controlplane.ResourceMeta{ID: "maint-window-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "maint-window-foreign"}, ProjectID: "prj-foreign"}},
		ClusterMaintenanceRuns:     []controlplane.ClusterMaintenanceRun{{ResourceMeta: controlplane.ResourceMeta{ID: "maint-run-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "maint-run-foreign"}, ProjectID: "prj-foreign"}},
		AgentCertificates:          []controlplane.AgentCertificate{{ResourceMeta: controlplane.ResourceMeta{ID: "cert-own"}, ClusterID: "cluster-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "cert-foreign"}, ClusterID: "cluster-foreign"}},
		RuntimeCertifications:      []controlplane.RuntimeCertificationRun{{ResourceMeta: controlplane.ResourceMeta{ID: "rtc-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "rtc-foreign"}, ProjectID: "prj-foreign"}},
		RecoveryCheckpoints:        []controlplane.RecoveryCheckpoint{{ResourceMeta: controlplane.ResourceMeta{ID: "rcp-own"}, ProjectID: "prj-own"}, {ResourceMeta: controlplane.ResourceMeta{ID: "rcp-foreign"}, ProjectID: "prj-foreign"}},
	}
	index := buildScopeIndex(snap, orgs, projects)
	own := []string{"oidc-own", "overlay-own", "bpr-own", "ctk-own", "crv-own", "crl-own", "op-own", "trace-own", "comp-own", "dest-own", "route-own", "evt-own", "del-own", "att-own", "cluster-own", "maint-profile-own", "maint-window-own", "maint-run-own", "cert-own", "rtc-own", "rcp-own"}
	foreign := []string{"oidc-foreign", "overlay-foreign", "bpr-foreign", "ctk-foreign", "crv-foreign", "crl-foreign", "op-foreign", "trace-foreign", "comp-foreign", "dest-foreign", "route-foreign", "evt-foreign", "del-foreign", "att-foreign", "cluster-foreign", "maint-profile-foreign", "maint-window-foreign", "maint-run-foreign", "cert-foreign", "rtc-foreign", "rcp-foreign"}
	for _, id := range own {
		if !index.resources[id] {
			t.Errorf("own scoped resource missing from audit index: %s", id)
		}
	}
	for _, id := range foreign {
		if index.resources[id] {
			t.Errorf("foreign resource leaked into audit index: %s", id)
		}
	}
}

type scopedAuditPagerProbe struct {
	controlplane.Store
	page            []controlplane.AuditEvent
	scopedCalls     int
	snapshotCalls   int
	organizationIDs []string
	projectIDs      []string
	limit           int
}

func (s *scopedAuditPagerProbe) ListAuditPageByScopes(_ context.Context, organizationIDs, projectIDs []string, limit int) ([]controlplane.AuditEvent, error) {
	s.scopedCalls++
	s.organizationIDs = append([]string(nil), organizationIDs...)
	s.projectIDs = append([]string(nil), projectIDs...)
	s.limit = limit
	return append([]controlplane.AuditEvent(nil), s.page...), nil
}

func (s *scopedAuditPagerProbe) Snapshot(ctx context.Context) (controlplane.Snapshot, error) {
	s.snapshotCalls++
	return s.Store.Snapshot(ctx)
}

func TestScopedAuditUsesBoundedAuthorizationAwareQuery(t *testing.T) {
	base := controlplane.NewMemoryStore()
	org, _, _, _ := seedOrganizationScope(t, base)
	if _, err := base.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: org.ID, Subject: "audit-bounded", Role: controlplane.OrganizationViewer}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	probe := &scopedAuditPagerProbe{Store: base, page: []controlplane.AuditEvent{{ID: "aud-scoped", ResourceID: org.ID, Action: "organization.read"}}}
	s := scopedServer(t, probe)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/audit-events?limit=10", "", "audit-bounded", "platform-viewer")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if probe.scopedCalls != 1 || probe.snapshotCalls != 0 {
		t.Fatalf("scoped audit must use bounded pager without global Snapshot: scoped=%d snapshot=%d", probe.scopedCalls, probe.snapshotCalls)
	}
}

func TestMemoryAuditOrderingMatchesNewestFirstContract(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "audit-order", DisplayName: "Audit Order"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "project", DisplayName: "Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.ListAudit(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ResourceID != project.ID || events[1].ResourceID != org.ID {
		t.Fatalf("audit ordering is not newest-first: %#v", events)
	}
}

func TestAuditHonorsExplicitProjectScope(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	org, err := base.CreateOrganization(ctx, controlplane.Organization{Name: "audit-project-org", DisplayName: "Audit Project Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := base.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "audit-project", DisplayName: "Audit Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	probe := &scopedAuditPagerProbe{Store: base, page: []controlplane.AuditEvent{{ID: "audit-project-row", ResourceID: project.ID, Action: "project.read"}}}
	s := New("test", nil, nil, probe)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?projectId="+project.ID+"&limit=25", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if probe.scopedCalls != 1 || probe.snapshotCalls != 0 {
		t.Fatalf("explicit project audit must use bounded scoped pager: scoped=%d snapshot=%d", probe.scopedCalls, probe.snapshotCalls)
	}
	if len(probe.projectIDs) != 1 || probe.projectIDs[0] != project.ID {
		t.Fatalf("project scope=%v want=%s", probe.projectIDs, project.ID)
	}
	if len(probe.organizationIDs) != 0 {
		t.Fatalf("project scope must exclude organization-wide audit resources: %v", probe.organizationIDs)
	}
	if probe.limit != 25 {
		t.Fatalf("limit=%d want=25", probe.limit)
	}
}

func TestAuditHonorsExplicitOrganizationScope(t *testing.T) {
	ctx := context.Background()
	base := controlplane.NewMemoryStore()
	orgA, _ := base.CreateOrganization(ctx, controlplane.Organization{Name: "audit-org-a", DisplayName: "Audit Org A"}, "admin")
	orgB, _ := base.CreateOrganization(ctx, controlplane.Organization{Name: "audit-org-b", DisplayName: "Audit Org B"}, "admin")
	projectA, _ := base.CreateProject(ctx, controlplane.Project{OrganizationID: orgA.ID, Name: "audit-a", DisplayName: "Audit A"}, "admin")
	_, _ = base.CreateProject(ctx, controlplane.Project{OrganizationID: orgB.ID, Name: "audit-b", DisplayName: "Audit B"}, "admin")
	probe := &scopedAuditPagerProbe{Store: base, page: []controlplane.AuditEvent{{ID: "audit-org-row", ResourceID: orgA.ID, Action: "organization.read"}}}
	s := New("test", nil, nil, probe)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?organizationId="+orgA.ID+"&limit=10", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if len(probe.organizationIDs) != 1 || probe.organizationIDs[0] != orgA.ID {
		t.Fatalf("organization scope=%v want=%s", probe.organizationIDs, orgA.ID)
	}
	if len(probe.projectIDs) != 1 || probe.projectIDs[0] != projectA.ID {
		t.Fatalf("project scope under organization=%v want=%s", probe.projectIDs, projectA.ID)
	}
}
