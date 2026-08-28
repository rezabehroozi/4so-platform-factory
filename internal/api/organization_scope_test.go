package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func scopedServer(t *testing.T, store controlplane.Store) *Server {
	t.Helper()
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	return New("scope-test", components, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
}

func scopedRequest(t *testing.T, s *Server, method, path, body, subject string, roles ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPut && strings.Contains(path, "/memberships/") {
		req.Header.Set("If-None-Match", "*")
	}
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: subject, Roles: roles, Expires: time.Now().Add(time.Hour).Unix()}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func seedOrganizationScope(t *testing.T, store controlplane.Store) (controlplane.Organization, controlplane.Project, controlplane.ClusterImport, controlplane.Operation) {
	t.Helper()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "tenant-" + time.Now().Format("150405.000000"), DisplayName: "Tenant"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "edge", DisplayName: "Edge", TokenDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: time.Now().Add(time.Hour)}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "APPLY", TargetRef: "cluster:" + imp.ID, DesiredRevision: "rev-1", Risk: "low"}, "scope-"+org.ID, "bootstrap-admin", "request-"+org.ID)
	if err != nil {
		t.Fatal(err)
	}
	return org, project, imp, op
}

func TestOrganizationScopeBlocksCrossTenantReadAndMutation(t *testing.T) {
	store := controlplane.NewMemoryStore()
	orgA, projectA, importA, opA := seedOrganizationScope(t, store)
	orgB, projectB, importB, opB := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgA.ID, Subject: "user-a", Role: controlplane.OrganizationOperator}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgB.ID, Subject: "user-b", Role: controlplane.OrganizationOperator}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)

	w := scopedRequest(t, s, http.MethodGet, "/api/v1/organizations", "", "user-a", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("organizations status=%d body=%s", w.Code, w.Body.String())
	}
	var orgs []controlplane.Organization
	if err := json.Unmarshal(w.Body.Bytes(), &orgs); err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 1 || orgs[0].ID != orgA.ID {
		t.Fatalf("cross-tenant organization leak: %#v", orgs)
	}

	w = scopedRequest(t, s, http.MethodGet, "/api/v1/projects", "", "user-a", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("projects status=%d body=%s", w.Code, w.Body.String())
	}
	var projects []controlplane.Project
	if err := json.Unmarshal(w.Body.Bytes(), &projects); err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 || projects[0].ID != projectA.ID {
		t.Fatalf("cross-tenant project leak: %#v", projects)
	}

	w = scopedRequest(t, s, http.MethodGet, "/api/v1/organizations/"+orgB.ID, "", "user-a", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign org status=%d body=%s", w.Code, w.Body.String())
	}

	w = scopedRequest(t, s, http.MethodGet, "/api/v1/cluster-imports", "", "user-a", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("imports status=%d body=%s", w.Code, w.Body.String())
	}
	var imports []controlplane.ClusterImport
	if err := json.Unmarshal(w.Body.Bytes(), &imports); err != nil {
		t.Fatal(err)
	}
	if len(imports) != 1 || imports[0].ID != importA.ID {
		t.Fatalf("cross-tenant cluster import leak: %#v", imports)
	}

	w = scopedRequest(t, s, http.MethodGet, "/api/v1/cluster-imports/"+importB.ID, "", "user-a", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign import status=%d body=%s", w.Code, w.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/operations", bytes.NewBufferString(`{"projectId":"`+projectB.ID+`","kind":"APPLY","targetRef":"foreign","desiredRevision":"rev-2","risk":"low"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "cross-tenant-denied")
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "user-a", Roles: []string{"platform-operator"}, Expires: time.Now().Add(time.Hour).Unix()}))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign mutation status=%d body=%s", w.Code, w.Body.String())
	}

	w = scopedRequest(t, s, http.MethodGet, "/api/v1/operations?projectId="+projectB.ID, "", "user-a", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign operation list status=%d body=%s", w.Code, w.Body.String())
	}

	w = scopedRequest(t, s, http.MethodGet, "/api/v1/control-plane/summary", "", "user-a", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("summary status=%d body=%s", w.Code, w.Body.String())
	}
	var summary map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]float64{"organizations": 1, "projects": 1, "operations": 1, "clusterImports": 1} {
		if got, ok := summary[key].(float64); !ok || got != expected {
			t.Fatalf("scoped summary %s=%v want=%v body=%s", key, summary[key], expected, w.Body.String())
		}
	}

	w = scopedRequest(t, s, http.MethodGet, "/api/v1/audit-events?limit=100", "", "user-a", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("audit status=%d body=%s", w.Code, w.Body.String())
	}
	var audit []controlplane.AuditEvent
	if err := json.Unmarshal(w.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	for _, event := range audit {
		for _, forbidden := range []string{orgB.ID, projectB.ID, importB.ID, opB.ID} {
			if event.ResourceID == forbidden {
				t.Fatalf("cross-tenant audit leak: %#v", event)
			}
		}
	}
	seenOwn := false
	for _, event := range audit {
		if event.ResourceID == opA.ID || event.ResourceID == importA.ID || event.ResourceID == projectA.ID || event.ResourceID == orgA.ID {
			seenOwn = true
			break
		}
	}
	if !seenOwn {
		t.Fatalf("own tenant audit unexpectedly empty: %#v", audit)
	}

}

func TestOrganizationMembershipRoleCapsAndRevocation(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, project, _, _ := seedOrganizationScope(t, store)
	membership, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: org.ID, Subject: "viewer", Role: controlplane.OrganizationAdmin}, 0, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)

	// A global viewer stays read-only even if organization membership says admin.
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/projects?organizationId="+org.ID, "", "viewer", "platform-viewer")
	if w.Code != http.StatusOK {
		t.Fatalf("viewer read status=%d body=%s", w.Code, w.Body.String())
	}
	w = scopedRequest(t, s, http.MethodPost, "/api/v1/projects", `{"organizationId":"`+org.ID+`","name":"denied","displayName":"Denied"}`, "viewer", "platform-viewer")
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer elevated by membership status=%d body=%s", w.Code, w.Body.String())
	}

	if _, err := store.RevokeOrganizationMembership(context.Background(), org.ID, "viewer", membership.Revision, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	w = scopedRequest(t, s, http.MethodGet, "/api/v1/projects?organizationId="+org.ID, "", "viewer", "platform-viewer")
	if w.Code != http.StatusForbidden {
		t.Fatalf("revoked membership still active status=%d body=%s", w.Code, w.Body.String())
	}

	// Keep project referenced so this test proves the scope, not an empty tenant.
	if project.ID == "" {
		t.Fatal("seed project missing")
	}
}

func TestDelegatedOrganizationAdminIsScopedToItsOrganization(t *testing.T) {
	store := controlplane.NewMemoryStore()
	orgA, _, _, _ := seedOrganizationScope(t, store)
	orgB, _, _, _ := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgA.ID, Subject: "delegated-admin", Role: controlplane.OrganizationAdmin}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)

	w := scopedRequest(t, s, http.MethodPut, "/api/v1/organizations/"+orgA.ID+"/memberships/member-a", `{"role":"organization-viewer"}`, "delegated-admin", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("delegated org admin could not grant membership status=%d body=%s", w.Code, w.Body.String())
	}
	w = scopedRequest(t, s, http.MethodPost, "/api/v1/projects", `{"organizationId":"`+orgA.ID+`","name":"delegated-project","displayName":"Delegated Project"}`, "delegated-admin", "platform-operator")
	if w.Code != http.StatusCreated {
		t.Fatalf("delegated org admin could not create project status=%d body=%s", w.Code, w.Body.String())
	}
	w = scopedRequest(t, s, http.MethodPut, "/api/v1/organizations/"+orgB.ID+"/memberships/member-b", `{"role":"organization-viewer"}`, "delegated-admin", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("delegated org admin escaped organization scope status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAccessContextPublishesEffectiveScopedRoles(t *testing.T) {
	store := controlplane.NewMemoryStore()
	orgViewer, projectViewer, _, _ := seedOrganizationScope(t, store)
	orgOperator, projectOperator, _, _ := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgViewer.ID, Subject: "scoped-operator", Role: controlplane.OrganizationViewer}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: orgOperator.ID, Subject: "scoped-operator", Role: controlplane.OrganizationOperator}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	w := scopedRequest(t, s, http.MethodGet, "/api/v1/access/context", "", "scoped-operator", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("access context status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		EffectiveOrganizationRoles map[string]string `json:"effectiveOrganizationRoles"`
		EffectiveProjectRoles      map[string]string `json:"effectiveProjectRoles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := body.EffectiveOrganizationRoles[orgViewer.ID]; got != "organization-viewer" {
		t.Fatalf("viewer organization effective role=%q body=%s", got, w.Body.String())
	}
	if got := body.EffectiveProjectRoles[projectViewer.ID]; got != "project-viewer" {
		t.Fatalf("viewer project effective role=%q body=%s", got, w.Body.String())
	}
	if got := body.EffectiveOrganizationRoles[orgOperator.ID]; got != "organization-operator" {
		t.Fatalf("operator organization effective role=%q body=%s", got, w.Body.String())
	}
	if got := body.EffectiveProjectRoles[projectOperator.ID]; got != "project-operator" {
		t.Fatalf("operator project effective role=%q body=%s", got, w.Body.String())
	}
}

func TestAccessContextCapsProjectScopedAPITokenOrganizationRole(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, project, _, _ := seedOrganizationScope(t, store)
	s := scopedServer(t, store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/context", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject:        "svc-project",
		Authentication: "api-token",
		Roles:          []string{"platform-operator"},
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		Expires:        time.Now().Add(time.Hour).Unix(),
	}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("access context status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		EffectiveOrganizationRoles map[string]string `json:"effectiveOrganizationRoles"`
		EffectiveProjectRoles      map[string]string `json:"effectiveProjectRoles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := body.EffectiveOrganizationRoles[org.ID]; got != "organization-viewer" {
		t.Fatalf("project-scoped API token organization role=%q body=%s", got, w.Body.String())
	}
	if got := body.EffectiveProjectRoles[project.ID]; got != "project-operator" {
		t.Fatalf("project-scoped API token project role=%q body=%s", got, w.Body.String())
	}
}

func TestAccessContextPreservesDirectProjectOverride(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, projectDirect, _, _ := seedOrganizationScope(t, store)
	projectInherited, err := store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "inherited", DisplayName: "Inherited"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: org.ID, Subject: "mapped-user", Role: controlplane.OrganizationAdmin}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/context", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject:           "mapped-user",
		Authentication:    "oidc",
		Roles:             []string{"platform-operator"},
		OrganizationRoles: map[string]string{org.ID: "organization-viewer"},
		ProjectRoles:      map[string]string{projectDirect.ID: "project-operator"},
		Expires:           time.Now().Add(time.Hour).Unix(),
	}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("access context status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		EffectiveOrganizationRoles map[string]string `json:"effectiveOrganizationRoles"`
		EffectiveProjectRoles      map[string]string `json:"effectiveProjectRoles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := body.EffectiveOrganizationRoles[org.ID]; got != "organization-viewer" {
		t.Fatalf("direct organization mapping should cap durable admin, got=%q", got)
	}
	if got := body.EffectiveProjectRoles[projectDirect.ID]; got != "project-operator" {
		t.Fatalf("direct project mapping should override inherited organization viewer, got=%q", got)
	}
	if got := body.EffectiveProjectRoles[projectInherited.ID]; got != "project-viewer" {
		t.Fatalf("unmapped project should inherit effective organization viewer, got=%q", got)
	}
}
