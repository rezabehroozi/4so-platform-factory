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

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func TestMCPProjectParityPreservesOrganizationAuthorityAndScope(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "mcp-project-org", DisplayName: "MCP Project Org"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	otherOrg, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "mcp-project-other-org", DisplayName: "MCP Project Other Org"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	seed, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "seed", DisplayName: "Seed"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: otherOrg.ID, Name: "foreign", DisplayName: "Foreign"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}

	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	call := func(id int, principal auth.Principal, name string, arguments map[string]any) *httptest.ResponseRecorder {
		body := map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments}}
		raw, _ := json.Marshal(body)
		req := mcpRequestForTest("tools/call", name, string(raw))
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	// Project-scoped service identities can discover only their own project even when
	// omitting organizationId, and can never call the administration-only creator.
	projectReader := auth.Principal{Subject: "project-reader", Roles: []string{"platform-operator"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read", "mcp.operate"}, OrganizationID: org.ID, ProjectID: seed.ID}
	w := call(1, projectReader, "projects", map[string]any{})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), seed.ID) || strings.Contains(w.Body.String(), foreign.ID) {
		t.Fatalf("project-scoped list leaked or omitted scope: %d %s", w.Code, w.Body.String())
	}
	w = call(2, projectReader, "project_create", map[string]any{"organizationId": org.ID, "name": "blocked", "displayName": "Blocked"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("project-scoped service identity widened scope: %d %s", w.Code, w.Body.String())
	}

	admin := auth.Principal{Subject: "delegated-admin", Roles: []string{"platform-admin"}, Authentication: "mcp-human", Permissions: []string{"read", "mcp.read", "mcp.operate"}, DelegationAccessProfile: "ADMINISTRATION", OrganizationID: org.ID}
	w = call(3, admin, "project_create", map[string]any{"organizationId": org.ID, "name": "payments", "displayName": "Payments"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Payments") {
		t.Fatalf("delegated organization admin could not create project: %d %s", w.Code, w.Body.String())
	}
	projects, err := store.ListProjects(ctx, org.ID)
	if err != nil || len(projects) != 2 {
		t.Fatalf("project was not committed to authoritative store: %+v %v", projects, err)
	}
	createdID := ""
	for _, project := range projects {
		if project.Name == "payments" {
			createdID = project.ID
		}
	}
	if createdID == "" {
		t.Fatalf("created project missing from authority: %+v", projects)
	}

	w = call(4, admin, "projects", map[string]any{"organizationId": org.ID})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), createdID) || strings.Contains(w.Body.String(), foreign.ID) {
		t.Fatalf("organization-scoped project listing drift: %d %s", w.Code, w.Body.String())
	}
	w = call(5, admin, "projects", map[string]any{"organizationId": otherOrg.ID})
	if w.Code != http.StatusForbidden {
		t.Fatalf("delegated organization admin crossed organization boundary: %d %s", w.Code, w.Body.String())
	}
}
