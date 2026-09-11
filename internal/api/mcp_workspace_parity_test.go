package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func TestMCPWorkspaceParityUsesAuthoritativeProjectScopedStore(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "mcp-ws-org", DisplayName: "MCP Workspace Org"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "mcp-ws-project", DisplayName: "MCP Workspace Project"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "mcp-ws-other", DisplayName: "MCP Workspace Other"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, _ := seedAPICluster(t, store, project, "mcp-workspace-cluster", 944)

	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	operator := auth.Principal{Subject: "workspace-operator", Roles: []string{"platform-operator"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read", "mcp.operate"}, OrganizationID: org.ID, ProjectID: project.ID}
	call := func(id int, principal auth.Principal, name string, arguments map[string]any) *httptest.ResponseRecorder {
		body := map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments}}
		raw, _ := json.Marshal(body)
		req := mcpRequestForTest("tools/call", name, string(raw))
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	w := call(1, operator, "workspace_create", map[string]any{"projectId": project.ID, "name": "payments", "displayName": "Payments", "description": "production payment workspace"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), controlplane.WorkspaceAuthority) {
		t.Fatalf("create workspace failed: %d %s", w.Code, w.Body.String())
	}
	workspaces, err := store.ListWorkspaces(ctx, project.ID)
	if err != nil || len(workspaces) != 1 || workspaces[0].CreatedBy != operator.Subject {
		t.Fatalf("workspace not authoritative: %+v %v", workspaces, err)
	}
	workspace := workspaces[0]

	w = call(2, operator, "workspaces", map[string]any{"projectId": project.ID})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), workspace.ID) {
		t.Fatalf("list workspace failed: %d %s", w.Code, w.Body.String())
	}
	w = call(3, operator, "workspace", map[string]any{"id": workspace.ID})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), workspace.Digest) {
		t.Fatalf("get workspace failed: %d %s", w.Code, w.Body.String())
	}

	w = call(4, operator, "workspace_binding_create", map[string]any{"workspaceId": workspace.ID, "clusterId": cluster.ID, "namespace": "payments"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), cluster.ID) {
		t.Fatalf("create binding failed: %d %s", w.Code, w.Body.String())
	}
	bindings, err := store.ListWorkspaceBindings(ctx, workspace.ID)
	if err != nil || len(bindings) != 1 || bindings[0].State != controlplane.WorkspaceBindingActive {
		t.Fatalf("binding not authoritative: %+v %v", bindings, err)
	}
	binding := bindings[0]

	w = call(5, operator, "workspace_bindings", map[string]any{"workspaceId": workspace.ID})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), binding.ID) {
		t.Fatalf("list bindings failed: %d %s", w.Code, w.Body.String())
	}
	w = call(6, operator, "workspace_binding_revoke", map[string]any{"bindingId": binding.ID, "expectedRevision": binding.Revision})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), string(controlplane.WorkspaceBindingRevoked)) {
		t.Fatalf("revoke binding failed: %d %s", w.Code, w.Body.String())
	}

	readOnly := operator
	readOnly.Permissions = []string{"read", "mcp.read"}
	w = call(7, readOnly, "workspace_create", map[string]any{"projectId": project.ID, "name": "blocked", "displayName": "Blocked"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only MCP principal mutated workspace: %d %s", w.Code, w.Body.String())
	}

	otherPrincipal := auth.Principal{Subject: "other-operator", Roles: []string{"platform-operator"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read", "mcp.operate"}, OrganizationID: org.ID, ProjectID: other.ID}
	w = call(8, otherPrincipal, "workspace", map[string]any{"id": workspace.ID})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "project read access") {
		t.Fatalf("cross-project workspace read was not denied: %d %s", w.Code, w.Body.String())
	}

	if got := fmt.Sprint(workspace.ProjectID); got != project.ID {
		t.Fatalf("workspace project drift: %s", got)
	}
}
