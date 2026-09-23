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
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func callGeneratedMCPTool(t *testing.T, srv *Server, principal auth.Principal, id int, name string, arguments map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments}}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := mcpRequestForTest("tools/call", name, string(raw))
	req.Header.Set("X-Request-ID", "req-generated-parity")
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestMCPGeneratedRouteParityCreatesDurableJobAndReplaysWithoutDuplicateMutation(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "ai-route-org", DisplayName: "AI Route Org"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	admin := auth.Principal{Subject: "delegated-admin", Roles: []string{"platform-admin"}, Authentication: "mcp-human", Permissions: []string{"read", "mcp.read", "mcp.operate"}, DelegationAccessProfile: "ADMINISTRATION", AuthorizedClientID: "external-agent", OrganizationID: org.ID}
	tool := "api_post_projects"
	args := map[string]any{"idempotencyKey": "project-once", "body": map[string]any{"organizationId": org.ID, "name": "payments", "displayName": "Payments"}}

	first := callGeneratedMCPTool(t, srv, admin, 1, tool, args)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), controlplane.MCPDurableControlJobAuthority) || !strings.Contains(first.Body.String(), `"replay":false`) {
		jobs, _ := store.ListMCPControlJobs(ctx, org.ID, "", 10)
		t.Fatalf("generated mutation did not complete through durable authority: %d %s jobs=%+v", first.Code, first.Body.String(), jobs)
	}
	projects, err := store.ListProjects(ctx, org.ID)
	if err != nil || len(projects) != 1 {
		t.Fatalf("first mutation not committed exactly once: %+v %v", projects, err)
	}
	jobs, err := store.ListMCPControlJobs(ctx, org.ID, "", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("durable control job missing: %+v %v", jobs, err)
	}
	if jobs[0].State != controlplane.MCPControlJobSucceeded || jobs[0].ToolName != tool || jobs[0].OAuthClientID != "external-agent" || jobs[0].DelegationProfile != "ADMINISTRATION" || jobs[0].RequestDigest == "" || jobs[0].ResponseDigest == "" {
		t.Fatalf("durable job identity/evidence incomplete: %+v", jobs[0])
	}

	second := callGeneratedMCPTool(t, srv, admin, 2, tool, args)
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), `"replay":true`) || !strings.Contains(second.Body.String(), jobs[0].ID) {
		t.Fatalf("terminal result was not replayed: %d %s", second.Code, second.Body.String())
	}
	projects, err = store.ListProjects(ctx, org.ID)
	if err != nil || len(projects) != 1 {
		t.Fatalf("replay duplicated mutation: %+v %v", projects, err)
	}
	jobs2, _ := store.ListMCPControlJobs(ctx, org.ID, "", 10)
	if len(jobs2) != 1 {
		t.Fatalf("replay created duplicate job: %+v", jobs2)
	}

	missing := callGeneratedMCPTool(t, srv, admin, 3, tool, map[string]any{"body": map[string]any{"organizationId": org.ID, "name": "missing-key", "displayName": "Missing"}})
	if missing.Code == http.StatusOK || !strings.Contains(missing.Body.String(), "idempotencyKey is required") {
		t.Fatalf("mutation without idempotency key was not rejected: %d %s", missing.Code, missing.Body.String())
	}
}

func TestMCPGeneratedAdministrationToolsAreHiddenFromAPITokens(t *testing.T) {
	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), controlplane.NewMemoryStore())
	principal := auth.Principal{Subject: "service", Roles: []string{"platform-admin"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read", "mcp.operate"}}
	req := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	for _, tool := range srv.mcpVisibleTools(req) {
		if tool.AdministrationOnly {
			t.Fatalf("API token can see administration-only tool %s", tool.Name)
		}
		if strings.Contains(tool.Name, "_approve") {
			t.Fatalf("API token can see approval tool %s", tool.Name)
		}
	}
}

func TestMCPRouteParityRegistryHasNoUnclassifiedStableRoute(t *testing.T) {
	registry := loadMCPRouteParityRegistry()
	if registry.RouteCount != 353 {
		t.Fatalf("unexpected stable route count: %d", registry.RouteCount)
	}
	if registry.Counts["tool-read"] != 169 || registry.Counts["tool-operate"] != 71 || registry.Counts["tool-admin"] != 73 || registry.Counts["security-excluded"] != 40 {
		t.Fatalf("route parity summary drift: %+v", registry.Counts)
	}
	for _, route := range registry.Routes {
		if route.Disposition == "tool-operate" || route.Disposition == "tool-admin" {
			if !route.DurableJob || !route.IdempotencyRequired {
				t.Fatalf("AI mutation lacks durable semantics: %+v", route)
			}
		}
	}
}

func TestMCPRouteParityClassifiesExternalIntegrationPreviewsAsReadOnly(t *testing.T) {
	registry := loadMCPRouteParityRegistry()
	want := map[string]string{
		"/api/v1/external-registry/admission":            "tool-read",
		"/api/v1/notification-provider-contracts":        "tool-read",
		"/api/v1/notification-routes/{id}/policy-digest": "tool-read",
	}
	seen := map[string]bool{}
	for _, route := range registry.Routes {
		disposition, ok := want[route.Path]
		if !ok {
			continue
		}
		seen[route.Path] = true
		if route.Disposition != disposition || route.DurableJob || route.IdempotencyRequired {
			t.Fatalf("external integration preview route must stay read-only: %+v", route)
		}
	}
	for path := range want {
		if !seen[path] {
			t.Fatalf("external integration route missing from MCP parity: %s", path)
		}
	}
}

func TestAIControlJobListingDoesNotWidenProjectScope(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	orgA, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "job-org-a", DisplayName: "Job Org A"}, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "job-org-b", DisplayName: "Job Org B"}, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	projectA, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgA.ID, Name: "a", DisplayName: "A"}, "bootstrap")
	projectB, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgB.ID, Name: "b", DisplayName: "B"}, "bootstrap")
	makeJob := func(org, project, key string) controlplane.MCPControlJob {
		job, _, e := store.CreateMCPControlJob(ctx, controlplane.MCPControlJob{ToolName: "api_post_test", Family: "test", Action: "test", Method: "POST", Route: "/api/v1/test", Risk: "medium", ActorID: "actor", Authentication: "api-token", OAuthClientID: "client", OrganizationID: org, ProjectID: project, IdempotencyKey: key, RequestDigest: controlplane.MCPControlRequestDigest("api_post_test", []byte(key)), LeaseOwner: "test"}, time.Minute, time.Now().UTC())
		if e != nil {
			t.Fatal(e)
		}
		return job
	}
	jobA := makeJob(orgA.ID, projectA.ID, "a")
	jobB := makeJob(orgB.ID, projectB.ID, "b")
	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	principal := auth.Principal{Subject: "project-reader", Roles: []string{"platform-viewer"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read"}, OrganizationID: orgA.ID, ProjectID: projectA.ID}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ai/control-jobs", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), jobA.ID) || strings.Contains(w.Body.String(), jobB.ID) {
		t.Fatalf("AI control job list widened project scope: %d %s", w.Code, w.Body.String())
	}
	foreign := httptest.NewRequest(http.MethodGet, "/api/v1/ai/control-jobs?projectId="+projectB.ID, nil)
	foreign = foreign.WithContext(auth.WithPrincipal(foreign.Context(), principal))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, foreign)
	if w.Code != http.StatusForbidden {
		t.Fatalf("explicit foreign project scope accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestAIPersianWritingIntegrationIsReadOnlyAndPinned(t *testing.T) {
	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), controlplane.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ai/persian-writing", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Persian-writing integration endpoint failed: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"PERSIAN_WRITING_INTEGRATION_V1", "PERSIAN_WRITING_GATE_V1", "1.3.5", "118c2167f30cafe18df13c0ba85f98f50dad1894", "formal-but-human", `"runtimeNetworkDependency":false`, `"fontAssetsRedistributed":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Persian-writing authority missing %q: %s", want, body)
		}
	}
	registry := loadMCPRouteParityRegistry()
	found := false
	for _, route := range registry.Routes {
		if route.Path == "/api/v1/ai/persian-writing" {
			found = true
			if route.Disposition != "tool-read" || route.DurableJob || route.IdempotencyRequired || route.ToolName != "api_get_ai_persian_writing" {
				t.Fatalf("unexpected Persian-writing MCP disposition: %+v", route)
			}
		}
	}
	if !found {
		t.Fatal("Persian-writing route missing from MCP route-parity authority")
	}
}

func TestAIControlJobRecoveryResolutionIsHumanAdminOnlyAndNeverMCPCallable(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 10, 13, 0, 0, 0, time.UTC)
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "recovery-org", DisplayName: "Recovery Org"}, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	input := controlplane.MCPControlJob{ToolName: "api_post_projects", Family: "projects", Action: "create", Method: "POST", Route: "/api/v1/projects", Risk: "medium", ActorID: "delegated-user", Authentication: "mcp-human", OAuthClientID: "chatgpt", DelegationProfile: "OPERATE", OrganizationID: org.ID, IdempotencyKey: "recovery-http", RequestDigest: controlplane.MCPControlRequestDigest("api_post_projects", []byte("recovery-http")), LeaseOwner: "req-old"}
	job, _, err := store.CreateMCPControlJob(ctx, input, time.Minute, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	job, replay, err := store.CreateMCPControlJob(ctx, input, time.Minute, now)
	if err != nil || !replay || job.State != controlplane.MCPControlJobRecoveryRequired {
		t.Fatalf("job=%+v replay=%v err=%v", job, replay, err)
	}

	srv := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	body := `{"resolution":"CONFIRMED_SUCCEEDED","readbackDigest":"sha256:` + strings.Repeat("a", 64) + `","evidenceDigest":"sha256:` + strings.Repeat("b", 64) + `"}`
	viewer := apiRequest(t, srv.Handler(), http.MethodPost, "/api/v1/ai/control-jobs/"+job.ID+"/resolve-recovery", body, map[string]string{"X-Actor-ID": "viewer", "X-Actor-Role": "platform-viewer", "If-Match": fmt.Sprintf("\"%d\"", job.Revision)})
	if viewer.Code != http.StatusForbidden {
		t.Fatalf("viewer recovery status=%d body=%s", viewer.Code, viewer.Body.String())
	}
	admin := apiRequest(t, srv.Handler(), http.MethodPost, "/api/v1/ai/control-jobs/"+job.ID+"/resolve-recovery", body, map[string]string{"X-Actor-ID": "operator-a", "X-Actor-Role": "platform-admin", "If-Match": fmt.Sprintf("\"%d\"", job.Revision)})
	if admin.Code != http.StatusOK || !strings.Contains(admin.Body.String(), controlplane.MCPControlJobRecoveryAuthority) || !strings.Contains(admin.Body.String(), "CONFIRMED_SUCCEEDED") {
		t.Fatalf("admin recovery status=%d body=%s", admin.Code, admin.Body.String())
	}
	resolved, err := store.GetMCPControlJob(ctx, job.ID)
	if err != nil || resolved.State != controlplane.MCPControlJobSucceeded || resolved.RecoveredBy != "operator-a" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}

	registry := loadMCPRouteParityRegistry()
	found := false
	for _, route := range registry.Routes {
		if route.Method == http.MethodPost && route.Path == "/api/v1/ai/control-jobs/{id}/resolve-recovery" {
			found = true
			if route.Disposition != "security-excluded" || route.ToolName != "" || !strings.Contains(strings.ToLower(route.ExclusionReason), "operator") {
				t.Fatalf("recovery resolution must be security-excluded from MCP: %+v", route)
			}
		}
	}
	if !found {
		t.Fatal("recovery resolution route missing from route-parity registry")
	}
}


func TestMCPVirtualClusterLifecycleRoutesAreTypedAndDeleteIsExplicitlyConfirmed(t *testing.T) {
	registry := loadMCPRouteParityRegistry()
	want := map[string]string{
		"/api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/suspend": "",
		"/api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/resume": "",
		"/api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/delete": "delete-virtual-cluster",
	}
	seen := map[string]bool{}
	for _, route := range registry.Routes {
		confirmation, ok := want[route.Path]
		if !ok { continue }
		seen[route.Path] = true
		if route.Disposition != "tool-operate" || !route.DurableJob || !route.IdempotencyRequired {
			t.Fatalf("virtual cluster lifecycle route lost MCP authority: %+v", route)
		}
		if confirmation != "" {
			if route.ConfirmationHeader != "X-Confirm-Delete" || route.ConfirmationValue != confirmation || route.Risk != "high" {
				t.Fatalf("virtual cluster delete confirmation/risk mismatch: %+v", route)
			}
		}
	}
	for path := range want {
		if !seen[path] { t.Fatalf("virtual cluster lifecycle route missing from MCP parity: %s", path) }
	}
}
