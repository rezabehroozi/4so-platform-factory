package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/baseline"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/labmodel"
)

func TestLabGuideEndpointReturnsCanonicalMatrix(t *testing.T) {
	s := New("0.0.216", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/lab/guide", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var guide labmodel.Guide
	if err := json.Unmarshal(w.Body.Bytes(), &guide); err != nil {
		t.Fatal(err)
	}
	if guide.Authority != "LAB_CERTIFICATION_MATRIX_V2" || len(guide.Matrix) != 14 {
		t.Fatalf("unexpected guide: %#v", guide)
	}
}

func mcpRequestForTest(method, name, body string) *http.Request {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		panic(err)
	}
	params, _ := request["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
		request["params"] = params
	}
	meta, _ := params["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		params["_meta"] = meta
	}
	meta["io.modelcontextprotocol/protocolVersion"] = mcpProtocolVersion
	if _, ok := meta["io.modelcontextprotocol/clientInfo"]; !ok {
		meta["io.modelcontextprotocol/clientInfo"] = map[string]any{"name": "4so-test-client", "version": "1.0.0"}
	}
	if _, ok := meta["io.modelcontextprotocol/clientCapabilities"]; !ok {
		meta["io.modelcontextprotocol/clientCapabilities"] = map[string]any{}
	}
	raw, err := json.Marshal(request)
	if err != nil {
		panic(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	r.Header.Set("Mcp-Method", method)
	if name != "" {
		r.Header.Set("Mcp-Name", name)
	}
	return r
}

func TestMCPModernDiscoverListAndCallAreReadOnly(t *testing.T) {
	s := New("0.0.216", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tc := range []struct {
		method, name, body, want string
	}{
		{"server/discover", "", `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`, `"supportedVersions"`},
		{"tools/list", "", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, `"lab_guide"`},
		{"tools/call", "lab_guide", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lab_guide","arguments":{}}}`, `LAB_CERTIFICATION_MATRIX_V2`},
		{"tools/call", "target_architecture_model", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"target_architecture_model","arguments":{}}}`, `PROGRAM_PHASE_MODEL_V67`},
		{"tools/call", "mcp_delegation_architecture", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mcp_delegation_architecture","arguments":{}}}`, `MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1`},
		{"tools/call", "mcp_action_registry", `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"mcp_action_registry","arguments":{}}}`, `MCP_PRODUCT_ACTION_REGISTRY_V1`},
		{"tools/call", "platform_version", `{"jsonrpc":"2.0","id":61,"method":"tools/call","params":{"name":"platform_version","arguments":{}}}`, `0.0.216`},
		{"tools/call", "baselines", `{"jsonrpc":"2.0","id":62,"method":"tools/call","params":{"name":"baselines","arguments":{}}}`, `secure-namespace-foundation`},
		{"tools/call", "tenancy_plans", `{"jsonrpc":"2.0","id":63,"method":"tools/call","params":{"name":"tenancy_plans","arguments":{}}}`, `"small"`},
		{"tools/call", "day2_campaign_engine", `{"jsonrpc":"2.0","id":64,"method":"tools/call","params":{"name":"day2_campaign_engine","arguments":{}}}`, `GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1`},
		{"tools/call", "catalog_signing_identity", `{"jsonrpc":"2.0","id":65,"method":"tools/call","params":{"name":"catalog_signing_identity","arguments":{}}}`, `Ed25519`},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, mcpRequestForTest(tc.method, tc.name, tc.body))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("method=%s status=%d body=%s", tc.method, w.Code, w.Body.String())
		}
	}
	listReq := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	listW := httptest.NewRecorder()
	s.Handler().ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK || strings.Contains(listW.Body.String(), `"operation_cancel"`) || strings.Contains(listW.Body.String(), `"cluster_maintenance_request"`) {
		t.Fatalf("unauthenticated inner MCP list leaked mutating tools: status=%d body=%s", listW.Code, listW.Body.String())
	}
	mutateBody := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"operation_cancel","arguments":{"id":"op-test","expectedRevision":1,"reason":"test"}}}`
	mutateW := httptest.NewRecorder()
	s.Handler().ServeHTTP(mutateW, mcpRequestForTest("tools/call", "operation_cancel", mutateBody))
	if mutateW.Code != http.StatusForbidden || !strings.Contains(mutateW.Body.String(), "not authorized") {
		t.Fatalf("unauthenticated inner MCP mutation was not denied before dispatch: status=%d body=%s", mutateW.Code, mutateW.Body.String())
	}

	// The outer development auth middleware injects a local-development
	// platform-admin principal for loopback REST/UI compatibility. MCP must
	// remain read-only in that mode unless an explicit token/delegation is used.
	devReq := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`)
	devPrincipal := auth.Principal{Subject: "local-development", Authentication: "local", Roles: []string{"platform-admin"}}
	devReq = devReq.WithContext(auth.WithPrincipal(devReq.Context(), devPrincipal))
	devW := httptest.NewRecorder()
	s.Handler().ServeHTTP(devW, devReq)
	if devW.Code != http.StatusOK {
		t.Fatalf("development MCP tools/list status=%d body=%s", devW.Code, devW.Body.String())
	}
	var listed struct {
		Result struct {
			Tools []mcpTool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(devW.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode development MCP tools/list: %v body=%s", err, devW.Body.String())
	}
	for _, tool := range listed.Result.Tools {
		if tool.RequiredPermission != controlplane.APITokenPermissionMCPRead || tool.AdministrationOnly {
			t.Fatalf("development MCP leaked non-read tool %q permission=%q administrationOnly=%v", tool.Name, tool.RequiredPermission, tool.AdministrationOnly)
		}
	}
}

func TestMCPRejectsHeaderBodyDisagreement(t *testing.T) {
	s := New("0.0.216", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Mcp-Method") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCPAcceptsModernClientMetadataShape(t *testing.T) {
	s := New("0.0.216", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"lab_guide","arguments":{},"_meta":{"io.modelcontextprotocol/clientInfo":{"name":"external-lab-agent","version":"1.0"},"io.modelcontextprotocol/clientCapabilities":{"tools":{}}}}}`
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, mcpRequestForTest("tools/call", "lab_guide", body))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "LAB_CERTIFICATION_MATRIX_V2") {
		t.Fatalf("modern MCP client metadata was rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCPAPITokenRequiresDedicatedReadPermission(t *testing.T) {
	s := New("0.0.217", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	base := mcpRequestForTest("tools/list", "", body)
	principal := auth.Principal{Subject: "svc-1", Roles: []string{"platform-viewer"}, Authentication: "api-token", Permissions: []string{"read"}}
	denied := base.WithContext(auth.WithPrincipal(base.Context(), principal))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, denied)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only token unexpectedly accessed MCP: status=%d body=%s", w.Code, w.Body.String())
	}

	allowedReq := mcpRequestForTest("tools/list", "", body)
	principal.Permissions = []string{"read", "mcp.read"}
	allowedReq = allowedReq.WithContext(auth.WithPrincipal(allowedReq.Context(), principal))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, allowedReq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ai_runtime_policy") {
		t.Fatalf("mcp.read rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCPOIDCViewerCanReadButCannotGainMutationTools(t *testing.T) {
	s := New("0.0.217", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Subject: "viewer", Roles: []string{"platform-viewer"}, Authentication: "oidc"}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "authorized client identity") {
		t.Fatalf("human OIDC token without OAuth client/grant unexpectedly accessed MCP: %d %s", w.Code, w.Body.String())
	}
}

func TestMCPGuideToolListMatchesRuntimeTools(t *testing.T) {
	guide := labmodel.Model()
	runtime := map[string]mcpTool{}
	for _, tool := range mcpTools() {
		runtime[tool.Name] = tool
	}
	// The lab guide owns the curated human-readable tool families. The generated
	// route-parity authority owns the complete stable REST surface. Both must be
	// represented by the runtime; duplicating hundreds of generated names in the
	// lab guide would create a second source of truth.
	for _, name := range append(append([]string{}, guide.MCP.Tools...), guide.MCP.MutatingTools...) {
		if _, ok := runtime[name]; !ok {
			t.Fatalf("lab guide MCP tool %q is not exposed by runtime", name)
		}
	}
	for _, route := range loadMCPRouteParityRegistry().Routes {
		if route.Disposition == "security-excluded" {
			if route.ToolName != "" {
				t.Fatalf("security-excluded route unexpectedly has tool: %s %s", route.Method, route.Path)
			}
			continue
		}
		if _, ok := runtime[route.ToolName]; !ok {
			t.Fatalf("route-parity MCP tool %q is missing for %s %s", route.ToolName, route.Method, route.Path)
		}
	}
}

func TestMCPProjectScopedOperationToolUsesAuthoritativeStore(t *testing.T) {
	s, _, _, op, _ := aiDiagnosisFixture(t)
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"operation_status","arguments":{"id":"` + op.ID + `"}}}`
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, mcpRequestForTest("tools/call", "operation_status", body))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), op.ID) {
		t.Fatalf("operation tool status=%d body=%s", w.Code, w.Body.String())
	}
	invalid := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"operation_status","arguments":{}}}`
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, mcpRequestForTest("tools/call", "operation_status", invalid))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing id accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestMCP20260728RequiresMetadataAndCompleteResults(t *testing.T) {
	s := New("0.0.225", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	missingMeta := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}}`))
	missingMeta.Header.Set("Content-Type", "application/json")
	missingMeta.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	missingMeta.Header.Set("Mcp-Method", "tools/list")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, missingMeta)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":-32602`) {
		t.Fatalf("missing MCP metadata accepted: status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":12,"method":"tools/list"}`))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"resultType":"complete"`) || !strings.Contains(w.Body.String(), "io.modelcontextprotocol/serverInfo") {
		t.Fatalf("2026-07-28 complete result metadata missing: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCP20260728UsesProtocolSpecificHeaderErrors(t *testing.T) {
	s := New("0.0.225", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mismatch := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":21,"method":"tools/list"}`)
	mismatch.Header.Set("MCP-Protocol-Version", "2099-01-01")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, mismatch)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":-32020`) {
		t.Fatalf("header/body mismatch did not use HeaderMismatch: status=%d body=%s", w.Code, w.Body.String())
	}

	unsupportedBody := `{"jsonrpc":"2.0","id":22,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`
	unsupported := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(unsupportedBody))
	unsupported.Header.Set("Content-Type", "application/json")
	unsupported.Header.Set("MCP-Protocol-Version", "2099-01-01")
	unsupported.Header.Set("Mcp-Method", "tools/list")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, unsupported)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":-32022`) || !strings.Contains(w.Body.String(), mcpProtocolVersion) {
		t.Fatalf("unsupported protocol did not use UnsupportedProtocolVersion: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCP20260728AcceptsBase64McpNameSentinel(t *testing.T) {
	s := New("0.0.225", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := mcpRequestForTest("tools/call", "lab_guide", `{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"lab_guide","arguments":{}}}`)
	r.Header.Set("Mcp-Name", "=?base64?bGFiX2d1aWRl?=")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "LAB_CERTIFICATION_MATRIX_V2") {
		t.Fatalf("base64 Mcp-Name sentinel rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCPRejectsTrailingJSONValue(t *testing.T) {
	s := New("0.0.225", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := `{"jsonrpc":"2.0","id":41,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + mcpProtocolVersion + `","io.modelcontextprotocol/clientCapabilities":{}}}} {}`
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	r.Header.Set("Mcp-Method", "tools/list")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":-32700`) {
		t.Fatalf("trailing JSON value accepted: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCPExternalClientTCPInteroperabilityAndProjectScope(t *testing.T) {
	s, store, project, op, _ := aiDiagnosisFixture(t)
	ctx := context.Background()
	foreignProject, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: project.OrganizationID, Name: "mcp-foreign-project", DisplayName: "MCP Foreign Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	foreignOp, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: foreignProject.ID, Kind: "cluster.inspect", TargetRef: "cluster/foreign", DesiredRevision: "sha256:" + strings.Repeat("b", 64), Risk: "low", Class: controlplane.OperationClassReadOnly}, "mcp-foreign-op", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}

	product := s.Handler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer external-good" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		principal := auth.Principal{
			Subject:        "external-mcp-client",
			Roles:          []string{"platform-viewer"},
			Authentication: "api-token",
			Permissions:    []string{"read", "mcp.read"},
			OrganizationID: project.OrganizationID,
			ProjectID:      project.ID,
		}
		product.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	}))
	defer server.Close()

	script := filepath.Join("..", "..", "scripts", "mcp_external_client_certify.py")
	cmd := exec.Command("python3", script,
		"--endpoint", server.URL+"/mcp",
		"--token", "external-good",
		"--operation-id", op.ID,
		"--project-id", project.ID,
		"--forbidden-operation-id", foreignOp.ID,
		"--timeout", "5",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("external MCP client failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "MCP_EXTERNAL_CLIENT_CERTIFICATION_PASS") || !strings.Contains(string(output), "negativeScope=checked") {
		t.Fatalf("external MCP client did not produce certification authority: %s", output)
	}
}

func TestMCPDelegatedOperationCancelRequiresOperateScopeAndRevision(t *testing.T) {
	s, store, project, op, _ := aiDiagnosisFixture(t)
	readPrincipal := auth.Principal{Subject: "reader-agent", Roles: []string{"platform-operator"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read"}, OrganizationID: project.OrganizationID, ProjectID: project.ID}
	listReq := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":61,"method":"tools/list"}`)
	listReq = listReq.WithContext(auth.WithPrincipal(listReq.Context(), readPrincipal))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, listReq)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"operation_cancel"`) {
		t.Fatalf("read-only MCP client saw delegated mutation tool: %d %s", w.Code, w.Body.String())
	}

	cancelBody := fmt.Sprintf(`{"jsonrpc":"2.0","id":62,"method":"tools/call","params":{"name":"operation_cancel","arguments":{"id":%q,"expectedRevision":%d,"reason":"operator requested stop"}}}`, op.ID, op.Revision)
	denied := mcpRequestForTest("tools/call", "operation_cancel", cancelBody)
	denied = denied.WithContext(auth.WithPrincipal(denied.Context(), readPrincipal))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, denied)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not authorized") {
		t.Fatalf("read-only token unexpectedly cancelled operation: %d %s", w.Code, w.Body.String())
	}

	operator := readPrincipal
	operator.Subject = "delegated-operator-agent"
	operator.Permissions = []string{"read", "mcp.read", "mcp.operate"}
	allowed := mcpRequestForTest("tools/call", "operation_cancel", cancelBody)
	allowed = allowed.WithContext(auth.WithPrincipal(allowed.Context(), operator))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, allowed)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "MCP_AGENT_DELEGATED_OPERATION_AUTHORITY_V1") {
		t.Fatalf("delegated operation cancel failed: %d %s", w.Code, w.Body.String())
	}
	updated, err := store.GetOperation(context.Background(), op.ID)
	if err != nil || updated.Revision != op.Revision+1 || (updated.State != controlplane.OperationCancelled && updated.State != controlplane.OperationCancelRequested) {
		t.Fatalf("durable operation was not cancelled through store authority: op=%#v err=%v", updated, err)
	}

	stale := mcpRequestForTest("tools/call", "operation_cancel", cancelBody)
	stale = stale.WithContext(auth.WithPrincipal(stale.Context(), operator))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, stale)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "stale") {
		t.Fatalf("stale expectedRevision did not fail closed: %d %s", w.Code, w.Body.String())
	}
}

func TestMCPStreamableHTTPRejectsInvalidMediaTypeAndBrowserOrigin(t *testing.T) {
	s := New("0.0.225", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := `{"jsonrpc":"2.0","id":51,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + mcpProtocolVersion + `","io.modelcontextprotocol/clientCapabilities":{}}}}`

	wrongMedia := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	wrongMedia.Header.Set("Content-Type", "text/plain; a=application/json")
	wrongMedia.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	wrongMedia.Header.Set("Mcp-Method", "tools/list")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, wrongMedia)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("invalid MCP media type accepted: status=%d body=%s", w.Code, w.Body.String())
	}

	browserOrigin := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	browserOrigin.Header.Set("Content-Type", "application/json")
	browserOrigin.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	browserOrigin.Header.Set("Mcp-Method", "tools/list")
	browserOrigin.Header.Set("Origin", "https://attacker.example")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, browserOrigin)
	if w.Code != http.StatusForbidden {
		t.Fatalf("browser Origin MCP request accepted without an origin policy: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCPHighImpactMaintenanceRequestStopsAtIndependentApproval(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "mcp-maint-org", DisplayName: "MCP Maintenance Org"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "mcp-maint", DisplayName: "MCP Maintenance"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	cluster, rawToken, _ := seedAPICluster(t, store, project, "mcp-maint-cluster", 187)
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(rawToken), cluster.ExternalUID, controlplane.ClusterInventory{
		ObservedAt: time.Now().UTC(), Distribution: "rke2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}, KubernetesVersion: "1.31.0", Digest: "sha256:" + fmt.Sprintf("%064x", 8187),
		Nodes: []controlplane.ClusterNode{{Name: "worker-1", UID: "uid-worker-1", Ready: true, Roles: []string{"worker"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertClusterMaintenanceProfile(ctx, controlplane.ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: cluster.ID, Environment: controlplane.ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 300}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	window, err := store.CreateClusterMaintenanceWindow(ctx, controlplane.ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: cluster.ID, Name: "mcp-window", StartsAt: time.Now().UTC().Add(-time.Minute), EndsAt: time.Now().UTC().Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 300}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}

	s := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	reader := auth.Principal{Subject: "maintenance-reader-agent", Roles: []string{"platform-operator"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read"}, OrganizationID: org.ID, ProjectID: project.ID}
	contextBody := fmt.Sprintf(`{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"cluster_maintenance_context","arguments":{"id":%q}}}`, cluster.ID)
	r := mcpRequestForTest("tools/call", "cluster_maintenance_context", contextBody)
	r = r.WithContext(auth.WithPrincipal(r.Context(), reader))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), window.ID) || !strings.Contains(w.Body.String(), controlplane.ClusterMaintenanceAuthorityMethod) {
		t.Fatalf("maintenance context failed: %d %s", w.Code, w.Body.String())
	}

	operator := reader
	operator.Subject = "maintenance-request-agent"
	operator.Permissions = []string{"read", "mcp.read", "mcp.operate"}
	requestBody := fmt.Sprintf(`{"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"cluster_maintenance_request","arguments":{"clusterId":%q,"windowId":%q,"nodeNames":["worker-1"],"idempotencyKey":"mcp-maint-1"}}}`, cluster.ID, window.ID)
	r = mcpRequestForTest("tools/call", "cluster_maintenance_request", requestBody)
	r = r.WithContext(auth.WithPrincipal(r.Context(), operator))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"approvalRequired":true`) || !strings.Contains(w.Body.String(), `"requesterMayApprove":false`) || !strings.Contains(w.Body.String(), string(controlplane.OperationAwaitingApproval)) {
		t.Fatalf("maintenance delegated request failed to stop at approval: %d %s", w.Code, w.Body.String())
	}
	runs, err := store.ListClusterMaintenanceRuns(ctx, cluster.ID)
	if err != nil || len(runs) != 1 || runs[0].State != controlplane.ClusterMaintenanceAwaitingApproval || runs[0].RequestedBy != operator.Subject {
		t.Fatalf("maintenance run authority mismatch: runs=%+v err=%v", runs, err)
	}
	ops, err := store.ListOperations(ctx, project.ID)
	if err != nil || len(ops) != 1 || ops[0].State != controlplane.OperationAwaitingApproval {
		t.Fatalf("maintenance operation did not remain approval-gated: ops=%+v err=%v", ops, err)
	}

	// Replaying the exact request is idempotent and never self-approves it.
	r = mcpRequestForTest("tools/call", "cluster_maintenance_request", requestBody)
	r = r.WithContext(auth.WithPrincipal(r.Context(), operator))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"idempotentReplay":true`) {
		t.Fatalf("maintenance MCP idempotent replay failed: %d %s", w.Code, w.Body.String())
	}
	visible := s.mcpVisibleTools(r.WithContext(auth.WithPrincipal(r.Context(), operator)))
	for _, tool := range visible {
		if tool.Name == "cluster_maintenance_approve" || tool.Name == "identity_admin_job_approve" || tool.Name == "upgrade_campaign_approve" {
			t.Fatalf("requesting API-token agent was given an administration approval tool: %s", tool.Name)
		}
	}

	// A distinct human ADMINISTRATION delegation can approve the request through
	// a separate typed tool, while the original requester remains unable to do so.
	selfApprover := auth.Principal{Subject: operator.Subject, Roles: []string{"platform-admin"}, Authentication: "mcp-human", DelegationAccessProfile: "ADMINISTRATION", OrganizationID: org.ID, ProjectID: project.ID}
	approveBody := fmt.Sprintf(`{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{"name":"cluster_maintenance_approve","arguments":{"id":%q,"expectedRevision":%d}}}`, runs[0].ID, runs[0].Revision)
	r = mcpRequestForTest("tools/call", "cluster_maintenance_approve", approveBody)
	r = r.WithContext(auth.WithPrincipal(r.Context(), selfApprover))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "separation of duties") {
		t.Fatalf("requester self-approval was not rejected: %d %s", w.Code, w.Body.String())
	}
	approver := selfApprover
	approver.Subject = "maintenance-independent-admin"
	r = mcpRequestForTest("tools/call", "cluster_maintenance_approve", approveBody)
	r = r.WithContext(auth.WithPrincipal(r.Context(), approver))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), string(controlplane.ClusterMaintenanceQueued)) {
		t.Fatalf("independent MCP maintenance approval failed: %d %s", w.Code, w.Body.String())
	}
}

func TestMCPDelegatedRegistryCoversAssuranceAndUpgradeWithoutSelfApproval(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "mcp-registry-org", DisplayName: "MCP Registry Org"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "mcp-registry", DisplayName: "MCP Registry"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, baselineDeployment := seedAPICluster(t, store, project, "mcp-registry-cluster", 288)
	group, _, err := store.CreateFleetGroup(ctx, controlplane.FleetGroup{ProjectID: project.ID, Name: "mcp-registry-fleet", DisplayName: "MCP Registry Fleet", ClusterIDs: []string{cluster.ID}, IdempotencyKey: "mcp-registry-fleet", RequestDigest: fmt.Sprintf("sha256:%064x", 9288)}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	checkpoint, err := store.CreateRecoveryCheckpoint(ctx, controlplane.RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "s3://backup/mcp-registry", EvidenceDigest: fmt.Sprintf("sha256:%064x", 9388), CompletedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}

	s := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	s.ConfigureFleetImport("registry.example/agent@sha256:"+strings.Repeat("a", 64), "registry.example/probe@sha256:"+strings.Repeat("b", 64), "https://factory.example", "")
	principal := auth.Principal{Subject: "registry-agent", Roles: []string{"platform-operator"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read", "mcp.operate"}, OrganizationID: org.ID, ProjectID: project.ID}
	call := func(id int, name, args string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, name, args)
		r := mcpRequestForTest("tools/call", name, body)
		r = r.WithContext(auth.WithPrincipal(r.Context(), principal))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	w := call(81, "drift_scan_request", fmt.Sprintf(`{"projectId":%q,"clusterIds":[%q],"idempotencyKey":"mcp-drift-1"}`, project.ID, cluster.ID))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"family":"assurance"`) || !strings.Contains(w.Body.String(), `"risk":"low"`) {
		t.Fatalf("drift request failed: %d %s", w.Code, w.Body.String())
	}
	scans, err := store.ListDriftScans(ctx, project.ID, "")
	if err != nil || len(scans) != 1 {
		t.Fatalf("drift scan not persisted: %+v %v", scans, err)
	}

	w = call(82, "runtime_verification_request", fmt.Sprintf(`{"projectId":%q,"clusterId":%q,"baselineDeploymentId":%q,"idempotencyKey":"mcp-runtime-1"}`, project.ID, cluster.ID, baselineDeployment.ID))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"family":"assurance"`) {
		t.Fatalf("runtime verification request failed: %d %s", w.Code, w.Body.String())
	}
	verifications, err := store.ListRuntimeVerifications(ctx, project.ID, cluster.ID, baselineDeployment.ID)
	if err != nil || len(verifications) != 1 {
		t.Fatalf("runtime verification not persisted: %+v %v", verifications, err)
	}

	start, end := now.Add(10*time.Minute), now.Add(2*time.Hour)
	w = call(83, "upgrade_campaign_request", fmt.Sprintf(`{"projectId":%q,"fleetGroupId":%q,"targetVersion":%q,"maintenanceWindowStart":%q,"maintenanceWindowEnd":%q,"recoveryCheckpointIds":[%q],"idempotencyKey":"mcp-upgrade-1"}`, project.ID, group.ID, baseline.SecureNamespaceUpgradeVersion, start.Format(time.RFC3339), end.Format(time.RFC3339), checkpoint.ID))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"approvalRequired":true`) || !strings.Contains(w.Body.String(), `"requesterMayApprove":false`) || !strings.Contains(w.Body.String(), string(controlplane.UpgradeCampaignAwaitingApproval)) {
		t.Fatalf("upgrade request failed to stop at approval: %d %s", w.Code, w.Body.String())
	}
	campaigns, err := store.ListUpgradeCampaigns(ctx, project.ID, group.ID)
	if err != nil || len(campaigns) != 1 || campaigns[0].State != controlplane.UpgradeCampaignAwaitingApproval || campaigns[0].RequestedBy != principal.Subject {
		t.Fatalf("upgrade authority mismatch: %+v %v", campaigns, err)
	}
	listReq := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":90,"method":"tools/list"}`)
	listReq = listReq.WithContext(auth.WithPrincipal(listReq.Context(), principal))
	for _, tool := range s.mcpVisibleTools(listReq) {
		if strings.Contains(tool.Name, "approve") {
			t.Fatalf("API-token delegated registry exposed administration approval tool: %s", tool.Name)
		}
	}
}

func TestMCPSupportBundleRequestUsesDurableSealedEvidencePipeline(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "mcp-support-org", DisplayName: "MCP Support Org"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "mcp-support", DisplayName: "MCP Support"}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	s := New("0.0.test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	principal := auth.Principal{Subject: "support-agent", Roles: []string{"platform-operator"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read", "mcp.operate"}, OrganizationID: org.ID, ProjectID: project.ID}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"support_bundle_request","arguments":{"profile":"fleet-diagnostics","projectId":%q,"idempotencyKey":"support-1"}}}`, project.ID)
	call := func() *httptest.ResponseRecorder {
		r := mcpRequestForTest("tools/call", "support_bundle_request", body)
		r = r.WithContext(auth.WithPrincipal(r.Context(), principal))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := call()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), supportBundleOperationKind) || !strings.Contains(w.Body.String(), `"statusTool":"operation_status"`) {
		t.Fatalf("support bundle MCP request failed: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "downloadUrl") || strings.Contains(w.Body.String(), "payload") {
		t.Fatalf("support bundle payload/download leaked inline through MCP: %s", w.Body.String())
	}
	ops, err := store.ListOperations(ctx, project.ID)
	if err != nil || len(ops) != 1 || ops[0].Kind != supportBundleOperationKind || ops[0].State != controlplane.OperationQueued {
		t.Fatalf("support bundle durable operation mismatch: ops=%+v err=%v", ops, err)
	}
	w = call()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"replay":true`) {
		t.Fatalf("support bundle MCP idempotent replay failed: %d %s", w.Code, w.Body.String())
	}
	ops, _ = store.ListOperations(ctx, project.ID)
	if len(ops) != 1 {
		t.Fatalf("idempotent replay duplicated support bundle operation: %+v", ops)
	}
}
