package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/auth"
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
	if guide.Authority != "LAB_CERTIFICATION_MATRIX_V1" || len(guide.Matrix) != 14 {
		t.Fatalf("unexpected guide: %#v", guide)
	}
}

func mcpRequestForTest(method, name, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
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
		{"tools/call", "lab_guide", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lab_guide","arguments":{}}}`, `LAB_CERTIFICATION_MATRIX_V1`},
		{"tools/call", "target_architecture_model", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"target_architecture_model","arguments":{}}}`, `PROGRAM_PHASE_MODEL_V3`},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, mcpRequestForTest(tc.method, tc.name, tc.body))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("method=%s status=%d body=%s", tc.method, w.Code, w.Body.String())
		}
	}
	for _, tool := range mcpTools() {
		if strings.Contains(tool.Name, "create") || strings.Contains(tool.Name, "apply") || strings.Contains(tool.Name, "delete") || strings.Contains(tool.Name, "repair") {
			t.Fatalf("mutating MCP tool leaked into foundation: %s", tool.Name)
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
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "LAB_CERTIFICATION_MATRIX_V1") {
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
	if w.Code != http.StatusOK {
		t.Fatalf("viewer MCP read failed: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "ai.execute") || strings.Contains(w.Body.String(), "delete_cluster") {
		t.Fatalf("mutation authority leaked: %s", w.Body.String())
	}
}

func TestMCPGuideToolListMatchesRuntimeTools(t *testing.T) {
	guide := labmodel.Model()
	want := map[string]bool{}
	for _, name := range guide.MCP.Tools {
		want[name] = true
	}
	got := map[string]bool{}
	for _, tool := range mcpTools() {
		got[tool.Name] = true
	}
	if len(got) != len(want) {
		t.Fatalf("lab guide/runtime MCP tool count drift: guide=%v runtime=%v", guide.MCP.Tools, got)
	}
	for name := range want {
		if !got[name] {
			t.Fatalf("lab guide MCP tool %q is not exposed by runtime", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Fatalf("runtime MCP tool %q is missing from lab guide authority", name)
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
