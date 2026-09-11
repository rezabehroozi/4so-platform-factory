package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type failingEntropyReader struct{}

func (failingEntropyReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestOIDCLoginFailsClosedWhenEntropyUnavailable(t *testing.T) {
	manager, err := New(Config{
		Enabled:       true,
		Issuer:        "https://issuer.test",
		InternalBase:  "https://issuer.internal",
		ClientID:      "platform-console",
		RedirectURL:   "https://platform.test/auth/callback",
		SessionSecret: strings.Repeat("s", 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.entropy = failingEntropyReader{}

	r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	manager.login(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if location := w.Header().Get("Location"); location != "" {
		t.Fatalf("login redirected despite entropy failure: %q", location)
	}
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("login emitted cookies despite entropy failure: %#v", cookies)
	}
}

func TestSignedSessionRoundTrip(t *testing.T) {
	testSecret := strings.Repeat("s", 40)
	manager, err := New(Config{Enabled: true, Issuer: "https://issuer.test", InternalBase: "http://issuer", ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	original := Principal{Subject: "user-1", Email: "user@example.test", Expires: time.Now().Add(time.Hour).Unix()}
	signed, err := manager.sign(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Principal
	if err = manager.unsign(signed, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Subject != original.Subject {
		t.Fatalf("decoded=%+v", decoded)
	}
}

func TestReadOnlyPostClassification(t *testing.T) {
	for _, path := range []string{
		"/api/v1/blueprints/validate",
		"/api/v1/installations/plans",
		"/api/v1/blueprint-releases/compare",
		"/api/v1/runtime-closure-reports/verify",
		"/api/v1/support-bundles",
		"/api/v1/ai/diagnose",
		"/mcp",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if requiresOperatorRole(req) {
			t.Fatalf("read-only POST %s unexpectedly requires operator role", path)
		}
	}
	for _, path := range []string{
		"/api/v1/marketplace/recommendations",
		"/api/v1/system-services/git/repositories",
		"/api/v1/system-services/git/revisions",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if !requiresOperatorRole(req) {
			t.Fatalf("mutating POST %s unexpectedly classified read-only", path)
		}
	}
}

func TestBootstrapBypass(t *testing.T) {
	testSecret := strings.Repeat("s", 40)
	bootstrapValue := strings.Repeat("b", 32)
	manager, _ := New(Config{Enabled: true, Issuer: "https://issuer.test", InternalBase: "http://issuer", ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: testSecret, BootstrapToken: bootstrapValue})
	handler := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Actor-ID") != "bootstrap-installer" {
			t.Fatalf("actor=%q", r.Header.Get("X-Actor-ID"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	request.Header.Set("X-Platform-Bootstrap-Token", bootstrapValue)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestJWTVerification(t *testing.T) {
	testSecret := strings.Repeat("s", 40)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kid": kid, "kty": "RSA", "use": "sig", "n": n, "e": e}}})
	}))
	defer server.Close()
	issuer := "https://issuer.test"
	manager, _ := New(Config{Enabled: true, Issuer: issuer, InternalBase: server.URL, ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: testSecret})
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
	claims, _ := json.Marshal(map[string]any{"sub": "user-1", "iss": issuer, "aud": "platform-console", "exp": time.Now().Add(time.Hour).Unix(), "nonce": "nonce", "realm_access": map[string]any{"roles": []string{"platform-admin"}}})
	left := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(left))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	token := left + "." + base64.RawURLEncoding.EncodeToString(signature)
	principal, err := manager.verifyJWT(context.Background(), token, "nonce")
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "user-1" || len(principal.Roles) != 1 {
		t.Fatalf("principal=%+v", principal)
	}
}

func TestDisabledAuthWithoutExplicitDevelopmentRejects(t *testing.T) {
	manager, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler must not be reached") }))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestBootstrapTokenIsEndpointScoped(t *testing.T) {
	manager, err := New(Config{Enabled: true, Issuer: "https://issuer.test", InternalBase: "https://issuer.internal", ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: strings.Repeat("s", 40), BootstrapToken: strings.Repeat("b", 32)})
	if err != nil {
		t.Fatal(err)
	}
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/catalog/releases", nil)
	r.Header.Set("X-Platform-Bootstrap-Token", strings.Repeat("b", 32))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bootstrap token unexpectedly authorized non-bootstrap endpoint: status=%d body=%s", w.Code, w.Body.String())
	}
}
func TestDisabledAuthInjectsLocalActorContract(t *testing.T) {
	manager, err := New(Config{Enabled: false, LocalDevelopment: true})
	if err != nil {
		t.Fatal(err)
	}
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Actor-ID"); got != "local-development" {
			t.Fatalf("actor=%q", got)
		}
		if got := r.Header.Get("X-Actor-Role"); got != "platform-admin" {
			t.Fatalf("role=%q", got)
		}
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.Subject != "local-development" {
			t.Fatalf("principal=%#v ok=%v", principal, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestDisabledAuthOverwritesSpoofedActorHeaders(t *testing.T) {
	manager, err := New(Config{Enabled: false, LocalDevelopment: true})
	if err != nil {
		t.Fatal(err)
	}
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Actor-ID"); got != "local-development" {
			t.Fatalf("actor=%q", got)
		}
		if got := r.Header.Get("X-Actor-Role"); got != "platform-admin" {
			t.Fatalf("role=%q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", nil)
	r.Header.Set("X-Actor-ID", "attacker")
	r.Header.Set("X-Actor-Role", "platform-admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestBootstrapAuthOverwritesSpoofedActorHeaders(t *testing.T) {
	manager, err := New(Config{Enabled: true, Issuer: "https://issuer.test", InternalBase: "http://issuer", ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: strings.Repeat("s", 40), BootstrapToken: strings.Repeat("b", 32)})
	if err != nil {
		t.Fatal(err)
	}
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.Subject != "bootstrap-installer" || !HasAnyRole(principal, "platform-admin") {
			t.Fatalf("principal=%+v ok=%v", principal, ok)
		}
		if got := r.Header.Get("X-Actor-ID"); got != "bootstrap-installer" {
			t.Fatalf("actor=%q", got)
		}
		if got := r.Header.Get("X-Actor-Role"); got != "platform-admin" {
			t.Fatalf("role=%q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects", nil)
	r.Header.Set("X-Platform-Bootstrap-Token", strings.Repeat("b", 32))
	r.Header.Set("X-Actor-ID", "attacker")
	r.Header.Set("X-Actor-Role", "platform-viewer")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAuthenticatedSessionOverwritesSpoofedActorAndRole(t *testing.T) {
	manager, err := New(Config{Enabled: true, Issuer: "https://issuer.test", InternalBase: "http://issuer", ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: strings.Repeat("s", 40)})
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{Subject: "operator-1", Roles: []string{"platform-operator"}, Expires: time.Now().Add(time.Hour).Unix()}
	session, err := manager.sign(principal)
	if err != nil {
		t.Fatal(err)
	}
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Actor-ID"); got != "operator-1" {
			t.Fatalf("actor=%q", got)
		}
		if got := r.Header.Get("X-Actor-Role"); got != "platform-operator" {
			t.Fatalf("role=%q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects", nil)
	r.AddCookie(&http.Cookie{Name: "platform_session", Value: session})
	r.Header.Set("X-Actor-ID", "attacker")
	r.Header.Set("X-Actor-Role", "platform-admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestViewerMutationIsRejected(t *testing.T) {
	manager, err := New(Config{Enabled: true, Issuer: "https://issuer.test", InternalBase: "http://issuer", ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: strings.Repeat("s", 40)})
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{Subject: "viewer-1", Roles: []string{"platform-viewer"}, Expires: time.Now().Add(time.Hour).Unix()}
	session, err := manager.sign(principal)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects", nil)
	r.AddCookie(&http.Cookie{Name: "platform_session", Value: session})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d called=%v body=%s", w.Code, called, w.Body.String())
	}
}

func TestViewerMayUsePureValidationPost(t *testing.T) {
	manager, err := New(Config{Enabled: true, Issuer: "https://issuer.test", InternalBase: "http://issuer", ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: strings.Repeat("s", 40)})
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{Subject: "viewer-1", Roles: []string{"platform-viewer"}, Expires: time.Now().Add(time.Hour).Unix()}
	session, err := manager.sign(principal)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/v1/blueprints/validate",
		"/api/v1/blueprints/authoring-roundtrip",
		"/api/v1/blueprints/resolve",
		"/api/v1/compatibility/evaluate",
		"/api/v1/plans",
		"/api/v1/installations/plans",
		"/api/v1/runtime-closure-reports/verify",
		"/api/v1/support-bundles",
	} {
		t.Run(path, func(t *testing.T) {
			called := false
			h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
			r := httptest.NewRequest(http.MethodPost, path, nil)
			r.AddCookie(&http.Cookie{Name: "platform_session", Value: session})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent || !called {
				t.Fatalf("path=%s status=%d called=%v body=%s", path, w.Code, called, w.Body.String())
			}
		})
	}
}

func TestOIDCSessionReResolvesGroupsAndExpiresAtPropagationTTL(t *testing.T) {
	role := "platform-operator"
	mapper := func(_ context.Context, groups []string) (GroupMappingResult, error) {
		if len(groups) == 1 && groups[0] == "ops" {
			return GroupMappingResult{Roles: []string{role}, OrganizationRoles: map[string]string{"org-1": "organization-operator"}, MappingDigest: "sha256:" + strings.Repeat("a", 64)}, nil
		}
		return GroupMappingResult{}, nil
	}
	manager, err := New(Config{Enabled: true, Issuer: "https://issuer.test", InternalBase: "http://issuer", ClientID: "platform-console", RedirectURL: "https://platform.test/auth/callback", SessionSecret: strings.Repeat("s", 40), GroupMapper: mapper, GroupPropagationTTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{Subject: "user-1", Groups: []string{"ops"}, Roles: []string{"stale-role"}, MappedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), Authentication: "oidc"}
	session, _ := manager.sign(principal)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	r.AddCookie(&http.Cookie{Name: "platform_session", Value: session})
	got, err := manager.authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if !HasAnyRole(got, "platform-operator") || got.OrganizationRoles["org-1"] != "organization-operator" {
		t.Fatalf("mapped=%#v", got)
	}
	role = "platform-viewer"
	got, err = manager.authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if !HasAnyRole(got, "platform-viewer") || HasAnyRole(got, "platform-operator") {
		t.Fatalf("mapping change not applied %#v", got)
	}
	principal.MappedAt = time.Now().Add(-6 * time.Minute).Unix()
	session, _ = manager.sign(principal)
	expired := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	expired.AddCookie(&http.Cookie{Name: "platform_session", Value: session})
	if _, err = manager.authenticate(expired); err == nil {
		t.Fatal("stale group session accepted")
	}
}

func TestAllowedRequestFailsClosedWhenSecurityAuditUnavailable(t *testing.T) {
	manager, err := New(Config{
		Enabled:        true,
		Issuer:         "https://issuer.test",
		InternalBase:   "http://issuer",
		ClientID:       "platform-console",
		RedirectURL:    "https://platform.test/auth/callback",
		SessionSecret:  strings.Repeat("s", 40),
		BootstrapToken: strings.Repeat("b", 32),
		AuditSink: func(context.Context, SecurityAuditRecord) error {
			return errors.New("audit persistence unavailable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	r.Header.Set("X-Platform-Bootstrap-Token", strings.Repeat("b", 32))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("status=%d called=%v body=%s", w.Code, called, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "SECURITY_AUDIT_UNAVAILABLE") {
		t.Fatalf("body=%s", w.Body.String())
	}
}

func TestDeniedRequestSurfacesSecurityAuditBackpressure(t *testing.T) {
	manager, err := New(Config{
		Enabled:        true,
		Issuer:         "https://issuer.test",
		InternalBase:   "http://issuer",
		ClientID:       "platform-console",
		RedirectURL:    "https://platform.test/auth/callback",
		SessionSecret:  strings.Repeat("s", 40),
		BootstrapToken: strings.Repeat("b", 32),
		AuditSink: func(context.Context, SecurityAuditRecord) error {
			return errors.New("audit backpressure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{Subject: "viewer-1", Roles: []string{"platform-viewer"}, Authentication: "oidc"}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", nil)
	w := httptest.NewRecorder()
	if manager.authorizePrincipalForRequest(w, r, principal) {
		t.Fatal("denied request unexpectedly authorized")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "SECURITY_AUDIT_UNAVAILABLE") {
		t.Fatalf("body=%s", w.Body.String())
	}
}

func TestMCPProtectedResourceMetadata(t *testing.T) {
	manager, err := New(Config{
		Enabled:        true,
		Issuer:         "https://identity.example.test/realms/4so",
		InternalBase:   "https://identity.internal",
		ClientID:       "platform-console",
		RedirectURL:    "https://platform.example.test/auth/callback",
		MCPResourceURL: "https://platform.example.test/mcp",
		MCPAudience:    "platform-mcp",
		SessionSecret:  strings.Repeat("s", 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	manager.Routes(mux)
	r := httptest.NewRequest(http.MethodGet, "https://platform.example.test/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Resource != "https://platform.example.test/mcp" || len(payload.AuthorizationServers) != 1 || payload.AuthorizationServers[0] != "https://identity.example.test/realms/4so" {
		t.Fatalf("payload=%+v", payload)
	}
	if strings.Join(payload.ScopesSupported, ",") != "mcp.read,mcp.operate" {
		t.Fatalf("scopes=%v", payload.ScopesSupported)
	}
}

func TestMCPUnauthorizedIncludesProtectedResourceChallenge(t *testing.T) {
	manager, err := New(Config{
		Enabled:        true,
		Issuer:         "https://identity.example.test/realms/4so",
		InternalBase:   "https://identity.internal",
		ClientID:       "platform-console",
		RedirectURL:    "https://platform.example.test/auth/callback",
		MCPResourceURL: "https://platform.example.test/mcp",
		MCPAudience:    "platform-mcp",
		SessionSecret:  strings.Repeat("s", 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := manager.RequireAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler must not be reached") }))
	r := httptest.NewRequest(http.MethodPost, "https://platform.example.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	want := `Bearer resource_metadata="https://platform.example.test/.well-known/oauth-protected-resource"`
	if got := w.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate=%q want=%q", got, want)
	}
}

func TestMCPBearerUsesDedicatedAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "mcp-key"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kid": kid, "kty": "RSA", "use": "sig", "n": n, "e": e}}})
	}))
	defer jwks.Close()
	issuer := "https://identity.example.test/realms/4so"
	manager, err := New(Config{Enabled: true, Issuer: issuer, InternalBase: jwks.URL, ClientID: "platform-console", RedirectURL: "https://platform.example.test/auth/callback", MCPAudience: "platform-mcp", SessionSecret: strings.Repeat("s", 40)})
	if err != nil {
		t.Fatal(err)
	}
	makeToken := func(aud string) string {
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
		claims, _ := json.Marshal(map[string]any{"sub": "user-1", "iss": issuer, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "realm_access": map[string]any{"roles": []string{"platform-admin"}}})
		left := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(left))
		signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		return left + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	mcpReq := httptest.NewRequest(http.MethodPost, "https://platform.example.test/mcp", nil)
	mcpReq.Header.Set("Authorization", "Bearer "+makeToken("platform-mcp"))
	principal, err := manager.authenticate(mcpReq)
	if err != nil || principal.Subject != "user-1" {
		t.Fatalf("MCP audience rejected: principal=%+v err=%v", principal, err)
	}
	wrong := httptest.NewRequest(http.MethodPost, "https://platform.example.test/mcp", nil)
	wrong.Header.Set("Authorization", "Bearer "+makeToken("platform-console"))
	if _, err := manager.authenticate(wrong); err == nil {
		t.Fatal("MCP accepted UI-console audience")
	}
	apiReq := httptest.NewRequest(http.MethodGet, "https://platform.example.test/api/v1/version", nil)
	apiReq.Header.Set("Authorization", "Bearer "+makeToken("platform-console"))
	if _, err := manager.authenticate(apiReq); err != nil {
		t.Fatalf("normal API audience unexpectedly rejected: %v", err)
	}
}
