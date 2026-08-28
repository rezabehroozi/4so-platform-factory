package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/apitoken"
	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func TestServiceAccountAPITokenScopeExpiryRotationAndRevocation(t *testing.T) {
	store := controlplane.NewMemoryStore()
	server := New("test", nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), store)
	server.ConfigureFleetImport("registry.test/platform-agent@sha256:"+strings.Repeat("a", 64), "registry.test/platform-probe@sha256:"+strings.Repeat("b", 64), "https://platform.example.test", "")
	manager, err := auth.New(auth.Config{LocalDevelopment: true, BearerAuthenticator: apitoken.Authenticator{Store: store}.Authenticate})
	if err != nil {
		t.Fatal(err)
	}
	root := http.NewServeMux()
	root.Handle("/api/", manager.RequireAPI(server.Handler()))
	do := func(method, path, body, bearer string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		root.ServeHTTP(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, target any) {
		if err := json.Unmarshal(w.Body.Bytes(), target); err != nil {
			t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), err)
		}
	}
	w := do(http.MethodPost, "/api/v1/organizations", `{"name":"acme","displayName":"Acme"}`, "", nil)
	if w.Code != 201 {
		t.Fatalf("org %d %s", w.Code, w.Body.String())
	}
	var org controlplane.Organization
	decode(w, &org)
	w = do(http.MethodPost, "/api/v1/projects", `{"organizationId":"`+org.ID+`","name":"prod","displayName":"Prod"}`, "", nil)
	if w.Code != 201 {
		t.Fatalf("project %d %s", w.Code, w.Body.String())
	}
	var prod controlplane.Project
	decode(w, &prod)
	w = do(http.MethodPost, "/api/v1/projects", `{"organizationId":"`+org.ID+`","name":"other","displayName":"Other"}`, "", nil)
	if w.Code != 201 {
		t.Fatalf("project2 %d %s", w.Code, w.Body.String())
	}
	var other controlplane.Project
	decode(w, &other)
	w = do(http.MethodPost, "/api/v1/service-accounts", `{"organizationId":"`+org.ID+`","projectId":"`+prod.ID+`","name":"automation","displayName":"Automation","productRole":"platform-operator"}`, "", nil)
	if w.Code != 201 {
		t.Fatalf("service account %d %s", w.Code, w.Body.String())
	}
	var sa controlplane.ServiceAccount
	decode(w, &sa)
	expires := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	w = do(http.MethodPost, "/api/v1/service-accounts/"+sa.ID+"/tokens", `{"expiresAt":"`+expires+`","permissions":["operate"]}`, "", map[string]string{"Idempotency-Key": "issue-main"})
	if w.Code != 201 {
		t.Fatalf("issue %d %s", w.Code, w.Body.String())
	}
	var issued apiTokenSecretResponse
	decode(w, &issued)
	if issued.Value == "" || issued.Token.TokenDigest != "" {
		t.Fatalf("secret response %#v", issued)
	}
	raw := issued.Value
	// A response-loss retry with the same request identity must not mint a second valid secret.
	w = do(http.MethodPost, "/api/v1/service-accounts/"+sa.ID+"/tokens", `{"expiresAt":"`+expires+`","permissions":["operate"]}`, "", map[string]string{"Idempotency-Key": "issue-main"})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "TOKEN_ISSUANCE_ALREADY_COMMITTED") {
		t.Fatalf("duplicate issue status=%d body=%s", w.Code, w.Body.String())
	}
	// Project-scoped API token sees only its project.
	w = do(http.MethodGet, "/api/v1/projects?organizationId="+org.ID, "", raw, nil)
	if w.Code != 200 {
		t.Fatalf("list project %d %s", w.Code, w.Body.String())
	}
	var projects []controlplane.Project
	decode(w, &projects)
	if len(projects) != 1 || projects[0].ID != prod.ID {
		t.Fatalf("scope leaked %#v", projects)
	}
	// Operate permission permits a project mutation in scope.
	w = do(http.MethodPost, "/api/v1/cluster-imports", `{"projectId":"`+prod.ID+`","name":"cluster-a","displayName":"Cluster A"}`, raw, nil)
	if w.Code != 201 {
		t.Fatalf("in-scope mutation %d %s", w.Code, w.Body.String())
	}
	var importResponse struct {
		Import controlplane.ClusterImport `json:"import"`
	}
	decode(w, &importResponse)
	imp := importResponse.Import
	// The same token cannot touch another project or organization-wide mutation.
	w = do(http.MethodPost, "/api/v1/cluster-imports", `{"projectId":"`+other.ID+`","name":"cluster-b","displayName":"Cluster B"}`, raw, nil)
	if w.Code != 403 {
		t.Fatalf("cross-project=%d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodPut, "/api/v1/organizations/"+org.ID+"/entitlement", `{"planId":"enterprise","maxTenants":10}`, raw, nil)
	if w.Code != 403 {
		t.Fatalf("org mutation=%d %s", w.Code, w.Body.String())
	}
	// Non-human service accounts cannot satisfy critical platform-admin approval.
	w = do(http.MethodPost, "/api/v1/cluster-imports/"+imp.ID+"/approve", "{}", raw, map[string]string{"If-Match": "1"})
	if w.Code != 403 {
		t.Fatalf("service approval=%d %s", w.Code, w.Body.String())
	}
	// A project-scoped token must not receive organization-wide summary metadata.
	w = do(http.MethodGet, "/api/v1/control-plane/summary", "", raw, nil)
	if w.Code != 200 {
		t.Fatalf("summary %d %s", w.Code, w.Body.String())
	}
	var summary map[string]any
	decode(w, &summary)
	if summary["projects"] != float64(1) || summary["entitlements"] != float64(0) || summary["oemProfiles"] != float64(0) {
		t.Fatalf("project token summary leaked organization metadata %#v", summary)
	}
	// Audit is scoped to the exact project; organization-wide security management events are not exposed.
	w = do(http.MethodGet, "/api/v1/audit-events?limit=100", "", raw, nil)
	if w.Code != 200 {
		t.Fatalf("audit %d %s", w.Code, w.Body.String())
	}
	var audit []controlplane.AuditEvent
	decode(w, &audit)
	for _, event := range audit {
		if event.ResourceType == "organization_membership" || event.ResourceType == "organization_entitlement" || event.ResourceType == "oem_profile" {
			t.Fatalf("project token leaked organization-wide audit event %#v", event)
		}
	}
	// Rotate invalidates old token immediately and returns the replacement once.
	w = do(http.MethodPost, "/api/v1/service-accounts/"+sa.ID+"/tokens/"+issued.Token.ID+"/rotate", `{}`, "", map[string]string{"If-Match": "1", "X-Confirm-Rotate": "rotate-api-token", "Idempotency-Key": "rotate-main"})
	if w.Code != 201 {
		t.Fatalf("rotate %d %s", w.Code, w.Body.String())
	}
	var rotated apiTokenSecretResponse
	decode(w, &rotated)
	if rotated.Value == "" {
		t.Fatal("rotation did not return replacement secret")
	}
	w = do(http.MethodPost, "/api/v1/service-accounts/"+sa.ID+"/tokens/"+issued.Token.ID+"/rotate", `{}`, "", map[string]string{"If-Match": "1", "X-Confirm-Rotate": "rotate-api-token", "Idempotency-Key": "rotate-main"})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "TOKEN_ROTATION_ALREADY_COMMITTED") {
		t.Fatalf("duplicate rotate status=%d body=%s", w.Code, w.Body.String())
	}
	tokenList := do(http.MethodGet, "/api/v1/service-accounts/"+sa.ID+"/tokens", "", "", nil)
	var persistedTokens []controlplane.APIToken
	decode(tokenList, &persistedTokens)
	if len(persistedTokens) != 2 {
		t.Fatalf("response-loss retry minted extra token: %d", len(persistedTokens))
	}
	w = do(http.MethodGet, "/api/v1/projects", "", raw, nil)
	if w.Code != 401 {
		t.Fatalf("old token after rotate=%d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodGet, "/api/v1/projects", "", rotated.Value, nil)
	if w.Code != 200 {
		t.Fatalf("new token=%d %s", w.Code, w.Body.String())
	}
	// Revoking the service account invalidates all replacement tokens immediately.
	w = do(http.MethodPost, "/api/v1/service-accounts/"+sa.ID+"/revoke", "", "", map[string]string{"If-Match": "1", "X-Confirm-Revoke": "revoke-service-account"})
	if w.Code != 200 {
		t.Fatalf("revoke sa %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodGet, "/api/v1/projects", "", rotated.Value, nil)
	if w.Code != 401 {
		t.Fatalf("token after account revoke=%d %s", w.Code, w.Body.String())
	}
}

func TestReadOnlyAPITokenCannotMutate(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "acme", DisplayName: "Acme"}, "admin")
	prj, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "admin")
	sa, _ := store.CreateServiceAccount(ctx, controlplane.ServiceAccount{OrganizationID: org.ID, ProjectID: prj.ID, Name: "reader", DisplayName: "Reader", ProductRole: "platform-operator"}, "admin")
	raw, prefix, digest, _ := apitoken.Generate("tok_read")
	_, err := store.CreateAPIToken(ctx, controlplane.APIToken{ResourceMeta: controlplane.ResourceMeta{ID: "tok_read"}, ServiceAccountID: sa.ID, TokenPrefix: prefix, TokenDigest: digest, Permissions: []string{"read"}, ExpiresAt: time.Now().Add(time.Hour), IdempotencyKey: "readonly-fixed"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, slog.Default(), store)
	manager, _ := auth.New(auth.Config{LocalDevelopment: true, BearerAuthenticator: apitoken.Authenticator{Store: store}.Authenticate})
	root := http.NewServeMux()
	root.Handle("/api/", manager.RequireAPI(server.Handler()))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/cluster-imports", strings.NewReader(`{"projectId":"`+prj.ID+`","name":"blocked","displayName":"Blocked"}`))
	r.Header.Set("Authorization", "Bearer "+raw)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	root.ServeHTTP(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "TOKEN_PERMISSION_REQUIRED") {
		t.Fatalf("read token mutation=%d %s", w.Code, w.Body.String())
	}
}
