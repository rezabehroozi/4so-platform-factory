package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/integrations"
)

func TestGitProviderCredentialReferenceRotationRuntime(t *testing.T) {
	t.Setenv("PF_GIT_SECRET_A", "secret-a")
	t.Setenv("PF_GIT_SECRET_B", "secret-b")
	var expected atomic.Value
	expected.Store("secret-a")
	forgejo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "test"})
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "platform-admin" || pass != expected.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/orgs/platform":
			_ = json.NewEncoder(w).Encode(map[string]string{"username": "platform"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/platform/desired-state":
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "desired-state", "html_url": "https://git.local/platform/desired-state", "clone_url": "https://git.local/platform/desired-state.git", "owner": map[string]string{"login": "platform"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer forgejo.Close()
	store := controlplane.NewMemoryStore()
	resolver := func(ctx context.Context) (integrations.GitConnection, error) {
		p, c, err := store.GetDefaultGitProvider(ctx)
		if err != nil {
			return integrations.GitConnection{}, err
		}
		return integrations.GitConnection{ProviderID: p.ID, ProviderName: p.Name, BaseURL: p.BaseURL, CredentialID: c.ID, Username: c.Username, SecretRef: c.SecretRef}, nil
	}
	s := New("0.0.65", nil, nil, store)
	s.ConfigureSystemServices(integrations.New(integrations.Config{GitConnectionResolver: resolver, RepositoryBootstrapEnabled: true}))
	h := s.Handler()
	headers := map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin"}
	w := apiRequest(t, h, http.MethodPost, "/api/v1/git-credentials", `{"name":"internal-forgejo","username":"platform-admin","secretRef":"env://PF_GIT_SECRET_A"}`, headers)
	if w.Code != 201 {
		t.Fatalf("credential %d %s", w.Code, w.Body.String())
	}
	var c1 controlplane.GitCredential
	_ = json.Unmarshal(w.Body.Bytes(), &c1)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/git-providers", `{"name":"internal-forgejo","kind":"FORGEJO","baseUrl":"`+forgejo.URL+`","credentialId":"`+c1.ID+`","default":true}`, headers)
	if w.Code != 201 {
		t.Fatalf("provider %d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/system-services/git/repositories", `{"organization":"platform","name":"desired-state","private":true}`, headers)
	if w.Code != 200 {
		t.Fatalf("initial git %d %s", w.Code, w.Body.String())
	}
	operatorHeaders := map[string]string{"X-Actor-ID": "operator", "X-Actor-Role": "platform-operator"}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/system-services/git/repositories", `{"organization":"platform","name":"operator-denied","private":true}`, operatorHeaders)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "PLATFORM_ADMIN_REQUIRED") {
		t.Fatalf("platform operator must not mutate managed Git repository authority: %d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/system-services/git/revisions", `{}`, operatorHeaders)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "PLATFORM_ADMIN_REQUIRED") {
		t.Fatalf("platform operator must not publish managed Git revision authority: %d %s", w.Code, w.Body.String())
	}
	expected.Store("secret-b")
	rotateHeaders := map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin", "If-Match": "\"1\""}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/git-credentials/"+c1.ID+"/rotate", `{"secretRef":"env://PF_GIT_SECRET_B"}`, rotateHeaders)
	if w.Code != 200 {
		t.Fatalf("rotate %d %s", w.Code, w.Body.String())
	}
	var rotated struct {
		Replacement controlplane.GitCredential `json:"replacement"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	w = apiRequest(t, h, http.MethodPost, "/api/v1/system-services/git/repositories", `{"organization":"platform","name":"desired-state","private":true}`, headers)
	if w.Code != 200 {
		t.Fatalf("rotated git %d %s", w.Code, w.Body.String())
	}
	revokeHeaders := map[string]string{"X-Actor-ID": "admin", "X-Actor-Role": "platform-admin", "If-Match": "\"1\""}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/git-credentials/"+rotated.Replacement.ID+"/revoke", `{}`, revokeHeaders)
	if w.Code != 200 {
		t.Fatalf("revoke %d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/system-services/git/repositories", `{"organization":"platform","name":"desired-state","private":true}`, headers)
	if w.Code != 502 {
		t.Fatalf("revoked credential should fail closed, got %d %s", w.Code, w.Body.String())
	}
	audit, _ := store.ListAudit(context.Background(), 100)
	raw, _ := json.Marshal(audit)
	if strings.Contains(string(raw), "secret-a") || strings.Contains(string(raw), "secret-b") {
		t.Fatal("raw secret material leaked into audit")
	}
	snap, _ := store.Snapshot(context.Background())
	snapRaw, _ := json.Marshal(snap)
	if strings.Contains(string(snapRaw), "secret-a") || strings.Contains(string(snapRaw), "secret-b") {
		t.Fatal("raw secret material leaked into state")
	}
	_ = os.Getenv("PF_GIT_SECRET_A")
}
