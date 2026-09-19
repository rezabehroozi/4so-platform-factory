package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type argoObserverFixture struct {
	mu          sync.Mutex
	tokenExists bool
	loginCalls  int
	deleteCalls int
	createCalls int
}

func (f *argoObserverFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/api/v1/session/userinfo":
			if r.Header.Get("Authorization") == "Bearer observer-valid" || r.Header.Get("Authorization") == "Bearer observer-new" {
				_ = json.NewEncoder(w).Encode(map[string]any{"loggedIn": true, "username": gitOpsObserverAccount})
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case r.URL.Path == "/api/v1/account/can-i/applications/get/platform/platform-appliance":
			if r.Header.Get("Authorization") == "Bearer observer-valid" || r.Header.Get("Authorization") == "Bearer observer-new" {
				_ = json.NewEncoder(w).Encode(map[string]string{"value": "yes"})
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case r.URL.Path == "/api/v1/session" && r.Method == http.MethodPost:
			f.loginCalls++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["username"] != "admin" || body["password"] != "admin-pass" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "admin-session"})
		case r.URL.Path == "/api/v1/account/"+gitOpsObserverAccount && r.Method == http.MethodGet:
			if r.Header.Get("Authorization") != "Bearer admin-session" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			tokens := []map[string]string{}
			if f.tokenExists {
				tokens = append(tokens, map[string]string{"id": gitOpsObserverTokenID})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": gitOpsObserverAccount, "tokens": tokens})
		case r.URL.Path == "/api/v1/account/"+gitOpsObserverAccount+"/token/"+gitOpsObserverTokenID && r.Method == http.MethodDelete:
			if r.Header.Get("Authorization") != "Bearer admin-session" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			f.deleteCalls++
			f.tokenExists = false
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/api/v1/account/"+gitOpsObserverAccount+"/token" && r.Method == http.MethodPost:
			if r.Header.Get("Authorization") != "Bearer admin-session" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			f.createCalls++
			f.tokenExists = true
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "observer-new"})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestBootstrapArgoObserverTokenReusesValidProductToken(t *testing.T) {
	fixture := &argoObserverFixture{tokenExists: true}
	server := fixture.server(t)
	defer server.Close()

	token, generated, err := bootstrapArgoObserverToken(context.Background(), server.Client(), server.URL, "", "observer-valid")
	if err != nil {
		t.Fatal(err)
	}
	if token != "observer-valid" || generated {
		t.Fatalf("token=%q generated=%v", token, generated)
	}
	if fixture.loginCalls != 0 || fixture.createCalls != 0 || fixture.deleteCalls != 0 {
		t.Fatalf("valid token unexpectedly used bootstrap account: %+v", fixture)
	}
}

func TestBootstrapArgoObserverTokenRecoversOrphanedTokenRegistration(t *testing.T) {
	fixture := &argoObserverFixture{tokenExists: true}
	server := fixture.server(t)
	defer server.Close()

	token, generated, err := bootstrapArgoObserverToken(context.Background(), server.Client(), server.URL, "admin-pass", "stale-product-token")
	if err != nil {
		t.Fatal(err)
	}
	if token != "observer-new" || !generated {
		t.Fatalf("token=%q generated=%v", token, generated)
	}
	if fixture.loginCalls != 1 || fixture.deleteCalls != 1 || fixture.createCalls != 1 {
		t.Fatalf("crash recovery did not replace the orphaned token exactly once: %+v", fixture)
	}
}

func TestBootstrapArgoObserverTokenFailsClosedWithoutRecoveryCredential(t *testing.T) {
	fixture := &argoObserverFixture{}
	server := fixture.server(t)
	defer server.Close()

	_, _, err := bootstrapArgoObserverToken(context.Background(), server.Client(), server.URL, "", "stale-product-token")
	if err == nil || !strings.Contains(err.Error(), "initial admin password is unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMergeObserverRBACIsIdempotentAndPreservesExistingPolicy(t *testing.T) {
	existing := "p, role:existing, applications, get, other/*, allow\n"
	once := mergeObserverRBAC(existing)
	twice := mergeObserverRBAC(once)
	if once != twice {
		t.Fatalf("RBAC merge is not idempotent:\n%s\n---\n%s", once, twice)
	}
	for _, required := range []string{
		"p, role:existing, applications, get, other/*, allow",
		"p, role:platform-observer, applications, get, platform/platform-appliance, allow",
		"g, platform-observer, role:platform-observer",
	} {
		if !strings.Contains(once, required) {
			t.Fatalf("merged RBAC missing %q:\n%s", required, once)
		}
	}
}
