package identityadmin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func testCertificateB64(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

type keycloakFixture struct {
	mu       sync.Mutex
	orgID    string
	orgAlias string
	provider *identityProviderRepresentation
	linked   bool
	tokens   int
}

func (f *keycloakFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
				w.WriteHeader(400)
				return
			}
			if r.Form.Get("username") != "platform-admin" || r.Form.Get("password") != "correct-secret" || r.Form.Get("client_id") != "admin-cli" {
				t.Errorf("unexpected token form: %#v", r.Form)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			f.tokens++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 60})
			return
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/platform/organizations":
			if f.orgID == "" || r.URL.Query().Get("search") != f.orgAlias {
				_ = json.NewEncoder(w).Encode([]organizationRepresentation{})
				return
			}
			_ = json.NewEncoder(w).Encode([]organizationRepresentation{{ID: f.orgID, Alias: f.orgAlias, Name: "Acme", Enabled: true}})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/platform/organizations":
			var rep organizationRepresentation
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
				t.Errorf("decode org: %v", err)
				w.WriteHeader(400)
				return
			}
			f.orgAlias = rep.Alias
			f.orgID = "kc-org-1"
			w.WriteHeader(http.StatusCreated)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/platform/identity-provider/instances/") && r.Method == http.MethodGet:
			if f.provider == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(f.provider)
		case r.URL.Path == "/admin/realms/platform/identity-provider/instances" && r.Method == http.MethodPost:
			var rep identityProviderRepresentation
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
				t.Errorf("decode provider: %v", err)
				w.WriteHeader(400)
				return
			}
			f.provider = &rep
			w.WriteHeader(http.StatusCreated)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/platform/identity-provider/instances/") && r.Method == http.MethodPut:
			var rep identityProviderRepresentation
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
				t.Errorf("decode provider update: %v", err)
				w.WriteHeader(400)
				return
			}
			f.provider = &rep
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/platform/identity-provider/instances/") && r.Method == http.MethodDelete:
			f.provider = nil
			f.linked = false
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/organizations/kc-org-1/identity-providers/") && r.Method == http.MethodGet:
			if !f.linked || f.provider == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(f.provider)
		case r.URL.Path == "/admin/realms/platform/organizations/kc-org-1/identity-providers" && r.Method == http.MethodPost:
			var alias string
			if err := json.NewDecoder(r.Body).Decode(&alias); err != nil {
				t.Errorf("decode provider link: %v", err)
				w.WriteHeader(400)
				return
			}
			if f.provider == nil || alias != f.provider.Alias {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			f.linked = true
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/organizations/kc-org-1/identity-providers/") && r.Method == http.MethodDelete:
			f.linked = false
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected Keycloak request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func testClient(t *testing.T, serverURL string) *KeycloakClient {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(path, []byte("correct-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &KeycloakClient{BaseURL: serverURL, Realm: "platform", AdminRealm: "master", AdminUser: "platform-admin", PasswordFile: path}
}

func testBroker(t *testing.T, organizationID string) controlplane.SAMLBroker {
	t.Helper()
	normalized, err := controlplane.NormalizeSAMLBroker(controlplane.SAMLBroker{OrganizationID: organizationID, Alias: "corp-sso", DisplayName: "Corporate SSO", EntityID: "https://idp.example.test/entity", SingleSignOnServiceURL: "https://idp.example.test/sso", SingleLogoutServiceURL: "https://idp.example.test/slo", SigningCertificate: testCertificateB64(t), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	normalized.ResourceMeta = controlplane.ResourceMeta{}
	normalized.DesiredDigest = controlplane.SAMLBrokerDesiredDigest(normalized)
	return normalized
}

func TestKeycloakClientReconcileAndDeleteOrganizationScopedSAML(t *testing.T) {
	fixture := &keycloakFixture{}
	server := httptest.NewServer(fixture.handler(t))
	defer server.Close()
	client := testClient(t, server.URL)
	if err := client.Validate(); err != nil {
		t.Fatalf("validate client: %v", err)
	}
	organization := controlplane.Organization{ResourceMeta: controlplane.ResourceMeta{ID: "org-1"}, Name: "acme", DisplayName: "Acme Corp"}
	broker := testBroker(t, organization.ID)
	broker.ResourceMeta = controlplane.ResourceMeta{ID: "saml-1", Revision: 1}
	broker.DesiredDigest = controlplane.SAMLBrokerDesiredDigest(broker)
	fixture.orgAlias = keycloakOrganizationAlias(organization.ID)

	observed, err := client.ReconcileSAML(context.Background(), organization, broker)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if observed != broker.DesiredDigest {
		t.Fatalf("observed digest %q != desired %q", observed, broker.DesiredDigest)
	}
	fixture.mu.Lock()
	linked, provider := fixture.linked, fixture.provider
	fixture.mu.Unlock()
	if !linked || provider == nil || provider.ProviderID != "saml" || provider.Alias != broker.KeycloakAlias {
		t.Fatalf("provider not created and linked: linked=%v provider=%+v", linked, provider)
	}
	if provider.HideOnLogin == nil || !*provider.HideOnLogin {
		t.Fatalf("organization broker must stay hidden outside organization resolution: %+v", provider)
	}
	deleted, err := client.DeleteSAML(context.Background(), organization, broker)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !strings.HasPrefix(deleted, "sha256:") || len(deleted) != 71 {
		t.Fatalf("invalid deleted observed digest %q", deleted)
	}
	fixture.mu.Lock()
	linked, provider = fixture.linked, fixture.provider
	fixture.mu.Unlock()
	if linked || provider != nil {
		t.Fatalf("delete was not observed: linked=%v provider=%+v", linked, provider)
	}
}

type fakeReconciler struct {
	digest string
	err    error
}

func (f fakeReconciler) ReconcileSAML(context.Context, controlplane.Organization, controlplane.SAMLBroker) (string, error) {
	return f.digest, f.err
}
func (f fakeReconciler) DeleteSAML(context.Context, controlplane.Organization, controlplane.SAMLBroker) (string, error) {
	return f.digest, f.err
}

func TestWorkerConsumesOnlyApprovedIdentityAdminJobs(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "acme", DisplayName: "Acme"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	broker := testBroker(t, org.ID)
	requestDigest := "sha256:" + strings.Repeat("a", 64)
	broker, job, _, err := store.RequestSAMLBrokerUpsert(ctx, broker, 0, "idem-1", requestDigest, "requester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ApproveIdentityAdminJob(ctx, job.ID, job.Revision, "requester"); err == nil {
		t.Fatal("self-approval must fail")
	}
	job, err = store.ApproveIdentityAdminJob(ctx, job.ID, job.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	worker := &Worker{Store: store, Reconciler: fakeReconciler{digest: broker.DesiredDigest}, Owner: "worker-1", Lease: time.Minute}
	processed, err := worker.RunOnce(ctx)
	if err != nil || !processed {
		t.Fatalf("run once processed=%v err=%v", processed, err)
	}
	got, err := store.GetIdentityAdminJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != controlplane.IdentityAdminSucceeded || got.EvidenceDigest == "" || got.TaskLeaseOwner != "" {
		t.Fatalf("unexpected completed job: %+v", got)
	}
	gotBroker, err := store.GetSAMLBroker(ctx, broker.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotBroker.State != controlplane.SAMLBrokerReady || gotBroker.ObservedDigest != broker.DesiredDigest {
		t.Fatalf("unexpected broker: %+v", gotBroker)
	}
	if processed, err = worker.RunOnce(ctx); err != nil || processed {
		t.Fatalf("empty queue should be idle processed=%v err=%v", processed, err)
	}
}

func TestKeycloakClientRejectsLooseCredentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := &KeycloakClient{BaseURL: "http://127.0.0.1:8080", PasswordFile: path}
	if err := client.Validate(); err == nil || !strings.Contains(err.Error(), "group/world") {
		t.Fatalf("expected permission validation, got %v", err)
	}
}

func Example_keycloakOrganizationAlias() {
	fmt.Println(strings.HasPrefix(keycloakOrganizationAlias("organization-123"), "4so-"))
	// Output: true
}
