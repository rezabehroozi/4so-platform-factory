package samlbroker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crossplane/crossplane-runtime/v2/pkg/meta"

	identityv1alpha1 "platform.4so.io/factory/providers/crossplane/apis/identity/v1alpha1"
	factorysdk "platform.4so.io/factory/sdk/go"
)

func newTestExternal(t *testing.T, handler http.HandlerFunc) *external {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := factorysdk.NewClient(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.BearerToken = "delegated-token"
	return &external{client: c}
}

func testBroker() *identityv1alpha1.SAMLBroker {
	return &identityv1alpha1.SAMLBroker{Spec: identityv1alpha1.SAMLBrokerSpec{ForProvider: identityv1alpha1.SAMLBrokerParameters{
		OrganizationID: "org-1", Alias: "corp", DisplayName: "Corporate", EntityID: "https://idp.example/entity",
		SingleSignOnServiceURL: "https://idp.example/sso", SigningCertificate: "public-cert", Enabled: true,
	}}}
}

func TestCreateUsesProductAPIRouteAndNeverSelfApproves(t *testing.T) {
	calls := 0
	e := newTestExternal(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/identity/saml-brokers" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer delegated-token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		key, _ := body["idempotencyKey"].(string)
		if !strings.HasPrefix(key, "crossplane-saml-create-") {
			t.Fatalf("idempotencyKey=%q", key)
		}
		if _, exists := body["approve"]; exists {
			t.Fatal("provider attempted approval bypass")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"broker": map[string]any{"id": "broker-1", "revision": 1, "organizationId": "org-1", "alias": "corp", "displayName": "Corporate", "entityId": "https://idp.example/entity", "singleSignOnServiceUrl": "https://idp.example/sso", "signingCertificate": "public-cert", "enabled": true, "state": "PENDING_APPROVAL"},
			"job":    map[string]any{"id": "job-1", "brokerId": "broker-1", "state": "AWAITING_APPROVAL"},
		})
	})
	cr := testBroker()
	if _, err := e.Create(context.Background(), cr); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || meta.GetExternalName(cr) != "broker-1" {
		t.Fatalf("calls=%d external=%q", calls, meta.GetExternalName(cr))
	}
	if !cr.Status.AtProvider.ApprovalRequired || cr.Status.AtProvider.JobState != "AWAITING_APPROVAL" {
		t.Fatalf("status=%#v", cr.Status.AtProvider)
	}
}

func TestObserveDoesNotMutateAndProjectsRevision(t *testing.T) {
	e := newTestExternal(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected mutation %s", r.Method)
		}
		if r.URL.Query().Get("organizationId") != "org-1" {
			t.Fatalf("query=%q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "broker-1", "revision": 7, "organizationId": "org-1", "alias": "corp", "displayName": "Corporate", "entityId": "https://idp.example/entity", "singleSignOnServiceUrl": "https://idp.example/sso", "signingCertificate": "public-cert", "enabled": true, "state": "ACTIVE"}})
	})
	cr := testBroker()
	meta.SetExternalName(cr, "broker-1")
	obs, err := e.Observe(context.Background(), cr)
	if err != nil {
		t.Fatal(err)
	}
	if !obs.ResourceExists || !obs.ResourceUpToDate || cr.Status.AtProvider.Revision != 7 {
		t.Fatalf("obs=%#v status=%#v", obs, cr.Status.AtProvider)
	}
}

func TestUpdateIsRevisionFenced(t *testing.T) {
	e := newTestExternal(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/identity/saml-brokers/broker-1" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("If-Match") != "7" {
			t.Fatalf("If-Match=%q", r.Header.Get("If-Match"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"broker": map[string]any{"id": "broker-1", "revision": 8, "organizationId": "org-1", "alias": "corp", "displayName": "Corporate", "entityId": "https://idp.example/entity", "singleSignOnServiceUrl": "https://idp.example/sso", "signingCertificate": "public-cert", "enabled": true, "state": "ACTIVE"}, "job": map[string]any{"id": "job-2", "state": "SUCCEEDED"}})
	})
	cr := testBroker()
	meta.SetExternalName(cr, "broker-1")
	cr.Status.AtProvider.Revision = 7
	if _, err := e.Update(context.Background(), cr); err != nil {
		t.Fatal(err)
	}
	if cr.Status.AtProvider.Revision != 8 {
		t.Fatalf("revision=%d", cr.Status.AtProvider.Revision)
	}
}

func TestMutationKeyNamespaceIsIndependentFromTerraform(t *testing.T) {
	d := testBroker().Spec.ForProvider
	cp, err := mutationKey("update", "broker-1", 7, d)
	if err != nil {
		t.Fatal(err)
	}
	tf, err := factorysdk.DeterministicMutationKey("terraform-saml", "update", "broker-1", 7, d)
	if err != nil {
		t.Fatal(err)
	}
	if cp == tf {
		t.Fatal("Crossplane and Terraform replay identities collided")
	}
}
