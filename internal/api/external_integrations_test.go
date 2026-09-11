package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/externalregistry"
)

func TestNotificationProviderContractEndpointAndPolicyDigest(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, project, _, _ := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: org.ID, Subject: "operator", Role: controlplane.OrganizationOperator}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	dest, err := store.CreateNotificationDestination(context.Background(), controlplane.NotificationDestination{OrganizationID: org.ID, Name: "console", Kind: controlplane.NotificationDestinationConsole}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	route, err := store.CreateNotificationRoute(context.Background(), controlplane.NotificationRoute{OrganizationID: org.ID, ProjectID: project.ID, Name: "ops", Enabled: true, EventPatterns: []string{"operation.*"}, MinimumSeverity: controlplane.NotificationWarning, DestinationIDs: []string{dest.ID}}, "bootstrap-admin")
	if err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)

	w := scopedRequest(t, s, http.MethodGet, "/api/v1/notification-provider-contracts", "", "operator", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("contracts status=%d body=%s", w.Code, w.Body.String())
	}
	var contracts []controlplane.NotificationProviderContract
	if err := json.Unmarshal(w.Body.Bytes(), &contracts); err != nil {
		t.Fatal(err)
	}
	if len(contracts) != 2 || contracts[1].Authority != controlplane.NotificationProviderAdapterAuthority {
		t.Fatalf("contracts=%+v", contracts)
	}

	w = scopedRequest(t, s, http.MethodGet, "/api/v1/notification-routes/"+route.ID+"/policy-digest", "", "operator", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("digest status=%d body=%s", w.Code, w.Body.String())
	}
	var digest struct{ Authority, Digest, RouteID string }
	if err := json.Unmarshal(w.Body.Bytes(), &digest); err != nil {
		t.Fatal(err)
	}
	if digest.Authority != controlplane.NotificationPreferenceDigestAuthority || digest.RouteID != route.ID || !strings.HasPrefix(digest.Digest, "sha256:") {
		t.Fatalf("digest=%+v", digest)
	}
}

func TestExternalRegistryAdmissionIsScopedAndReadOnly(t *testing.T) {
	store := controlplane.NewMemoryStore()
	org, project, _, _ := seedOrganizationScope(t, store)
	if _, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: org.ID, Subject: "operator", Role: controlplane.OrganizationOperator}, 0, "bootstrap-admin"); err != nil {
		t.Fatal(err)
	}
	s := scopedServer(t, store)
	body := `{"organizationId":"` + org.ID + `","projectId":"` + project.ID + `","registryUrl":"https://registry.example.test","imageReference":"registry.example.test/team/app@sha256:` + strings.Repeat("a", 64) + `","direction":"IMPORT","credentialRef":"cred_read"}`
	w := scopedRequest(t, s, http.MethodPost, "/api/v1/external-registry/admission", body, "operator", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("admission status=%d body=%s", w.Code, w.Body.String())
	}
	var result externalregistry.Result
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Admitted || result.Authority != externalregistry.Authority || result.ManagedRegistrySoT != "zot" {
		t.Fatalf("result=%+v", result)
	}

	bad := `{"organizationId":"` + org.ID + `","projectId":"` + project.ID + `","registryUrl":"https://registry.example.test","imageReference":"registry.example.test/team/app:latest","direction":"IMPORT"}`
	w = scopedRequest(t, s, http.MethodPost, "/api/v1/external-registry/admission", bad, "operator", "platform-operator")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mutable ref status=%d body=%s", w.Code, w.Body.String())
	}
}
