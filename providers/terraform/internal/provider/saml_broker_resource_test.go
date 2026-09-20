package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestSAMLMutationKeyIsStableAndRevisionFenced(t *testing.T) {
	desired := samlBrokerDesired{
		OrganizationID: "org-1",
		Alias: "corp",
		DisplayName: "Corporate",
		EntityID: "https://idp.example/entity",
		SingleSignOnServiceURL: "https://idp.example/sso",
		SigningCertificate: "ZmFrZS1jZXJ0",
		Enabled: true,
	}
	first, err := samlMutationKey("update", "broker-1", 7, desired)
	if err != nil {
		t.Fatal(err)
	}
	second, err := samlMutationKey("update", "broker-1", 7, desired)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("idempotency key is not deterministic: %q != %q", first, second)
	}
	changedRevision, err := samlMutationKey("update", "broker-1", 8, desired)
	if err != nil {
		t.Fatal(err)
	}
	if first == changedRevision {
		t.Fatal("revision change did not change idempotency key")
	}
	deleteKey, err := samlMutationKey("delete", "broker-1", 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == deleteKey {
		t.Fatal("different mutation produced same idempotency key")
	}
}

func TestApplyBrokerStateExposesApprovalWithoutHidingDesiredState(t *testing.T) {
	data := samlBrokerResourceModel{}
	broker := samlBrokerAPI{
		ID: "broker-1",
		Revision: 3,
		OrganizationID: "org-1",
		Alias: "corp",
		DisplayName: "Corporate",
		EntityID: "https://idp.example/entity",
		SingleSignOnServiceURL: "https://idp.example/sso",
		SigningCertificate: "ZmFrZS1jZXJ0",
		Enabled: true,
		State: "PENDING_APPROVAL",
		DesiredDigest: "sha256:desired",
	}
	job := identityAdminJobAPI{ID: "job-1", BrokerID: "broker-1", State: "AWAITING_APPROVAL"}
	applyBrokerState(&data, broker, job)
	if data.ID != types.StringValue("broker-1") || data.Revision != types.Int64Value(3) {
		t.Fatalf("resource identity/revision not projected: %#v", data)
	}
	if !data.ApprovalRequired.ValueBool() || data.JobState.ValueString() != "AWAITING_APPROVAL" {
		t.Fatalf("approval state hidden: %#v", data)
	}
}

func TestSAMLResourceRoutesComeOnlyFromGeneratedProductAPI(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/v1/identity/saml-brokers"},
		{"GET", "/api/v1/identity/saml-brokers"},
		{"PUT", "/api/v1/identity/saml-brokers/{id}"},
		{"DELETE", "/api/v1/identity/saml-brokers/{id}"},
		{"GET", "/api/v1/identity/admin-jobs"},
	} {
		route, err := productRoute(tc.method, tc.path)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		if route.ResourceScopeStatus != "OWNER_CLASSIFIED" {
			t.Fatalf("%s %s is not owner classified", tc.method, tc.path)
		}
	}
}
