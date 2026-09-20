package factorysdk

import (
	"strings"
	"testing"
)

func TestDeterministicMutationKeyIsStableAndFenced(t *testing.T) {
	desired := map[string]any{
		"displayName": "Corporate",
		"enabled":     true,
	}
	first, err := DeterministicMutationKey("terraform-saml", "update", "broker-1", 7, desired)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeterministicMutationKey("terraform-saml", "update", "broker-1", 7, desired)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("mutation key is not deterministic: %q != %q", first, second)
	}
	changedRevision, _ := DeterministicMutationKey("terraform-saml", "update", "broker-1", 8, desired)
	if first == changedRevision {
		t.Fatal("revision fence did not affect mutation key")
	}
	changedNamespace, _ := DeterministicMutationKey("crossplane-saml", "update", "broker-1", 7, desired)
	if first == changedNamespace {
		t.Fatal("client namespace did not affect mutation key")
	}
	if !strings.HasPrefix(first, "terraform-saml-update-") {
		t.Fatalf("unexpected key prefix %q", first)
	}
}

func TestDeterministicMutationKeyRejectsInvalidIdentity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		namespace string
		action    string
		revision  int64
	}{
		{name: "missing namespace", action: "create"},
		{name: "missing action", namespace: "terraform"},
		{name: "negative revision", namespace: "terraform", action: "update", revision: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DeterministicMutationKey(tc.namespace, tc.action, "", tc.revision, nil); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDeterministicMutationKeyPropagatesJSONEncodingFailure(t *testing.T) {
	_, err := DeterministicMutationKey("terraform", "create", "", 0, func() {})
	if err == nil || !strings.Contains(err.Error(), "encode deterministic mutation identity") {
		t.Fatalf("unexpected error: %v", err)
	}
}
