package catalog

import "testing"

func TestEmbeddedUpstreamAdmissionMatchesEmbeddedCatalog(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := LoadUpstreamAdmission()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateUpstreamAdmission(admission, components); err != nil {
		t.Fatalf("embedded upstream admission drifted from embedded catalog: %v", err)
	}
}

func TestValidateUpstreamAdmissionRejectsReadyCatalogPinDrift(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := LoadUpstreamAdmission()
	if err != nil {
		t.Fatal(err)
	}
	var target string
	for _, row := range admission.Spec.Components {
		if row.Status == "ready-for-acquisition" {
			target = row.Component
			break
		}
	}
	if target == "" {
		t.Fatal("fixture has no ready upstream admission component")
	}
	component := components[target]
	component.Spec.Release = "99.99.99"
	components[target] = component
	if err := ValidateUpstreamAdmission(admission, components); err == nil {
		t.Fatal("ready admission with drifted catalog release was accepted")
	}
}

func TestValidateUpstreamAdmissionRequiresCiliumRuntimeTransitionUntilGatewayAPI161Resolved(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := LoadUpstreamAdmission()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range admission.Spec.Components {
		row := &admission.Spec.Components[i]
		if row.Component != "cilium" {
			continue
		}
		found = true
		if row.Status != "ready-for-acquisition" {
			t.Fatalf("Cilium source candidate is not acquisition-ready: %q", row.Status)
		}
		row.RuntimeStatus = "eligible-after-source-resolution"
	}
	if !found {
		t.Skip("Cilium admission row is already retired")
	}
	if err := ValidateUpstreamAdmission(admission, components); err == nil {
		t.Fatal("Cilium runtime suitability was admitted before the Gateway API 1.6.1 transition")
	}
}

func TestValidateUpstreamAdmissionRejectsRuntimeBlockerWithoutBlockerEvidence(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := LoadUpstreamAdmission()
	if err != nil {
		t.Fatal(err)
	}
	if len(admission.Spec.Components) == 0 {
		t.Skip("all upstream admission rows are retired after source acquisition")
	}
	row := &admission.Spec.Components[0]
	row.RuntimeStatus = "review-required"
	row.ReviewEvidence = []UpstreamAdmissionReviewEvidence{{
		Kind: "release", URL: "https://example.test/release", Summary: "non-blocker evidence only",
	}}
	if err := ValidateUpstreamAdmission(admission, components); err == nil {
		t.Fatal("runtime-blocked candidate without blocker evidence was accepted")
	}
}
