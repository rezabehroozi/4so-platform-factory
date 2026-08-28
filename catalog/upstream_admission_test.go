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
