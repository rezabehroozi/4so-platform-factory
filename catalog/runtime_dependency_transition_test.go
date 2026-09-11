package catalog

import "testing"

func TestEmbeddedRuntimeDependencyTransitionMatchesCatalog(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := LoadUpstreamAdmission()
	if err != nil {
		t.Fatal(err)
	}
	transition, err := LoadRuntimeDependencyTransition()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntimeDependencyTransition(transition, components, admission); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeDependencyTransitionCannotPromoteCiliumRuntimeEarly(t *testing.T) {
	components, _ := Load()
	admission, _ := LoadUpstreamAdmission()
	transition, _ := LoadRuntimeDependencyTransition()
	transition.Spec.Cilium.RuntimeStatus = "eligible"
	if err := ValidateRuntimeDependencyTransition(transition, components, admission); err == nil {
		t.Fatal("early Cilium runtime promotion was accepted")
	}
}

func TestRuntimeDependencyTransitionAcceptsResolvedCiliumAfterAdmissionRetirement(t *testing.T) {
	components, _ := Load()
	admission, _ := LoadUpstreamAdmission()
	transition, _ := LoadRuntimeDependencyTransition()
	cilium := components["cilium"]
	cilium.Spec.Source.Resolved = true
	components["cilium"] = cilium
	filtered := admission.Spec.Components[:0]
	for _, row := range admission.Spec.Components {
		if row.Component != "cilium" {
			filtered = append(filtered, row)
		}
	}
	admission.Spec.Components = filtered
	transition.Spec.Cilium.SourceStatus = "source-acquired"
	if err := ValidateRuntimeDependencyTransition(transition, components, admission); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeDependencyTransitionRejectsRetiredAdmissionWithoutResolvedSource(t *testing.T) {
	components, _ := Load()
	admission, _ := LoadUpstreamAdmission()
	transition, _ := LoadRuntimeDependencyTransition()
	cilium := components["cilium"]
	cilium.Spec.Source.Resolved = false
	components["cilium"] = cilium
	filtered := admission.Spec.Components[:0]
	for _, row := range admission.Spec.Components {
		if row.Component != "cilium" {
			filtered = append(filtered, row)
		}
	}
	admission.Spec.Components = filtered
	transition.Spec.Cilium.SourceStatus = "source-acquired"
	if err := ValidateRuntimeDependencyTransition(transition, components, admission); err == nil {
		t.Fatal("retired Cilium admission was accepted before source resolution")
	}
}
