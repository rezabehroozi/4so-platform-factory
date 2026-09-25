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
	// The canonical S1 queue may legitimately be empty after exact source closure.
	// Recreate one unresolved Helm candidate in-memory so this remains a real
	// negative control for ready-row/catalog pin drift.
	target := "capsule"
	component, ok := components[target]
	if !ok {
		t.Fatal("capsule fixture missing")
	}
	version := component.Spec.Release
	component.Spec.Source.Resolved = false
	component.Spec.Source.BundleKey = ""
	component.Spec.Source.ArtifactDigest = ""
	component.Spec.Source.RenderManifestDigest = ""
	component.Spec.Source.SourceLockDigest = ""
	component.Spec.Source.ImageInventoryDigest = ""
	component.Spec.Source.LicenseManifestDigest = ""
	component.Spec.Source.SBOM = ""
	component.Spec.Source.Provenance = ""
	component.Spec.Source.SignatureVerification = ""
	component.Spec.VersionPolicy = "exact-upstream-admitted-pending-source-acquisition"
	components[target] = component
	admission.Spec.Components = []UpstreamAdmissionComponent{{
		CatalogConstraint: version,
		Chart: component.Spec.Delivery.Chart,
		Component: target,
		LicenseSPDX: "Apache-2.0",
		Rationale: "synthetic unresolved negative-control fixture",
		SelectedVersion: &version,
		Source: "https://example.test/charts",
		Status: "ready-for-acquisition",
		RuntimeStatus: "eligible-after-source-resolution",
		UpstreamVersion: &version,
	}}
	if err := ValidateUpstreamAdmission(admission, components); err != nil {
		t.Fatalf("synthetic ready admission fixture invalid before drift: %v", err)
	}
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
