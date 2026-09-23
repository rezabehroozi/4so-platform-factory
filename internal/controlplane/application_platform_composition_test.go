package controlplane

import (
	"strings"
	"testing"
)

func appDigest(ch byte) string { return "sha256:" + strings.Repeat(string(ch), 64) }

func TestWorkloadCompositionSuppressesObservedNativeCapabilityDeterministically(t *testing.T) {
	workload := WorkloadType{
		ProjectID: "prj-1", Name: "api", Version: "1.0.0", InputSchemaDigest: appDigest('a'),
		AllowedTraitKinds: []string{"security", "ingress"},
	}
	ingress := CapabilityTrait{ProjectID: "prj-1", Name: "public-ingress", Version: "1.0.0", Kind: "ingress", Capability: "networking.ingress", InputSchemaDigest: appDigest('b'), NativeSuppression: true}
	security := CapabilityTrait{ProjectID: "prj-1", Name: "restricted", Version: "1.0.0", Kind: "security", Capability: "security.pod-policy", InputSchemaDigest: appDigest('c'), NativeSuppression: true}

	first, err := ResolveWorkloadComposition(workload, []CapabilityTrait{security, ingress}, []string{"security.pod-policy"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveWorkloadComposition(workload, []CapabilityTrait{ingress, security}, []string{"security.pod-policy"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Authority != WorkloadCompositionAuthority || first.ResolutionDigest != second.ResolutionDigest {
		t.Fatalf("composition is not deterministic: first=%#v second=%#v", first, second)
	}
	actions := map[string]string{}
	for _, decision := range first.Decisions {
		actions[decision.Capability] = decision.Action
	}
	if actions["security.pod-policy"] != TraitDecisionSuppressNative || actions["networking.ingress"] != TraitDecisionApply {
		t.Fatalf("unexpected trait resolution: %#v", first.Decisions)
	}
}

func TestWorkloadCompositionRejectsDuplicateOrUnownedCapabilities(t *testing.T) {
	workload := WorkloadType{ProjectID: "prj-1", Name: "api", Version: "1.0.0", InputSchemaDigest: appDigest('a'), AllowedTraitKinds: []string{"observability"}}
	trait := CapabilityTrait{ProjectID: "prj-1", Name: "metrics", Version: "1.0.0", Kind: "observability", Capability: "monitoring.metrics", InputSchemaDigest: appDigest('b')}
	if _, err := ResolveWorkloadComposition(workload, []CapabilityTrait{trait}, []string{"monitoring.metrics"}); err == nil {
		t.Fatal("native capability collision without suppression was accepted")
	}
	trait.NativeSuppression = true
	other := trait
	other.Name = "metrics-two"
	if _, err := ResolveWorkloadComposition(workload, []CapabilityTrait{trait, other}, nil); err == nil {
		t.Fatal("duplicate trait capability ownership was accepted")
	}
	trait.ProjectID = "prj-2"
	if _, err := ResolveWorkloadComposition(workload, []CapabilityTrait{trait}, nil); err == nil {
		t.Fatal("cross-project trait composition was accepted")
	}
}

func TestManagedResourceTypeRequiresSecretReferencesForSensitiveOutputs(t *testing.T) {
	base := ManagedResourceType{
		ProjectID: "prj-1", Name: "postgres", Version: "1.0.0", Category: "database", Provisioner: "product-api",
		InputSchemaDigest: appDigest('d'), DeletePolicy: "retain", RetentionPolicy: "customer-data",
		ReadinessConditions: []string{"endpoint-ready", "credentials-ready"},
		Outputs: []ManagedResourceOutput{
			{Name: "endpoint", Type: "endpoint"},
			{Name: "credentials", Type: "string", Sensitive: true},
		},
	}
	if _, err := NormalizeManagedResourceType(base); err == nil {
		t.Fatal("plaintext-shaped sensitive resource output was accepted")
	}
	base.Outputs[1] = ManagedResourceOutput{Name: "credentials", Type: "secret-reference", Sensitive: true, SecretReference: true}
	normalized, err := NormalizeManagedResourceType(base)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Digest == "" || normalized.Outputs[0].Name != "credentials" || normalized.Outputs[1].Name != "endpoint" {
		t.Fatalf("managed resource normalization drift: %#v", normalized)
	}
	if normalized.Outputs[0].Type != "secret-reference" || !normalized.Outputs[0].SecretReference {
		t.Fatalf("secret output contract lost: %#v", normalized.Outputs)
	}
}

func TestWorkspaceProfileReleaseAndEnvironmentBindingAreImmutableDigestAuthorities(t *testing.T) {
	profile, err := NormalizeWorkspaceProfile(WorkspaceProfile{
		ProjectID: "prj-1", Name: "production", Version: "1.0.0",
		AuthorityRefs: []ApplicationAuthorityRef{
			{Kind: "cost-policy", ID: "cost-standard", Digest: appDigest('e')},
			{Kind: "policy-set", ID: "policy-production", Digest: appDigest('f')},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := NormalizeApplicationRelease(ApplicationRelease{
		ProjectID: "prj-1", Name: "payments", Version: "2.1.0",
		WorkloadTypeDigest: appDigest('a'), TraitDigests: []string{appDigest('b')},
		ManagedResourceDigests: []string{appDigest('c')}, WorkspaceProfileDigest: profile.Digest, SourceDigest: appDigest('d'),
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NormalizeEnvironmentBinding(EnvironmentBinding{
		ProjectID: "prj-1", ReleaseID: "rel-payments-2-1-0", ReleaseDigest: release.Digest,
		WorkspaceID: "ws-prod", ClusterID: "cluster-1", Namespace: "payments", Environment: "production",
		CapabilityResolutionDigest: appDigest('9'),
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Digest == "" || release.Digest == "" || binding.Digest == "" {
		t.Fatalf("immutable digest authority incomplete: profile=%#v release=%#v binding=%#v", profile, release, binding)
	}
	changed := binding
	changed.Namespace = "payments-canary"
	changed, err = NormalizeEnvironmentBinding(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Digest == binding.Digest {
		t.Fatal("environment binding digest did not change with desired target scope")
	}
}

func TestApplicationPlatformAuthorityConstantsRemainExplicit(t *testing.T) {
	for name, value := range map[string]string{
		"workload": WorkloadTypeAuthority,
		"trait": CapabilityTraitAuthority,
		"composition": WorkloadCompositionAuthority,
		"resource": ManagedResourceTypeAuthority,
		"workspaceProfile": WorkspaceProfileAuthority,
		"release": ApplicationReleaseAuthority,
		"binding": EnvironmentBindingAuthority,
	} {
		if value == "" || !strings.HasSuffix(value, "_V1") {
			t.Fatalf("%s authority is not explicit/versioned: %q", name, value)
		}
	}
}
