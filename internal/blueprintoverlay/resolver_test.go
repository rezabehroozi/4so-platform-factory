package blueprintoverlay

import (
	"encoding/json"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/domain"
)

func overlayValue(v any) json.RawMessage { raw, _ := json.Marshal(v); return raw }
func baseBlueprint() domain.Blueprint {
	return domain.Blueprint{APIVersion: "platform.4so.io/v1alpha1", Kind: "PlatformBlueprint", Metadata: domain.BlueprintMetadata{Name: "base", Version: "1.0.0"}, Spec: domain.BlueprintSpec{
		Description: "base description",
		Delivery:    domain.Delivery{Mode: "gitops", Repository: "https://git.example.com/base.git", OCIRegistry: "registry.example.com/platform", Revision: "main", RevisionType: "branch"},
		FieldOwnership: []domain.FieldOwnershipRule{
			{Path: "/spec/delivery/repository", Policy: ProviderOnly},
			{Path: "/spec/description", Policy: ProviderThenEnvironment},
		},
	}}
}
func TestResolveProviderThenEnvironmentWithProvenance(t *testing.T) {
	provider, _ := controlplane.NormalizeBlueprintOverlay(controlplane.BlueprintOverlay{ProjectID: "prj", Name: "vsphere", Version: "1.0.0", Scope: controlplane.BlueprintOverlayProvider, ScopeKey: "vsphere", Changes: []controlplane.BlueprintOverlayChange{{Path: "/spec/delivery/repository", Value: overlayValue("https://git.example.com/vsphere.git")}, {Path: "/spec/description", Value: overlayValue("provider description")}}})
	provider.ID = "bpo-provider"
	env, _ := controlplane.NormalizeBlueprintOverlay(controlplane.BlueprintOverlay{ProjectID: "prj", Name: "prod", Version: "1.0.0", Scope: controlplane.BlueprintOverlayEnvironment, ScopeKey: "production", Changes: []controlplane.BlueprintOverlayChange{{Path: "/spec/description", Value: overlayValue("production description")}}})
	env.ID = "bpo-env"
	resolved, resolution, err := Resolve(baseBlueprint(), &provider, &env)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Spec.Delivery.Repository != "https://git.example.com/vsphere.git" || resolved.Spec.Description != "production description" {
		t.Fatalf("unexpected resolution: %#v", resolved.Spec)
	}
	if resolution.ProviderOverlayID != provider.ID || resolution.EnvironmentOverlayID != env.ID || resolution.BaseBlueprintDigest == "" || resolution.OverlayDigest == "" || resolution.OwnershipDigest == "" {
		t.Fatalf("missing resolution provenance: %#v", resolution)
	}
	foundEnv := false
	for _, f := range resolution.Fields {
		if f.Path == "/spec/description" {
			foundEnv = true
			if f.EffectiveOwner != "ENVIRONMENT:production" || f.ProviderOverlayID != provider.ID || f.EnvironmentOverlayID != env.ID {
				t.Fatalf("unexpected field provenance: %#v", f)
			}
		}
	}
	if !foundEnv {
		t.Fatal("description field provenance missing")
	}
}
func TestResolveRejectsUnauthorizedOverride(t *testing.T) {
	env, _ := controlplane.NormalizeBlueprintOverlay(controlplane.BlueprintOverlay{ProjectID: "prj", Name: "prod", Version: "1.0.0", Scope: controlplane.BlueprintOverlayEnvironment, ScopeKey: "production", Changes: []controlplane.BlueprintOverlayChange{{Path: "/spec/delivery/repository", Value: overlayValue("https://git.example.com/evil.git")}}})
	if _, _, err := Resolve(baseBlueprint(), nil, &env); err == nil {
		t.Fatal("expected field ownership conflict")
	}
}
func TestResolveRejectsUnownedPath(t *testing.T) {
	provider, _ := controlplane.NormalizeBlueprintOverlay(controlplane.BlueprintOverlay{ProjectID: "prj", Name: "vsphere", Version: "1.0.0", Scope: controlplane.BlueprintOverlayProvider, ScopeKey: "vsphere", Changes: []controlplane.BlueprintOverlayChange{{Path: "/spec/delivery/ociRegistry", Value: overlayValue("other.example.com/x")}}})
	if _, _, err := Resolve(baseBlueprint(), &provider, nil); err == nil {
		t.Fatal("expected BLUEPRINT_ONLY conflict")
	}
}
