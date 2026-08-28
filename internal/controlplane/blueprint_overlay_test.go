package controlplane

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func rawValue(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func TestBlueprintOverlayFileStoreIsImmutableAndSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "overlay-org", DisplayName: "Overlay Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateBlueprintOverlay(ctx, BlueprintOverlay{ProjectID: project.ID, Name: "vsphere-prod", Version: "1.0.0", Scope: BlueprintOverlayProvider, ScopeKey: "vsphere", Changes: []BlueprintOverlayChange{{Path: "/spec/delivery/repository", Value: rawValue("https://git.example.com/vsphere.git")}}}, "author")
	if err != nil {
		t.Fatal(err)
	}
	if created.Digest == "" || created.Revision != 1 {
		t.Fatalf("unexpected overlay: %#v", created)
	}
	if _, err := store.CreateBlueprintOverlay(ctx, BlueprintOverlay{ProjectID: project.ID, Name: "vsphere-prod", Version: "1.0.0", Scope: BlueprintOverlayProvider, ScopeKey: "vsphere", Changes: []BlueprintOverlayChange{{Path: "/spec/description", Value: rawValue("x")}}}, "author"); err != ErrDuplicateName {
		t.Fatalf("expected duplicate immutable version, got %v", err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetBlueprintOverlay(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != created.Digest || string(got.Changes[0].Value) != string(created.Changes[0].Value) {
		t.Fatalf("overlay did not survive restart: %#v", got)
	}
}

func TestBlueprintRevisionRejectsWrongScopeAndCrossProjectOverlay(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "scope-org", DisplayName: "Scope Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "one", DisplayName: "One"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "two", DisplayName: "Two"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	env, err := store.CreateBlueprintOverlay(ctx, BlueprintOverlay{ProjectID: project.ID, Name: "prod-env", Version: "1.0.0", Scope: BlueprintOverlayEnvironment, ScopeKey: "prod", Changes: []BlueprintOverlayChange{{Path: "/spec/description", Value: rawValue("prod")}}}, "author")
	if err != nil {
		t.Fatal(err)
	}
	providerOther, err := store.CreateBlueprintOverlay(ctx, BlueprintOverlay{ProjectID: other.ID, Name: "vsphere", Version: "1.0.0", Scope: BlueprintOverlayProvider, ScopeKey: "vsphere", Changes: []BlueprintOverlayChange{{Path: "/spec/description", Value: rawValue("provider")}}}, "author")
	if err != nil {
		t.Fatal(err)
	}
	base := BlueprintRevision{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "1.0.0", BlueprintDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payload: []byte(`{"kind":"PlatformBlueprint"}`)}
	wrongScope := base
	wrongScope.ProviderOverlayID = env.ID
	if _, err := store.CreateBlueprintRevision(ctx, wrongScope, "author"); err == nil {
		t.Fatal("expected ENVIRONMENT overlay to be rejected as provider overlay")
	}
	crossProject := base
	crossProject.ProviderOverlayID = providerOther.ID
	if _, err := store.CreateBlueprintRevision(ctx, crossProject, "author"); err == nil {
		t.Fatal("expected cross-project provider overlay to be rejected")
	}
}

func TestBlueprintOverlayRejectsPlaintextSecretShapedField(t *testing.T) {
	_, err := NormalizeBlueprintOverlay(BlueprintOverlay{ProjectID: "project-1", Name: "bad-secret", Version: "1.0.0", Scope: BlueprintOverlayEnvironment, ScopeKey: "prod", Changes: []BlueprintOverlayChange{{Path: "/spec/components/0/settings/apiToken", Value: rawValue("plaintext-secret-value")}}})
	if err == nil {
		t.Fatal("expected plaintext secret-shaped overlay path to be rejected")
	}
	if _, err := NormalizeBlueprintOverlay(BlueprintOverlay{ProjectID: "project-1", Name: "good-ref", Version: "1.0.0", Scope: BlueprintOverlayEnvironment, ScopeKey: "prod", Changes: []BlueprintOverlayChange{{Path: "/spec/components/0/settings/apiTokenRef", Value: rawValue("secret/path")}}}); err != nil {
		t.Fatalf("secret reference path must remain allowed: %v", err)
	}
}
