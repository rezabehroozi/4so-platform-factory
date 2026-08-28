package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestBlueprintReleaseLifecycleLocksPublishedContent(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "blueprint-org", DisplayName: "Blueprint Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.CreateBlueprintRevision(ctx, BlueprintRevision{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "1.0.0", BlueprintDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payload: []byte(`{"kind":"PlatformBlueprint"}`)}, "author")
	if err != nil {
		t.Fatal(err)
	}
	release, err := store.CreateBlueprintRelease(ctx, BlueprintRelease{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "1.0.0", CurrentRevisionID: revision.ID, CurrentBlueprintDigest: revision.BlueprintDigest, CatalogDigest: revision.CatalogDigest, PlanStatus: "planning-only"}, "author")
	if err != nil {
		t.Fatal(err)
	}
	if release.State != BlueprintDraft {
		t.Fatalf("state=%s", release.State)
	}

	review, err := store.TransitionBlueprintRelease(ctx, release.ID, release.Revision, BlueprintReview, "author")
	if err != nil {
		t.Fatal(err)
	}
	published, err := store.TransitionBlueprintRelease(ctx, release.ID, review.Revision, BlueprintPublished, "approver")
	if err != nil {
		t.Fatal(err)
	}
	if published.State != BlueprintPublished || published.PublishedAt == nil || published.PublishedBy != "approver" {
		t.Fatalf("published=%#v", published)
	}

	_, err = store.UpdateBlueprintReleaseDraft(ctx, published.ID, published.Revision, revision.ID, revision.BlueprintDigest, revision.CatalogDigest, false, "planning-only", nil, "author")
	if !errors.Is(err, ErrImmutable) {
		t.Fatalf("published draft update err=%v", err)
	}

	deprecated, err := store.TransitionBlueprintRelease(ctx, published.ID, published.Revision, BlueprintDeprecated, "admin")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.TransitionBlueprintRelease(ctx, deprecated.ID, deprecated.Revision, BlueprintRevoked, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != BlueprintRevoked || revoked.RevokedAt == nil {
		t.Fatalf("revoked=%#v", revoked)
	}
	if _, err := store.TransitionBlueprintRelease(ctx, revoked.ID, revoked.Revision, BlueprintDraft, "admin"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("revoked transition err=%v", err)
	}
}

func TestBlueprintUpgradeEdgeRequiresPublishedSameBlueprint(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, Organization{Name: "upgrade-org", DisplayName: "Upgrade Org"}, "admin")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	mkRevision := func(version, digest string) BlueprintRevision {
		v, err := store.CreateBlueprintRevision(ctx, BlueprintRevision{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: version, BlueprintDigest: digest, CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payload: []byte(`{"kind":"PlatformBlueprint"}`)}, "author")
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	r1 := mkRevision("1.0.0", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	one, err := store.CreateBlueprintRelease(ctx, BlueprintRelease{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "1.0.0", CurrentRevisionID: r1.ID, CurrentBlueprintDigest: r1.BlueprintDigest, CatalogDigest: r1.CatalogDigest}, "author")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionBlueprintRelease(ctx, one.ID, one.Revision, BlueprintReview, "author"); err != nil {
		t.Fatal(err)
	}
	one, _ = store.GetBlueprintRelease(ctx, one.ID)
	one, err = store.TransitionBlueprintRelease(ctx, one.ID, one.Revision, BlueprintPublished, "approver")
	if err != nil {
		t.Fatal(err)
	}

	r2 := mkRevision("1.1.0", "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	two, err := store.CreateBlueprintRelease(ctx, BlueprintRelease{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "1.1.0", CurrentRevisionID: r2.ID, CurrentBlueprintDigest: r2.BlueprintDigest, CatalogDigest: r2.CatalogDigest, UpgradeFromIDs: []string{one.ID}}, "author")
	if err != nil {
		t.Fatal(err)
	}
	if len(two.UpgradeFromIDs) != 1 || two.UpgradeFromIDs[0] != one.ID {
		t.Fatalf("upgrade edges=%v", two.UpgradeFromIDs)
	}
}

func TestBlueprintReleaseFileStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "control-plane.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "blueprint-file-org", DisplayName: "Blueprint File Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.CreateBlueprintRevision(ctx, BlueprintRevision{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "2.0.0", BlueprintDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payload: []byte(`{"kind":"PlatformBlueprint"}`)}, "author")
	if err != nil {
		t.Fatal(err)
	}
	release, err := store.CreateBlueprintRelease(ctx, BlueprintRelease{ProjectID: project.ID, BlueprintName: "foundation", BlueprintVersion: "2.0.0", CurrentRevisionID: revision.ID, CurrentBlueprintDigest: revision.BlueprintDigest, CatalogDigest: revision.CatalogDigest, PlanStatus: "planning-only"}, "author")
	if err != nil {
		t.Fatal(err)
	}
	review, err := store.TransitionBlueprintRelease(ctx, release.ID, release.Revision, BlueprintReview, "author")
	if err != nil {
		t.Fatal(err)
	}
	published, err := store.TransitionBlueprintRelease(ctx, review.ID, review.Revision, BlueprintPublished, "approver")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetBlueprintRelease(ctx, published.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != BlueprintPublished || got.CurrentRevisionID != revision.ID || got.PublishedBy != "approver" {
		t.Fatalf("blueprint release did not survive restart: %#v", got)
	}
}
