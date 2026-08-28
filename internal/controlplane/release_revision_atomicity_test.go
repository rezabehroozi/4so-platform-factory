package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func atomicBlueprintRevision(projectID, name, version, digestByte string) BlueprintRevision {
	payload := []byte(`{"apiVersion":"platform.4so.io/v1alpha1","kind":"PlatformBlueprint","metadata":{"name":"` + name + `"}}`)
	return BlueprintRevision{
		ProjectID:        projectID,
		BlueprintName:    name,
		BlueprintVersion: version,
		BlueprintDigest:  "sha256:" + digestByte,
		CatalogDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Payload:          payload,
	}
}

func TestCatalogAtomicCreateRejectsDuplicateWithoutRevisionSideEffects(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "catalog-pair", DisplayName: "Catalog Pair"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	payload1 := []byte(`[{"name":"one"}]`)
	revision1 := CatalogRevision{OrganizationID: org.ID, CatalogName: "private-standard", CatalogVersion: "1.0.0", ManifestDigest: digestPayload(payload1), Payload: payload1}
	_, _, err = store.CreateCatalogReleaseWithRevision(ctx, revision1, CatalogRelease{Visibility: CatalogVisibilityPrivate, Channel: CatalogChannelCandidate}, "author")
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload2 := []byte(`[{"name":"two"}]`)
	revision2 := CatalogRevision{OrganizationID: org.ID, CatalogName: "private-standard", CatalogVersion: "1.0.0", ManifestDigest: digestPayload(payload2), Payload: payload2}
	if _, _, err = store.CreateCatalogReleaseWithRevision(ctx, revision2, CatalogRelease{Visibility: CatalogVisibilityPrivate, Channel: CatalogChannelCandidate}, "author"); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate create err=%v", err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.CatalogRevisions) != len(before.CatalogRevisions) || len(after.Audit) != len(before.Audit) || len(after.Outbox) != len(before.Outbox) {
		t.Fatalf("duplicate catalog release persisted side effects: revisions %d->%d audits %d->%d outbox %d->%d", len(before.CatalogRevisions), len(after.CatalogRevisions), len(before.Audit), len(after.Audit), len(before.Outbox), len(after.Outbox))
	}
}

func TestBlueprintAtomicCreateRejectsDuplicateWithoutRevisionSideEffects(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "blueprint-pair", DisplayName: "Blueprint Pair"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	revision1 := atomicBlueprintRevision(project.ID, "foundation", "1.0.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, _, err = store.CreateBlueprintReleaseWithRevision(ctx, revision1, BlueprintRelease{}, "author")
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	revision2 := atomicBlueprintRevision(project.ID, "foundation", "1.0.0", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if _, _, err = store.CreateBlueprintReleaseWithRevision(ctx, revision2, BlueprintRelease{}, "author"); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate create err=%v", err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Revisions) != len(before.Revisions) || len(after.Audit) != len(before.Audit) || len(after.Outbox) != len(before.Outbox) {
		t.Fatalf("duplicate blueprint release persisted side effects: revisions %d->%d audits %d->%d outbox %d->%d", len(before.Revisions), len(after.Revisions), len(before.Audit), len(after.Audit), len(before.Outbox), len(after.Outbox))
	}
}

func TestFileStoreAtomicBlueprintDraftConflictSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "control-plane.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	org, err := store.CreateOrganization(ctx, Organization{Name: "file-pair", DisplayName: "File Pair"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	revision1 := atomicBlueprintRevision(project.ID, "foundation", "1.0.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, release, err := store.CreateBlueprintReleaseWithRevision(ctx, revision1, BlueprintRelease{}, "author")
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	revision2 := atomicBlueprintRevision(project.ID, "foundation", "1.0.0", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if _, _, err = store.UpdateBlueprintReleaseDraftWithRevision(ctx, release.ID, release.Revision+9, revision2, false, "planning-only", nil, "author"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update err=%v", err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Revisions) != len(before.Revisions) || len(after.Audit) != len(before.Audit) || len(after.Outbox) != len(before.Outbox) {
		t.Fatalf("stale FileStore update persisted after restart: revisions %d->%d audits %d->%d outbox %d->%d", len(before.Revisions), len(after.Revisions), len(before.Audit), len(after.Audit), len(before.Outbox), len(after.Outbox))
	}
}
