package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
)

func catalogTestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func signCatalogForTest(t *testing.T, store Store, release CatalogRelease, key CatalogTrustKey, privateKey ed25519.PrivateKey, actor string) CatalogRelease {
	t.Helper()
	payload, err := CatalogSignaturePayload(release)
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	updated, err := store.SubmitCatalogReleaseReview(context.Background(), release.ID, release.Revision, key.ID, key.Fingerprint, sig, actor)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func TestCatalogGovernanceLifecyclePromotionAndTrustRevocation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "acme", DisplayName: "ACME"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.CreateCatalogTrustKey(ctx, CatalogTrustKey{OrganizationID: org.ID, Name: "release", PublicKey: base64.StdEncoding.EncodeToString(publicKey)}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`[{"apiVersion":"platform.4so.io/v1alpha1","kind":"PlatformComponent","metadata":{"name":"cilium"},"spec":{}}]`)
	digest := catalogTestDigest(raw)
	revision, err := store.CreateCatalogRevision(ctx, CatalogRevision{OrganizationID: org.ID, CatalogName: "private-standard", CatalogVersion: "1.0.0", ManifestDigest: digest, Payload: raw}, "author")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := store.CreateCatalogRelease(ctx, CatalogRelease{OrganizationID: org.ID, CatalogName: "private-standard", CatalogVersion: "1.0.0", Visibility: CatalogVisibilityPrivate, Channel: CatalogChannelCandidate, CurrentRevisionID: revision.ID, ManifestDigest: digest}, "author")
	if err != nil {
		t.Fatal(err)
	}
	candidate = signCatalogForTest(t, store, candidate, key, privateKey, "author")
	candidate, err = store.TransitionCatalogRelease(ctx, candidate.ID, candidate.Revision, CatalogPublished, "approver")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.State != CatalogPublished || candidate.SigningKeyFingerprint != key.Fingerprint {
		t.Fatalf("unexpected published release: %+v", candidate)
	}

	render, err := store.CreateCatalogRelease(ctx, CatalogRelease{OrganizationID: org.ID, CatalogName: "private-standard", CatalogVersion: "1.0.0", Visibility: CatalogVisibilityPrivate, Channel: CatalogChannelRender, CurrentRevisionID: revision.ID, ManifestDigest: digest, SourceReleaseID: candidate.ID}, "author")
	if err != nil {
		t.Fatal(err)
	}
	render = signCatalogForTest(t, store, render, key, privateKey, "author")
	key, err = store.RevokeCatalogTrustKey(ctx, key.ID, key.Revision, "security-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionCatalogRelease(ctx, render.ID, render.Revision, CatalogPublished, "approver"); err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("expected revoked trust key to block publish, got %v", err)
	}
}

func TestCatalogGovernanceFileStoreRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "authority.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.CreateCatalogTrustKey(ctx, CatalogTrustKey{Name: "platform-release", PublicKey: base64.StdEncoding.EncodeToString(publicKey)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`[]`)
	revision, err := store.CreateCatalogRevision(ctx, CatalogRevision{CatalogName: "platform", CatalogVersion: "1.0.0", ManifestDigest: catalogTestDigest(raw), Payload: raw}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	release, err := store.CreateCatalogRelease(ctx, CatalogRelease{CatalogName: "platform", CatalogVersion: "1.0.0", Visibility: CatalogVisibilityPlatform, Channel: CatalogChannelCandidate, CurrentRevisionID: revision.ID, ManifestDigest: revision.ManifestDigest}, "admin")
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, err := reopened.GetCatalogTrustKey(ctx, key.ID)
	if err != nil || gotKey.Fingerprint != key.Fingerprint {
		t.Fatalf("trust key restart mismatch: %+v %v", gotKey, err)
	}
	gotRelease, err := reopened.GetCatalogRelease(ctx, release.ID)
	if err != nil || gotRelease.ManifestDigest != release.ManifestDigest {
		t.Fatalf("catalog release restart mismatch: %+v %v", gotRelease, err)
	}
	gotRevision, err := reopened.GetCatalogRevision(ctx, revision.ID)
	if err != nil || string(gotRevision.Payload) != string(raw) {
		t.Fatalf("catalog revision restart mismatch: %+v %v", gotRevision, err)
	}
}
