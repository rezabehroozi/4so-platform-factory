package controlplane

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitCredentialReferenceRotationAndFilePersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := store.CreateGitCredential(ctx, GitCredential{Name: "internal-forgejo", Username: "platform-admin", SecretRef: "env://PF_GIT_SECRET_A"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	p, err := store.CreateGitProvider(ctx, GitProvider{Name: "internal-forgejo", Kind: "FORGEJO", BaseURL: "https://git.example.test", CredentialID: c1.ID, Default: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	old, c2, err := store.RotateGitCredential(ctx, c1.ID, c1.Revision, GitCredential{SecretRef: "env://PF_GIT_SECRET_B"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if old.State != GitCredentialRevoked || c2.State != GitCredentialActive {
		t.Fatalf("old=%+v new=%+v", old, c2)
	}
	rebound, cred, err := store.GetDefaultGitProvider(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.ID != p.ID || rebound.CredentialID != c2.ID || cred.SecretRef != "env://PF_GIT_SECRET_B" {
		t.Fatalf("provider=%+v credential=%+v", rebound, cred)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snap)
	if strings.Contains(string(raw), "super-secret-a") || strings.Contains(string(raw), "super-secret-b") {
		t.Fatal("raw secret material entered snapshot")
	}
	reloaded, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rp, rc, err := reloaded.GetDefaultGitProvider(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rp.CredentialID != c2.ID || rc.SecretRef != "env://PF_GIT_SECRET_B" {
		t.Fatalf("reloaded provider=%+v credential=%+v", rp, rc)
	}
}
