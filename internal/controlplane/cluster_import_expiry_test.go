package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClusterImportExpiryIsTruthfulAndReleasesName(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStoreWith(func() time.Time { return now }, nil)
	ctx := context.Background()
	org, err := s.CreateOrganization(ctx, Organization{Name: "expiry-org", DisplayName: "Expiry Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "expiry-project", DisplayName: "Expiry Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imp, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "edge", DisplayName: "Edge", TokenDigest: token, ExpiresAt: now.Add(5 * time.Minute)}, "operator")
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(6 * time.Minute)
	got, err := s.GetClusterImport(ctx, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != ClusterImportExpired {
		t.Fatalf("expired import rendered as %s", got.State)
	}
	listed, err := s.ListClusterImports(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].State != ClusterImportExpired {
		t.Fatalf("expired import list=%+v", listed)
	}
	if _, _, err = s.ClaimClusterImport(ctx, imp.ID, token, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "uid-expired", "test-agent"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expired token claim error=%v", err)
	}
	if _, err = s.RevokeClusterImport(ctx, imp.ID, imp.Revision, "operator"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expired import revoke error=%v", err)
	}

	replacement, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "edge", DisplayName: "Edge replacement", TokenDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ExpiresAt: now.Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatalf("replacement after natural expiry: %v", err)
	}
	if replacement.ID == imp.ID {
		t.Fatal("replacement reused expired import identity")
	}

	persisted, err := s.GetClusterImport(ctx, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != ClusterImportExpired || persisted.Revision != imp.Revision+1 {
		t.Fatalf("expired authority not materialized on replacement: %+v", persisted)
	}
	if persisted.TokenDigest != "sha256:expired" {
		t.Fatalf("expired enrollment credential was not invalidated: %q", persisted.TokenDigest)
	}
	audit, err := s.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range audit {
		if event.ResourceID == imp.ID && event.Action == "cluster_import.expired" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("cluster_import.expired audit event missing")
	}
}

func TestClusterImportExpiryMaterializationSurvivesFileStoreRestart(t *testing.T) {
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	path := t.TempDir() + "/state.json"
	f := &FileStore{MemoryStore: NewMemoryStoreWith(func() time.Time { return now }, nil), path: path}
	ctx := context.Background()
	org, err := f.CreateOrganization(ctx, Organization{Name: "file-expiry-org", DisplayName: "File Expiry Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := f.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "file-expiry-project", DisplayName: "File Expiry Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err := f.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "edge", DisplayName: "Edge", TokenDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", ExpiresAt: now.Add(5 * time.Minute)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Minute)
	if _, err = f.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "edge", DisplayName: "Edge replacement", TokenDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", ExpiresAt: now.Add(time.Hour)}, "operator"); err != nil {
		t.Fatalf("replacement after expiry: %v", err)
	}

	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	old, err := reopened.GetClusterImport(ctx, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != ClusterImportExpired || old.Revision != imp.Revision+1 {
		t.Fatalf("reopened expired import=%+v", old)
	}
	reopened.mu.RLock()
	digest := reopened.clusterImports[imp.ID].TokenDigest
	reopened.mu.RUnlock()
	if digest != "sha256:expired" {
		t.Fatalf("reopened expired credential digest=%q", digest)
	}
}
