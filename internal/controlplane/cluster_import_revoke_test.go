package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestClusterImportRevokeReleasesActiveNameAndInvalidatesToken(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	org, err := s.CreateOrganization(ctx, Organization{Name: "revoke-org", DisplayName: "Revoke Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "revoke-project", DisplayName: "Revoke Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "edge", DisplayName: "Edge", TokenDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := s.RevokeClusterImport(ctx, imp.ID, imp.Revision, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != ClusterImportRevoked || revoked.Revision != 2 {
		t.Fatalf("revoked=%+v", revoked)
	}
	if _, _, err = s.ClaimClusterImport(ctx, imp.ID, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "uid-old", "test-agent"); err == nil {
		t.Fatal("revoked token unexpectedly claimed")
	}
	if _, err = s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "edge", DisplayName: "Edge replacement", TokenDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ExpiresAt: time.Now().Add(time.Hour)}, "operator"); err != nil {
		t.Fatalf("replacement import after revoke: %v", err)
	}
}
