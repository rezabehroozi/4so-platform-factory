package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRevokeManagedClusterInvalidatesAgentAndAllowsReenrollment(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	org, err := s.CreateOrganization(ctx, Organization{Name: "acme", DisplayName: "Acme"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "edge-1", DisplayName: "Edge 1", TokenDigest: "sha256:enroll", ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = s.ApproveClusterImport(ctx, imp.ID, imp.Revision, "admin-2")
	if err != nil {
		t.Fatal(err)
	}
	imp, cluster, err := s.ClaimClusterImport(ctx, imp.ID, "sha256:enroll", "sha256:agent", "external-1", "0.0.34")
	if err != nil {
		t.Fatal(err)
	}
	firstPrincipal := imp.AgentServiceAccount
	if firstPrincipal == "" || firstPrincipal != FleetAgentServiceAccountName(imp.ID) {
		t.Fatalf("first enrollment principal is not import-scoped: import=%#v", imp)
	}
	cluster, imp, err = s.RevokeManagedCluster(ctx, cluster.ID, cluster.Revision, "admin-2")
	if err != nil {
		t.Fatal(err)
	}
	if cluster.ConnectionState != "REVOKED" || imp.State != ClusterImportRevoked || imp.AgentTokenDigest != "" {
		t.Fatalf("cluster=%#v import=%#v", cluster, imp)
	}
	if _, err = s.HeartbeatCluster(ctx, cluster.ID, "sha256:agent", cluster.ExternalUID, "0.0.34"); !errors.Is(err, ErrValidation) {
		t.Fatalf("old agent token must fail, err=%v", err)
	}
	replacement, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "edge-1", DisplayName: "Edge 1 replacement", TokenDigest: "sha256:new-enroll", ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatalf("create re-enrollment after revocation failed: %v", err)
	}
	replacement, err = s.ApproveClusterImport(ctx, replacement.ID, replacement.Revision, "admin-2")
	if err != nil {
		t.Fatalf("approve re-enrollment after revocation failed: %v", err)
	}
	if _, _, err = s.ClaimClusterImport(ctx, replacement.ID, "sha256:new-enroll", "sha256:new-agent", cluster.ExternalUID, "0.0.212"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("same-UID re-enrollment must remain blocked until target RBAC revocation is acknowledged, err=%v", err)
	}
	fenceDigest := ClusterTargetRBACRevocationFenceDigest(cluster)
	if _, err = s.AcknowledgeManagedClusterTargetRBACRevocation(ctx, cluster.ID, cluster.Revision, "sha256:"+strings.Repeat("0", 64), "admin-2"); !errors.Is(err, ErrValidation) {
		t.Fatalf("wrong target-RBAC revocation fence digest was accepted: %v", err)
	}
	unchanged, err := s.GetManagedCluster(ctx, cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Revision != cluster.Revision || unchanged.TargetRBACRevocationAcknowledgedAt != nil || unchanged.TargetRBACRevocationAcknowledgedDigest != "" {
		t.Fatalf("wrong digest mutated revocation acknowledgement authority: before=%#v after=%#v", cluster, unchanged)
	}
	cluster, err = s.AcknowledgeManagedClusterTargetRBACRevocation(ctx, cluster.ID, cluster.Revision, fenceDigest, "admin-2")
	if err != nil {
		t.Fatalf("acknowledge target RBAC revocation fence: %v", err)
	}
	if !ClusterTargetRBACRevocationAcknowledged(cluster) {
		t.Fatalf("target RBAC revocation acknowledgement did not bind to the current fence: %#v", cluster)
	}
	replacement, replacementCluster, err := s.ClaimClusterImport(ctx, replacement.ID, "sha256:new-enroll", "sha256:new-agent", cluster.ExternalUID, "0.0.212")
	if err != nil {
		t.Fatalf("claim re-enrollment with the same physical cluster UID after fence acknowledgement failed: %v", err)
	}
	if replacementCluster.ID == cluster.ID || replacementCluster.ExternalUID != cluster.ExternalUID || replacementCluster.ConnectionState != "CONNECTED" {
		t.Fatalf("replacementCluster=%#v revokedCluster=%#v", replacementCluster, cluster)
	}
	if replacement.AgentServiceAccount == "" || replacement.AgentServiceAccount != FleetAgentServiceAccountName(replacement.ID) {
		t.Fatalf("replacement enrollment principal is not import-scoped: import=%#v", replacement)
	}
	if replacement.AgentServiceAccount == firstPrincipal {
		t.Fatalf("re-enrollment inherited revoked mutation principal %q", firstPrincipal)
	}
}

func TestClaimClusterImportRejectsConcurrentDuplicatePhysicalClusterAuthority(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	org, err := s.CreateOrganization(ctx, Organization{Name: "dup-uid-org", DisplayName: "Duplicate UID Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	claim := func(name, enrollment, agent string) (ManagedCluster, error) {
		imp, e := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: name, DisplayName: name, TokenDigest: enrollment, ExpiresAt: time.Now().Add(time.Hour)}, "operator")
		if e != nil {
			return ManagedCluster{}, e
		}
		imp, e = s.ApproveClusterImport(ctx, imp.ID, imp.Revision, "admin-2")
		if e != nil {
			return ManagedCluster{}, e
		}
		_, cluster, e := s.ClaimClusterImport(ctx, imp.ID, enrollment, agent, "physical-cluster-uid", "0.0.207")
		return cluster, e
	}
	if _, err = claim("edge-a", "sha256:enroll-a", "sha256:agent-a"); err != nil {
		t.Fatalf("first physical cluster claim failed: %v", err)
	}
	if _, err = claim("edge-b", "sha256:enroll-b", "sha256:agent-b"); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate active physical cluster claim must be rejected, err=%v", err)
	}
}
