package controlplane

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestOIDCGroupMappingResolutionAndRevocation(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, Organization{Name: "acme", DisplayName: "Acme"}, "owner")
	prj, _ := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "owner")
	admin, err := s.CreateOIDCGroupMapping(ctx, OIDCGroupMapping{Group: "pf-admins", ProductRole: "platform-admin"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateOIDCGroupMapping(ctx, OIDCGroupMapping{Group: "acme-ops", ProductRole: "platform-operator", OrganizationID: org.ID, OrganizationRole: OrganizationOperator, ProjectID: prj.ID, ProjectRole: "project-admin"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ResolveOIDCGroups(ctx, []string{"acme-ops", "pf-admins"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Method != OIDCGroupMappingMethod || len(res.ProductRoles) != 2 || res.OrganizationRoles[org.ID] != "organization-operator" || res.ProjectRoles[prj.ID] != "project-admin" || res.MappingDigest == "" {
		t.Fatalf("resolution=%#v", res)
	}
	if _, err = s.RevokeOIDCGroupMapping(ctx, admin.ID, admin.Revision, "owner"); err != nil {
		t.Fatal(err)
	}
	res, _ = s.ResolveOIDCGroups(ctx, []string{"pf-admins"})
	if len(res.ProductRoles) != 0 {
		t.Fatalf("revoked mapping still grants %#v", res)
	}
}

func TestSecurityAuditHashChainAndFileRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, in := range []SecurityAuditInput{{Category: "AUTHENTICATION", Decision: "ALLOW", ActorID: "user-1", Authentication: "oidc", Method: "GET", Path: "/api/v1/projects", ReasonCode: "OIDC_AUTHENTICATED"}, {Category: "AUTHORIZATION", Decision: "ALLOW", ActorID: "user-1", Authentication: "oidc", Method: "GET", Path: "/api/v1/projects", ReasonCode: "PRODUCT_RBAC_ALLOWED"}, {Category: "SCOPE_AUTHORIZATION", Decision: "DENY", ActorID: "user-1", Authentication: "oidc", Method: "GET", Path: "/api/v1/projects/x", ReasonCode: "PROJECT_ACCESS_DENIED", ScopeType: "project", ScopeID: "x"}} {
		if _, err = s.AppendSecurityAudit(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.ListSecurityAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[2].PreviousDigest != events[1].Digest {
		t.Fatalf("events=%#v", events)
	}
	if err = ValidateSecurityAuditChain(events); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := reopened.ListSecurityAudit(ctx, 100)
	if len(again) != 3 || again[2].Digest != events[2].Digest {
		t.Fatalf("restart events=%#v", again)
	}
	bad := append([]SecurityAuditEvent(nil), again...)
	bad[1].ReasonCode = "tampered"
	if err = ValidateSecurityAuditChain(bad); err == nil {
		t.Fatal("tampered chain accepted")
	}
}

func TestSecurityAuditChainTimeStable(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 123000000, time.UTC)
	s := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { return prefix + "_fixed" })
	_, err := s.AppendSecurityAudit(context.Background(), SecurityAuditInput{Category: "AUTHENTICATION", Decision: "DENY", ActorID: "anonymous", ReasonCode: "bad"})
	if err != nil {
		t.Fatal(err)
	}
	events, _ := s.ListSecurityAudit(context.Background(), 10)
	if len(events) != 1 || SecurityAuditEventDigest(events[0]) != events[0].Digest {
		t.Fatalf("digest unstable %#v", events)
	}
}
