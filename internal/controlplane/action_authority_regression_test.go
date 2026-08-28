package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestActionAuthorityRejectsStaleMembershipEntitlementAndOEMWrites(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	org, err := s.CreateOrganization(ctx, Organization{Name: "authority-a", DisplayName: "Authority A"}, "admin")
	if err != nil {
		t.Fatal(err)
	}

	membership, err := s.UpsertOrganizationMembership(ctx, OrganizationMembership{OrganizationID: org.ID, Subject: "member", Role: OrganizationViewer}, 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := s.RevokeOrganizationMembership(ctx, org.ID, "member", membership.Revision, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpsertOrganizationMembership(ctx, OrganizationMembership{OrganizationID: org.ID, Subject: "member", Role: OrganizationAdmin}, membership.Revision, "stale-admin"); err != ErrConflict {
		t.Fatalf("stale membership write err=%v", err)
	}
	current, err := s.GetOrganizationMembership(ctx, org.ID, "member")
	if err != nil {
		t.Fatal(err)
	}
	if current.State != OrganizationMembershipRevoked || current.Revision != revoked.Revision {
		t.Fatalf("membership=%+v", current)
	}

	ent, err := s.UpsertEntitlement(ctx, Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	ent2, err := s.UpsertEntitlement(ctx, Entitlement{OrganizationID: org.ID, Edition: "enterprise"}, ent.Revision, "admin-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpsertEntitlement(ctx, Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, ent.Revision, "stale-admin"); err != ErrConflict {
		t.Fatalf("stale entitlement write err=%v", err)
	}
	currentEnt, _ := s.GetEntitlement(ctx, org.ID)
	if currentEnt.Edition != "enterprise" || currentEnt.Revision != ent2.Revision {
		t.Fatalf("entitlement=%+v", currentEnt)
	}

	// Re-enable OEM and prove stale OEM forms cannot overwrite a newer profile.
	ent3, err := s.UpsertEntitlement(ctx, Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, ent2.Revision, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_ = ent3
	oem, err := s.UpsertOEMProfile(ctx, OEMProfile{OrganizationID: org.ID, BrandName: "A", ProductTitle: "Platform A", DefaultLocale: "en"}, 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	oem2, err := s.UpsertOEMProfile(ctx, OEMProfile{OrganizationID: org.ID, BrandName: "B", ProductTitle: "Platform B", DefaultLocale: "en"}, oem.Revision, "admin-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpsertOEMProfile(ctx, OEMProfile{OrganizationID: org.ID, BrandName: "STALE", ProductTitle: "Stale", DefaultLocale: "en"}, oem.Revision, "stale-admin"); err != ErrConflict {
		t.Fatalf("stale OEM write err=%v", err)
	}
	currentOEM, _ := s.GetOEMProfile(ctx, org.ID)
	if currentOEM.BrandName != "B" || currentOEM.Revision != oem2.Revision {
		t.Fatalf("oem=%+v", currentOEM)
	}
}

func TestAPITokenIdempotencyPreventsDuplicateIssueAndRotate(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	now := time.Now().UTC()
	org, _ := s.CreateOrganization(ctx, Organization{Name: "token-idem", DisplayName: "Token Idem"}, "admin")
	project, _ := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "admin")
	sa, err := s.CreateServiceAccount(ctx, ServiceAccount{OrganizationID: org.ID, ProjectID: project.ID, Name: "automation", DisplayName: "Automation", ProductRole: "platform-operator"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.CreateAPIToken(ctx, APIToken{ServiceAccountID: sa.ID, TokenPrefix: "pft.first", TokenDigest: "sha256:" + repeatHex("1"), IdempotencyKey: "issue-request-1", Permissions: []string{"operate"}, ExpiresAt: now.Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateAPIToken(ctx, APIToken{ServiceAccountID: sa.ID, TokenPrefix: "pft.duplicate", TokenDigest: "sha256:" + repeatHex("2"), IdempotencyKey: "issue-request-1", Permissions: []string{"operate"}, ExpiresAt: now.Add(time.Hour)}, "admin"); err != ErrConflict {
		t.Fatalf("duplicate issue err=%v", err)
	}
	_, replacement, err := s.RotateAPIToken(ctx, first.ID, first.Revision, APIToken{TokenPrefix: "pft.rotated", TokenDigest: "sha256:" + repeatHex("3"), IdempotencyKey: "rotate-request-1", Permissions: []string{"operate"}, ExpiresAt: now.Add(2 * time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.RotateAPIToken(ctx, first.ID, first.Revision, APIToken{TokenPrefix: "pft.rotated-again", TokenDigest: "sha256:" + repeatHex("4"), IdempotencyKey: "rotate-request-1", Permissions: []string{"operate"}, ExpiresAt: now.Add(2 * time.Hour)}, "admin"); err != ErrConflict {
		t.Fatalf("duplicate rotation err=%v", err)
	}
	byKey, err := s.GetAPITokenByIdempotencyKey(ctx, sa.ID, "rotate-request-1")
	if err != nil || byKey.ID != replacement.ID {
		t.Fatalf("byKey=%+v err=%v", byKey, err)
	}
	tokens, _ := s.ListAPITokens(ctx, sa.ID)
	if len(tokens) != 2 {
		t.Fatalf("tokens=%d want=2", len(tokens))
	}
}
