package apitoken

import (
	"context"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestAPIAuthenticatorExpiryRotationRevocation(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	seq := 0
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return prefix + "_fixed_" + string(rune('a'+seq)) })
	org, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "acme", DisplayName: "Acme"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	prj, err := store.CreateProject(context.Background(), controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	sa, err := store.CreateServiceAccount(context.Background(), controlplane.ServiceAccount{OrganizationID: org.ID, ProjectID: prj.ID, Name: "automation", DisplayName: "Automation", ProductRole: "platform-operator"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	raw, prefix, digest, err := Generate("tok_fixed")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := store.CreateAPIToken(context.Background(), controlplane.APIToken{ResourceMeta: controlplane.ResourceMeta{ID: "tok_fixed"}, ServiceAccountID: sa.ID, TokenPrefix: prefix, TokenDigest: digest, Permissions: []string{"operate"}, ExpiresAt: now.Add(time.Hour), IdempotencyKey: "authn-fixed"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	authn := Authenticator{Store: store, Now: func() time.Time { return now }}
	principal, err := authn.Authenticate(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if principal.OrganizationID != org.ID || principal.ProjectID != prj.ID || principal.Authentication != "api-token" {
		t.Fatalf("bad principal %#v", principal)
	}
	if _, err = authn.Authenticate(context.Background(), raw+"x"); err == nil {
		t.Fatal("tampered token accepted")
	}
	now = now.Add(2 * time.Hour)
	if _, err = authn.Authenticate(context.Background(), raw); err == nil {
		t.Fatal("expired token accepted")
	}
	now = now.Add(-2 * time.Hour)
	if _, err = store.RevokeAPIToken(context.Background(), tok.ID, tok.Revision, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = authn.Authenticate(context.Background(), raw); err == nil {
		t.Fatal("revoked token accepted")
	}
}
