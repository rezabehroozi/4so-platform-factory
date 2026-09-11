package controlplane

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func newMCPDelegationTestStore() *MemoryStore {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	n := 0
	return NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { n++; return fmt.Sprintf("%s_%d", prefix, n) })
}

func TestMCPHumanDelegationLifecycleAndClientRevocation(t *testing.T) {
	ctx := context.Background()
	s := newMCPDelegationTestStore()
	org, err := s.CreateOrganization(ctx, Organization{Name: "acme", DisplayName: "Acme"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	prj, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	client, err := s.CreateMCPTrustedClient(ctx, MCPTrustedClient{ClientID: "claude-desktop", DisplayName: "Claude", Provider: "claude", RedirectURIs: []string{"https://client.example/callback"}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := s.CreateMCPDelegationGrant(ctx, MCPDelegationGrant{Issuer: "https://id.example/realms/4so", Subject: "user-1", ClientID: client.ClientID, OrganizationID: org.ID, ProjectID: prj.ID, AccessProfile: MCPDelegationOperate, ConsentDigest: "abcd", ExpiresAt: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)}, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetActiveMCPDelegationGrant(ctx, grant.Issuer, grant.Subject, grant.ClientID, time.Date(2026, 9, 6, 12, 30, 0, 0, time.UTC)); err != nil {
		t.Fatalf("active grant lookup: %v", err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.MCPTrustedClients) != 1 || len(snap.MCPDelegationGrants) != 1 {
		t.Fatalf("snapshot missing MCP delegation authority: %#v", snap)
	}
	restored := newMCPDelegationTestStore()
	if err := restored.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.GetActiveMCPDelegationGrant(ctx, grant.Issuer, grant.Subject, grant.ClientID, time.Date(2026, 9, 6, 12, 30, 0, 0, time.UTC)); err != nil {
		t.Fatalf("restored active grant lookup: %v", err)
	}
	if _, err := s.RevokeMCPTrustedClient(ctx, client.ID, client.Revision, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetActiveMCPDelegationGrant(ctx, grant.Issuer, grant.Subject, grant.ClientID, time.Date(2026, 9, 6, 12, 31, 0, 0, time.UTC)); err == nil {
		t.Fatal("revoking trusted client must immediately invalidate grants")
	}
}

func TestMCPDelegationRejectsUntrustedClientAndOverlongExpiry(t *testing.T) {
	ctx := context.Background()
	s := newMCPDelegationTestStore()
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	if _, err := s.CreateMCPDelegationGrant(ctx, MCPDelegationGrant{Issuer: "https://id.example", Subject: "u", ClientID: "unknown", AccessProfile: MCPDelegationAdministration, ConsentDigest: "x", ExpiresAt: now.Add(time.Hour)}, "u"); err == nil {
		t.Fatal("untrusted client grant was accepted")
	}
	c, err := s.CreateMCPTrustedClient(ctx, MCPTrustedClient{ClientID: "chatgpt", DisplayName: "ChatGPT", Provider: "chatgpt"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMCPDelegationGrant(ctx, MCPDelegationGrant{Issuer: "https://id.example", Subject: "u", ClientID: c.ClientID, AccessProfile: MCPDelegationAdministration, ConsentDigest: "x", ExpiresAt: now.Add(31 * 24 * time.Hour)}, "u"); err == nil {
		t.Fatal("grant longer than 30 days was accepted")
	}
}
