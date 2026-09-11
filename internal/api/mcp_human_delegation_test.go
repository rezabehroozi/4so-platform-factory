package api

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func TestMCPHumanDelegationEnforcesTrustedClientGrantAndImmediateRevocation(t *testing.T) {
	store := controlplane.NewMemoryStore()
	s := New("test", nil, nil, store)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "org", DisplayName: "Org"}, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	prj, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPTrustedClient(ctx, controlplane.MCPTrustedClient{ClientID: "claude-client", DisplayName: "Claude", Provider: "claude"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{Issuer: "https://id.example/realms/4so", AuthorizedClientID: client.ClientID, Subject: "user-1", Roles: []string{"platform-operator"}, Authentication: "oidc", Expires: time.Now().Add(time.Hour).Unix()}
	req := httptest.NewRequest("POST", "/api/v1/mcp/delegation-grants/preview", nil).WithContext(auth.WithPrincipal(ctx, principal))
	preview, err := s.buildMCPConsentPreview(req, mcpConsentInput{ClientID: client.ClientID, ProjectID: prj.ID, AccessProfile: controlplane.MCPDelegationOperate, ExpiresInHours: 24})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := store.CreateMCPDelegationGrant(ctx, controlplane.MCPDelegationGrant{Issuer: principal.Issuer, Subject: principal.Subject, ClientID: client.ClientID, OrganizationID: preview.OrganizationID, ProjectID: preview.ProjectID, AccessProfile: preview.AccessProfile, ConsentDigest: preview.ConsentDigest, ExpiresAt: preview.ExpiresAt}, principal.Subject)
	if err != nil {
		t.Fatal(err)
	}
	mcpReq := httptest.NewRequest("POST", "/mcp", nil).WithContext(auth.WithPrincipal(ctx, principal))
	delegated, err := s.applyMCPHumanDelegation(mcpReq)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := auth.PrincipalFromContext(delegated.Context())
	if !ok || got.Authentication != "mcp-human" || got.ProjectID != prj.ID || got.DelegationAccessProfile != "OPERATE" {
		t.Fatalf("unexpected delegated principal: %#v", got)
	}
	if _, err := store.RevokeMCPDelegationGrant(ctx, grant.ID, grant.Revision, principal.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyMCPHumanDelegation(mcpReq); err == nil {
		t.Fatal("revoked grant did not immediately reject still-valid OAuth principal")
	}
}

func TestMCPPlatformDelegationRequiresCurrentPlatformAdmin(t *testing.T) {
	store := controlplane.NewMemoryStore()
	s := New("test", nil, nil, store)
	ctx := context.Background()
	client, err := store.CreateMCPTrustedClient(ctx, controlplane.MCPTrustedClient{ClientID: "chatgpt-client", DisplayName: "ChatGPT", Provider: "chatgpt"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	base := auth.Principal{Issuer: "https://id.example/realms/4so", AuthorizedClientID: client.ClientID, Subject: "u", Authentication: "oidc", Expires: time.Now().Add(time.Hour).Unix()}
	req := httptest.NewRequest("POST", "/api/v1/mcp/delegation-grants/preview", nil)
	operator := base
	operator.Roles = []string{"platform-operator"}
	req = req.WithContext(auth.WithPrincipal(ctx, operator))
	if _, err := s.buildMCPConsentPreview(req, mcpConsentInput{ClientID: client.ClientID, AccessProfile: controlplane.MCPDelegationAdministration, ExpiresInHours: 24}); err == nil {
		t.Fatal("platform-wide delegation accepted for non-admin")
	}
	admin := base
	admin.Roles = []string{"platform-admin"}
	req = req.WithContext(auth.WithPrincipal(ctx, admin))
	preview, err := s.buildMCPConsentPreview(req, mcpConsentInput{ClientID: client.ClientID, AccessProfile: controlplane.MCPDelegationAdministration, ExpiresInHours: 24})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := store.CreateMCPDelegationGrant(ctx, controlplane.MCPDelegationGrant{Issuer: admin.Issuer, Subject: admin.Subject, ClientID: client.ClientID, AccessProfile: controlplane.MCPDelegationAdministration, ConsentDigest: preview.ConsentDigest, ExpiresAt: preview.ExpiresAt}, admin.Subject)
	if err != nil {
		t.Fatal(err)
	}
	mcpReq := httptest.NewRequest("POST", "/mcp", nil).WithContext(auth.WithPrincipal(ctx, admin))
	if _, err = s.applyMCPHumanDelegation(mcpReq); err != nil {
		t.Fatalf("admin grant rejected: %v", err)
	}
	downgraded := admin
	downgraded.Roles = []string{"platform-operator"}
	mcpReq = mcpReq.WithContext(auth.WithPrincipal(ctx, downgraded))
	if _, err = s.applyMCPHumanDelegation(mcpReq); err == nil {
		t.Fatalf("platform grant preserved authority after admin downgrade: %#v", grant)
	}
}
