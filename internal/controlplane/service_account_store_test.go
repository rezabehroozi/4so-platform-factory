package controlplane

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceAccountTokenLifecycleAndFilePersistence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	store.MemoryStore.now = func() time.Time { return now }
	org, err := store.CreateOrganization(ctx, Organization{Name: "acme", DisplayName: "Acme"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	sa, err := store.CreateServiceAccount(ctx, ServiceAccount{OrganizationID: org.ID, ProjectID: project.ID, Name: "deploy", DisplayName: "Deploy", ProductRole: "platform-operator"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CreateAPIToken(ctx, APIToken{ResourceMeta: ResourceMeta{ID: "tok_a"}, ServiceAccountID: sa.ID, TokenPrefix: "pft.tok_a", TokenDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Permissions: []string{"operate"}, ExpiresAt: now.Add(24 * time.Hour), IdempotencyKey: "issue-a"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(token.Permissions) != 2 {
		t.Fatalf("permissions=%v", token.Permissions)
	}
	_, next, err := store.RotateAPIToken(ctx, token.ID, token.Revision, APIToken{ResourceMeta: ResourceMeta{ID: "tok_b"}, TokenPrefix: "pft.tok_b", TokenDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ExpiresAt: now.Add(48 * time.Hour), IdempotencyKey: "rotate-a"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	old, err := reloaded.GetAPIToken(ctx, token.ID)
	if err != nil {
		t.Fatal(err)
	}
	byKey, err := reloaded.GetAPITokenByIdempotencyKey(ctx, sa.ID, "rotate-a")
	if err != nil || byKey.ID != next.ID {
		t.Fatalf("idempotency authority was not persisted: token=%+v err=%v", byKey, err)
	}
	if old.State != APITokenRevoked {
		t.Fatalf("old state=%s", old.State)
	}
	current, err := reloaded.GetAPIToken(ctx, next.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != APITokenActive || current.TokenDigest == "" {
		t.Fatalf("new token %#v", current)
	}
	sa2, err := reloaded.GetServiceAccount(ctx, sa.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reloaded.RevokeServiceAccount(ctx, sa2.ID, sa2.Revision, "admin"); err != nil {
		t.Fatal(err)
	}
	reloadedAgain, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	current, err = reloadedAgain.GetAPIToken(ctx, next.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != APITokenRevoked {
		t.Fatalf("token not revoked with service account: %s", current.State)
	}
}

func TestAPITokenAICapabilityPermissionsFollowServiceAccountRole(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Now().UTC()
	org, _ := store.CreateOrganization(ctx, Organization{Name: "ai-token-org", DisplayName: "AI Token"}, "admin")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "ai-token-project", DisplayName: "AI Token Project"}, "admin")
	operator, err := store.CreateServiceAccount(ctx, ServiceAccount{OrganizationID: org.ID, ProjectID: project.ID, Name: "ai-operator", DisplayName: "AI Operator", ProductRole: "platform-operator"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CreateAPIToken(ctx, APIToken{ResourceMeta: ResourceMeta{ID: "tok_ai"}, ServiceAccountID: operator.ID, TokenPrefix: "pft.tok_ai", TokenDigest: "sha256:" + "a" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Permissions: []string{APITokenPermissionRead, APITokenPermissionMCPRead, APITokenPermissionAIDiagnose}, ExpiresAt: now.Add(time.Hour), IdempotencyKey: "ai-token"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{APITokenPermissionRead: false, APITokenPermissionMCPRead: false, APITokenPermissionAIDiagnose: false}
	for _, permission := range token.Permissions {
		if _, ok := wanted[permission]; ok {
			wanted[permission] = true
		}
	}
	for permission, ok := range wanted {
		if !ok {
			t.Fatalf("missing permission %s from %v", permission, token.Permissions)
		}
	}

	viewer, err := store.CreateServiceAccount(ctx, ServiceAccount{OrganizationID: org.ID, ProjectID: project.ID, Name: "ai-viewer", DisplayName: "AI Viewer", ProductRole: "platform-viewer"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateAPIToken(ctx, APIToken{ResourceMeta: ResourceMeta{ID: "tok_view"}, ServiceAccountID: viewer.ID, TokenPrefix: "pft.tok_view", TokenDigest: "sha256:" + "b" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Permissions: []string{APITokenPermissionRead, APITokenPermissionAIDiagnose}, ExpiresAt: now.Add(time.Hour), IdempotencyKey: "viewer-ai-token"}, "admin")
	if err == nil {
		t.Fatal("platform-viewer service account unexpectedly received ai.diagnose")
	}
	_, err = store.CreateAPIToken(ctx, APIToken{ResourceMeta: ResourceMeta{ID: "tok_mcp"}, ServiceAccountID: viewer.ID, TokenPrefix: "pft.tok_mcp", TokenDigest: "sha256:" + "c" + "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Permissions: []string{APITokenPermissionRead, APITokenPermissionMCPRead}, ExpiresAt: now.Add(time.Hour), IdempotencyKey: "viewer-mcp-token"}, "admin")
	if err != nil {
		t.Fatalf("viewer mcp.read should be allowed: %v", err)
	}
}
