package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func workspaceTestCluster(t *testing.T, store Store, projectID, name, uid string) ManagedCluster {
	t.Helper()
	ctx := context.Background()
	token := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	agent := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	imp, err := store.CreateClusterImport(ctx, ClusterImport{ProjectID: projectID, Name: name, DisplayName: name, TokenDigest: token, ExpiresAt: time.Now().Add(time.Hour)}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, token, agent, uid, "0.0.test")
	if err != nil {
		t.Fatal(err)
	}
	return cluster
}

func TestWorkspaceAuthorityProjectScopeBindingAndRevocation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, Organization{Name: "workspace-org", DisplayName: "Workspace Org"}, "owner")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	other, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "other", DisplayName: "Other"}, "owner")
	cluster := workspaceTestCluster(t, store, project.ID, "cluster-a", "uid-workspace-a")
	foreignCluster := workspaceTestCluster(t, store, other.ID, "cluster-b", "uid-workspace-b")

	workspace, err := store.CreateWorkspace(ctx, Workspace{ProjectID: project.ID, Name: "team-a", DisplayName: "Team A", Description: "Cross-cluster namespace boundary"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Digest == "" || workspace.Revision != 1 {
		t.Fatalf("workspace=%#v", workspace)
	}

	binding, err := store.CreateWorkspaceBinding(ctx, WorkspaceBinding{WorkspaceID: workspace.ID, ClusterID: cluster.ID, Namespace: "payments"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if binding.ProjectID != project.ID || binding.State != WorkspaceBindingActive {
		t.Fatalf("binding=%#v", binding)
	}

	if _, err = store.CreateWorkspaceBinding(ctx, WorkspaceBinding{WorkspaceID: workspace.ID, ClusterID: foreignCluster.ID, Namespace: "foreign"}, "owner"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project cluster binding must be hidden as not found, got %v", err)
	}

	second, err := store.CreateWorkspace(ctx, Workspace{ProjectID: project.ID, Name: "team-b", DisplayName: "Team B"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateWorkspaceBinding(ctx, WorkspaceBinding{WorkspaceID: second.ID, ClusterID: cluster.ID, Namespace: "payments"}, "owner"); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("active namespace must not belong to two workspaces, got %v", err)
	}

	revoked, err := store.RevokeWorkspaceBinding(ctx, binding.ID, binding.Revision, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != WorkspaceBindingRevoked || revoked.RevokedAt == nil || revoked.Revision != 2 {
		t.Fatalf("revoked=%#v", revoked)
	}
	rebound, err := store.CreateWorkspaceBinding(ctx, WorkspaceBinding{WorkspaceID: second.ID, ClusterID: cluster.ID, Namespace: "payments"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if rebound.WorkspaceID != second.ID {
		t.Fatalf("rebound=%#v", rebound)
	}
}

func TestWorkspaceFileStorePersistsAuthority(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	org, _ := store.CreateOrganization(ctx, Organization{Name: "workspace-file", DisplayName: "Workspace File"}, "owner")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	cluster := workspaceTestCluster(t, store, project.ID, "cluster-a", "uid-workspace-file")
	workspace, err := store.CreateWorkspace(ctx, Workspace{ProjectID: project.ID, Name: "team-a", DisplayName: "Team A"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := store.CreateWorkspaceBinding(ctx, WorkspaceBinding{WorkspaceID: workspace.ID, ClusterID: cluster.ID, Namespace: "payments"}, "owner")
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetWorkspace(ctx, workspace.ID)
	if err != nil || got.Digest != workspace.Digest {
		t.Fatalf("workspace after reopen=%#v err=%v", got, err)
	}
	bindings, err := reopened.ListWorkspaceBindings(ctx, workspace.ID)
	if err != nil || len(bindings) != 1 || bindings[0].ID != binding.ID {
		t.Fatalf("bindings=%#v err=%v", bindings, err)
	}
}

func TestWorkspaceRestoreRejectsCrossProjectBinding(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, Organization{Name: "workspace-restore", DisplayName: "Workspace Restore"}, "owner")
	p1, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "one", DisplayName: "One"}, "owner")
	p2, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "two", DisplayName: "Two"}, "owner")
	cluster := workspaceTestCluster(t, store, p2.ID, "cluster-b", "uid-workspace-restore")
	workspace, _ := store.CreateWorkspace(ctx, Workspace{ProjectID: p1.ID, Name: "team-a", DisplayName: "Team A"}, "owner")
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snap.WorkspaceBindings = append(snap.WorkspaceBindings, WorkspaceBinding{ResourceMeta: ResourceMeta{ID: "wsb_bad", Revision: 1, CreatedAt: now, UpdatedAt: now}, WorkspaceID: workspace.ID, ProjectID: p1.ID, ClusterID: cluster.ID, Namespace: "bad", State: WorkspaceBindingActive, CreatedBy: "owner"})
	if err := NewMemoryStore().Restore(snap); !errors.Is(err, ErrValidation) {
		t.Fatalf("cross-project workspace snapshot must be rejected, got %v", err)
	}
}
