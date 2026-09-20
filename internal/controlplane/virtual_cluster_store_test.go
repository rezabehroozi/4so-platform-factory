package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"platform.4so.io/factory/internal/virtualcluster"
)

func virtualClusterStoreFixture(t *testing.T, store Store) (Workspace, WorkspaceBinding) {
	t.Helper()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "vcluster-org", DisplayName: "Virtual Cluster Org"}, "owner")
	if err != nil { t.Fatal(err) }
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	if err != nil { t.Fatal(err) }
	cluster := workspaceTestCluster(t, store, project.ID, "host-a", "uid-vcluster-host")
	workspace, err := store.CreateWorkspace(ctx, Workspace{ProjectID: project.ID, Name: "developers", DisplayName: "Developers"}, "owner")
	if err != nil { t.Fatal(err) }
	binding, err := store.CreateWorkspaceBinding(ctx, WorkspaceBinding{WorkspaceID: workspace.ID, ClusterID: cluster.ID, Namespace: "developers"}, "owner")
	if err != nil { t.Fatal(err) }
	return workspace, binding
}

func virtualClusterCreateRequest(workspace Workspace, binding WorkspaceBinding) VirtualClusterCreateRequest {
	return VirtualClusterCreateRequest{
		WorkspaceID: workspace.ID, WorkspaceBindingID: binding.ID,
		Spec: virtualcluster.Request{Name: "api-dev", Profile: virtualcluster.ProfileDeveloper, KubernetesVersion: "v1.34.2", CPUMilli: 2000, MemoryMiB: 4096, StorageGiB: 20, MaxNamespaces: 3, SleepAfterMinutes: 60},
		IdempotencyKey: "vcluster-api-dev",
		RequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
}

func TestVirtualClusterCreateDerivesWorkspaceBindingAuthorityAndReplays(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	workspace, binding := virtualClusterStoreFixture(t, store)
	request := virtualClusterCreateRequest(workspace, binding)
	created, replay, err := store.CreateVirtualCluster(ctx, request, "owner")
	if err != nil || replay {
		t.Fatalf("created=%#v replay=%v err=%v", created, replay, err)
	}
	if created.ProjectID != workspace.ProjectID || created.WorkspaceID != workspace.ID || created.WorkspaceBindingID != binding.ID || created.HostClusterID != binding.ClusterID || created.HostNamespace != binding.Namespace {
		t.Fatalf("derived authority drift: %#v", created)
	}
	if created.State != virtualcluster.StateRequested || created.PendingAction != virtualcluster.ActionProvision || created.DesiredDigest == "" {
		t.Fatalf("lifecycle creation drift: %#v", created)
	}
	replayed, replay, err := store.CreateVirtualCluster(ctx, request, "other")
	if err != nil || !replay || replayed.ID != created.ID || replayed.Revision != created.Revision {
		t.Fatalf("replay=%#v replayFlag=%v err=%v", replayed, replay, err)
	}
	request.RequestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, _, err = store.CreateVirtualCluster(ctx, request, "owner"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict not enforced: %v", err)
	}
}

func TestVirtualClusterCreateRejectsRevokedBindingAndUnsafeQuota(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	workspace, binding := virtualClusterStoreFixture(t, store)
	revoked, err := store.RevokeWorkspaceBinding(ctx, binding.ID, binding.Revision, "owner")
	if err != nil { t.Fatal(err) }
	request := virtualClusterCreateRequest(workspace, revoked)
	if _, _, err = store.CreateVirtualCluster(ctx, request, "owner"); !errors.Is(err, ErrValidation) {
		t.Fatalf("revoked binding admitted: %v", err)
	}

	store = NewMemoryStore()
	workspace, binding = virtualClusterStoreFixture(t, store)
	request = virtualClusterCreateRequest(workspace, binding)
	request.Spec.CPUMilli = 4001
	if _, _, err = store.CreateVirtualCluster(ctx, request, "owner"); !errors.Is(err, ErrValidation) {
		t.Fatalf("unsafe quota admitted: %v", err)
	}
}

func TestVirtualClusterFileStorePersistsDurableAuthority(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil { t.Fatal(err) }
	workspace, binding := virtualClusterStoreFixture(t, store)
	request := virtualClusterCreateRequest(workspace, binding)
	created, _, err := store.CreateVirtualCluster(ctx, request, "owner")
	if err != nil { t.Fatal(err) }
	reopened, err := OpenFileStore(path)
	if err != nil { t.Fatal(err) }
	got, err := reopened.GetVirtualCluster(ctx, created.ID)
	if err != nil || got.DesiredDigest != created.DesiredDigest || got.HostNamespace != binding.Namespace {
		t.Fatalf("persisted virtual cluster=%#v err=%v", got, err)
	}
}

func TestVirtualClusterRestoreRejectsBindingAuthorityDrift(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	workspace, binding := virtualClusterStoreFixture(t, store)
	created, _, err := store.CreateVirtualCluster(ctx, virtualClusterCreateRequest(workspace, binding), "owner")
	if err != nil { t.Fatal(err) }
	snap, err := store.Snapshot(ctx)
	if err != nil { t.Fatal(err) }
	if len(snap.VirtualClusters) != 1 || snap.VirtualClusters[0].ID != created.ID {
		t.Fatalf("snapshot=%#v", snap.VirtualClusters)
	}
	snap.VirtualClusters[0].HostNamespace = "tampered"
	if err := NewMemoryStore().Restore(snap); !errors.Is(err, ErrValidation) {
		t.Fatalf("authority-drift snapshot admitted: %v", err)
	}
}
