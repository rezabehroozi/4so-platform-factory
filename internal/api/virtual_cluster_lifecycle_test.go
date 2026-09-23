package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/virtualcluster"
)

func setVirtualClusterStateForAPITest(t *testing.T, store *controlplane.MemoryStore, id string, state virtualcluster.State) controlplane.VirtualCluster {
	t.Helper()
	snapshot, err := store.Snapshot(context.Background())
	if err != nil { t.Fatal(err) }
	for i := range snapshot.VirtualClusters {
		if snapshot.VirtualClusters[i].ID == id {
			snapshot.VirtualClusters[i].State = state
			snapshot.VirtualClusters[i].PendingAction = ""
			snapshot.VirtualClusters[i].TaskAction = ""
			snapshot.VirtualClusters[i].TaskLeaseExpiresAt = nil
			snapshot.VirtualClusters[i].TaskDispatchedAt = nil
			if err = store.Restore(snapshot); err != nil { t.Fatal(err) }
			v, getErr := store.GetVirtualCluster(context.Background(), id)
			if getErr != nil { t.Fatal(getErr) }
			return v
		}
	}
	t.Fatalf("virtual cluster %s not found in snapshot", id)
	return controlplane.VirtualCluster{}
}

func lifecycleHTTPRequest(t *testing.T, srv *Server, method, path, actor, role, key string, revision int64, confirm string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	req.Header.Set("X-Actor-ID", actor)
	req.Header.Set("X-Actor-Role", role)
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", revision))
	if confirm != "" { req.Header.Set("X-Confirm-Delete", confirm) }
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestVirtualClusterLifecycleHTTPExactReplayAndProtectedDelete(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "vcl-life", DisplayName: "VCL Life"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "host-life", "uid-vcl-life")
	workspace, _ := store.CreateWorkspace(ctx, controlplane.Workspace{ProjectID: project.ID, Name: "developers", DisplayName: "Developers"}, "owner")
	binding, _ := store.CreateWorkspaceBinding(ctx, controlplane.WorkspaceBinding{WorkspaceID: workspace.ID, ClusterID: cluster.ID, Namespace: "developers"}, "owner")
	created, _, err := store.CreateVirtualCluster(ctx, controlplane.VirtualClusterCreateRequest{
		WorkspaceID: workspace.ID, WorkspaceBindingID: binding.ID,
		Spec: virtualcluster.Request{Name: "life", Profile: virtualcluster.ProfileDeveloper, KubernetesVersion: "v1.34.2", CPUMilli: 2000, MemoryMiB: 4096, StorageGiB: 20, MaxNamespaces: 3, SleepAfterMinutes: 60},
		IdempotencyKey: "create-life", RequestDigest: "sha256:"+strings.Repeat("a",64),
	}, "owner")
	if err != nil { t.Fatal(err) }
	active := setVirtualClusterStateForAPITest(t, store, created.ID, virtualcluster.StateActive)
	srv := scopedServer(t, store)
	path := "/api/v1/workspaces/"+workspace.ID+"/virtual-clusters/"+active.ID+"/suspend"
	first := lifecycleHTTPRequest(t, srv, http.MethodPost, path, "owner", "platform-operator", "suspend-once", active.Revision, "")
	if first.Code != http.StatusAccepted { t.Fatalf("suspend=%d %s", first.Code, first.Body.String()) }
	var envelope struct { VirtualCluster controlplane.VirtualCluster `json:"virtualCluster"`; IdempotentReplay bool `json:"idempotentReplay"` }
	if err = json.Unmarshal(first.Body.Bytes(), &envelope); err != nil { t.Fatal(err) }
	if envelope.VirtualCluster.State != virtualcluster.StateSuspending || envelope.VirtualCluster.PendingAction != virtualcluster.ActionSuspend {
		t.Fatalf("suspend envelope=%+v", envelope)
	}
	replay := lifecycleHTTPRequest(t, srv, http.MethodPost, path, "owner", "platform-operator", "suspend-once", active.Revision, "")
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("stale-revision exact replay=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body.String())
	}

	active = setVirtualClusterStateForAPITest(t, store, created.ID, virtualcluster.StateActive)
	deletePath := "/api/v1/workspaces/"+workspace.ID+"/virtual-clusters/"+active.ID+"/delete"
	missing := lifecycleHTTPRequest(t, srv, http.MethodPost, deletePath, "owner", "platform-operator", "delete-once", active.Revision, "")
	if missing.Code != http.StatusPreconditionRequired || !strings.Contains(missing.Body.String(), "delete-virtual-cluster") {
		t.Fatalf("unconfirmed delete=%d %s", missing.Code, missing.Body.String())
	}
	confirmed := lifecycleHTTPRequest(t, srv, http.MethodPost, deletePath, "owner", "platform-operator", "delete-once", active.Revision, "delete-virtual-cluster")
	if confirmed.Code != http.StatusAccepted || !strings.Contains(confirmed.Body.String(), string(virtualcluster.StateDeleting)) {
		t.Fatalf("confirmed delete=%d %s", confirmed.Code, confirmed.Body.String())
	}
}


func TestVirtualClusterDiagnosticsProjectionIsBoundedAndReadOnly(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "vcl-diag", DisplayName: "VCL Diagnostics"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform-diag", DisplayName: "Platform Diagnostics"}, "owner")
	cluster := workspaceAPICluster(t, store, project.ID, "host-diag", "uid-vcl-diag")
	workspace, _ := store.CreateWorkspace(ctx, controlplane.Workspace{ProjectID: project.ID, Name: "diag", DisplayName: "Diagnostics"}, "owner")
	binding, _ := store.CreateWorkspaceBinding(ctx, controlplane.WorkspaceBinding{WorkspaceID: workspace.ID, ClusterID: cluster.ID, Namespace: "diag"}, "owner")
	created, _, err := store.CreateVirtualCluster(ctx, controlplane.VirtualClusterCreateRequest{
		WorkspaceID: workspace.ID, WorkspaceBindingID: binding.ID,
		Spec: virtualcluster.Request{Name: "diag", Profile: virtualcluster.ProfileDeveloper, KubernetesVersion: "v1.34.2", CPUMilli: 2000, MemoryMiB: 4096, StorageGiB: 20, MaxNamespaces: 3, SleepAfterMinutes: 60},
		IdempotencyKey: "diag-create", RequestDigest: "sha256:"+strings.Repeat("d",64),
	}, "owner")
	if err != nil { t.Fatal(err) }

	srv := scopedServer(t, store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/"+workspace.ID+"/virtual-clusters/"+created.ID+"?includeDiagnostics=true", nil)
	req.Header.Set("X-Actor-ID", "owner")
	req.Header.Set("X-Actor-Role", "platform-operator")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("diagnostics=%d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		VirtualClusterDiagnosticsAuthority,
		`"readOnly":true`,
		`"physicalCertificationInferred":false`,
		`"virtualClusterId":"` + created.ID + `"`,
		`"workspaceId":"` + workspace.ID + `"`,
		`"clusterId":"` + cluster.ID + `"`,
		`"namespace":"diag"`,
		`"virtual_cluster.created"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %q: %s", want, body)
		}
	}
}
