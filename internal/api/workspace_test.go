package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func workspaceAPICluster(t *testing.T, store controlplane.Store, projectID, name, uid string) controlplane.ManagedCluster {
	t.Helper()
	ctx := context.Background()
	token := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	agent := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: projectID, Name: name, DisplayName: name, TokenDigest: token, ExpiresAt: time.Now().Add(time.Hour)}, "owner")
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

func TestWorkspaceHTTPAuthorityAndProjectNegativeControls(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	orgA, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "workspace-api-a", DisplayName: "Workspace A"}, "owner")
	projectA, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgA.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	orgB, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "workspace-api-b", DisplayName: "Workspace B"}, "outsider")
	projectB, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgB.ID, Name: "other", DisplayName: "Other"}, "outsider")
	clusterA := workspaceAPICluster(t, store, projectA.ID, "cluster-a", "uid-workspace-api-a")
	clusterB := workspaceAPICluster(t, store, projectB.ID, "cluster-b", "uid-workspace-api-b")
	srv := scopedServer(t, store)

	body := fmt.Sprintf(`{"projectId":%q,"name":"team-a","displayName":"Team A","description":"Cross-cluster product boundary"}`, projectA.ID)
	w := scopedRequest(t, srv, http.MethodPost, "/api/v1/workspaces", body, "owner", "platform-operator")
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	workspace := decodeBody[controlplane.Workspace](t, w)

	bindingBody := fmt.Sprintf(`{"clusterId":%q,"namespace":"payments"}`, clusterA.ID)
	w = scopedRequest(t, srv, http.MethodPost, "/api/v1/workspaces/"+workspace.ID+"/bindings", bindingBody, "owner", "platform-operator")
	if w.Code != http.StatusCreated {
		t.Fatalf("binding=%d body=%s", w.Code, w.Body.String())
	}
	binding := decodeBody[controlplane.WorkspaceBinding](t, w)

	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/workspaces/"+workspace.ID+"/bindings", "", "owner", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("bindings=%d body=%s", w.Code, w.Body.String())
	}
	var bindings []controlplane.WorkspaceBinding
	if err := json.Unmarshal(w.Body.Bytes(), &bindings); err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].ID != binding.ID {
		t.Fatalf("bindings=%#v", bindings)
	}

	w = scopedRequest(t, srv, http.MethodPost, "/api/v1/workspaces/"+workspace.ID+"/bindings", fmt.Sprintf(`{"clusterId":%q,"namespace":"foreign"}`, clusterB.ID), "owner", "platform-operator")
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-project cluster binding=%d body=%s", w.Code, w.Body.String())
	}

	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/workspaces/"+workspace.ID, "", "outsider", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-project workspace get=%d body=%s", w.Code, w.Body.String())
	}
	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/workspaces?projectId="+projectA.ID, "", "outsider", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-project workspace list=%d body=%s", w.Code, w.Body.String())
	}

	revokeBody := fmt.Sprintf(`{"expectedRevision":%d}`, binding.Revision)
	w = scopedRequest(t, srv, http.MethodPost, "/api/v1/workspaces/"+workspace.ID+"/bindings/"+binding.ID+"/revoke", revokeBody, "owner", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("revoke=%d body=%s", w.Code, w.Body.String())
	}
	revoked := decodeBody[controlplane.WorkspaceBinding](t, w)
	if revoked.State != controlplane.WorkspaceBindingRevoked || revoked.Revision != binding.Revision+1 {
		t.Fatalf("revoked=%#v", revoked)
	}
}


func TestVirtualClusterHTTPAuthorityReplaysAndScopesToWorkspace(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	orgA, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "vcluster-api-a", DisplayName: "Virtual A"}, "owner")
	projectA, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgA.ID, Name: "platform", DisplayName: "Platform"}, "owner")
	clusterA := workspaceAPICluster(t, store, projectA.ID, "host-a", "uid-vcluster-api-a")
	workspaceA, err := store.CreateWorkspace(ctx, controlplane.Workspace{ProjectID: projectA.ID, Name: "developers", DisplayName: "Developers"}, "owner")
	if err != nil { t.Fatal(err) }
	bindingA, err := store.CreateWorkspaceBinding(ctx, controlplane.WorkspaceBinding{WorkspaceID: workspaceA.ID, ClusterID: clusterA.ID, Namespace: "developers"}, "owner")
	if err != nil { t.Fatal(err) }

	orgB, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "vcluster-api-b", DisplayName: "Virtual B"}, "outsider")
	projectB, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: orgB.ID, Name: "other", DisplayName: "Other"}, "outsider")
	clusterB := workspaceAPICluster(t, store, projectB.ID, "host-b", "uid-vcluster-api-b")
	workspaceB, _ := store.CreateWorkspace(ctx, controlplane.Workspace{ProjectID: projectB.ID, Name: "other-team", DisplayName: "Other Team"}, "outsider")
	bindingB, _ := store.CreateWorkspaceBinding(ctx, controlplane.WorkspaceBinding{WorkspaceID: workspaceB.ID, ClusterID: clusterB.ID, Namespace: "other-team"}, "outsider")

	srv := scopedServer(t, store)
	body := fmt.Sprintf(`{"workspaceBindingId":%q,"name":"api-dev","profile":"developer","kubernetesVersion":"v1.34.2","cpuMilli":2000,"memoryMiB":4096,"storageGiB":20,"maxNamespaces":3,"sleepAfterMinutes":60}`, bindingA.ID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/"+workspaceA.ID+"/virtual-clusters", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Actor-ID", "owner")
	req.Header.Set("X-Actor-Role", "platform-operator")
	req.Header.Set("Idempotency-Key", "vcluster-api-create")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	var createdEnvelope struct {
		VirtualCluster controlplane.VirtualCluster `json:"virtualCluster"`
		IdempotentReplay bool `json:"idempotentReplay"`
		Authority string `json:"authority"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &createdEnvelope); err != nil { t.Fatal(err) }
	created := createdEnvelope.VirtualCluster
	if created.WorkspaceID != workspaceA.ID || created.WorkspaceBindingID != bindingA.ID || created.ProjectID != projectA.ID || createdEnvelope.Authority != controlplane.VirtualClusterStoreAuthority {
		t.Fatalf("created envelope=%#v", createdEnvelope)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/"+workspaceA.ID+"/virtual-clusters", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Actor-ID", "owner")
	req.Header.Set("X-Actor-Role", "platform-operator")
	req.Header.Set("Idempotency-Key", "vcluster-api-create")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("replay=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}

	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/workspaces/"+workspaceA.ID+"/virtual-clusters", "", "owner", "platform-operator")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), created.ID) {
		t.Fatalf("list=%d body=%s", w.Code, w.Body.String())
	}
	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/workspaces/"+workspaceA.ID+"/virtual-clusters/"+created.ID, "", "owner", "platform-operator")
	if w.Code != http.StatusOK {
		t.Fatalf("get=%d body=%s", w.Code, w.Body.String())
	}

	w = scopedRequest(t, srv, http.MethodGet, "/api/v1/workspaces/"+workspaceA.ID+"/virtual-clusters", "", "outsider", "platform-operator")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-project list=%d body=%s", w.Code, w.Body.String())
	}
	foreignBody := fmt.Sprintf(`{"workspaceBindingId":%q,"name":"foreign","profile":"developer","kubernetesVersion":"v1.34.2","cpuMilli":1000,"memoryMiB":2048,"storageGiB":10,"maxNamespaces":2,"sleepAfterMinutes":60}`, bindingB.ID)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/"+workspaceA.ID+"/virtual-clusters", strings.NewReader(foreignBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Actor-ID", "owner")
	req.Header.Set("X-Actor-Role", "platform-operator")
	req.Header.Set("Idempotency-Key", "vcluster-cross-binding")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-workspace binding=%d body=%s", w.Code, w.Body.String())
	}
}
