package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
