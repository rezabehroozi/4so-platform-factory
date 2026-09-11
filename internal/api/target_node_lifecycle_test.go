package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

func seedLifecycleAPICluster(t *testing.T) (*controlplane.MemoryStore, http.Handler, controlplane.ManagedCluster) {
	t.Helper()
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "node-lifecycle", DisplayName: "Node Lifecycle"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := "node-lifecycle-enrollment-token-abcdefghijklmnopqrstuvwxyz"
	agentToken := "node-lifecycle-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "cluster", DisplayName: "Cluster", TokenDigest: credentialDigest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest(agentToken), "uid-node-lifecycle", "0.0.310")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agentToken), cluster.ExternalUID, controlplane.ClusterInventory{
		ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.33.2", Digest: fmt.Sprintf("sha256:%064x", 88001),
		Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, controlplane.ClusterMaintenanceFencedReportCapability},
		Nodes:        []controlplane.ClusterNode{{Name: "worker-1", UID: "uid-worker-1", Roles: []string{"worker"}, Ready: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	server := New("test", components, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	return store, server.Handler(), cluster
}

func TestTargetNodeLifecycleAuthorityAndPlanAPI(t *testing.T) {
	_, h, cluster := seedLifecycleAPICluster(t)
	w := apiRequest(t, h, http.MethodGet, "/api/v1/clusters/"+cluster.ID+"/node-lifecycle-authority", "", map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusOK {
		t.Fatalf("authority %d: %s", w.Code, w.Body.String())
	}
	authority := decodeBody[controlplane.TargetNodeLifecycleAuthority](t, w)
	if authority.Authority != controlplane.TargetNodeLifecycleAuthorityMethod || authority.PhysicalCertificationStatus != controlplane.TargetNodePhysicalCertificationDeferred || len(authority.Actions) != 7 {
		t.Fatalf("authority=%#v", authority)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+cluster.ID+"/node-lifecycle-plans", `{"action":"DRAIN","nodeName":"worker-1"}`, map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusOK {
		t.Fatalf("plan %d: %s", w.Code, w.Body.String())
	}
	plan := decodeBody[controlplane.TargetNodeLifecyclePlan](t, w)
	if !plan.Executable || plan.NodeUID != "uid-worker-1" || plan.PlanDigest == "" || plan.PhysicalCertificationStatus != controlplane.TargetNodePhysicalCertificationDeferred {
		t.Fatalf("plan=%#v", plan)
	}
	w = apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+cluster.ID+"/node-lifecycle-plans", `{"action":"OS_PATCH","nodeName":"worker-1"}`, map[string]string{"X-Actor-ID": "operator"})
	if w.Code != http.StatusOK {
		t.Fatalf("patch preview %d: %s", w.Code, w.Body.String())
	}
	patch := decodeBody[controlplane.TargetNodeLifecyclePlan](t, w)
	if patch.Executable || len(patch.Blockers) == 0 {
		t.Fatalf("pending patch adapter promoted: %#v", patch)
	}
}

func TestTargetNodeLifecyclePlanRejectsUnknownNode(t *testing.T) {
	_, h, cluster := seedLifecycleAPICluster(t)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/clusters/"+cluster.ID+"/node-lifecycle-plans", `{"action":"DRAIN","nodeName":"ghost"}`, map[string]string{"X-Actor-ID": "operator"})
	if w.Code == http.StatusOK {
		t.Fatalf("unknown inventory node accepted: %s", w.Body.String())
	}
}

func TestMCPTargetNodeLifecycleReadToolsRemainPlanningOnly(t *testing.T) {
	store, _, cluster := seedLifecycleAPICluster(t)
	s := New("test", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	project, err := store.GetProject(context.Background(), cluster.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{Subject: "lifecycle-reader-agent", Roles: []string{"platform-viewer"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read"}, OrganizationID: project.OrganizationID, ProjectID: cluster.ProjectID}
	call := func(id int, name, arguments string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, name, arguments)
		r := mcpRequestForTest("tools/call", name, body)
		r = r.WithContext(auth.WithPrincipal(r.Context(), principal))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	w := call(901, "target_node_lifecycle_authority", fmt.Sprintf(`{"id":%q}`, cluster.ID))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), controlplane.TargetNodeLifecycleAuthorityMethod) || !strings.Contains(w.Body.String(), controlplane.TargetNodePhysicalCertificationDeferred) {
		t.Fatalf("lifecycle authority MCP failed: %d %s", w.Code, w.Body.String())
	}
	w = call(902, "target_node_lifecycle_plan", fmt.Sprintf(`{"clusterId":%q,"action":"DRAIN","nodeName":"worker-1"}`, cluster.ID))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"executable":true`) || !strings.Contains(w.Body.String(), "uid-worker-1") {
		t.Fatalf("drain impact plan MCP failed: %d %s", w.Code, w.Body.String())
	}
	w = call(903, "target_node_lifecycle_plan", fmt.Sprintf(`{"clusterId":%q,"action":"OS_PATCH","nodeName":"worker-1"}`, cluster.ID))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"executable":false`) || !strings.Contains(w.Body.String(), "TARGET_CAPABILITY_MISSING:"+controlplane.TargetNodeOSPatchCapability) {
		t.Fatalf("OS patch executor was not represented target-capability fail-closed: %d %s", w.Code, w.Body.String())
	}

	// A read-only MCP principal must see the two planning tools but no delegated mutation tools.
	listReq := mcpRequestForTest("tools/list", "", `{"jsonrpc":"2.0","id":904,"method":"tools/list"}`)
	listReq = listReq.WithContext(auth.WithPrincipal(listReq.Context(), principal))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, listReq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "target_node_lifecycle_plan") || strings.Contains(w.Body.String(), "cluster_maintenance_request") {
		t.Fatalf("read-only lifecycle tool visibility mismatch: %d %s", w.Code, w.Body.String())
	}
}
