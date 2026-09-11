package api

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestWorkloadExplorerAndSearchProjectionAreProjectScopedAndRebuildable(t *testing.T) {
	now := time.Now().UTC()
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	org, project, cluster := seedFleetSupportCluster(t, store, "user-a", "search-a", now)
	_, foreignProject, _ := seedFleetSupportCluster(t, store, "user-b", "search-b", now)
	inv, err := store.GetLatestClusterInventory(context.Background(), cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	inv.ObservedAt = now.Add(time.Second)
	inv.WorkloadExplorer = controlplane.ClusterWorkloadExplorer{Complete: true, Workloads: []controlplane.ClusterWorkloadObservation{{Kind: "Deployment", Namespace: "app", Name: "web", DesiredReplicas: 3, ReadyReplicas: 2, Images: []string{"registry.local/web@sha256:" + strings.Repeat("a", 64)}}}, Services: []controlplane.ClusterServiceObservation{{Namespace: "app", Name: "web", Type: "ClusterIP"}}, Ingresses: []controlplane.ClusterIngressObservation{{Namespace: "app", Name: "web", Hosts: []string{"web.example.test"}}}, PVCs: []controlplane.ClusterPVCObservation{{Namespace: "app", Name: "data", Phase: "Bound", Requested: "10Gi"}}, Events: []controlplane.ClusterEventObservation{{Namespace: "app", Type: "Warning", Reason: "Unhealthy", RegardingKind: "Deployment", RegardingName: "web", Message: "readiness probe failed", LastObservedAt: now}}}
	inv.WorkloadExplorer, err = controlplane.NormalizeClusterWorkloadExplorer(inv.WorkloadExplorer)
	if err != nil {
		t.Fatal(err)
	}
	inv.Digest = ""
	if _, _, err = store.UpsertClusterInventory(context.Background(), cluster.ID, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", cluster.ExternalUID, inv); err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperation(context.Background(), controlplane.OperationRequest{ProjectID: project.ID, Kind: "UPGRADE", TargetRef: "cluster:" + cluster.ID, DesiredRevision: "sha256:" + strings.Repeat("c", 64), Risk: "high"}, "search-op", "user-a", "req-search")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AppendEvidence(context.Background(), controlplane.EvidenceMetadata{OperationID: op.ID, Kind: "runtime-report", Digest: "sha256:" + strings.Repeat("d", 64), MediaType: "application/json", Location: "object://evidence/runtime.json", Size: 42}, "worker"); err != nil {
		t.Fatal(err)
	}
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	server := New("0.0.test", components, slog.Default(), store)
	principal := auth.Principal{Subject: "user-a", Roles: []string{"platform-viewer"}}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+cluster.ID+"/workloads", nil).WithContext(auth.WithPrincipal(context.Background(), principal))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("workload status=%d body=%s", w.Code, w.Body.String())
	}
	var explorer struct {
		Authority       string `json:"authority"`
		Fresh, Complete bool
		Workloads       []controlplane.ClusterWorkloadObservation `json:"workloads"`
		Events          []controlplane.ClusterEventObservation    `json:"events"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &explorer); err != nil {
		t.Fatal(err)
	}
	if explorer.Authority != controlplane.WorkloadExplorerAuthorityMethod || !explorer.Fresh || !explorer.Complete || len(explorer.Workloads) != 1 || explorer.Workloads[0].Name != "web" || len(explorer.Events) != 1 {
		t.Fatalf("unexpected explorer=%#v", explorer)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/search?projectId="+project.ID+"&q=runtime-report", nil).WithContext(auth.WithPrincipal(context.Background(), principal))
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "evidence:") {
		t.Fatalf("search status=%d body=%s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/search/projection/rebuild?projectId="+project.ID, nil).WithContext(auth.WithPrincipal(context.Background(), principal))
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), searchRebuildAuthority) || !strings.Contains(w.Body.String(), "postgresql-bounded") {
		t.Fatalf("rebuild status=%d body=%s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/search?projectId="+foreignProject.ID+"&q=cluster", nil).WithContext(auth.WithPrincipal(context.Background(), principal))
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign search status=%d body=%s", w.Code, w.Body.String())
	}

	mcpPrincipal := auth.Principal{Subject: "search-agent", Roles: []string{"platform-viewer"}, Authentication: "api-token", Permissions: []string{"read", "mcp.read"}, OrganizationID: org.ID, ProjectID: project.ID}
	mcpBody := `{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"ops_search","arguments":{"projectId":"` + project.ID + `","query":"runtime-report"}}}`
	mcpReq := mcpRequestForTest("tools/call", "ops_search", mcpBody)
	mcpReq = mcpReq.WithContext(auth.WithPrincipal(mcpReq.Context(), mcpPrincipal))
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, mcpReq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), searchProjectionAuthority) || !strings.Contains(w.Body.String(), `"sourceOfTruth":false`) || !strings.Contains(w.Body.String(), "evidence:") {
		t.Fatalf("MCP ops search status=%d body=%s", w.Code, w.Body.String())
	}

	foreignBody := `{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"ops_search","arguments":{"projectId":"` + foreignProject.ID + `","query":"cluster"}}}`
	foreignReq := mcpRequestForTest("tools/call", "ops_search", foreignBody)
	foreignReq = foreignReq.WithContext(auth.WithPrincipal(foreignReq.Context(), mcpPrincipal))
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, foreignReq)
	if w.Code != http.StatusForbidden {
		t.Fatalf("MCP foreign search status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestSearchProjectionScopesAuditBeforeLimitUnderCrossTenantLoad(t *testing.T) {
	now := time.Now().UTC()
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	_, project, cluster := seedFleetSupportCluster(t, store, "owner-a", "search-scope-a", now)
	_, foreignProject, foreignCluster := seedFleetSupportCluster(t, store, "owner-b", "search-scope-b", now)

	_, _, err := store.CreateOperation(context.Background(), controlplane.OperationRequest{
		ProjectID: project.ID, Kind: "AUDIT_SENTINEL", TargetRef: "cluster:" + cluster.ID,
		DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "low",
	}, "scope-sentinel", "owner-a", "search-sentinel-request")
	if err != nil {
		t.Fatal(err)
	}
	// Push the authorized audit event outside the legacy global 1000-row
	// window using unrelated tenant activity. A scope-after-LIMIT
	// implementation would lose search-sentinel-request here.
	for i := 0; i < searchAuditSourceLimit+25; i++ {
		_, _, err = store.CreateOperation(context.Background(), controlplane.OperationRequest{
			ProjectID: foreignProject.ID, Kind: "FOREIGN_LOAD", TargetRef: "cluster:" + foreignCluster.ID,
			DesiredRevision: "sha256:" + strings.Repeat("b", 64), Risk: "low",
		}, fmt.Sprintf("foreign-load-%04d", i), "owner-b", fmt.Sprintf("foreign-request-%04d", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	server := New("0.0.test", components, slog.Default(), store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?projectId="+project.ID+"&q=search-sentinel-request", nil).
		WithContext(auth.WithPrincipal(context.Background(), auth.Principal{Subject: "owner-a", Roles: []string{"platform-viewer"}}))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("search status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "search-sentinel-request") || !strings.Contains(w.Body.String(), `"scopeAppliedBeforeLimit":true`) {
		t.Fatalf("scoped audit sentinel disappeared under foreign load: %s", w.Body.String())
	}
}
