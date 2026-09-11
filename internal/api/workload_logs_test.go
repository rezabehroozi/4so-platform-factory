package api

import (
	"bytes"
	"context"
	"encoding/json"
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

func seedWorkloadLogAuthority(t *testing.T, store *controlplane.MemoryStore) (controlplane.Project, controlplane.ManagedCluster, string) {
	t.Helper()
	ctx := context.Background()
	actor := "workload-log-owner"
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "workload-logs", DisplayName: "Workload Logs"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "logs", DisplayName: "Logs", TokenDigest: "sha256:" + strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)}, actor)
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "workload-log-approver")
	if err != nil {
		t.Fatal(err)
	}
	agentToken := "workload-log-agent-secret-abcdefghijklmnopqrstuvwxyz"
	agentDigest := credentialDigest(agentToken)
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, imp.TokenDigest, agentDigest, "uid-workload-logs", "0.0.test")
	if err != nil {
		t.Fatal(err)
	}
	explorer, err := controlplane.NormalizeClusterWorkloadExplorer(controlplane.ClusterWorkloadExplorer{
		Complete:  true,
		Workloads: []controlplane.ClusterWorkloadObservation{{Kind: "Deployment", Namespace: "app", Name: "web", DesiredReplicas: 2, ReadyReplicas: 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv := controlplane.ClusterInventory{
		ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.34.9+rke2r1",
		Capabilities: []string{"workload-explorer-read", "cert.logs"}, WorkloadExplorer: explorer,
	}
	cluster, _, err = store.UpsertClusterInventory(ctx, cluster.ID, agentDigest, cluster.ExternalUID, inv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertOrganizationMembership(ctx, controlplane.OrganizationMembership{OrganizationID: org.ID, Subject: "workload-log-viewer", Role: controlplane.OrganizationViewer}, 0, actor); err != nil {
		t.Fatal(err)
	}
	return project, cluster, agentToken
}

func TestWorkloadLogQueryAgentRoundTripSealsBoundedEvidence(t *testing.T) {
	store := controlplane.NewMemoryStore()
	project, cluster, agentToken := seedWorkloadLogAuthority(t, store)
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	server := New("0.0.test", components, slog.Default(), store)
	handler := server.Handler()
	principal := auth.Principal{Subject: "workload-log-viewer", Roles: []string{"platform-viewer"}}

	body := `{"projectId":"` + project.ID + `","clusterId":"` + cluster.ID + `","namespace":"app","workloadKind":"deployment","workloadName":"web","mode":"TAIL","sinceSeconds":300,"limit":20}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workload-log-queries", bytes.NewBufferString(body)).WithContext(auth.WithPrincipal(context.Background(), principal))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "workload-log-roundtrip")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Operation controlplane.Operation `json:"operation"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Operation.Kind != workloadLogOperationKind || created.Operation.Class != controlplane.OperationClassReadOnly || created.Operation.DesiredRevision != cluster.InventoryDigest {
		t.Fatalf("unexpected operation=%+v clusterDigest=%s", created.Operation, cluster.InventoryDigest)
	}

	next := httptest.NewRequest(http.MethodGet, "/agent/v1/clusters/"+cluster.ID+"/workload-log-tasks/next", nil)
	next.Header.Set("Authorization", "Bearer "+agentToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, next)
	if w.Code != http.StatusOK {
		t.Fatalf("next status=%d body=%s", w.Code, w.Body.String())
	}
	var task workloadLogTask
	if err = json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.OperationID != created.Operation.ID || task.TaskFenceToken <= 0 || task.InventoryDigest != cluster.InventoryDigest || task.Request.Mode != "TAIL" || task.Request.WorkloadKind != "Deployment" {
		t.Fatalf("unexpected task=%+v", task)
	}

	timestamp := time.Now().UTC().Truncate(time.Millisecond)
	result := workloadLogResult{Success: true, TaskFenceToken: task.TaskFenceToken, Lines: []workloadLogLine{{Timestamp: timestamp, Pod: "web-7d9", Container: "app", Line: "ready"}}}
	raw, _ := json.Marshal(result)
	report := httptest.NewRequest(http.MethodPost, "/agent/v1/clusters/"+cluster.ID+"/workload-log-tasks/"+task.OperationID+"/result", bytes.NewReader(raw))
	report.Header.Set("Authorization", "Bearer "+agentToken)
	report.Header.Set("Content-Type", "application/json")
	report.Header.Set("If-Match", `"`+jsonNumber(task.OperationRevision)+`"`)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, report)
	if w.Code != http.StatusOK {
		t.Fatalf("report status=%d body=%s", w.Code, w.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/workload-log-queries/"+task.OperationID, nil).WithContext(auth.WithPrincipal(context.Background(), principal))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, get)
	if w.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", w.Code, w.Body.String())
	}
	var view struct {
		Ready     bool                          `json:"ready"`
		Operation controlplane.Operation        `json:"operation"`
		Evidence  controlplane.EvidenceMetadata `json:"evidence"`
		Lines     []workloadLogLine             `json:"lines"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Ready || view.Operation.State != controlplane.OperationSucceeded || !view.Evidence.Sealed || !view.Evidence.HasPayload || len(view.Lines) != 1 || view.Lines[0].Line != "ready" {
		t.Fatalf("unexpected view=%+v", view)
	}
}

func jsonNumber(v int64) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
