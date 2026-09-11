package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/supportbundle"
)

func seedFleetSupportCluster(t *testing.T, store controlplane.Store, actor, name string, observedAt time.Time) (controlplane.Organization, controlplane.Project, controlplane.ManagedCluster) {
	t.Helper()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: name, DisplayName: name}, actor)
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, actor)
	if err != nil {
		t.Fatal(err)
	}
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{ProjectID: project.ID, Name: "edge", DisplayName: "Edge", TokenDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: time.Now().Add(time.Hour)}, actor)
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "other-admin")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, imp.TokenDigest, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "uid-"+name, "0.0.39")
	if err != nil {
		t.Fatal(err)
	}
	inv := controlplane.ClusterInventory{ObservedAt: observedAt, Distribution: "rke2", KubernetesVersion: "v1.34.9+rke2r1", Nodes: []controlplane.ClusterNode{{Name: "n1", Ready: true, Architecture: "amd64"}}, StorageClasses: []controlplane.ClusterStorageClass{{Name: "replicated", Provisioner: "openebs.io/local", Default: true}}, Capacity: controlplane.ClusterCapacity{CPUCapacityMilli: 4000, CPUAllocatableMilli: 3600, MemoryCapacityBytes: 8 << 30, MemoryAllocatableBytes: 7 << 30, PodsCapacity: 110, PodsAllocatable: 100}, Networking: controlplane.ClusterNetworking{CNI: "cilium", IngressControllers: []string{"kube-system/rke2-ingress-nginx-controller"}}, Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, "agent-mtls", "storage-class-inventory"}}
	inv.Digest = controlplane.ClusterInventoryDigest(inv)
	cluster, _, err = store.UpsertClusterInventory(ctx, cluster.ID, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", cluster.ExternalUID, inv)
	if err != nil {
		t.Fatal(err)
	}
	return org, project, cluster
}

func TestFleetHealthTimelineAndSupportBundleScope(t *testing.T) {
	now := time.Now().UTC()
	clock := now.Add(-20 * time.Minute)
	store := controlplane.NewMemoryStoreWith(func() time.Time { return clock }, nil)
	_, projectA, clusterA := seedFleetSupportCluster(t, store, "user-a", "tenant-a", clock)
	clock = now
	_, _, clusterB := seedFleetSupportCluster(t, store, "user-b", "tenant-b", clock)
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("0.0.39", components, slog.Default(), store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/health?projectId="+projectA.ID, nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "user-a", Roles: []string{"platform-viewer"}}))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("fleet health status=%d body=%s", w.Code, w.Body.String())
	}
	var health struct {
		Clusters []struct {
			ClusterID         string `json:"clusterId"`
			InventoryState    string `json:"inventoryState"`
			StorageClassCount int    `json:"storageClassCount"`
			KubernetesSupport struct {
				Status string `json:"status"`
			} `json:"kubernetesSupport"`
		} `json:"clusters"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if len(health.Clusters) != 1 || health.Clusters[0].ClusterID != clusterA.ID || health.Clusters[0].InventoryState != "STALE" || health.Clusters[0].StorageClassCount != 1 || health.Clusters[0].KubernetesSupport.Status == "" {
		t.Fatalf("unexpected fleet health: %#v", health)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+clusterA.ID+"/timeline", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "user-a", Roles: []string{"platform-viewer"}}))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("cluster.inventory.updated")) {
		t.Fatalf("timeline status=%d body=%s", w.Code, w.Body.String())
	}

	body := `{"profile":"cluster-diagnostics","clusterId":"` + clusterA.ID + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/support-bundles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "user-a", Roles: []string{"platform-viewer"}}))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("support bundle status=%d body=%s", w.Code, w.Body.String())
	}
	if verification, verifyErr := supportbundle.Verify(w.Body.Bytes()); verifyErr != nil || !verification.Valid {
		t.Fatalf("support bundle verification=%#v err=%v", verification, verifyErr)
	}

	body = `{"profile":"cluster-diagnostics","clusterId":"` + clusterB.ID + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/support-bundles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "user-a", Roles: []string{"platform-viewer"}}))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign cluster support bundle status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestProjectSupportAuditScopesBeforeGlobalLimit(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "support-own", DisplayName: "Own"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	// Flood the global audit tail after the project event. The project support
	// view must filter the canonical snapshot first and only then apply its cap.
	for i := 0; i < 600; i++ {
		name := fmt.Sprintf("foreign-%04d", i)
		if _, err := store.CreateOrganization(ctx, controlplane.Organization{Name: name, DisplayName: name}, "foreign"); err != nil {
			t.Fatal(err)
		}
	}
	s := New("test", nil, slog.Default(), store)
	req := httptest.NewRequest(http.MethodGet, "/internal", nil)
	events, err := s.projectAuditEvents(req, project)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.ResourceID == project.ID && event.Action == "project.created" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("project audit was starved by newer foreign global events; got %d scoped events", len(events))
	}
}

func TestDurableSupportBundleJobLifecycleAndReplay(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 5, 12, 30, 0, 0, time.UTC)
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	_, _, cluster := seedFleetSupportCluster(t, store, "support-owner", "support-job", now)
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := New("0.0.test", components, slog.Default(), store)
	principal := auth.Principal{Subject: "support-owner", Roles: []string{"platform-viewer"}}
	body := `{"profile":"cluster-diagnostics","clusterId":"` + cluster.ID + `"}`
	create := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/support-bundle-jobs", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "support-job-stable")
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}
	w := create()
	if w.Code != http.StatusAccepted {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Operation controlplane.Operation `json:"operation"`
		Replay    bool                   `json:"replay"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Operation.State != controlplane.OperationQueued || created.Replay {
		t.Fatalf("created=%+v", created)
	}

	// Same request is idempotent before or after execution and must never create
	// a second ZIP job.
	w = create()
	if w.Code != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", w.Code, w.Body.String())
	}
	var replayed struct {
		Operation controlplane.Operation `json:"operation"`
		Replay    bool                   `json:"replay"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if !replayed.Replay || replayed.Operation.ID != created.Operation.ID {
		t.Fatalf("replayed=%+v created=%+v", replayed, created)
	}

	if err = s.ProcessSupportBundleJobsOnce(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	op, err := store.GetOperation(ctx, created.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != controlplane.OperationSucceeded || op.Attempt != 1 {
		t.Fatalf("completed operation=%+v", op)
	}
	evidence, err := store.ListEvidence(ctx, op.ID)
	if err != nil || len(evidence) != 1 || evidence[0].Kind != "support-bundle" || !evidence[0].HasPayload || !evidence[0].Sealed {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	_, payload, err := store.GetEvidencePayload(ctx, evidence[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if verification, verifyErr := supportbundle.Verify(payload); verifyErr != nil || !verification.Valid {
		t.Fatalf("verification=%+v err=%v", verification, verifyErr)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/support-bundle-jobs/"+op.ID+"/download", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("download status=%d content-type=%s body=%s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), payload) {
		t.Fatal("downloaded evidence payload differs from sealed operation evidence")
	}
}
