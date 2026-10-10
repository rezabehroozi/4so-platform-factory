package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/resourceexplorer"
)

func TestClusterWorkloadExplorerRejectsCursorFromChangedInventoryEpoch(t *testing.T) {
	now := time.Now().UTC()
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	_, _, cluster := seedFleetSupportCluster(t, store, "owner-cursor-snapshot", "resource-explorer-cursor-snapshot", now)
	const agentTokenDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	inv, err := store.GetLatestClusterInventory(context.Background(), cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	inv.ObservedAt = now
	inv.WorkloadExplorer = controlplane.ClusterWorkloadExplorer{
		Complete: true,
		Workloads: []controlplane.ClusterWorkloadObservation{
			{Kind: "Deployment", Namespace: "apps", Name: "web-a", DesiredReplicas: 2, ReadyReplicas: 2},
			{Kind: "Deployment", Namespace: "apps", Name: "web-b", DesiredReplicas: 2, ReadyReplicas: 2},
		},
	}
	inv.WorkloadExplorer, err = controlplane.NormalizeClusterWorkloadExplorer(inv.WorkloadExplorer)
	if err != nil {
		t.Fatal(err)
	}
	inv.Digest = ""
	_, firstStored, err := store.UpsertClusterInventory(context.Background(), cluster.ID, agentTokenDigest, cluster.ExternalUID, inv)
	if err != nil {
		t.Fatal(err)
	}

	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	server := New("0.0.test", components, slog.Default(), store)
	principal := auth.Principal{Subject: "owner-cursor-snapshot", Roles: []string{"platform-viewer"}}
	request := func(rawQuery string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+cluster.ID+"/workloads?"+rawQuery, nil).
			WithContext(auth.WithPrincipal(context.Background(), principal))
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		return w
	}

	first := request("apiVersion=apps%2Fv1&kind=Deployment&namespace=apps&limit=1")
	if first.Code != http.StatusOK {
		t.Fatalf("first page status=%d body=%s", first.Code, first.Body.String())
	}
	var firstPayload struct {
		ResourcePage resourceexplorer.ResourcePage `json:"resourcePage"`
	}
	if err = json.Unmarshal(first.Body.Bytes(), &firstPayload); err != nil {
		t.Fatal(err)
	}
	if !firstPayload.ResourcePage.HasMore || firstPayload.ResourcePage.NextCursor == "" {
		t.Fatalf("expected a continuation cursor from first inventory snapshot: %#v", firstPayload.ResourcePage)
	}

	// ClusterInventoryDigest deliberately excludes ObservedAt. A new observation
	// epoch with identical content must therefore keep the same content digest,
	// while the workload cursor must still fail closed instead of mixing epochs.
	now = now.Add(time.Second)
	latest, err := store.GetLatestClusterInventory(context.Background(), cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	latest.ObservedAt = now
	latest.Digest = ""
	_, secondStored, err := store.UpsertClusterInventory(context.Background(), cluster.ID, agentTokenDigest, cluster.ExternalUID, latest)
	if err != nil {
		t.Fatal(err)
	}
	if secondStored.Digest != firstStored.Digest {
		t.Fatalf("same-content inventory epoch unexpectedly changed digest: first=%s second=%s", firstStored.Digest, secondStored.Digest)
	}
	if !secondStored.ObservedAt.After(firstStored.ObservedAt) {
		t.Fatalf("inventory observation epoch did not advance: first=%s second=%s", firstStored.ObservedAt, secondStored.ObservedAt)
	}

	query := url.Values{
		"apiVersion": {"apps/v1"},
		"kind":       {"Deployment"},
		"namespace":  {"apps"},
		"limit":      {"1"},
		"cursor":     {firstPayload.ResourcePage.NextCursor},
	}
	second := request(query.Encode())
	if second.Code != http.StatusBadRequest {
		t.Fatalf("cursor from changed inventory epoch must fail closed: status=%d body=%s", second.Code, second.Body.String())
	}
	var problem struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err = json.Unmarshal(second.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Error.Code != "RESOURCE_EXPLORER_QUERY_INVALID" {
		t.Fatalf("unexpected changed-epoch cursor error: %#v body=%s", problem, second.Body.String())
	}
}
