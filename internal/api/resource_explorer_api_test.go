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

func TestClusterWorkloadExplorerAddsBoundedUnknownSafeResourcePageWithoutBreakingLegacyRows(t *testing.T) {
	now := time.Now().UTC()
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	_, project, cluster := seedFleetSupportCluster(t, store, "owner-a", "resource-explorer-a", now)
	inv, err := store.GetLatestClusterInventory(context.Background(), cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	inv.ObservedAt = now
	inv.WorkloadExplorer = controlplane.ClusterWorkloadExplorer{
		Complete: true,
		Workloads: []controlplane.ClusterWorkloadObservation{
			{Kind: "Deployment", Namespace: "apps", Name: "web-a", DesiredReplicas: 2, ReadyReplicas: 2},
			{Kind: "Deployment", Namespace: "apps", Name: "web-b", DesiredReplicas: 3, ReadyReplicas: 2},
		},
		Services: []controlplane.ClusterServiceObservation{{Namespace: "apps", Name: "web", Type: "ClusterIP"}},
	}
	inv.WorkloadExplorer, err = controlplane.NormalizeClusterWorkloadExplorer(inv.WorkloadExplorer)
	if err != nil {
		t.Fatal(err)
	}
	inv.Digest = ""
	_, stored, err := store.UpsertClusterInventory(context.Background(), cluster.ID, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", cluster.ExternalUID, inv)
	if err != nil {
		t.Fatal(err)
	}

	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	server := New("0.0.test", components, slog.Default(), store)
	principal := auth.Principal{Subject: "owner-a", Roles: []string{"platform-viewer"}}

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
	var payload struct {
		Workloads             []controlplane.ClusterWorkloadObservation `json:"workloads"`
		ResourcePage          resourceexplorer.ResourcePage             `json:"resourcePage"`
		ResourceReadOnly      bool                                      `json:"resourceReadOnly"`
		RawKubernetesMutation bool                                      `json:"rawKubernetesMutation"`
		PersonaJourneys       []resourceexplorer.PersonaTaskJourney     `json:"personaJourneys"`
	}
	if err = json.Unmarshal(first.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Workloads) != 2 {
		t.Fatalf("legacy workload rows changed: %#v", payload.Workloads)
	}
	if !payload.ResourceReadOnly || payload.RawKubernetesMutation {
		t.Fatalf("resource explorer mutation boundary drift: %#v", payload)
	}
	if payload.ResourcePage.Authority != resourceexplorer.BoundedResourceExplorerAuthority || len(payload.ResourcePage.Items) != 1 || !payload.ResourcePage.HasMore || payload.ResourcePage.NextCursor == "" {
		t.Fatalf("first resource page drift: %#v", payload.ResourcePage)
	}
	if len(payload.PersonaJourneys) != 3 {
		t.Fatalf("expected canonical operator/platform-engineer/developer journeys: %#v", payload.PersonaJourneys)
	}
	seenPersona := map[resourceexplorer.Persona]bool{}
	for _, journey := range payload.PersonaJourneys {
		seenPersona[journey.Persona] = true
		if journey.Authority != resourceexplorer.PersonaTaskJourneyAuthority || !journey.TaskLanguageFirst || journey.RawKubernetesMutation || len(journey.Tasks) == 0 {
			t.Fatalf("persona journey authority drift: %#v", journey)
		}
	}
	for _, persona := range []resourceexplorer.Persona{resourceexplorer.PersonaOperator, resourceexplorer.PersonaPlatformEngineer, resourceexplorer.PersonaDeveloper} {
		if !seenPersona[persona] {
			t.Fatalf("missing persona journey %q", persona)
		}
	}
	item := payload.ResourcePage.Items[0]
	if item.Key.Kind != "Deployment" || item.Key.Namespace != "apps" || item.State != resourceexplorer.TruthUnknown || item.Key.APIVersion != "apps/v1" || item.Key.UID != "" || item.SourceDigest != stored.Digest {
		t.Fatalf("unknown-safe inventory adaptation drift: %#v", item)
	}

	secondQuery := url.Values{"apiVersion": {"apps/v1"}, "kind": {"Deployment"}, "namespace": {"apps"}, "limit": {"1"}, "cursor": {payload.ResourcePage.NextCursor}}
	second := request(secondQuery.Encode())
	if second.Code != http.StatusOK {
		t.Fatalf("second page status=%d body=%s", second.Code, second.Body.String())
	}
	var next struct {
		ResourcePage resourceexplorer.ResourcePage `json:"resourcePage"`
	}
	if err = json.Unmarshal(second.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if len(next.ResourcePage.Items) != 1 || next.ResourcePage.HasMore || next.ResourcePage.Items[0].Key.Name == item.Key.Name || next.ResourcePage.Items[0].Key.APIVersion != "apps/v1" {
		t.Fatalf("cursor continuation drift: %#v", next.ResourcePage)
	}

	tamperedQuery := url.Values{"apiVersion": {"v1"}, "kind": {"Service"}, "namespace": {"apps"}, "limit": {"1"}, "cursor": {payload.ResourcePage.NextCursor}}
	tampered := request(tamperedQuery.Encode())
	if tampered.Code != http.StatusBadRequest {
		t.Fatalf("cursor reused across filters must fail closed: status=%d body=%s", tampered.Code, tampered.Body.String())
	}
	if project.ID == "" {
		t.Fatal("seeded project unexpectedly empty")
	}
}
