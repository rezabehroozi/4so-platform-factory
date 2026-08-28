package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/domain"
)

func TestCatalogDraftStaleRevisionDoesNotPersistOrphanRevision(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "catalog-atomic", DisplayName: "Catalog Atomic"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	server := New("test", components, nil, store)
	h := server.Handler()

	createBody, _ := json.Marshal(map[string]any{
		"organizationId": org.ID,
		"catalogName":    "atomic-catalog",
		"catalogVersion": "1.0.0",
		"visibility":     "PRIVATE",
		"channel":        "CANDIDATE",
		"components":     catalog.Sorted(components),
	})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/catalog-releases", string(createBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Release controlplane.CatalogRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed := catalog.Sorted(components)
	changed[0].Spec.DisplayName += " updated"
	updateBody, _ := json.Marshal(map[string]any{"components": changed})
	w = apiRequest(t, h, http.MethodPut, "/api/v1/catalog-releases/"+created.Release.ID+"/draft", string(updateBody), map[string]string{
		"X-Actor-ID": "author",
		"If-Match":   fmt.Sprintf("\"%d\"", created.Release.Revision+99),
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("stale update=%d body=%s", w.Code, w.Body.String())
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.CatalogRevisions) != len(before.CatalogRevisions) {
		t.Fatalf("stale catalog draft update persisted orphan revision: before=%d after=%d", len(before.CatalogRevisions), len(after.CatalogRevisions))
	}
}

func TestBlueprintDraftStaleRevisionDoesNotPersistOrphanRevision(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "blueprint-atomic", DisplayName: "Blueprint Atomic"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	h := scopedServer(t, store).Handler()
	raw, err := os.ReadFile("../../blueprints/enterprise-private-cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	var blueprint domain.Blueprint
	if err = json.Unmarshal(raw, &blueprint); err != nil {
		t.Fatal(err)
	}
	createBody, _ := json.Marshal(map[string]any{"projectId": project.ID, "blueprint": blueprint})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases", string(createBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Release controlplane.BlueprintRelease `json:"release"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blueprint.Spec.Description += " atomic-update"
	updateBody, _ := json.Marshal(map[string]any{"blueprint": blueprint})
	w = apiRequest(t, h, http.MethodPut, "/api/v1/blueprint-releases/"+created.Release.ID+"/draft", string(updateBody), map[string]string{
		"X-Actor-ID": "author",
		"If-Match":   fmt.Sprintf("\"%d\"", created.Release.Revision+99),
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("stale update=%d body=%s", w.Code, w.Body.String())
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Revisions) != len(before.Revisions) {
		t.Fatalf("stale blueprint draft update persisted orphan revision: before=%d after=%d", len(before.Revisions), len(after.Revisions))
	}
}
