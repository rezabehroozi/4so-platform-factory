package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/domain"
)

func TestBlueprintOverlayResolveAndPersistProvenanceAPI(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "overlay-api", DisplayName: "Overlay API"}, "admin")
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
	var bp domain.Blueprint
	if err = json.Unmarshal(raw, &bp); err != nil {
		t.Fatal(err)
	}
	bp.Spec.FieldOwnership = []domain.FieldOwnershipRule{{Path: "/spec/delivery/repository", Policy: "PROVIDER_ONLY"}, {Path: "/spec/description", Policy: "PROVIDER_THEN_ENVIRONMENT"}}

	createOverlay := func(body map[string]any) controlplane.BlueprintOverlay {
		b, _ := json.Marshal(body)
		w := apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-overlays", string(b), map[string]string{"X-Actor-ID": "author"})
		if w.Code != http.StatusCreated {
			t.Fatalf("overlay create=%d body=%s", w.Code, w.Body.String())
		}
		var out controlplane.BlueprintOverlay
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	provider := createOverlay(map[string]any{"projectId": project.ID, "name": "vsphere", "version": "1.0.0", "scope": "PROVIDER", "scopeKey": "vsphere", "changes": []map[string]any{{"path": "/spec/delivery/repository", "value": "https://git.company.test/platform.git"}, {"path": "/spec/description", "value": "provider standard"}}})
	environment := createOverlay(map[string]any{"projectId": project.ID, "name": "production", "version": "1.0.0", "scope": "ENVIRONMENT", "scopeKey": "production", "changes": []map[string]any{{"path": "/spec/description", "value": "production standard"}}})

	request := map[string]any{"projectId": project.ID, "providerOverlayId": provider.ID, "environmentOverlayId": environment.ID, "blueprint": bp}
	body, _ := json.Marshal(request)
	w := apiRequest(t, h, http.MethodPost, "/api/v1/blueprints/resolve", string(body), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusOK {
		t.Fatalf("resolve=%d body=%s", w.Code, w.Body.String())
	}
	var preview struct {
		Blueprint  domain.Blueprint                 `json:"blueprint"`
		Resolution controlplane.BlueprintResolution `json:"resolution"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Blueprint.Spec.Description != "production standard" || preview.Blueprint.Spec.Delivery.Repository != "https://git.company.test/platform.git" {
		t.Fatalf("unexpected preview: %#v", preview.Blueprint.Spec)
	}
	if preview.Resolution.ProviderOverlayID != provider.ID || preview.Resolution.EnvironmentOverlayID != environment.ID {
		t.Fatalf("resolution=%#v", preview.Resolution)
	}

	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-releases", string(body), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("release create=%d body=%s", w.Code, w.Body.String())
	}
	var created struct {
		Release controlplane.BlueprintRelease `json:"release"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	w = apiRequest(t, h, http.MethodGet, "/api/v1/blueprint-releases/"+created.Release.ID, "", map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusOK {
		t.Fatalf("get=%d body=%s", w.Code, w.Body.String())
	}
	var view struct {
		Revision      controlplane.BlueprintRevision   `json:"revision"`
		Blueprint     domain.Blueprint                 `json:"blueprint"`
		BaseBlueprint domain.Blueprint                 `json:"baseBlueprint"`
		Resolution    controlplane.BlueprintResolution `json:"resolution"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.BaseBlueprint.Spec.Description == view.Blueprint.Spec.Description || view.Blueprint.Spec.Description != "production standard" {
		t.Fatalf("base/resolved not preserved: base=%q resolved=%q", view.BaseBlueprint.Spec.Description, view.Blueprint.Spec.Description)
	}
	if view.Revision.BaseBlueprintDigest == "" || view.Revision.OverlayDigest == "" || view.Revision.OwnershipDigest == "" || view.Revision.ProviderOverlayID != provider.ID || view.Revision.EnvironmentOverlayID != environment.ID {
		t.Fatalf("revision provenance missing: %#v", view.Revision)
	}
}

func TestBlueprintOverlayAPIRejectsOwnershipConflict(t *testing.T) {
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "overlay-conflict", DisplayName: "Overlay Conflict"}, "admin")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "admin")
	h := scopedServer(t, store).Handler()
	raw, _ := os.ReadFile("../../blueprints/enterprise-private-cloud.json")
	var bp domain.Blueprint
	_ = json.Unmarshal(raw, &bp)
	bp.Spec.FieldOwnership = []domain.FieldOwnershipRule{{Path: "/spec/delivery/repository", Policy: "PROVIDER_ONLY"}}
	overlayBody, _ := json.Marshal(map[string]any{"projectId": project.ID, "name": "prod", "version": "1.0.0", "scope": "ENVIRONMENT", "scopeKey": "production", "changes": []map[string]any{{"path": "/spec/delivery/repository", "value": "https://git.company.test/prod.git"}}})
	w := apiRequest(t, h, http.MethodPost, "/api/v1/blueprint-overlays", string(overlayBody), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	var overlay controlplane.BlueprintOverlay
	_ = json.Unmarshal(w.Body.Bytes(), &overlay)
	body, _ := json.Marshal(map[string]any{"projectId": project.ID, "environmentOverlayId": overlay.ID, "blueprint": bp})
	w = apiRequest(t, h, http.MethodPost, "/api/v1/blueprints/resolve", string(body), map[string]string{"X-Actor-ID": "author"})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected ownership conflict, got %d body=%s", w.Code, w.Body.String())
	}
}
