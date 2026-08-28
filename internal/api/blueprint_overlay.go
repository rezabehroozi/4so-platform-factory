package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/domain"
)

type blueprintOverlayInput struct {
	ProjectID string                                `json:"projectId"`
	Name      string                                `json:"name"`
	Version   string                                `json:"version"`
	Scope     controlplane.BlueprintOverlayScope    `json:"scope"`
	ScopeKey  string                                `json:"scopeKey"`
	Changes   []controlplane.BlueprintOverlayChange `json:"changes"`
}

type blueprintResolveInput struct {
	ProjectID            string           `json:"projectId"`
	CatalogReleaseID     string           `json:"catalogReleaseId,omitempty"`
	ProviderOverlayID    string           `json:"providerOverlayId,omitempty"`
	EnvironmentOverlayID string           `json:"environmentOverlayId,omitempty"`
	Blueprint            domain.Blueprint `json:"blueprint"`
}

func (s *Server) createBlueprintOverlay(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input blueprintOverlayInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if _, err = s.requireProjectAccess(r, input.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	created, err := s.store.CreateBlueprintOverlay(r.Context(), controlplane.BlueprintOverlay{ProjectID: input.ProjectID, Name: input.Name, Version: input.Version, Scope: input.Scope, ScopeKey: input.ScopeKey, Changes: input.Changes}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}
func (s *Server) getBlueprintOverlay(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetBlueprintOverlay(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) listBlueprintOverlays(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	scope := controlplane.BlueprintOverlayScope(strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("scope"))))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	items, err := s.store.ListBlueprintOverlays(r.Context(), projectID, scope)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	items = filterProjectScoped(items, allowed, all, func(v controlplane.BlueprintOverlay) string { return v.ProjectID })
	writeJSON(w, http.StatusOK, items)
}
func (s *Server) resolveBlueprintPreview(w http.ResponseWriter, r *http.Request) {
	var input blueprintResolveInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if _, err := s.requireProjectAccess(r, input.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	components, certificationAuthorityVerified, err := s.blueprintCatalogComponents(r, input.ProjectID, input.CatalogReleaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	provider, environment, err := s.blueprintOverlayInputs(r, input.ProjectID, input.ProviderOverlayID, input.EnvironmentOverlayID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	revision, resolved, resolution, plan, validation, err := blueprintMaterial(input.Blueprint, provider, environment, components, certificationAuthorityVerified)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "BLUEPRINT_RESOLUTION_FAILED", err.Error())
		return
	}
	if !validation.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"validation": validation, "blueprint": resolved, "resolution": resolution})
		return
	}
	// Preview returns the calculated immutable material without persisting it.
	revision.ID = ""
	revision.ProjectID = input.ProjectID
	revision.Payload = nil
	revision.BasePayload = nil
	revision.ResolutionPayload = nil
	writeJSON(w, http.StatusOK, map[string]any{"blueprint": resolved, "resolution": resolution, "material": revision, "plan": plan, "validation": validation})
}
