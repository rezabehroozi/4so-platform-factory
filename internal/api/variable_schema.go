package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

type variableSchemaInput struct {
	ProjectID string                            `json:"projectId"`
	Name      string                            `json:"name"`
	Version   string                            `json:"version"`
	Variables []controlplane.VariableDefinition `json:"variables"`
}

func (s *Server) createVariableSchema(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input variableSchemaInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if _, err = s.requireProjectAccess(r, input.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	created, err := s.store.CreateVariableSchema(r.Context(), controlplane.VariableSchema{ProjectID: input.ProjectID, Name: input.Name, Version: input.Version, Variables: input.Variables}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) getVariableSchema(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetVariableSchema(r.Context(), r.PathValue("id"))
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

func (s *Server) listVariableSchemas(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	items, err := s.store.ListVariableSchemas(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	items = filterProjectScoped(items, allowed, all, func(v controlplane.VariableSchema) string { return v.ProjectID })
	writeJSON(w, http.StatusOK, items)
}
