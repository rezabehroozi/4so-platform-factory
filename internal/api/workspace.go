package api

import (
	"net/http"
	"strconv"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

type workspaceInput struct {
	ProjectID   string `json:"projectId"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

type workspaceBindingInput struct {
	ClusterID string `json:"clusterId"`
	Namespace string `json:"namespace"`
}

type workspaceBindingRevokeInput struct {
	ExpectedRevision int64 `json:"expectedRevision"`
}

func (s *Server) createWorkspace(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input workspaceInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if _, err = s.requireProjectAccess(r, input.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	created, err := s.store.CreateWorkspace(r.Context(), controlplane.Workspace{ProjectID: input.ProjectID, Name: input.Name, DisplayName: input.DisplayName, Description: input.Description}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) getWorkspace(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetWorkspace(r.Context(), r.PathValue("id"))
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

func (s *Server) listWorkspaces(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.Workspace, error)
	if pager, ok := s.store.(workspacePageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.Workspace, error) {
			return pager.ListWorkspacesPage(r.Context(), ids, all, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.Workspace, error) { return s.store.ListWorkspaces(r.Context(), projectID) }, page, func(item controlplane.Workspace) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}

func (s *Server) createWorkspaceBinding(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	workspace, err := s.store.GetWorkspace(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, workspace.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	var input workspaceBindingInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	created, err := s.store.CreateWorkspaceBinding(r.Context(), controlplane.WorkspaceBinding{WorkspaceID: workspace.ID, ClusterID: input.ClusterID, Namespace: input.Namespace}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) listWorkspaceBindings(w http.ResponseWriter, r *http.Request) {
	workspace, err := s.store.GetWorkspace(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, workspace.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	items, err := s.store.ListWorkspaceBindings(r.Context(), workspace.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) revokeWorkspaceBinding(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	workspace, err := s.store.GetWorkspace(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, workspace.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	binding, err := s.store.GetWorkspaceBinding(r.Context(), r.PathValue("bindingId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if binding.WorkspaceID != workspace.ID || binding.ProjectID != workspace.ProjectID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	var input workspaceBindingRevokeInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if raw := strings.TrimSpace(r.Header.Get("If-Match")); input.ExpectedRevision == 0 && raw != "" {
		input.ExpectedRevision, _ = strconv.ParseInt(strings.Trim(raw, `"`), 10, 64)
	}
	if input.ExpectedRevision <= 0 {
		writeError(w, http.StatusBadRequest, "EXPECTED_REVISION_REQUIRED", "expectedRevision is required")
		return
	}
	out, err := s.store.RevokeWorkspaceBinding(r.Context(), binding.ID, input.ExpectedRevision, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
