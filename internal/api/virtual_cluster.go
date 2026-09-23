package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/virtualcluster"
)

type virtualClusterCreateInput struct {
	WorkspaceBindingID string                   `json:"workspaceBindingId"`
	Name               string                   `json:"name"`
	Profile            virtualcluster.ProfileID `json:"profile"`
	KubernetesVersion  string                   `json:"kubernetesVersion"`
	CPUMilli           int                      `json:"cpuMilli"`
	MemoryMiB          int                      `json:"memoryMiB"`
	StorageGiB         int                      `json:"storageGiB"`
	MaxNamespaces      int                      `json:"maxNamespaces"`
	SleepAfterMinutes  int                      `json:"sleepAfterMinutes,omitempty"`
}

func (s *Server) createVirtualCluster(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, ok := requireIdempotencyKey(w, r)
	if !ok {
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
	var in virtualClusterCreateInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	request := controlplane.VirtualClusterCreateRequest{
		WorkspaceID: workspace.ID,
		WorkspaceBindingID: strings.TrimSpace(in.WorkspaceBindingID),
		Spec: virtualcluster.Request{
			Name: in.Name,
			Profile: in.Profile,
			KubernetesVersion: in.KubernetesVersion,
			CPUMilli: in.CPUMilli,
			MemoryMiB: in.MemoryMiB,
			StorageGiB: in.StorageGiB,
			MaxNamespaces: in.MaxNamespaces,
			SleepAfterMinutes: in.SleepAfterMinutes,
		},
		IdempotencyKey: key,
		RequestDigest: digestValue(in),
	}
	v, replay, err := s.store.CreateVirtualCluster(r.Context(), request, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
		w.Header().Set("Idempotent-Replay", "true")
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{
		"virtualCluster": v,
		"idempotentReplay": replay,
		"authority": controlplane.VirtualClusterStoreAuthority,
	})
}

func (s *Server) listVirtualClusters(w http.ResponseWriter, r *http.Request) {
	workspace, err := s.store.GetWorkspace(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, workspace.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	items, err := s.store.ListVirtualClusters(r.Context(), workspace.ProjectID, workspace.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) getVirtualCluster(w http.ResponseWriter, r *http.Request) {
	workspace, err := s.store.GetWorkspace(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, workspace.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.GetVirtualCluster(r.Context(), r.PathValue("virtualClusterId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if v.WorkspaceID != workspace.ID || v.ProjectID != workspace.ProjectID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}


func (s *Server) requestVirtualClusterLifecycle(w http.ResponseWriter, r *http.Request, action virtualcluster.Action) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
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
	v, err := s.store.GetVirtualCluster(r.Context(), r.PathValue("virtualClusterId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if v.WorkspaceID != workspace.ID || v.ProjectID != workspace.ProjectID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	if action == virtualcluster.ActionDelete && strings.TrimSpace(r.Header.Get("X-Confirm-Delete")) != "delete-virtual-cluster" {
		writeError(w, http.StatusPreconditionRequired, "DELETE_CONFIRMATION_REQUIRED", "X-Confirm-Delete: delete-virtual-cluster is required")
		return
	}
	requestDigest := digestValue(map[string]any{
		"authority": virtualcluster.LifecycleAuthority,
		"workspaceId": workspace.ID,
		"virtualClusterId": v.ID,
		"action": action,
		"idempotencyKey": key,
	})
	updated, replay, err := s.store.RequestVirtualClusterLifecycle(r.Context(), v.ID, expected, string(action), key, requestDigest, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
		w.Header().Set("Idempotent-Replay", "true")
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, status, map[string]any{
		"virtualCluster": updated,
		"idempotentReplay": replay,
		"authority": virtualcluster.LifecycleAuthority,
	})
}

func (s *Server) suspendVirtualCluster(w http.ResponseWriter, r *http.Request) {
	s.requestVirtualClusterLifecycle(w, r, virtualcluster.ActionSuspend)
}

func (s *Server) resumeVirtualCluster(w http.ResponseWriter, r *http.Request) {
	s.requestVirtualClusterLifecycle(w, r, virtualcluster.ActionResume)
}

func (s *Server) deleteVirtualCluster(w http.ResponseWriter, r *http.Request) {
	s.requestVirtualClusterLifecycle(w, r, virtualcluster.ActionDelete)
}
