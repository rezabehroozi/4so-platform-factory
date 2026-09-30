package api

import (
	"net/http"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) previewApplicationDeploymentPlan(w http.ResponseWriter, r *http.Request) {
	st, ok := s.applicationPlatformAuthority(w)
	if !ok {
		return
	}
	binding, err := st.GetEnvironmentBinding(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !s.applicationProjectRead(w, r, binding.ProjectID) {
		return
	}
	release, err := st.GetApplicationRelease(r.Context(), binding.ReleaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	workspaceBinding, err := s.store.GetWorkspaceBinding(r.Context(), binding.WorkspaceBindingID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var runtime controlplane.ApplicationRuntimeSpec
	if err = decodeJSON(w, r, &runtime); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	plan, err := controlplane.ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, runtime)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}
