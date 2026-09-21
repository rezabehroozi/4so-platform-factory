package api

import (
	"errors"
	"net/http"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/virtualcluster"
)

type virtualClusterAgentTaskEnvelope struct {
	Task          controlplane.VirtualClusterTask `json:"task"`
	RuntimeSource virtualcluster.RuntimeSource    `json:"runtimeSource"`
}

func (s *Server) nextVirtualClusterTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	if !s.virtualClusterRuntimeReady {
		writeError(w, http.StatusServiceUnavailable, "VIRTUAL_CLUSTER_RUNTIME_SOURCE_NOT_READY", "sealed vCluster OSS runtime source is not configured")
		return
	}
	task, err := s.store.NextVirtualClusterTask(r.Context(), r.PathValue("id"), agentDigest, s.virtualClusterRuntimeDigest)
	if err != nil {
		if errors.Is(err, controlplane.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, task.ClusterRevision)
	writeJSON(w, http.StatusOK, virtualClusterAgentTaskEnvelope{Task: task, RuntimeSource: s.virtualClusterRuntimeSource})
}

func (s *Server) reportVirtualClusterTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.VirtualClusterTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result.VirtualClusterID = r.PathValue("virtualClusterId")
	v, err := s.store.ReportVirtualClusterTask(r.Context(), r.PathValue("id"), agentDigest, rev, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
