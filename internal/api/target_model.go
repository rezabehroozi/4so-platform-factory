package api

import (
	"net/http"

	"platform.4so.io/factory/internal/targetmodel"
)

func (s *Server) getTargetArchitectureModel(w http.ResponseWriter, r *http.Request) {
	_ = s
	writeJSON(w, http.StatusOK, targetmodel.ArchitectureModel())
}

func (s *Server) getMCPDelegationArchitecture(w http.ResponseWriter, r *http.Request) {
	_ = s
	writeJSON(w, http.StatusOK, targetmodel.MCPRemoteOAuthModel())
}
