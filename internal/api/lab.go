package api

import (
	"net/http"

	"platform.4so.io/factory/internal/labmodel"
)

func (s *Server) getLabGuide(w http.ResponseWriter, _ *http.Request) {
	_ = s
	writeJSON(w, http.StatusOK, labmodel.Model())
}
