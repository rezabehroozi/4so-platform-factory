package api

import (
	"net/http"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) getDay2CampaignEngine(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, controlplane.Day2CampaignEngineModel())
}
