package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/edgeauthority"
)

type edgeBootAttestationAssessmentInput struct {
	ProjectID string                  `json:"projectId"`
	Claim     edgeauthority.BootClaim `json:"claim"`
}

type edgeLocalAIProfileValidationInput struct {
	ProjectID string                       `json:"projectId"`
	Profile   edgeauthority.LocalAIProfile `json:"profile"`
}

func (s *Server) assessEdgeBootAttestation(w http.ResponseWriter, r *http.Request) {
	var in edgeBootAttestationAssessmentInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	if in.ProjectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_ID_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, in.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	assessment := edgeauthority.AssessBootClaim(in.Claim)
	writeJSON(w, http.StatusOK, map[string]any{
		"projectId": in.ProjectID,
		"assessment": assessment,
		"physicalEvidenceCollected": false,
		"physicalCertification": "NOT_RUN",
	})
}

func (s *Server) validateEdgeLocalAIProfile(w http.ResponseWriter, r *http.Request) {
	var in edgeLocalAIProfileValidationInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	if in.ProjectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_ID_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, in.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	if err := edgeauthority.ValidateLocalAIProfile(in.Profile); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "LOCAL_AI_PROFILE_REJECTED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"projectId": in.ProjectID,
		"authority": edgeauthority.LocalAIProfileAuthority,
		"admitted": true,
		"runtimeStarted": false,
		"physicalCertification": "NOT_RUN",
	})
}
