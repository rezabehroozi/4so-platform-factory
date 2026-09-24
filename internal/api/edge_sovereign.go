package api

import (
	"net/http"
	"strings"
	"time"

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

type edgeLocalPolicyCompileInput struct {
	ProjectID              string                 `json:"projectId"`
	SiteID                 string                 `json:"siteId"`
	Revision               int64                  `json:"revision"`
	DesiredStateDigest     string                 `json:"desiredStateDigest"`
	AllowedActions         []edgeauthority.Action `json:"allowedActions"`
	MaxOfflineSeconds      int64                  `json:"maxOfflineSeconds"`
	MaxQueuedEvidenceItems int                    `json:"maxQueuedEvidenceItems"`
	ValidUntil             time.Time              `json:"validUntil"`
}

type edgeOfflineMutationAdmissionInput struct {
	ProjectID         string                        `json:"projectId"`
	Policy            edgeauthority.LocalPolicy     `json:"policy"`
	Request           edgeauthority.MutationRequest `json:"request"`
	DisconnectedSince time.Time                     `json:"disconnectedSince"`
}

type edgeReconnectResolveInput struct {
	ProjectID                 string                        `json:"projectId"`
	Request                   edgeauthority.MutationRequest `json:"request"`
	CentralRevision           int64                         `json:"centralRevision"`
	CentralDesiredStateDigest string                        `json:"centralDesiredStateDigest"`
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

func (s *Server) compileEdgeLocalPolicy(w http.ResponseWriter, r *http.Request) {
	var in edgeLocalPolicyCompileInput
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
	policy, err := edgeauthority.CanonicalPolicy(
		in.SiteID, in.ProjectID, in.DesiredStateDigest, in.Revision, in.AllowedActions,
		time.Duration(in.MaxOfflineSeconds)*time.Second, in.MaxQueuedEvidenceItems, in.ValidUntil,
	)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "EDGE_LOCAL_POLICY_REJECTED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": edgeauthority.Authority,
		"policy": policy,
		"mutationExecuted": false,
		"requiresDurableOperationForExecution": true,
		"physicalCertification": "NOT_RUN",
	})
}

func (s *Server) admitEdgeOfflineMutation(w http.ResponseWriter, r *http.Request) {
	var in edgeOfflineMutationAdmissionInput
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
	if in.Policy.ProjectID != in.ProjectID || in.Request.ProjectID != in.ProjectID {
		writeError(w, http.StatusForbidden, "EDGE_PROJECT_SCOPE_MISMATCH", "policy/request are outside requested project")
		return
	}
	if err := edgeauthority.AdmitOfflineMutation(in.Policy, in.Request, time.Now().UTC(), in.DisconnectedSince); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "EDGE_OFFLINE_MUTATION_REJECTED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": edgeauthority.Authority,
		"admitted": true,
		"mutationExecuted": false,
		"requiresDurableOperationForExecution": true,
		"physicalCertification": "NOT_RUN",
	})
}

func (s *Server) resolveEdgeReconnect(w http.ResponseWriter, r *http.Request) {
	var in edgeReconnectResolveInput
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
	if in.Request.ProjectID != in.ProjectID {
		writeError(w, http.StatusForbidden, "EDGE_PROJECT_SCOPE_MISMATCH", "request is outside requested project")
		return
	}
	decision := edgeauthority.ResolveReconnect(in.Request, in.CentralRevision, in.CentralDesiredStateDigest)
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": edgeauthority.Authority,
		"decision": decision,
		"mutationExecuted": false,
		"physicalCertification": "NOT_RUN",
	})
}
