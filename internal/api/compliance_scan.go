package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/compliance"
	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) createComplianceProfile(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ProjectID       string              `json:"projectId"`
		Name            string              `json:"name"`
		MinimumSeverity compliance.Severity `json:"minimumSeverity"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	project, err := s.requireProjectAccess(r, strings.TrimSpace(in.ProjectID), organizationAdminAccess)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	v, err := s.store.CreateComplianceProfile(r.Context(), controlplane.ComplianceProfile{ProjectID: project.ID, Name: in.Name, BaselineAuthority: compliance.BaselineAuthority, MinimumSeverity: in.MinimumSeverity}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) listComplianceProfiles(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_ID_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeStoreError(w, err)
		return
	}
	v, err := s.store.ListComplianceProfiles(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createComplianceScan(w http.ResponseWriter, r *http.Request) {
	var in struct{ ProjectID, ClusterID, ProfileID, IdempotencyKey string }
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	project, err := s.requireProjectAccess(r, strings.TrimSpace(in.ProjectID), organizationWrite)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), strings.TrimSpace(in.ClusterID))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if cluster.ProjectID != project.ID {
		writeError(w, http.StatusForbidden, "PROJECT_SCOPE_DENIED", "cluster is outside project scope")
		return
	}
	profile, err := s.store.GetComplianceProfile(r.Context(), strings.TrimSpace(in.ProfileID))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if profile.ProjectID != project.ID {
		writeError(w, http.StatusForbidden, "PROJECT_SCOPE_DENIED", "profile is outside project scope")
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	digest := complianceRequestDigest(map[string]any{"projectId": project.ID, "clusterId": cluster.ID, "profileId": profile.ID, "inventoryDigest": cluster.InventoryDigest})
	v, replay, err := s.store.CreateComplianceScanRun(r.Context(), controlplane.ComplianceScanRun{ProjectID: project.ID, ClusterID: cluster.ID, ProfileID: profile.ID, IdempotencyKey: strings.TrimSpace(in.IdempotencyKey), RequestDigest: digest}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"scan": v, "idempotentReplay": replay})
}

func (s *Server) listComplianceScans(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_ID_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeStoreError(w, err)
		return
	}
	v, err := s.store.ListComplianceScanRuns(r.Context(), projectID, strings.TrimSpace(r.URL.Query().Get("clusterId")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) getComplianceScan(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetComplianceScanRun(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) listComplianceFindings(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "PROJECT_ID_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeStoreError(w, err)
		return
	}
	v, err := s.store.ListComplianceFindings(r.Context(), projectID, strings.TrimSpace(r.URL.Query().Get("runId")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createComplianceWaiver(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ProjectID, Fingerprint, Reason string
		ExpiresAt                      *time.Time `json:"expiresAt,omitempty"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err := s.requireProjectAccess(r, in.ProjectID, organizationAdminAccess); err != nil {
		writeStoreError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	v, err := s.store.CreateComplianceWaiver(r.Context(), controlplane.ComplianceWaiver{ProjectID: in.ProjectID, Fingerprint: in.Fingerprint, Reason: in.Reason, ExpiresAt: in.ExpiresAt}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}
func (s *Server) approveComplianceWaiver(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetComplianceWaiver(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationAdminAccess); err != nil {
		writeStoreError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	if strings.TrimSpace(current.RequestedBy) == actor {
		writeApprovalError(w, errSeparationOfDuties)
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.ApproveComplianceWaiver(r.Context(), current.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) revokeComplianceWaiver(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetComplianceWaiver(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationAdminAccess); err != nil {
		writeStoreError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RevokeComplianceWaiver(r.Context(), current.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) recheckComplianceFinding(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	runID := strings.TrimSpace(r.URL.Query().Get("runId"))
	fingerprint := strings.TrimSpace(r.PathValue("fingerprint"))
	if projectID == "" || runID == "" || fingerprint == "" {
		writeError(w, http.StatusBadRequest, "RECHECK_SCOPE_REQUIRED", "projectId, runId and fingerprint are required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationWrite); err != nil {
		writeStoreError(w, err)
		return
	}
	findings, err := s.store.ListComplianceFindings(r.Context(), projectID, runID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	matched := false
	for _, f := range findings {
		if f.Fingerprint == fingerprint {
			matched = true
			break
		}
	}
	if !matched {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	prior, err := s.store.GetComplianceScanRun(r.Context(), runID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in struct {
		IdempotencyKey string `json:"idempotencyKey"`
	}
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	key := strings.TrimSpace(in.IdempotencyKey)
	if key == "" {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "idempotencyKey is required for compliance recheck")
		return
	}
	digest := complianceRequestDigest(map[string]any{"recheckRunId": runID, "fingerprint": fingerprint, "profileId": prior.ProfileID, "clusterId": prior.ClusterID})
	v, _, err := s.store.CreateComplianceScanRun(r.Context(), controlplane.ComplianceScanRun{ProjectID: prior.ProjectID, ClusterID: prior.ClusterID, ProfileID: prior.ProfileID, IdempotencyKey: key, RequestDigest: digest}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) nextComplianceScanTask(w http.ResponseWriter, r *http.Request) {
	clusterID := r.PathValue("id")
	agentDigest, err := s.agentCredentialDigest(r, clusterID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	task, err := s.store.ClaimComplianceScanTask(r.Context(), clusterID, agentDigest, 90*time.Second, time.Now().UTC())
	if errors.Is(err, controlplane.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, task.RunRevision)
	writeJSON(w, http.StatusOK, task)
}
func (s *Server) reportComplianceScanTask(w http.ResponseWriter, r *http.Request) {
	clusterID := r.PathValue("id")
	agentDigest, err := s.agentCredentialDigest(r, clusterID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	var result controlplane.ComplianceScanTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	run, err := s.store.GetComplianceScanRun(r.Context(), r.PathValue("runId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	if expected != run.Revision {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if run.ClusterID != clusterID {
		writeError(w, http.StatusForbidden, "CLUSTER_SCOPE_DENIED", "scan belongs to a different cluster")
		return
	}
	if result.TaskFenceToken != run.TaskFenceToken {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	var out controlplane.ComplianceScanRun
	if strings.TrimSpace(result.Error) != "" {
		out, err = s.store.FailComplianceScan(r.Context(), run.ID, agentDigest, result.TaskFenceToken, result.Error, "agent:"+clusterID)
	} else {
		out, err = s.store.CompleteComplianceScan(r.Context(), run.ID, agentDigest, result.TaskFenceToken, result.Findings, "agent:"+clusterID)
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, out.Revision)
	writeJSON(w, http.StatusOK, out)
}

func complianceRequestDigest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
