package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
	"time"
)

type createRuntimeVerificationInput struct {
	ProjectID            string `json:"projectId"`
	ClusterID            string `json:"clusterId"`
	BaselineDeploymentID string `json:"baselineDeploymentId"`
}

func (s *Server) createRuntimeVerification(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required and must be at most 200 characters")
		return
	}
	if !strings.Contains(s.runtimeProbeImage, "@sha256:") {
		writeError(w, http.StatusServiceUnavailable, "RUNTIME_PROBE_UNAVAILABLE", "digest-pinned runtime probe image is not configured")
		return
	}
	var in createRuntimeVerificationInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	raw, _ := json.Marshal(in)
	sum := sha256.Sum256(raw)
	requestDigest := "sha256:" + hex.EncodeToString(sum[:])
	v, replay, err := s.store.CreateRuntimeVerification(r.Context(), controlplane.RuntimeVerification{
		ProjectID: in.ProjectID, ClusterID: in.ClusterID, BaselineDeploymentID: in.BaselineDeploymentID,
		ProbeImage: s.runtimeProbeImage, RequestDigest: requestDigest, IdempotencyKey: key,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"verification": v, "idempotentReplay": replay, "next": "agent-runtime-probe"})
}

func (s *Server) listRuntimeVerifications(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	v, err := s.store.ListRuntimeVerifications(r.Context(), projectID, r.URL.Query().Get("clusterId"), r.URL.Query().Get("baselineDeploymentId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	v = filterProjectScoped(v, allowed, all, func(item controlplane.RuntimeVerification) string { return item.ProjectID })
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) getRuntimeVerification(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetRuntimeVerification(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) retryRuntimeVerification(w http.ResponseWriter, r *http.Request) {
	current, lookupErr := s.store.GetRuntimeVerification(r.Context(), r.PathValue("id"))
	if lookupErr != nil {
		writeStoreError(w, lookupErr)
		return
	}
	if _, lookupErr = s.requireProjectAccess(r, current.ProjectID, organizationWrite); lookupErr != nil {
		writeScopeError(w, lookupErr)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RetryRuntimeVerification(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusAccepted, v)
}

func (s *Server) runtimeVerificationReport(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetRuntimeVerification(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), v.ClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	baseline, err := s.store.GetBaselineDeployment(r.Context(), v.BaselineDeploymentID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	report := map[string]any{
		"apiVersion": "platform.4so.io/v1alpha1", "kind": "PilotRuntimeReport",
		"metadata": map[string]any{"id": v.ID, "generatedAt": time.Now().UTC(), "reportDigest": v.ReportDigest},
		"product":  map[string]any{"name": "4SO Platform Factory", "version": s.version},
		"target":   map[string]any{"cluster": cluster, "baselineDeployment": baseline.ID, "baselineId": baseline.BaselineID, "baselineVersion": baseline.BaselineVersion},
		"result":   map[string]any{"state": v.State, "desiredDigest": v.DesiredDigest, "observedDigest": v.ObservedDigest, "checks": v.Checks, "error": v.LastError},
		"claims":   map[string]any{"runtimeVerified": v.State == controlplane.RuntimeVerificationSucceeded, "productionReady": false, "haCertified": false},
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "4so-runtime-report-"+v.ID+".json"))
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) nextRuntimeVerificationTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	v, err := s.store.NextRuntimeVerificationTask(r.Context(), r.PathValue("id"), agentDigest)
	if errors.Is(err, controlplane.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	baseline, err := s.store.GetBaselineDeployment(r.Context(), v.BaselineDeploymentID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, controlplane.RuntimeVerificationTask{
		VerificationID: v.ID, VerificationRevision: v.Revision, TaskFenceToken: v.TaskFenceToken, LeaseExpiresAt: *v.TaskLeaseExpiresAt, BaselineDeploymentID: v.BaselineDeploymentID,
		TargetNamespace: baseline.TargetNamespace, DesiredDigest: v.DesiredDigest, ProbeImage: v.ProbeImage,
	})
}
func (s *Server) reportRuntimeVerificationTask(w http.ResponseWriter, r *http.Request) {
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
	var result controlplane.RuntimeVerificationResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result.VerificationID = r.PathValue("verificationId")
	v, err := s.store.ReportRuntimeVerificationTask(r.Context(), r.PathValue("id"), agentDigest, rev, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
