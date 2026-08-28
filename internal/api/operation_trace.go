package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) appendOperationStep(w http.ResponseWriter, r *http.Request) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in struct {
		WorkerID   string                      `json:"workerId"`
		FenceToken int64                       `json:"fenceToken"`
		StepKey    string                      `json:"stepKey"`
		State      controlplane.OperationState `json:"state"`
		LastError  string                      `json:"lastError,omitempty"`
	}
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if strings.TrimSpace(in.WorkerID) == "" || op.LeaseOwner != strings.TrimSpace(in.WorkerID) || op.FenceToken != in.FenceToken || op.LeaseExpiresAt == nil || !op.LeaseExpiresAt.After(time.Now().UTC()) {
		writeStoreError(w, controlplane.ErrStaleFence)
		return
	}
	now := time.Now().UTC()
	step := controlplane.OperationStep{OperationID: op.ID, StepKey: strings.TrimSpace(in.StepKey), State: in.State, FenceToken: in.FenceToken, LastError: strings.TrimSpace(in.LastError), StartedAt: &now}
	if in.State == controlplane.OperationSucceeded || in.State == controlplane.OperationFailed || in.State == controlplane.OperationCancelled {
		step.FinishedAt = &now
	}
	created, err := s.store.AppendOperationStep(r.Context(), step, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func parseOperationStepPhase(raw string) (controlplane.OperationStepPhase, error) {
	phase := controlplane.OperationStepPhase(strings.ToUpper(strings.TrimSpace(raw)))
	if phase != controlplane.OperationStepPhaseForward && phase != controlplane.OperationStepPhaseCompensation {
		return "", fmt.Errorf("phase must be forward or compensation")
	}
	return phase, nil
}

func (s *Server) appendOperationStepTrace(w http.ResponseWriter, r *http.Request) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	phase, err := parseOperationStepPhase(r.PathValue("phase"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	var in struct {
		WorkerID      string                             `json:"workerId"`
		FenceToken    int64                              `json:"fenceToken"`
		TraceKey      string                             `json:"traceKey"`
		Level         controlplane.OperationStepLogLevel `json:"level"`
		EventType     string                             `json:"eventType"`
		Message       string                             `json:"message"`
		EvidenceKind  string                             `json:"evidenceKind"`
		MediaType     string                             `json:"mediaType"`
		Location      string                             `json:"location,omitempty"`
		PayloadBase64 string                             `json:"payloadBase64"`
	}
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(in.PayloadBase64))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_EVIDENCE_PAYLOAD", "payloadBase64 must be strict base64")
		return
	}
	trace, evidence, err := s.store.AppendOperationStepTrace(r.Context(), controlplane.OperationStepTraceInput{
		OperationID: op.ID, Phase: phase, StepKey: r.PathValue("stepKey"), TraceKey: in.TraceKey, Level: in.Level,
		EventType: in.EventType, Message: in.Message, EvidenceKind: in.EvidenceKind, MediaType: in.MediaType, Location: in.Location, Payload: payload,
	}, strings.TrimSpace(in.WorkerID), in.FenceToken, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"method": controlplane.OperationStepTraceMethod, "trace": trace, "evidence": evidence})
}

func (s *Server) getOperationEvidencePayload(w http.ResponseWriter, r *http.Request) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	evidence, payload, err := s.store.GetEvidencePayload(r.Context(), r.PathValue("evidenceId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if evidence.OperationID != op.ID {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "evidence is not attached to this operation")
		return
	}
	w.Header().Set("Content-Type", evidence.MediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.Header().Set("X-Evidence-Digest", evidence.Digest)
	w.Header().Set("X-Evidence-Kind", evidence.Kind)
	w.Header().Set("X-Operation-Step-Phase", string(evidence.Phase))
	w.Header().Set("X-Operation-Step-Key", evidence.StepKey)
	w.Header().Set("X-Operation-Step-Attempt", strconv.Itoa(evidence.Attempt))
	w.Header().Set("X-Operation-Step-Trace", evidence.TraceID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}
