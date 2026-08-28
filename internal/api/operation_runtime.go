package api

import (
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
	"time"
)

type operationWorkerInput struct {
	WorkerID     string `json:"workerId"`
	FenceToken   int64  `json:"fenceToken"`
	LeaseSeconds int    `json:"leaseSeconds,omitempty"`
}

func (s *Server) operationForWrite(w http.ResponseWriter, r *http.Request) (controlplane.Operation, string, int64, bool) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return controlplane.Operation{}, "", 0, false
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return controlplane.Operation{}, "", 0, false
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return controlplane.Operation{}, "", 0, false
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return controlplane.Operation{}, "", 0, false
	}
	return op, actor, rev, true
}

func (s *Server) transitionOperation(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in struct {
		State     controlplane.OperationState `json:"state"`
		LastError string                      `json:"lastError,omitempty"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.TransitionOperation(r.Context(), r.PathValue("id"), rev, in.State, strings.TrimSpace(in.LastError), actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) claimOperation(w http.ResponseWriter, r *http.Request) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	var in operationWorkerInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.WorkerID = strings.TrimSpace(in.WorkerID)
	if in.LeaseSeconds <= 0 {
		in.LeaseSeconds = 60
	}
	if in.LeaseSeconds > 600 {
		writeError(w, http.StatusBadRequest, "LEASE_TOO_LONG", "leaseSeconds must be <= 600")
		return
	}
	claim, err := s.store.ClaimOperation(r.Context(), op.ID, in.WorkerID, time.Duration(in.LeaseSeconds)*time.Second, time.Now().UTC())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (s *Server) startOperationAttempt(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.StartOperationAttempt(r.Context(), r.PathValue("id"), rev, strings.TrimSpace(in.WorkerID), in.FenceToken, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) beginOperationVerification(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.BeginOperationVerification(r.Context(), r.PathValue("id"), rev, strings.TrimSpace(in.WorkerID), in.FenceToken, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) reportOperationFailure(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in struct {
		WorkerID   string                              `json:"workerId"`
		FenceToken int64                               `json:"fenceToken"`
		Failure    controlplane.OperationFailureReport `json:"failure"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.ReportOperationFailure(r.Context(), r.PathValue("id"), rev, strings.TrimSpace(in.WorkerID), in.FenceToken, in.Failure, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) completeOperation(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.CompleteOperation(r.Context(), r.PathValue("id"), rev, strings.TrimSpace(in.WorkerID), in.FenceToken, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) cancelOperation(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.RequestOperationCancellation(r.Context(), r.PathValue("id"), rev, actor, in.Reason)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) acknowledgeOperationCancellation(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.AcknowledgeOperationCancellation(r.Context(), r.PathValue("id"), rev, strings.TrimSpace(in.WorkerID), in.FenceToken, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
