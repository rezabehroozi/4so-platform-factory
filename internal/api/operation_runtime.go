package api

import (
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

type operationWorkerInput struct {
	WorkerID     string `json:"workerId,omitempty"`
	FenceToken   int64  `json:"fenceToken"`
	LeaseSeconds int    `json:"leaseSeconds,omitempty"`
}

// operationForWrite is the human/operator mutation boundary. It is intentionally
// not used by raw execution-plane actions such as claim/attempt/trace/complete.
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
	var in struct {
		State     controlplane.OperationState `json:"state"`
		LastError string                      `json:"lastError,omitempty"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	_, worker, rev, ok := s.operationForExecution(w, r, "", true)
	if !ok {
		return
	}
	v, err := s.store.TransitionOperation(r.Context(), r.PathValue("id"), rev, in.State, strings.TrimSpace(in.LastError), worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) claimOperation(w http.ResponseWriter, r *http.Request) {
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	op, worker, _, ok := s.operationForExecution(w, r, in.WorkerID, false)
	if !ok {
		return
	}
	if in.LeaseSeconds <= 0 {
		in.LeaseSeconds = 60
	}
	if in.LeaseSeconds > 600 {
		writeError(w, http.StatusBadRequest, "LEASE_TOO_LONG", "leaseSeconds must be <= 600")
		return
	}
	claim, err := s.store.ClaimOperation(r.Context(), op.ID, worker, time.Duration(in.LeaseSeconds)*time.Second, time.Now().UTC())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (s *Server) renewOperationLease(w http.ResponseWriter, r *http.Request) {
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	op, worker, _, ok := s.operationForExecution(w, r, in.WorkerID, false)
	if !ok {
		return
	}
	if in.FenceToken <= 0 {
		writeError(w, http.StatusBadRequest, "FENCE_TOKEN_REQUIRED", "fenceToken must be positive")
		return
	}
	if in.LeaseSeconds <= 0 {
		in.LeaseSeconds = 60
	}
	if in.LeaseSeconds > 600 {
		writeError(w, http.StatusBadRequest, "LEASE_TOO_LONG", "leaseSeconds must be <= 600")
		return
	}
	claim, err := s.store.RenewOperationLease(r.Context(), op.ID, worker, in.FenceToken, time.Duration(in.LeaseSeconds)*time.Second, time.Now().UTC())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (s *Server) startOperationAttempt(w http.ResponseWriter, r *http.Request) {
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	_, worker, rev, ok := s.operationForExecution(w, r, in.WorkerID, true)
	if !ok {
		return
	}
	v, err := s.store.StartOperationAttempt(r.Context(), r.PathValue("id"), rev, worker, in.FenceToken, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) beginOperationVerification(w http.ResponseWriter, r *http.Request) {
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	_, worker, rev, ok := s.operationForExecution(w, r, in.WorkerID, true)
	if !ok {
		return
	}
	v, err := s.store.BeginOperationVerification(r.Context(), r.PathValue("id"), rev, worker, in.FenceToken, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) reportOperationFailure(w http.ResponseWriter, r *http.Request) {
	var in struct {
		WorkerID   string                              `json:"workerId,omitempty"`
		FenceToken int64                               `json:"fenceToken"`
		Failure    controlplane.OperationFailureReport `json:"failure"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	_, worker, rev, ok := s.operationForExecution(w, r, in.WorkerID, true)
	if !ok {
		return
	}
	v, err := s.store.ReportOperationFailure(r.Context(), r.PathValue("id"), rev, worker, in.FenceToken, in.Failure, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) completeOperation(w http.ResponseWriter, r *http.Request) {
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	_, worker, rev, ok := s.operationForExecution(w, r, in.WorkerID, true)
	if !ok {
		return
	}
	v, err := s.store.CompleteOperation(r.Context(), r.PathValue("id"), rev, worker, in.FenceToken, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
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
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	v, err := s.store.RequestOperationCancellation(r.Context(), r.PathValue("id"), rev, actor, in.Reason)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) acknowledgeOperationCancellation(w http.ResponseWriter, r *http.Request) {
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	_, worker, rev, ok := s.operationForExecution(w, r, in.WorkerID, true)
	if !ok {
		return
	}
	v, err := s.store.AcknowledgeOperationCancellation(r.Context(), r.PathValue("id"), rev, worker, in.FenceToken, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
