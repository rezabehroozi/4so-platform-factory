package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) setOperationCompensationPlan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Steps []controlplane.CompensationPlanStep `json:"steps"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	_, worker, rev, ok := s.operationForExecution(w, r, "", true)
	if !ok {
		return
	}
	op, steps, err := s.store.SetOperationCompensationPlan(r.Context(), r.PathValue("id"), rev, in.Steps, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"operation": op, "method": controlplane.CompensationPlanMethod, "steps": steps})
}

func (s *Server) recordOperationForwardStepCompleted(w http.ResponseWriter, r *http.Request) {
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	_, worker, rev, ok := s.operationForExecution(w, r, in.WorkerID, true)
	if !ok {
		return
	}
	step, op, err := s.store.RecordOperationForwardStepCompleted(r.Context(), r.PathValue("id"), strings.TrimSpace(r.PathValue("stepKey")), rev, worker, in.FenceToken, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"operation": op, "step": step})
}

// beginOperationCompensation is an operator recovery intent, not an executor
// progress report. The immutable plan must already exist; execution of its
// steps is protected by operation.execute below.
func (s *Server) beginOperationCompensation(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	op, err := s.store.BeginOperationCompensation(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusOK, op)
}

func (s *Server) claimNextOperationCompensationStep(w http.ResponseWriter, r *http.Request) {
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	op, worker, _, ok := s.operationForExecution(w, r, in.WorkerID, false)
	if !ok {
		return
	}
	step, updated, err := s.store.ClaimNextOperationCompensationStep(r.Context(), op.ID, worker, in.FenceToken, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"operation": updated, "step": step})
}

func (s *Server) completeOperationCompensationStep(w http.ResponseWriter, r *http.Request) {
	var in struct {
		WorkerID       string `json:"workerId,omitempty"`
		FenceToken     int64  `json:"fenceToken"`
		EvidenceDigest string `json:"evidenceDigest"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	op, worker, _, ok := s.operationForExecution(w, r, in.WorkerID, false)
	if !ok {
		return
	}
	step, updated, err := s.store.CompleteOperationCompensationStep(r.Context(), op.ID, strings.TrimSpace(r.PathValue("stepKey")), worker, in.FenceToken, strings.TrimSpace(in.EvidenceDigest), worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"operation": updated, "step": step})
}

func (s *Server) failOperationCompensationStep(w http.ResponseWriter, r *http.Request) {
	var in struct {
		WorkerID   string                               `json:"workerId,omitempty"`
		FenceToken int64                                `json:"fenceToken"`
		Failure    controlplane.CompensationStepFailure `json:"failure"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	op, worker, _, ok := s.operationForExecution(w, r, in.WorkerID, false)
	if !ok {
		return
	}
	step, updated, err := s.store.ReportOperationCompensationStepFailure(r.Context(), op.ID, strings.TrimSpace(r.PathValue("stepKey")), worker, in.FenceToken, in.Failure, worker)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"operation": updated, "step": step})
}
