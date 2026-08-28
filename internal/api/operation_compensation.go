package api

import (
	"net/http"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
)

func (s *Server) setOperationCompensationPlan(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in struct {
		Steps []controlplane.CompensationPlanStep `json:"steps"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	op, steps, err := s.store.SetOperationCompensationPlan(r.Context(), r.PathValue("id"), rev, in.Steps, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"operation": op, "method": controlplane.CompensationPlanMethod, "steps": steps})
}

func (s *Server) recordOperationForwardStepCompleted(w http.ResponseWriter, r *http.Request) {
	_, actor, rev, ok := s.operationForWrite(w, r)
	if !ok {
		return
	}
	var in operationWorkerInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	step, op, err := s.store.RecordOperationForwardStepCompleted(r.Context(), r.PathValue("id"), strings.TrimSpace(r.PathValue("stepKey")), rev, strings.TrimSpace(in.WorkerID), in.FenceToken, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, 200, map[string]any{"operation": op, "step": step})
}

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
	writeJSON(w, 200, op)
}

func (s *Server) claimNextOperationCompensationStep(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in operationWorkerInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	step, updated, err := s.store.ClaimNextOperationCompensationStep(r.Context(), op.ID, strings.TrimSpace(in.WorkerID), in.FenceToken, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, 200, map[string]any{"operation": updated, "step": step})
}

func (s *Server) completeOperationCompensationStep(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in struct {
		WorkerID       string `json:"workerId"`
		FenceToken     int64  `json:"fenceToken"`
		EvidenceDigest string `json:"evidenceDigest"`
	}
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	step, updated, err := s.store.CompleteOperationCompensationStep(r.Context(), op.ID, strings.TrimSpace(r.PathValue("stepKey")), strings.TrimSpace(in.WorkerID), in.FenceToken, strings.TrimSpace(in.EvidenceDigest), actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, 200, map[string]any{"operation": updated, "step": step})
}

func (s *Server) failOperationCompensationStep(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in struct {
		WorkerID   string                               `json:"workerId"`
		FenceToken int64                                `json:"fenceToken"`
		Failure    controlplane.CompensationStepFailure `json:"failure"`
	}
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	step, updated, err := s.store.ReportOperationCompensationStepFailure(r.Context(), op.ID, strings.TrimSpace(r.PathValue("stepKey")), strings.TrimSpace(in.WorkerID), in.FenceToken, in.Failure, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, 200, map[string]any{"operation": updated, "step": step})
}
