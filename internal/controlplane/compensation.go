package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const CompensationPlanMethod = "GENERIC_COMPENSATION_ORCHESTRATION_V1"

func validCompensationStrategy(v CompensationStrategy) bool {
	switch v {
	case CompensationNone, CompensationAutomaticRollback, CompensationRestorePreviousRevision, CompensationPreserveDataRestoreController, CompensationProviderRecovery, CompensationManualRecovery, CompensationIrreversible:
		return true
	default:
		return false
	}
}

func normalizedCompensationPlan(steps []CompensationPlanStep) ([]CompensationPlanStep, error) {
	if len(steps) == 0 {
		return nil, fmt.Errorf("%w: at least one compensation plan step is required", ErrValidation)
	}
	out := append([]CompensationPlanStep(nil), steps...)
	sort.Slice(out, func(i, j int) bool { return out[i].ForwardOrder < out[j].ForwardOrder })
	seen := map[string]bool{}
	for i := range out {
		out[i].StepKey = strings.TrimSpace(out[i].StepKey)
		out[i].Action = strings.TrimSpace(out[i].Action)
		out[i].InputDigest = strings.TrimSpace(out[i].InputDigest)
		if out[i].StepKey == "" || seen[out[i].StepKey] {
			return nil, fmt.Errorf("%w: compensation stepKey must be non-empty and unique", ErrValidation)
		}
		seen[out[i].StepKey] = true
		if out[i].ForwardOrder != i+1 {
			return nil, fmt.Errorf("%w: compensation forwardOrder must be contiguous starting at 1", ErrValidation)
		}
		if !validCompensationStrategy(out[i].Strategy) {
			return nil, fmt.Errorf("%w: unsupported compensation strategy %q", ErrValidation, out[i].Strategy)
		}
		if out[i].Strategy != CompensationNone && out[i].Action == "" {
			return nil, fmt.Errorf("%w: compensation action is required for %s", ErrValidation, out[i].StepKey)
		}
		if !strings.HasPrefix(out[i].InputDigest, "sha256:") || len(out[i].InputDigest) != 71 {
			return nil, fmt.Errorf("%w: compensation inputDigest must be sha256:<64 hex>", ErrValidation)
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(out[i].InputDigest, "sha256:")); err != nil {
			return nil, fmt.Errorf("%w: invalid compensation inputDigest", ErrValidation)
		}
		if out[i].MaxAttempts == 0 {
			out[i].MaxAttempts = 3
		}
		if out[i].MaxAttempts < 1 || out[i].MaxAttempts > 10 {
			return nil, fmt.Errorf("%w: compensation maxAttempts must be between 1 and 10", ErrValidation)
		}
	}
	return out, nil
}

func compensationPlanDigest(steps []CompensationPlanStep) string {
	raw, _ := json.Marshal(struct {
		Method string                 `json:"method"`
		Steps  []CompensationPlanStep `json:"steps"`
	}{Method: CompensationPlanMethod, Steps: steps})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *MemoryStore) SetOperationCompensationPlan(_ context.Context, id string, expected int64, plan []CompensationPlanStep, actor string) (Operation, []OperationCompensationStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, nil, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, nil, ErrConflict
	}
	if op.State != OperationPlanning {
		return Operation{}, nil, fmt.Errorf("%w: compensation plan is immutable after PLANNING", ErrPrerequisite)
	}
	if op.Class == OperationClassReadOnly {
		return Operation{}, nil, fmt.Errorf("%w: read-only operations do not accept compensation plans", ErrValidation)
	}
	normalized, err := normalizedCompensationPlan(plan)
	if err != nil {
		return Operation{}, nil, err
	}
	for key, step := range s.compensationSteps {
		if step.OperationID == id {
			delete(s.compensationSteps, key)
		}
	}
	now := nowUTC(s.now)
	rows := make([]OperationCompensationStep, 0, len(normalized))
	for _, in := range normalized {
		step := OperationCompensationStep{
			ResourceMeta: ResourceMeta{ID: s.id("cmp"), Revision: 1, CreatedAt: now, UpdatedAt: now},
			OperationID:  id, StepKey: in.StepKey, ForwardOrder: in.ForwardOrder, Strategy: in.Strategy, Action: in.Action,
			InputDigest: in.InputDigest, MaxAttempts: in.MaxAttempts, State: CompensationStepPending,
		}
		s.compensationSteps[id+":"+step.StepKey] = step
		rows = append(rows, step)
	}
	op.CompensationPlanDigest = compensationPlanDigest(normalized)
	op.CompensationStepCount = len(rows)
	op.CompensationCursor = 0
	op.CompensationStartedAt = nil
	op.CompensationFinishedAt = nil
	op.CompensationFailureStep = ""
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.compensation_plan_bound", "operation", id, op.Revision, map[string]any{"method": CompensationPlanMethod, "digest": op.CompensationPlanDigest, "steps": len(rows)})
	s.appendOutboxLocked("operation", id, "operation.compensation_plan_bound", op)
	return op, rows, nil
}

func (s *MemoryStore) ListOperationCompensationSteps(_ context.Context, operationID string) ([]OperationCompensationStep, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []OperationCompensationStep{}
	for _, step := range s.compensationSteps {
		if step.OperationID == operationID {
			out = append(out, step)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ForwardOrder < out[j].ForwardOrder })
	return out, nil
}

func (s *MemoryStore) RecordOperationForwardStepCompleted(_ context.Context, id, stepKey string, expected int64, worker string, fence int64, actor string) (OperationCompensationStep, Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return OperationCompensationStep{}, Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return OperationCompensationStep{}, Operation{}, ErrConflict
	}
	if op.State != OperationRunning && op.State != OperationVerifying {
		return OperationCompensationStep{}, Operation{}, ErrInvalidTransition
	}
	if !OperationLeaseActive(op, worker, fence, nowUTC(s.now)) {
		return OperationCompensationStep{}, Operation{}, ErrStaleFence
	}
	if op.CompensationPlanDigest == "" {
		return OperationCompensationStep{}, Operation{}, fmt.Errorf("%w: operation has no bound compensation plan", ErrPrerequisite)
	}
	key := id + ":" + strings.TrimSpace(stepKey)
	step, ok := s.compensationSteps[key]
	if !ok {
		return OperationCompensationStep{}, Operation{}, ErrNotFound
	}
	if step.ForwardCompleted {
		return step, op, nil
	}
	for _, candidate := range s.compensationSteps {
		if candidate.OperationID == id && candidate.ForwardOrder < step.ForwardOrder && !candidate.ForwardCompleted {
			return OperationCompensationStep{}, Operation{}, fmt.Errorf("%w: forward steps must complete in plan order", ErrPrerequisite)
		}
	}
	now := nowUTC(s.now)
	step.ForwardCompleted = true
	step.ForwardCompletedAt = &now
	step.Revision++
	step.UpdatedAt = now
	s.compensationSteps[key] = step
	op.CompensationCursor = step.ForwardOrder
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.forward_step_completed", "operationCompensationStep", step.ID, step.Revision, map[string]any{"operationId": id, "stepKey": step.StepKey, "forwardOrder": step.ForwardOrder})
	s.appendOutboxLocked("operationCompensationStep", step.ID, "operation.forward_step_completed", step)
	return step, op, nil
}

func (s *MemoryStore) hasCompensatableForwardLocked(operationID string) bool {
	for _, step := range s.compensationSteps {
		if step.OperationID == operationID && step.ForwardCompleted && step.Strategy != CompensationNone {
			return true
		}
	}
	return false
}

func (s *MemoryStore) BeginOperationCompensation(_ context.Context, id string, expected int64, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if op.State != OperationFailed && op.State != OperationCancelRequested {
		return Operation{}, ErrInvalidTransition
	}
	if op.CompensationPlanDigest == "" || op.CompensationStepCount == 0 {
		return Operation{}, fmt.Errorf("%w: operation has no compensation plan", ErrPrerequisite)
	}
	now := nowUTC(s.now)
	if !s.hasCompensatableForwardLocked(id) {
		op.State = OperationRolledBack
		op.CompensationStartedAt = &now
		op.CompensationFinishedAt = &now
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
	} else {
		op.State = OperationRollingBack
		op.CompensationStartedAt = &now
		op.CompensationFinishedAt = nil
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
	}
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.compensation_started", "operation", id, op.Revision, map[string]any{"state": op.State, "planDigest": op.CompensationPlanDigest})
	s.appendOutboxLocked("operation", id, "operation.compensation_started", op)
	return op, nil
}

func (s *MemoryStore) ClaimNextOperationCompensationStep(_ context.Context, id, worker string, fence int64, actor string) (OperationCompensationStep, Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return OperationCompensationStep{}, Operation{}, ErrNotFound
	}
	if op.State != OperationRollingBack {
		return OperationCompensationStep{}, Operation{}, ErrInvalidTransition
	}
	if op.LeaseOwner != worker || op.FenceToken != fence || op.LeaseExpiresAt == nil || !op.LeaseExpiresAt.After(nowUTC(s.now)) {
		return OperationCompensationStep{}, Operation{}, ErrStaleFence
	}
	var candidates []OperationCompensationStep
	for _, step := range s.compensationSteps {
		if step.OperationID == id && step.ForwardCompleted && step.Strategy != CompensationNone && step.State == CompensationStepPending {
			candidates = append(candidates, step)
		}
	}
	if len(candidates) == 0 {
		allDone := true
		for _, step := range s.compensationSteps {
			if step.OperationID == id && step.ForwardCompleted && step.Strategy != CompensationNone && step.State != CompensationStepSucceeded && step.State != CompensationStepSkipped {
				allDone = false
				break
			}
		}
		if allDone {
			now := nowUTC(s.now)
			op.State = OperationRolledBack
			op.CompensationFinishedAt = &now
			op.LeaseOwner = ""
			op.LeaseExpiresAt = nil
			op.Revision++
			op.UpdatedAt = now
			s.operations[id] = op
			s.appendAuditLocked(actor, "operation.compensation_completed", "operation", id, op.Revision, map[string]any{"planDigest": op.CompensationPlanDigest})
			s.appendOutboxLocked("operation", id, "operation.compensation_completed", op)
			return OperationCompensationStep{}, op, ErrNotFound
		}
		return OperationCompensationStep{}, op, ErrNotClaimable
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ForwardOrder > candidates[j].ForwardOrder })
	step := candidates[0]
	key := id + ":" + step.StepKey
	now := nowUTC(s.now)
	if step.Strategy == CompensationManualRecovery || step.Strategy == CompensationIrreversible {
		step.State = CompensationStepManualRequired
		step.LastError = "automatic compensation is not available for strategy " + string(step.Strategy)
		step.FinishedAt = &now
		step.Revision++
		step.UpdatedAt = now
		s.compensationSteps[key] = step
		op.State = OperationNeedsOperator
		op.CompensationFailureStep = step.StepKey
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
		op.Revision++
		op.UpdatedAt = now
		s.operations[id] = op
		s.appendAuditLocked(actor, "operation.compensation_needs_operator", "operation", id, op.Revision, map[string]any{"stepKey": step.StepKey, "strategy": step.Strategy})
		s.appendOutboxLocked("operation", id, "operation.compensation_needs_operator", op)
		return step, op, fmt.Errorf("%w: compensation step requires operator recovery", ErrPrerequisite)
	}
	if step.Attempt >= step.MaxAttempts {
		return OperationCompensationStep{}, op, fmt.Errorf("%w: compensation retry budget exhausted", ErrPrerequisite)
	}
	step.State = CompensationStepRunning
	step.Attempt++
	step.FenceToken = fence
	step.StartedAt = &now
	step.FinishedAt = nil
	step.LastError = ""
	step.Revision++
	step.UpdatedAt = now
	s.compensationSteps[key] = step
	op.CompensationCursor = step.ForwardOrder
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.compensation_step_started", "operationCompensationStep", step.ID, step.Revision, map[string]any{"operationId": id, "stepKey": step.StepKey, "attempt": step.Attempt, "forwardOrder": step.ForwardOrder})
	s.appendOutboxLocked("operationCompensationStep", step.ID, "operation.compensation_step_started", step)
	return step, op, nil
}

func (s *MemoryStore) CompleteOperationCompensationStep(_ context.Context, id, stepKey, worker string, fence int64, evidenceDigest, actor string) (OperationCompensationStep, Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return OperationCompensationStep{}, Operation{}, ErrNotFound
	}
	if op.State != OperationRollingBack || !OperationLeaseActive(op, worker, fence, nowUTC(s.now)) {
		return OperationCompensationStep{}, Operation{}, ErrStaleFence
	}
	key := id + ":" + strings.TrimSpace(stepKey)
	step, ok := s.compensationSteps[key]
	if !ok {
		return OperationCompensationStep{}, Operation{}, ErrNotFound
	}
	if step.State != CompensationStepRunning || step.FenceToken != fence {
		return OperationCompensationStep{}, Operation{}, ErrInvalidTransition
	}
	evidenceDigest = strings.TrimSpace(evidenceDigest)
	if !strings.HasPrefix(evidenceDigest, "sha256:") || len(evidenceDigest) != 71 {
		return OperationCompensationStep{}, Operation{}, fmt.Errorf("%w: compensation evidence digest is required", ErrValidation)
	}
	if !s.hasSealedStepEvidenceLocked(id, OperationStepPhaseCompensation, step.StepKey, step.Attempt, evidenceDigest) {
		return OperationCompensationStep{}, Operation{}, fmt.Errorf("%w: compensation evidence must be sealed by the step trace authority for the same step and attempt", ErrPrerequisite)
	}
	now := nowUTC(s.now)
	step.State = CompensationStepSucceeded
	step.EvidenceDigest = evidenceDigest
	step.FinishedAt = &now
	step.LastError = ""
	step.Revision++
	step.UpdatedAt = now
	s.compensationSteps[key] = step

	remaining := false
	for _, candidate := range s.compensationSteps {
		if candidate.OperationID == id && candidate.ForwardCompleted && candidate.Strategy != CompensationNone && candidate.State != CompensationStepSucceeded && candidate.State != CompensationStepSkipped {
			remaining = true
			break
		}
	}
	if !remaining {
		op.State = OperationRolledBack
		op.CompensationFinishedAt = &now
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
	}
	op.CompensationFailureStep = ""
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.compensation_step_succeeded", "operationCompensationStep", step.ID, step.Revision, map[string]any{"operationId": id, "stepKey": step.StepKey, "evidenceDigest": evidenceDigest})
	s.appendOutboxLocked("operationCompensationStep", step.ID, "operation.compensation_step_succeeded", step)
	if op.State == OperationRolledBack {
		s.appendAuditLocked(actor, "operation.compensation_completed", "operation", id, op.Revision, map[string]any{"planDigest": op.CompensationPlanDigest})
		s.appendOutboxLocked("operation", id, "operation.compensation_completed", op)
	}
	return step, op, nil
}

func (s *MemoryStore) ReportOperationCompensationStepFailure(_ context.Context, id, stepKey, worker string, fence int64, failure CompensationStepFailure, actor string) (OperationCompensationStep, Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return OperationCompensationStep{}, Operation{}, ErrNotFound
	}
	if op.State != OperationRollingBack || !OperationLeaseActive(op, worker, fence, nowUTC(s.now)) {
		return OperationCompensationStep{}, Operation{}, ErrStaleFence
	}
	key := id + ":" + strings.TrimSpace(stepKey)
	step, ok := s.compensationSteps[key]
	if !ok {
		return OperationCompensationStep{}, Operation{}, ErrNotFound
	}
	if step.State != CompensationStepRunning || step.FenceToken != fence {
		return OperationCompensationStep{}, Operation{}, ErrInvalidTransition
	}
	failure.Message = strings.TrimSpace(failure.Message)
	if failure.Message == "" {
		return OperationCompensationStep{}, Operation{}, fmt.Errorf("%w: compensation failure message is required", ErrValidation)
	}
	now := nowUTC(s.now)
	step.LastError = failure.Message
	step.FinishedAt = &now
	if failure.Retryable && step.Attempt < step.MaxAttempts {
		step.State = CompensationStepPending
		step.FenceToken = 0
	} else {
		step.State = CompensationStepFailed
		op.State = OperationRollbackFailed
		op.CompensationFailureStep = step.StepKey
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
	}
	step.Revision++
	step.UpdatedAt = now
	s.compensationSteps[key] = step
	op.LastError = failure.Message
	op.Revision++
	op.UpdatedAt = now
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.compensation_step_failed", "operationCompensationStep", step.ID, step.Revision, map[string]any{"operationId": id, "stepKey": step.StepKey, "attempt": step.Attempt, "retryable": failure.Retryable, "state": step.State})
	s.appendOutboxLocked("operationCompensationStep", step.ID, "operation.compensation_step_failed", step)
	return step, op, nil
}

// NormalizeCompensationPlan validates and canonicalizes a compensation plan for persistence adapters.
func NormalizeCompensationPlan(steps []CompensationPlanStep) ([]CompensationPlanStep, error) {
	return normalizedCompensationPlan(steps)
}

// CompensationPlanDigest returns the immutable digest of a canonical compensation plan.
func CompensationPlanDigest(steps []CompensationPlanStep) string {
	return compensationPlanDigest(steps)
}
