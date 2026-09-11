package persistence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"sort"
	"strings"
)

func (s *PostgresStore) SetOperationCompensationPlan(ctx context.Context, id string, expected int64, plan []controlplane.CompensationPlanStep, actor string) (controlplane.Operation, []controlplane.OperationCompensationStep, error) {
	normalized, err := controlplane.NormalizeCompensationPlan(plan)
	if err != nil {
		return controlplane.Operation{}, nil, err
	}
	var out controlplane.Operation
	var rows []controlplane.OperationCompensationStep
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		attemptRows := make([]controlplane.OperationCompensationStep, 0, len(normalized))
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if op.State != controlplane.OperationPlanning {
			return fmt.Errorf("%w: compensation plan is immutable after PLANNING", controlplane.ErrPrerequisite)
		}
		if op.Class == controlplane.OperationClassReadOnly {
			return fmt.Errorf("%w: read-only operations do not accept compensation plans", controlplane.ErrValidation)
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM operation_compensation_steps WHERE operation_id=$1`, id); err != nil {
			return err
		}
		now := utcNow(s.now)
		for _, in := range normalized {
			step := controlplane.OperationCompensationStep{ResourceMeta: controlplane.ResourceMeta{ID: s.id("cmp"), Revision: 1, CreatedAt: now, UpdatedAt: now}, OperationID: id, StepKey: in.StepKey, ForwardOrder: in.ForwardOrder, Strategy: in.Strategy, Action: in.Action, InputDigest: in.InputDigest, MaxAttempts: in.MaxAttempts, State: controlplane.CompensationStepPending}
			if _, err = tx.ExecContext(ctx, `INSERT INTO operation_compensation_steps(id,operation_id,revision,step_key,forward_order,strategy,action,input_digest,max_attempts,forward_completed,state,attempt,fence_token,evidence_digest,last_error,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,false,$9,0,0,'','',$10,$10)`, step.ID, id, step.StepKey, step.ForwardOrder, string(step.Strategy), step.Action, step.InputDigest, step.MaxAttempts, string(step.State), now); err != nil {
				return mapDBError(err)
			}
			attemptRows = append(attemptRows, step)
		}
		op.CompensationPlanDigest = controlplane.CompensationPlanDigest(normalized)
		op.CompensationStepCount = len(attemptRows)
		op.CompensationCursor = 0
		op.CompensationStartedAt = nil
		op.CompensationFinishedAt = nil
		op.CompensationFailureStep = ""
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,compensation_plan_digest=$3,compensation_step_count=$4,compensation_cursor=0,compensation_started_at=NULL,compensation_finished_at=NULL,compensation_failure_step='',updated_at=$5 WHERE id=$1`, id, op.Revision, op.CompensationPlanDigest, op.CompensationStepCount, now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.compensation_plan_bound", "operation", id, op.Revision, "", map[string]any{"method": controlplane.CompensationPlanMethod, "digest": op.CompensationPlanDigest, "steps": len(attemptRows)}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.compensation_plan_bound", op); err != nil {
			return err
		}
		out = op
		rows = attemptRows
		return nil
	})
	return out, rows, err
}

func (s *PostgresStore) ListOperationCompensationSteps(ctx context.Context, operationID string) ([]controlplane.OperationCompensationStep, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+compensationStepColumns+` FROM operation_compensation_steps WHERE operation_id=$1 ORDER BY forward_order,id`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []controlplane.OperationCompensationStep
	for rows.Next() {
		v, err := scanCompensationStep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RecordOperationForwardStepCompleted(ctx context.Context, id, stepKey string, expected int64, worker string, fence int64, actor string) (controlplane.OperationCompensationStep, controlplane.Operation, error) {
	var outStep controlplane.OperationCompensationStep
	var outOp controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if op.State != controlplane.OperationRunning && op.State != controlplane.OperationVerifying {
			return controlplane.ErrInvalidTransition
		}
		if !controlplane.OperationLeaseActive(op, worker, fence, utcNow(s.now)) {
			return controlplane.ErrStaleFence
		}
		if op.CompensationPlanDigest == "" {
			return fmt.Errorf("%w: operation has no bound compensation plan", controlplane.ErrPrerequisite)
		}
		step, err := scanCompensationStep(tx.QueryRowContext(ctx, `SELECT `+compensationStepColumns+` FROM operation_compensation_steps WHERE operation_id=$1 AND step_key=$2 FOR UPDATE`, id, strings.TrimSpace(stepKey)))
		if err != nil {
			return mapDBError(err)
		}
		if step.ForwardCompleted {
			outStep, outOp = step, op
			return nil
		}
		var incomplete int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM operation_compensation_steps WHERE operation_id=$1 AND forward_order < $2 AND forward_completed=false`, id, step.ForwardOrder).Scan(&incomplete); err != nil {
			return err
		}
		if incomplete > 0 {
			return fmt.Errorf("%w: forward steps must complete in plan order", controlplane.ErrPrerequisite)
		}
		now := utcNow(s.now)
		step.ForwardCompleted = true
		step.ForwardCompletedAt = &now
		step.Revision++
		step.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operation_compensation_steps SET revision=$3,forward_completed=true,forward_completed_at=$4,updated_at=$4 WHERE operation_id=$1 AND step_key=$2`, id, step.StepKey, step.Revision, now); err != nil {
			return err
		}
		op.CompensationCursor = step.ForwardOrder
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,compensation_cursor=$3,updated_at=$4 WHERE id=$1`, id, op.Revision, op.CompensationCursor, now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.forward_step_completed", "operationCompensationStep", step.ID, step.Revision, "", map[string]any{"operationId": id, "stepKey": step.StepKey, "forwardOrder": step.ForwardOrder}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operationCompensationStep", step.ID, "operation.forward_step_completed", step); err != nil {
			return err
		}
		outStep, outOp = step, op
		return nil
	})
	return outStep, outOp, err
}

func (s *PostgresStore) BeginOperationCompensation(ctx context.Context, id string, expected int64, actor string) (controlplane.Operation, error) {
	var out controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if op.State != controlplane.OperationFailed && op.State != controlplane.OperationCancelRequested {
			return controlplane.ErrInvalidTransition
		}
		if op.CompensationPlanDigest == "" || op.CompensationStepCount == 0 {
			return fmt.Errorf("%w: operation has no compensation plan", controlplane.ErrPrerequisite)
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM operation_compensation_steps WHERE operation_id=$1 AND forward_completed=true AND strategy <> 'NONE'`, id).Scan(&count); err != nil {
			return err
		}
		now := utcNow(s.now)
		op.CompensationStartedAt = &now
		op.CompensationFinishedAt = nil
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
		if count == 0 {
			op.State = controlplane.OperationRolledBack
			op.CompensationFinishedAt = &now
		} else {
			op.State = controlplane.OperationRollingBack
		}
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,compensation_started_at=$4,compensation_finished_at=$5,lease_owner=NULL,lease_expires_at=NULL,updated_at=$4 WHERE id=$1`, id, op.Revision, string(op.State), now, op.CompensationFinishedAt); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.compensation_started", "operation", id, op.Revision, "", map[string]any{"state": op.State, "planDigest": op.CompensationPlanDigest}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.compensation_started", op); err != nil {
			return err
		}
		out = op
		return nil
	})
	return out, err
}

func (s *PostgresStore) ClaimNextOperationCompensationStep(ctx context.Context, id, worker string, fence int64, actor string) (controlplane.OperationCompensationStep, controlplane.Operation, error) {
	var outStep controlplane.OperationCompensationStep
	var outOp controlplane.Operation
	var postErr error
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		postErr = nil
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.State != controlplane.OperationRollingBack {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		if !controlplane.OperationLeaseActive(op, worker, fence, now) {
			return controlplane.ErrStaleFence
		}
		step, err := scanCompensationStep(tx.QueryRowContext(ctx, `SELECT `+compensationStepColumns+` FROM operation_compensation_steps WHERE operation_id=$1 AND forward_completed=true AND strategy <> 'NONE' AND state='PENDING' ORDER BY forward_order DESC LIMIT 1 FOR UPDATE`, id))
		if errors.Is(err, sql.ErrNoRows) {
			var remaining int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM operation_compensation_steps WHERE operation_id=$1 AND forward_completed=true AND strategy <> 'NONE' AND state NOT IN ('SUCCEEDED','SKIPPED')`, id).Scan(&remaining); err != nil {
				return err
			}
			if remaining == 0 {
				op.State = controlplane.OperationRolledBack
				op.CompensationFinishedAt = &now
				op.LeaseOwner = ""
				op.LeaseExpiresAt = nil
				op.Revision++
				op.UpdatedAt = now
				if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,compensation_finished_at=$4,lease_owner=NULL,lease_expires_at=NULL,updated_at=$4 WHERE id=$1`, id, op.Revision, string(op.State), now); err != nil {
					return err
				}
				if err = s.appendAuditTx(ctx, tx, actor, "operation.compensation_completed", "operation", id, op.Revision, "", map[string]any{"planDigest": op.CompensationPlanDigest}); err != nil {
					return err
				}
				if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.compensation_completed", op); err != nil {
					return err
				}
				outOp = op
				postErr = controlplane.ErrNotFound
				return nil
			}
			return controlplane.ErrNotClaimable
		}
		if err != nil {
			return mapDBError(err)
		}
		if step.Strategy == controlplane.CompensationManualRecovery || step.Strategy == controlplane.CompensationIrreversible {
			step.State = controlplane.CompensationStepManualRequired
			step.LastError = "automatic compensation is not available for strategy " + string(step.Strategy)
			step.FinishedAt = &now
			step.Revision++
			step.UpdatedAt = now
			if _, err = tx.ExecContext(ctx, `UPDATE operation_compensation_steps SET revision=$3,state=$4,last_error=$5,finished_at=$6,updated_at=$6 WHERE operation_id=$1 AND step_key=$2`, id, step.StepKey, step.Revision, string(step.State), step.LastError, now); err != nil {
				return err
			}
			op.State = controlplane.OperationNeedsOperator
			op.CompensationFailureStep = step.StepKey
			op.LeaseOwner = ""
			op.LeaseExpiresAt = nil
			op.Revision++
			op.UpdatedAt = now
			if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,compensation_failure_step=$4,lease_owner=NULL,lease_expires_at=NULL,updated_at=$5 WHERE id=$1`, id, op.Revision, string(op.State), step.StepKey, now); err != nil {
				return err
			}
			if err = s.appendAuditTx(ctx, tx, actor, "operation.compensation_needs_operator", "operation", id, op.Revision, "", map[string]any{"stepKey": step.StepKey, "strategy": step.Strategy}); err != nil {
				return err
			}
			if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.compensation_needs_operator", op); err != nil {
				return err
			}
			outStep, outOp = step, op
			postErr = fmt.Errorf("%w: compensation step requires operator recovery", controlplane.ErrPrerequisite)
			return nil
		}
		if step.Attempt >= step.MaxAttempts {
			return fmt.Errorf("%w: compensation retry budget exhausted", controlplane.ErrPrerequisite)
		}
		step.State = controlplane.CompensationStepRunning
		step.Attempt++
		step.FenceToken = fence
		step.StartedAt = &now
		step.FinishedAt = nil
		step.LastError = ""
		step.Revision++
		step.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operation_compensation_steps SET revision=$3,state=$4,attempt=$5,fence_token=$6,started_at=$7,finished_at=NULL,last_error='',updated_at=$7 WHERE operation_id=$1 AND step_key=$2`, id, step.StepKey, step.Revision, string(step.State), step.Attempt, fence, now); err != nil {
			return err
		}
		op.CompensationCursor = step.ForwardOrder
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,compensation_cursor=$3,updated_at=$4 WHERE id=$1`, id, op.Revision, op.CompensationCursor, now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.compensation_step_started", "operationCompensationStep", step.ID, step.Revision, "", map[string]any{"operationId": id, "stepKey": step.StepKey, "attempt": step.Attempt, "forwardOrder": step.ForwardOrder}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operationCompensationStep", step.ID, "operation.compensation_step_started", step); err != nil {
			return err
		}
		outStep, outOp = step, op
		return nil
	})
	if err != nil {
		return outStep, outOp, err
	}
	return outStep, outOp, postErr
}

func (s *PostgresStore) CompleteOperationCompensationStep(ctx context.Context, id, stepKey, worker string, fence int64, evidenceDigest, actor string) (controlplane.OperationCompensationStep, controlplane.Operation, error) {
	evidenceDigest = strings.TrimSpace(evidenceDigest)
	if !strings.HasPrefix(evidenceDigest, "sha256:") || len(evidenceDigest) != 71 {
		return controlplane.OperationCompensationStep{}, controlplane.Operation{}, fmt.Errorf("%w: compensation evidence digest is required", controlplane.ErrValidation)
	}
	var outStep controlplane.OperationCompensationStep
	var outOp controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.State != controlplane.OperationRollingBack || !controlplane.OperationLeaseActive(op, worker, fence, utcNow(s.now)) {
			return controlplane.ErrStaleFence
		}
		step, err := scanCompensationStep(tx.QueryRowContext(ctx, `SELECT `+compensationStepColumns+` FROM operation_compensation_steps WHERE operation_id=$1 AND step_key=$2 FOR UPDATE`, id, strings.TrimSpace(stepKey)))
		if err != nil {
			return mapDBError(err)
		}
		if step.State != controlplane.CompensationStepRunning || step.FenceToken != fence {
			return controlplane.ErrInvalidTransition
		}
		var sealedPayload []byte
		var sealedDigest string
		var sealedSize int64
		err = tx.QueryRowContext(ctx, `SELECT p.payload,p.digest,p.size_bytes FROM evidence_metadata e JOIN operation_evidence_payloads p ON p.evidence_id=e.id WHERE e.operation_id=$1 AND e.step_phase='COMPENSATION' AND e.step_key=$2 AND e.attempt=$3 AND e.digest=$4 AND e.sealed=true AND e.has_payload=true`, id, step.StepKey, step.Attempt, evidenceDigest).Scan(&sealedPayload, &sealedDigest, &sealedSize)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: compensation evidence must be sealed by the step trace authority for the same step and attempt", controlplane.ErrPrerequisite)
		}
		if err != nil {
			return err
		}
		if sealedDigest != evidenceDigest || sealedSize != int64(len(sealedPayload)) || tracePayloadDigest(sealedPayload) != evidenceDigest {
			return fmt.Errorf("%w: compensation evidence payload integrity mismatch", controlplane.ErrConflict)
		}
		now := utcNow(s.now)
		step.State = controlplane.CompensationStepSucceeded
		step.EvidenceDigest = evidenceDigest
		step.FinishedAt = &now
		step.LastError = ""
		step.Revision++
		step.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operation_compensation_steps SET revision=$3,state=$4,evidence_digest=$5,finished_at=$6,last_error='',updated_at=$6 WHERE operation_id=$1 AND step_key=$2`, id, step.StepKey, step.Revision, string(step.State), evidenceDigest, now); err != nil {
			return err
		}
		var remaining int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM operation_compensation_steps WHERE operation_id=$1 AND forward_completed=true AND strategy <> 'NONE' AND state NOT IN ('SUCCEEDED','SKIPPED')`, id).Scan(&remaining); err != nil {
			return err
		}
		if remaining == 0 {
			op.State = controlplane.OperationRolledBack
			op.CompensationFinishedAt = &now
			op.LeaseOwner = ""
			op.LeaseExpiresAt = nil
		}
		op.CompensationFailureStep = ""
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,compensation_finished_at=$4,compensation_failure_step='',lease_owner=NULLIF($5,''),lease_expires_at=$6,updated_at=$7 WHERE id=$1`, id, op.Revision, string(op.State), op.CompensationFinishedAt, op.LeaseOwner, op.LeaseExpiresAt, now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.compensation_step_succeeded", "operationCompensationStep", step.ID, step.Revision, "", map[string]any{"operationId": id, "stepKey": step.StepKey, "evidenceDigest": evidenceDigest}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operationCompensationStep", step.ID, "operation.compensation_step_succeeded", step); err != nil {
			return err
		}
		if op.State == controlplane.OperationRolledBack {
			if err = s.appendAuditTx(ctx, tx, actor, "operation.compensation_completed", "operation", id, op.Revision, "", map[string]any{"planDigest": op.CompensationPlanDigest}); err != nil {
				return err
			}
			if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.compensation_completed", op); err != nil {
				return err
			}
		}
		outStep, outOp = step, op
		return nil
	})
	return outStep, outOp, err
}

func (s *PostgresStore) ReportOperationCompensationStepFailure(ctx context.Context, id, stepKey, worker string, fence int64, failure controlplane.CompensationStepFailure, actor string) (controlplane.OperationCompensationStep, controlplane.Operation, error) {
	failure.Message = strings.TrimSpace(failure.Message)
	if failure.Message == "" {
		return controlplane.OperationCompensationStep{}, controlplane.Operation{}, fmt.Errorf("%w: compensation failure message is required", controlplane.ErrValidation)
	}
	var outStep controlplane.OperationCompensationStep
	var outOp controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.State != controlplane.OperationRollingBack || !controlplane.OperationLeaseActive(op, worker, fence, utcNow(s.now)) {
			return controlplane.ErrStaleFence
		}
		step, err := scanCompensationStep(tx.QueryRowContext(ctx, `SELECT `+compensationStepColumns+` FROM operation_compensation_steps WHERE operation_id=$1 AND step_key=$2 FOR UPDATE`, id, strings.TrimSpace(stepKey)))
		if err != nil {
			return mapDBError(err)
		}
		if step.State != controlplane.CompensationStepRunning || step.FenceToken != fence {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		step.LastError = failure.Message
		step.FinishedAt = &now
		if failure.Retryable && step.Attempt < step.MaxAttempts {
			step.State = controlplane.CompensationStepPending
			step.FenceToken = 0
		} else {
			step.State = controlplane.CompensationStepFailed
			op.State = controlplane.OperationRollbackFailed
			op.CompensationFailureStep = step.StepKey
			op.LeaseOwner = ""
			op.LeaseExpiresAt = nil
		}
		step.Revision++
		step.UpdatedAt = now
		op.LastError = failure.Message
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operation_compensation_steps SET revision=$3,state=$4,fence_token=$5,finished_at=$6,last_error=$7,updated_at=$6 WHERE operation_id=$1 AND step_key=$2`, id, step.StepKey, step.Revision, string(step.State), step.FenceToken, now, step.LastError); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,compensation_failure_step=$4,lease_owner=NULLIF($5,''),lease_expires_at=$6,last_error=$7,updated_at=$8 WHERE id=$1`, id, op.Revision, string(op.State), op.CompensationFailureStep, op.LeaseOwner, op.LeaseExpiresAt, op.LastError, now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.compensation_step_failed", "operationCompensationStep", step.ID, step.Revision, "", map[string]any{"operationId": id, "stepKey": step.StepKey, "attempt": step.Attempt, "retryable": failure.Retryable, "state": step.State}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operationCompensationStep", step.ID, "operation.compensation_step_failed", step); err != nil {
			return err
		}
		outStep, outOp = step, op
		return nil
	})
	return outStep, outOp, err
}

// Compile-time guard for deterministic ordering helpers used by SQL and memory adapters.
var _ = sort.Slice
