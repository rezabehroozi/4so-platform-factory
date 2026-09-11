package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *PostgresStore) bindDestructiveRecoveryTx(ctx context.Context, tx *sql.Tx, op *controlplane.Operation, now time.Time) error {
	if op.Class != controlplane.OperationClassDestructive {
		return nil
	}
	clusterID := controlplane.OperationTargetClusterID(op.TargetRef)
	if clusterID == "" {
		return fmt.Errorf("%w: destructive operations require a cluster:<id> target", controlplane.ErrPrerequisite)
	}
	if strings.TrimSpace(op.RecoveryCheckpointID) == "" {
		return fmt.Errorf("%w: destructive operation requires a verified recovery checkpoint", controlplane.ErrPrerequisite)
	}
	cp, err := scanRecoveryCheckpoint(tx.QueryRowContext(ctx, `SELECT `+recoveryCheckpointColumns+` FROM recovery_checkpoints WHERE id=$1 FOR SHARE`, op.RecoveryCheckpointID))
	if err != nil {
		return mapDBError(err)
	}
	if cp.ProjectID != op.ProjectID || cp.ClusterID != clusterID || cp.State != controlplane.RecoveryCheckpointVerified || !cp.ExpiresAt.After(now) {
		return fmt.Errorf("%w: recovery checkpoint is unavailable for the destructive target", controlplane.ErrPrerequisite)
	}
	cluster, err := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR SHARE`, clusterID))
	if err != nil {
		return mapDBError(err)
	}
	if cluster.ProjectID != op.ProjectID || strings.TrimSpace(cluster.InventoryDigest) == "" || cluster.InventoryDigest != cp.InventoryDigest {
		return fmt.Errorf("%w: recovery checkpoint is stale for current target inventory", controlplane.ErrPrerequisite)
	}
	if op.RecoveryEvidenceDigest != "" && op.RecoveryEvidenceDigest != cp.EvidenceDigest {
		return fmt.Errorf("%w: recovery evidence changed after operation creation", controlplane.ErrPrerequisite)
	}
	if op.RecoveryInventoryDigest != "" && op.RecoveryInventoryDigest != cp.InventoryDigest {
		return fmt.Errorf("%w: recovery inventory binding changed after operation creation", controlplane.ErrPrerequisite)
	}
	op.RecoveryEvidenceDigest = cp.EvidenceDigest
	op.RecoveryInventoryDigest = cp.InventoryDigest
	return nil
}

func (s *PostgresStore) StartOperationAttempt(ctx context.Context, id string, expected int64, worker string, fence int64, actor string) (controlplane.Operation, error) {
	var out controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if op.State != controlplane.OperationQueued {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		if !controlplane.OperationLeaseActive(op, worker, fence, now) {
			return controlplane.ErrStaleFence
		}
		if err := s.bindDestructiveRecoveryTx(ctx, tx, &op, now); err != nil {
			return err
		}
		if op.Attempt >= op.RetryPolicy.MaxAttempts {
			return fmt.Errorf("%w: operation retry budget exhausted", controlplane.ErrPrerequisite)
		}
		op.Attempt++
		op.State = controlplane.OperationRunning
		op.NextAttemptAt = nil
		op.LastFailureClass = ""
		op.RetryExhausted = false
		op.Revision++
		op.UpdatedAt = now
		_, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,attempt=$4,next_attempt_at=NULL,last_failure_class='',retry_exhausted=false,recovery_evidence_digest=$5,recovery_inventory_digest=$6,updated_at=$7 WHERE id=$1`, id, op.Revision, string(op.State), op.Attempt, op.RecoveryEvidenceDigest, op.RecoveryInventoryDigest, now)
		if err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.attempt_started", "operation", id, op.Revision, "", map[string]any{"attempt": op.Attempt, "maxAttempts": op.RetryPolicy.MaxAttempts, "class": op.Class, "fenceToken": fence}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.attempt_started", op); err != nil {
			return err
		}
		out = op
		return nil
	})
	return out, err
}

func (s *PostgresStore) BeginOperationVerification(ctx context.Context, id string, expected int64, worker string, fence int64, actor string) (controlplane.Operation, error) {
	var out controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if op.State != controlplane.OperationRunning {
			return controlplane.ErrInvalidTransition
		}
		if !controlplane.OperationLeaseActive(op, worker, fence, utcNow(s.now)) {
			return controlplane.ErrStaleFence
		}
		now := utcNow(s.now)
		op.State = controlplane.OperationVerifying
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,updated_at=$4 WHERE id=$1`, id, op.Revision, string(op.State), now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.verification_started", "operation", id, op.Revision, "", map[string]any{"attempt": op.Attempt}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.verification_started", op); err != nil {
			return err
		}
		out = op
		return nil
	})
	return out, err
}

func (s *PostgresStore) ReportOperationFailure(ctx context.Context, id string, expected int64, worker string, fence int64, report controlplane.OperationFailureReport, actor string) (controlplane.Operation, error) {
	if !controlplane.ValidOperationFailureClass(report.Class) || strings.TrimSpace(report.Message) == "" || report.RetryAfterSeconds < 0 {
		return controlplane.Operation{}, fmt.Errorf("%w: failure class and message are required", controlplane.ErrValidation)
	}
	var out controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if op.State != controlplane.OperationRunning && op.State != controlplane.OperationVerifying && op.State != controlplane.OperationRollingBack {
			return controlplane.ErrInvalidTransition
		}
		if !controlplane.OperationLeaseActive(op, worker, fence, utcNow(s.now)) {
			return controlplane.ErrStaleFence
		}
		now := utcNow(s.now)
		op.LastError = strings.TrimSpace(report.Message)
		op.LastFailureClass = report.Class
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
		retryable := controlplane.IsRetryableOperationFailure(op.RetryPolicy, report.Class)
		if retryable && op.Attempt < op.RetryPolicy.MaxAttempts {
			next := now.Add(controlplane.OperationBackoff(op.RetryPolicy, op.Attempt, report.RetryAfterSeconds))
			op.State = controlplane.OperationRetryWait
			op.NextAttemptAt = &next
			op.RetryExhausted = false
		} else {
			op.State = controlplane.OperationFailed
			op.NextAttemptAt = nil
			op.RetryExhausted = retryable && op.Attempt >= op.RetryPolicy.MaxAttempts
		}
		op.Revision++
		op.UpdatedAt = now
		_, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,last_error=$4,last_failure_class=$5,retry_exhausted=$6,next_attempt_at=$7,lease_owner=NULL,lease_expires_at=NULL,updated_at=$8 WHERE id=$1`, id, op.Revision, string(op.State), op.LastError, string(op.LastFailureClass), op.RetryExhausted, op.NextAttemptAt, now)
		if err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.failure_reported", "operation", id, op.Revision, "", map[string]any{"attempt": op.Attempt, "failureClass": report.Class, "code": report.Code, "retryable": retryable, "retryExhausted": op.RetryExhausted, "nextAttemptAt": op.NextAttemptAt}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.failure_reported", op); err != nil {
			return err
		}
		out = op
		return nil
	})
	return out, err
}

func (s *PostgresStore) CompleteOperation(ctx context.Context, id string, expected int64, worker string, fence int64, actor string) (controlplane.Operation, error) {
	var out controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if op.State != controlplane.OperationVerifying {
			return fmt.Errorf("%w: operation success requires VERIFYING postconditions", controlplane.ErrPrerequisite)
		}
		if !controlplane.OperationLeaseActive(op, worker, fence, utcNow(s.now)) {
			return controlplane.ErrStaleFence
		}
		now := utcNow(s.now)
		op.State = controlplane.OperationSucceeded
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
		op.NextAttemptAt = nil
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,lease_owner=NULL,lease_expires_at=NULL,next_attempt_at=NULL,updated_at=$4 WHERE id=$1`, id, op.Revision, string(op.State), now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.succeeded", "operation", id, op.Revision, "", map[string]any{"attempt": op.Attempt}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.succeeded", op); err != nil {
			return err
		}
		out = op
		return nil
	})
	return out, err
}

func (s *PostgresStore) RequestOperationCancellation(ctx context.Context, id string, expected int64, actor, reason string) (controlplane.Operation, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return controlplane.Operation{}, fmt.Errorf("%w: cancellation reason is required", controlplane.ErrValidation)
	}
	var out controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if controlplane.IsTerminal(op.State) || op.State == controlplane.OperationCancelRequested {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		op.CancelRequestedBy = actor
		op.CancelRequestedAt = &now
		op.CancelReason = reason
		switch op.State {
		case controlplane.OperationRunning, controlplane.OperationVerifying, controlplane.OperationRollingBack:
			op.State = controlplane.OperationCancelRequested
		default:
			op.State = controlplane.OperationCancelled
			op.LeaseOwner = ""
			op.LeaseExpiresAt = nil
			op.NextAttemptAt = nil
		}
		op.Revision++
		op.UpdatedAt = now
		_, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,cancel_requested_by=$4,cancel_requested_at=$5,cancel_reason=$6,lease_owner=NULLIF($7,''),lease_expires_at=$8,next_attempt_at=$9,updated_at=$10 WHERE id=$1`, id, op.Revision, string(op.State), actor, now, reason, op.LeaseOwner, op.LeaseExpiresAt, op.NextAttemptAt, now)
		if err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.cancellation_requested", "operation", id, op.Revision, "", map[string]any{"state": op.State, "reason": reason}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.cancellation_requested", op); err != nil {
			return err
		}
		out = op
		return nil
	})
	return out, err
}

func (s *PostgresStore) AcknowledgeOperationCancellation(ctx context.Context, id string, expected int64, worker string, fence int64, actor string) (controlplane.Operation, error) {
	var out controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if op.Revision != expected {
			return controlplane.ErrConflict
		}
		if op.State != controlplane.OperationCancelRequested {
			return controlplane.ErrInvalidTransition
		}
		var compensatable int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM operation_compensation_steps WHERE operation_id=$1 AND forward_completed=true AND strategy <> 'NONE'`, id).Scan(&compensatable); err != nil {
			return err
		}
		if compensatable > 0 {
			return fmt.Errorf("%w: completed mutating steps require compensation before cancellation can complete", controlplane.ErrPrerequisite)
		}
		if !controlplane.OperationLeaseActive(op, worker, fence, utcNow(s.now)) {
			return controlplane.ErrStaleFence
		}
		now := utcNow(s.now)
		op.State = controlplane.OperationCancelled
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
		op.NextAttemptAt = nil
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,lease_owner=NULL,lease_expires_at=NULL,next_attempt_at=NULL,updated_at=$4 WHERE id=$1`, id, op.Revision, string(op.State), now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.cancelled_at_safe_boundary", "operation", id, op.Revision, "", map[string]any{"attempt": op.Attempt, "reason": op.CancelReason}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", id, "operation.cancelled", op); err != nil {
			return err
		}
		out = op
		return nil
	})
	return out, err
}
