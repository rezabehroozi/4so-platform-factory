package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *PostgresStore) transitionOwnerOperationTx(ctx context.Context, tx *sql.Tx, op *controlplane.Operation, to controlplane.OperationState, actor, event string, payload map[string]any) error {
	if !controlplane.CanTransition(op.State, to) {
		return controlplane.ErrInvalidTransition
	}
	now := utcNow(s.now)
	op.State = to
	op.Revision++
	op.UpdatedAt = now
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,updated_at=$4 WHERE id=$1`, op.ID, op.Revision, string(op.State), now); err != nil {
		return err
	}
	if event == "" {
		event = "operation.transitioned"
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["state"] = to
	if err := s.appendAuditTx(ctx, tx, actor, event, "operation", op.ID, op.Revision, "", payload); err != nil {
		return err
	}
	return s.appendOutboxTx(ctx, tx, "operation", op.ID, event, *op)
}

func (s *PostgresStore) cancelOwnerDestructiveOperationTx(ctx context.Context, tx *sql.Tx, operationID, actor, reason string) error {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return nil
	}
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, operationID))
	if err != nil {
		return mapDBError(err)
	}
	if op.Class != controlplane.OperationClassDestructive {
		return fmt.Errorf("%w: previous owner destructive operation binding is invalid", controlplane.ErrPrerequisite)
	}
	if op.State == controlplane.OperationCancelled {
		return nil
	}
	if !controlplane.CanTransition(op.State, controlplane.OperationCancelled) {
		return fmt.Errorf("%w: previous destructive operation %s cannot be superseded from %s", controlplane.ErrPrerequisite, op.ID, op.State)
	}
	return s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationCancelled, actor, "operation.owner_superseded", map[string]any{"reason": strings.TrimSpace(reason)})
}

func (s *PostgresStore) createOwnerDestructiveOperationTx(ctx context.Context, tx *sql.Tx, projectID, clusterID, kind, ownerID string, ownerRevision int64, desiredDigest, recoveryCheckpointID, actor, ownerRequestDigest string, awaitApproval bool) (controlplane.Operation, error) {
	projectID, clusterID, kind, ownerID = strings.TrimSpace(projectID), strings.TrimSpace(clusterID), strings.TrimSpace(kind), strings.TrimSpace(ownerID)
	recoveryCheckpointID = strings.TrimSpace(recoveryCheckpointID)
	if projectID == "" || clusterID == "" || kind == "" || ownerID == "" || recoveryCheckpointID == "" || strings.TrimSpace(actor) == "" {
		return controlplane.Operation{}, fmt.Errorf("%w: destructive owner workflow requires project, cluster, owner, actor and recovery checkpoint", controlplane.ErrPrerequisite)
	}
	request := controlplane.OperationRequest{
		ProjectID:            projectID,
		Kind:                 kind,
		TargetRef:            "cluster:" + clusterID,
		DesiredRevision:      controlplane.OwnerDestructiveDesiredRevision(kind, ownerID, ownerRevision, desiredDigest, recoveryCheckpointID),
		Risk:                 "critical",
		Class:                controlplane.OperationClassDestructive,
		RecoveryCheckpointID: recoveryCheckpointID,
	}
	key := fmt.Sprintf("owner:%s:%s:%d", kind, ownerID, ownerRevision)
	digest := operationDigest(request)
	existing, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, projectID, key))
	if err == nil {
		if existing.RequestDigest != digest {
			return controlplane.Operation{}, controlplane.ErrIdempotencyConflict
		}
		return existing, nil
	}
	if err != sql.ErrNoRows {
		return controlplane.Operation{}, err
	}
	now := utcNow(s.now)
	op := controlplane.Operation{
		ResourceMeta:         controlplane.ResourceMeta{ID: s.id("op"), Revision: 1, CreatedAt: now, UpdatedAt: now},
		ProjectID:            projectID,
		Kind:                 kind,
		TargetRef:            request.TargetRef,
		DesiredRevision:      request.DesiredRevision,
		State:                controlplane.OperationDraft,
		Risk:                 "critical",
		Class:                controlplane.OperationClassDestructive,
		RetryPolicy:          controlplane.RetryPolicyForOperationClass(controlplane.OperationClassDestructive),
		RecoveryCheckpointID: recoveryCheckpointID,
		IdempotencyKey:       key,
		RequestDigest:        digest,
		ActorID:              actor,
	}
	if err = s.bindDestructiveRecoveryTx(ctx, tx, &op, now); err != nil {
		return controlplane.Operation{}, err
	}
	retryPolicy, _ := json.Marshal(op.RetryPolicy)
	if _, err = tx.ExecContext(ctx, `INSERT INTO operations(id,project_id,revision,kind,target_ref,desired_revision,state,risk,operation_class,retry_policy,attempt,retry_exhausted,recovery_checkpoint_id,recovery_evidence_digest,recovery_inventory_digest,idempotency_key,request_digest,actor_id,fence_token,last_error,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9::jsonb,0,false,$10,$11,$12,$13,$14,$15,0,'',$16,$16)`, op.ID, op.ProjectID, op.Kind, op.TargetRef, op.DesiredRevision, string(op.State), op.Risk, string(op.Class), retryPolicy, op.RecoveryCheckpointID, op.RecoveryEvidenceDigest, op.RecoveryInventoryDigest, op.IdempotencyKey, op.RequestDigest, op.ActorID, now); err != nil {
		return controlplane.Operation{}, mapDBError(err)
	}
	if err = s.appendAuditTx(ctx, tx, actor, "operation.created", "operation", op.ID, op.Revision, ownerRequestDigest, map[string]any{"ownerKind": kind, "ownerId": ownerID, "state": op.State}); err != nil {
		return controlplane.Operation{}, err
	}
	if err = s.appendOutboxTx(ctx, tx, "operation", op.ID, "operation.created", op); err != nil {
		return controlplane.Operation{}, err
	}
	if err = s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationPlanning, actor, "operation.owner_planning", map[string]any{"ownerKind": kind, "ownerId": ownerID}); err != nil {
		return controlplane.Operation{}, err
	}
	if err = s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationAwaitingApproval, actor, "operation.owner_approval_required", map[string]any{"ownerKind": kind, "ownerId": ownerID}); err != nil {
		return controlplane.Operation{}, err
	}
	if !awaitApproval {
		if err = s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationApproved, actor, "operation.owner_approved", map[string]any{"ownerKind": kind, "ownerId": ownerID, "approval": "explicit-destructive-request"}); err != nil {
			return controlplane.Operation{}, err
		}
		if err = s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationQueued, actor, "operation.owner_queued", map[string]any{"ownerKind": kind, "ownerId": ownerID}); err != nil {
			return controlplane.Operation{}, err
		}
	}
	return op, nil
}

func (s *PostgresStore) approveOwnerDestructiveOperationTx(ctx context.Context, tx *sql.Tx, operationID, projectID, clusterID, actor string) (controlplane.Operation, error) {
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, strings.TrimSpace(operationID)))
	if err != nil {
		return controlplane.Operation{}, mapDBError(err)
	}
	if op.ProjectID != projectID || controlplane.OperationTargetClusterID(op.TargetRef) != clusterID || op.Class != controlplane.OperationClassDestructive {
		return controlplane.Operation{}, fmt.Errorf("%w: owner destructive operation binding is invalid", controlplane.ErrPrerequisite)
	}
	if op.State != controlplane.OperationAwaitingApproval {
		return controlplane.Operation{}, controlplane.ErrInvalidTransition
	}
	if err = s.bindDestructiveRecoveryTx(ctx, tx, &op, utcNow(s.now)); err != nil {
		return controlplane.Operation{}, err
	}
	if err = s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationApproved, actor, "operation.owner_approved", nil); err != nil {
		return controlplane.Operation{}, err
	}
	if err = s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationQueued, actor, "operation.owner_queued", nil); err != nil {
		return controlplane.Operation{}, err
	}
	return op, nil
}

func (s *PostgresStore) startOwnerDestructiveOperationTx(ctx context.Context, tx *sql.Tx, operationID, projectID, clusterID, actor string) (controlplane.Operation, error) {
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, strings.TrimSpace(operationID)))
	if err != nil {
		return controlplane.Operation{}, mapDBError(err)
	}
	if op.ProjectID != projectID || controlplane.OperationTargetClusterID(op.TargetRef) != clusterID || op.Class != controlplane.OperationClassDestructive || op.State != controlplane.OperationQueued {
		return controlplane.Operation{}, fmt.Errorf("%w: owner destructive operation is not safely queued", controlplane.ErrPrerequisite)
	}
	now := utcNow(s.now)
	if err = s.bindDestructiveRecoveryTx(ctx, tx, &op, now); err != nil {
		return controlplane.Operation{}, err
	}
	if op.Attempt >= op.RetryPolicy.MaxAttempts {
		return controlplane.Operation{}, fmt.Errorf("%w: owner destructive operation retry budget exhausted; submit a fresh recovery-bound request", controlplane.ErrPrerequisite)
	}
	op.Attempt++
	op.State = controlplane.OperationRunning
	op.LastFailureClass = ""
	op.RetryExhausted = false
	op.NextAttemptAt = nil
	op.Revision++
	op.UpdatedAt = now
	if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,attempt=$4,next_attempt_at=NULL,last_failure_class='',retry_exhausted=false,recovery_evidence_digest=$5,recovery_inventory_digest=$6,updated_at=$7 WHERE id=$1`, op.ID, op.Revision, string(op.State), op.Attempt, op.RecoveryEvidenceDigest, op.RecoveryInventoryDigest, now); err != nil {
		return controlplane.Operation{}, err
	}
	if err = s.appendAuditTx(ctx, tx, actor, "operation.owner_attempt_started", "operation", op.ID, op.Revision, "", map[string]any{"attempt": op.Attempt, "owner": op.Kind}); err != nil {
		return controlplane.Operation{}, err
	}
	if err = s.appendOutboxTx(ctx, tx, "operation", op.ID, "operation.owner_attempt_started", op); err != nil {
		return controlplane.Operation{}, err
	}
	return op, nil
}

func (s *PostgresStore) finishOwnerDestructiveOperationTx(ctx context.Context, tx *sql.Tx, operationID string, success bool, lastError, actor string) (controlplane.Operation, error) {
	op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, strings.TrimSpace(operationID)))
	if err != nil {
		return controlplane.Operation{}, mapDBError(err)
	}
	if op.Class != controlplane.OperationClassDestructive || op.State != controlplane.OperationRunning {
		return controlplane.Operation{}, controlplane.ErrInvalidTransition
	}
	now := utcNow(s.now)
	if !success {
		op.State = controlplane.OperationFailed
		op.LastError = strings.TrimSpace(lastError)
		if op.LastError == "" {
			op.LastError = "owner destructive workflow failed"
		}
		op.LastFailureClass = controlplane.OperationFailureUnknown
		op.RetryExhausted = true
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,last_error=$4,last_failure_class=$5,retry_exhausted=true,updated_at=$6 WHERE id=$1`, op.ID, op.Revision, string(op.State), op.LastError, string(op.LastFailureClass), now); err != nil {
			return controlplane.Operation{}, err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "operation.owner_failed", "operation", op.ID, op.Revision, "", map[string]any{"attempt": op.Attempt, "error": op.LastError}); err != nil {
			return controlplane.Operation{}, err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", op.ID, "operation.owner_failed", op); err != nil {
			return controlplane.Operation{}, err
		}
		return op, nil
	}
	if err = s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationVerifying, actor, "operation.owner_verification_started", map[string]any{"attempt": op.Attempt}); err != nil {
		return controlplane.Operation{}, err
	}
	if err = s.transitionOwnerOperationTx(ctx, tx, &op, controlplane.OperationSucceeded, actor, "operation.owner_succeeded", map[string]any{"attempt": op.Attempt}); err != nil {
		return controlplane.Operation{}, err
	}
	return op, nil
}
