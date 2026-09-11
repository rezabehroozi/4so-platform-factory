package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

func scanOperationRequestPayload(row interface{ Scan(...any) error }) (controlplane.OperationRequestPayload, error) {
	var v controlplane.OperationRequestPayload
	err := row.Scan(&v.OperationID, &v.PayloadDigest, &v.MediaType, &v.Payload, &v.CreatedAt)
	return v, err
}

func (s *PostgresStore) CreateOperationAwaitingApprovalWithPayload(ctx context.Context, request controlplane.OperationRequest, key, actor, requestID, mediaType string, payload []byte) (controlplane.Operation, bool, error) {
	key = strings.TrimSpace(key)
	actor = strings.TrimSpace(actor)
	mediaType = strings.TrimSpace(mediaType)
	if key == "" || len(key) > 200 || actor == "" || mediaType == "" || len(mediaType) > 160 || len(payload) == 0 || len(payload) > 1024*1024 {
		return controlplane.Operation{}, false, fmt.Errorf("%w: bounded idempotency key, actor, media type and payload are required", controlplane.ErrValidation)
	}
	if request.Risk != "low" && request.Risk != "medium" && request.Risk != "high" && request.Risk != "critical" {
		return controlplane.Operation{}, false, fmt.Errorf("%w: invalid operation risk", controlplane.ErrValidation)
	}
	class, classErr := controlplane.NormalizeOperationClass(request.Class)
	if classErr != nil {
		return controlplane.Operation{}, false, classErr
	}
	request.Class = class
	if request.ProjectID == "" || request.Kind == "" || request.TargetRef == "" || request.DesiredRevision == "" {
		return controlplane.Operation{}, false, fmt.Errorf("%w: projectId, kind, targetRef and desiredRevision are required", controlplane.ErrValidation)
	}
	requestDigest := operationDigest(request)
	payloadDigest := controlplane.OperationRequestPayloadDigest(payload)
	var result controlplane.Operation
	var replay bool
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, request.ProjectID, key))
		if err == nil {
			if existing.RequestDigest != requestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			sealed, payloadErr := scanOperationRequestPayload(tx.QueryRowContext(ctx, `SELECT operation_id,payload_digest,media_type,payload,created_at FROM operation_request_payloads WHERE operation_id=$1`, existing.ID))
			if payloadErr != nil {
				return mapDBError(payloadErr)
			}
			if sealed.PayloadDigest != payloadDigest || sealed.MediaType != mediaType {
				return controlplane.ErrIdempotencyConflict
			}
			result, replay = existing, true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now := utcNow(s.now)
		result = controlplane.Operation{
			ResourceMeta: controlplane.ResourceMeta{ID: s.id("op"), Revision: 3, CreatedAt: now, UpdatedAt: now},
			ProjectID:    request.ProjectID, Kind: request.Kind, TargetRef: request.TargetRef, DesiredRevision: request.DesiredRevision,
			State: controlplane.OperationAwaitingApproval, Risk: request.Risk, Class: class,
			RetryPolicy: controlplane.RetryPolicyForOperationClass(class), RecoveryCheckpointID: strings.TrimSpace(request.RecoveryCheckpointID),
			IdempotencyKey: key, RequestDigest: requestDigest, ActorID: actor,
		}
		if class == controlplane.OperationClassDestructive {
			if err := s.bindDestructiveRecoveryTx(ctx, tx, &result, now); err != nil {
				return err
			}
		}
		retryPolicy, _ := json.Marshal(result.RetryPolicy)
		if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,project_id,revision,kind,target_ref,desired_revision,state,risk,operation_class,retry_policy,attempt,retry_exhausted,recovery_checkpoint_id,recovery_evidence_digest,recovery_inventory_digest,idempotency_key,request_digest,actor_id,fence_token,last_error,created_at,updated_at) VALUES($1,$2,3,$3,$4,$5,$6,$7,$8,$9::jsonb,0,false,NULLIF($10,''),$11,$12,$13,$14,$15,0,'',$16,$16)`, result.ID, result.ProjectID, result.Kind, result.TargetRef, result.DesiredRevision, string(result.State), result.Risk, string(result.Class), retryPolicy, result.RecoveryCheckpointID, result.RecoveryEvidenceDigest, result.RecoveryInventoryDigest, result.IdempotencyKey, result.RequestDigest, result.ActorID, now); err != nil {
			return mapDBError(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_request_payloads(operation_id,payload_digest,media_type,payload,created_at) VALUES($1,$2,$3,$4,$5)`, result.ID, payloadDigest, mediaType, payload, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "operation.created", "operation", result.ID, 1, requestID, map[string]any{"state": controlplane.OperationDraft}); err != nil {
			return err
		}
		if err := s.appendAuditTx(ctx, tx, actor, "operation.planning", "operation", result.ID, 2, requestID, map[string]any{"state": controlplane.OperationPlanning}); err != nil {
			return err
		}
		if err := s.appendAuditTx(ctx, tx, actor, "operation.approval_required", "operation", result.ID, 3, requestID, map[string]any{"state": controlplane.OperationAwaitingApproval}); err != nil {
			return err
		}
		if err := s.appendAuditTx(ctx, tx, actor, "operation.request_payload.sealed", "operation", result.ID, 3, requestID, map[string]any{"authority": controlplane.OperationRequestPayloadAuthority, "payloadDigest": payloadDigest, "mediaType": mediaType}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "operation", result.ID, "operation.approval_required", result)
	})
	return result, replay, err
}

func (s *PostgresStore) GetOperationRequestPayload(ctx context.Context, operationID string) (controlplane.OperationRequestPayload, error) {
	v, err := scanOperationRequestPayload(s.db.QueryRowContext(ctx, `SELECT operation_id,payload_digest,media_type,payload,created_at FROM operation_request_payloads WHERE operation_id=$1`, strings.TrimSpace(operationID)))
	return v, mapDBError(err)
}

func (s *PostgresStore) listOperationRequestPayloads(ctx context.Context) ([]controlplane.OperationRequestPayload, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT operation_id,payload_digest,media_type,payload,created_at FROM operation_request_payloads ORDER BY operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.OperationRequestPayload{}
	for rows.Next() {
		v, err := scanOperationRequestPayload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ApproveOperationAndQueue(ctx context.Context, id string, expected int64, actor string) (controlplane.Operation, error) {
	actor = strings.TrimSpace(actor)
	var result controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if current.State != controlplane.OperationAwaitingApproval || actor == "" || actor == current.ActorID {
			return controlplane.ErrPrerequisite
		}
		now := utcNow(s.now)
		approvedRevision := current.Revision + 1
		queuedRevision := approvedRevision + 1
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state='QUEUED',updated_at=$3 WHERE id=$1 AND revision=$4`, current.ID, queuedRevision, now, expected); err != nil {
			return mapDBError(err)
		}
		current.State = controlplane.OperationQueued
		current.Revision = queuedRevision
		current.UpdatedAt = now
		if err := s.appendAuditTx(ctx, tx, actor, "operation.approved", "operation", current.ID, approvedRevision, "", map[string]any{"requester": current.ActorID, "separationOfDuties": true}); err != nil {
			return err
		}
		if err := s.appendAuditTx(ctx, tx, actor, "operation.queued_after_approval", "operation", current.ID, queuedRevision, "", map[string]any{"separationOfDuties": true}); err != nil {
			return err
		}
		if err := s.appendOutboxTx(ctx, tx, "operation", current.ID, "operation.queued", current); err != nil {
			return err
		}
		result = current
		return nil
	})
	return result, err
}
