package persistence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const operationStepTraceColumns = `id,operation_id,revision,step_phase,step_key,attempt,sequence,trace_key,level,event_type,message,evidence_id,evidence_digest,created_at,updated_at`

func scanOperationStepTrace(row interface{ Scan(...any) error }) (controlplane.OperationStepTrace, error) {
	var v controlplane.OperationStepTrace
	var phase, level string
	err := row.Scan(&v.ID, &v.OperationID, &v.Revision, &phase, &v.StepKey, &v.Attempt, &v.Sequence, &v.TraceKey, &level, &v.EventType, &v.Message, &v.EvidenceID, &v.EvidenceDigest, &v.CreatedAt, &v.UpdatedAt)
	v.Phase = controlplane.OperationStepPhase(phase)
	v.Level = controlplane.OperationStepLogLevel(level)
	return v, err
}

func tracePayloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateTraceInput(in controlplane.OperationStepTraceInput) (controlplane.OperationStepTraceInput, error) {
	in.OperationID = strings.TrimSpace(in.OperationID)
	in.StepKey = strings.TrimSpace(in.StepKey)
	in.TraceKey = strings.TrimSpace(in.TraceKey)
	in.EventType = strings.TrimSpace(in.EventType)
	in.Message = strings.TrimSpace(in.Message)
	in.EvidenceKind = strings.TrimSpace(in.EvidenceKind)
	in.MediaType = strings.TrimSpace(in.MediaType)
	in.Location = strings.TrimSpace(in.Location)
	if in.OperationID == "" || in.StepKey == "" || in.TraceKey == "" || in.EventType == "" || in.Message == "" {
		return in, fmt.Errorf("%w: operationId, stepKey, traceKey, eventType and message are required", controlplane.ErrValidation)
	}
	if in.Phase != controlplane.OperationStepPhaseForward && in.Phase != controlplane.OperationStepPhaseCompensation {
		return in, fmt.Errorf("%w: phase must be FORWARD or COMPENSATION", controlplane.ErrValidation)
	}
	switch in.Level {
	case controlplane.OperationStepLogDebug, controlplane.OperationStepLogInfo, controlplane.OperationStepLogWarn, controlplane.OperationStepLogError:
	default:
		return in, fmt.Errorf("%w: unsupported log level", controlplane.ErrValidation)
	}
	if in.EvidenceKind == "" || in.MediaType == "" || len(in.Payload) == 0 {
		return in, fmt.Errorf("%w: evidenceKind, mediaType and non-empty payload are required", controlplane.ErrValidation)
	}
	if len(in.Payload) > 1024*1024 {
		return in, fmt.Errorf("%w: step evidence payload exceeds 1 MiB", controlplane.ErrValidation)
	}
	in.Payload = append([]byte(nil), in.Payload...)
	return in, nil
}

func (s *PostgresStore) AppendOperationStepTrace(ctx context.Context, in controlplane.OperationStepTraceInput, worker string, fence int64, actor string) (controlplane.OperationStepTrace, controlplane.EvidenceMetadata, error) {
	in, err := validateTraceInput(in)
	if err != nil {
		return controlplane.OperationStepTrace{}, controlplane.EvidenceMetadata{}, err
	}
	worker = strings.TrimSpace(worker)
	if worker == "" || fence <= 0 {
		return controlplane.OperationStepTrace{}, controlplane.EvidenceMetadata{}, controlplane.ErrStaleFence
	}
	digest := tracePayloadDigest(in.Payload)
	var outTrace controlplane.OperationStepTrace
	var outEvidence controlplane.EvidenceMetadata
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, in.OperationID))
		if err != nil {
			return mapDBError(err)
		}
		if op.LeaseOwner != worker || op.FenceToken != fence || op.LeaseExpiresAt == nil || !op.LeaseExpiresAt.After(utcNow(s.now)) {
			return controlplane.ErrStaleFence
		}
		attempt := 0
		if in.Phase == controlplane.OperationStepPhaseForward {
			if op.State != controlplane.OperationRunning && op.State != controlplane.OperationVerifying && op.State != controlplane.OperationCancelRequested {
				return controlplane.ErrInvalidTransition
			}
			if op.Attempt < 1 {
				return fmt.Errorf("%w: operation attempt has not started", controlplane.ErrPrerequisite)
			}
			var stepID string
			if err = tx.QueryRowContext(ctx, `SELECT id FROM operation_steps WHERE operation_id=$1 AND attempt=$2 AND step_key=$3`, op.ID, op.Attempt, in.StepKey).Scan(&stepID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return fmt.Errorf("%w: forward operation step does not exist for current attempt", controlplane.ErrPrerequisite)
				}
				return err
			}
			attempt = op.Attempt
		} else {
			if op.State != controlplane.OperationRollingBack {
				return controlplane.ErrInvalidTransition
			}
			step, e := scanCompensationStep(tx.QueryRowContext(ctx, `SELECT `+compensationStepColumns+` FROM operation_compensation_steps WHERE operation_id=$1 AND step_key=$2`, op.ID, in.StepKey))
			if e != nil {
				return mapDBError(e)
			}
			if step.State != controlplane.CompensationStepRunning || step.FenceToken != fence || step.Attempt < 1 {
				return fmt.Errorf("%w: compensation step is not running under this fence", controlplane.ErrPrerequisite)
			}
			attempt = step.Attempt
		}

		existing, e := scanOperationStepTrace(tx.QueryRowContext(ctx, `SELECT `+operationStepTraceColumns+` FROM operation_step_traces WHERE operation_id=$1 AND step_phase=$2 AND step_key=$3 AND attempt=$4 AND trace_key=$5`, op.ID, string(in.Phase), in.StepKey, attempt, in.TraceKey))
		if e == nil {
			evidence, evErr := scanEvidence(tx.QueryRowContext(ctx, `SELECT `+evidenceColumns+` FROM evidence_metadata WHERE id=$1`, existing.EvidenceID))
			if evErr != nil {
				return evErr
			}
			if existing.Level != in.Level || existing.EventType != in.EventType || existing.Message != in.Message || existing.EvidenceDigest != digest || evidence.Kind != in.EvidenceKind || evidence.MediaType != in.MediaType {
				return controlplane.ErrIdempotencyConflict
			}
			outTrace, outEvidence = existing, evidence
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}

		var sequence int64
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM operation_step_traces WHERE operation_id=$1 AND step_phase=$2 AND step_key=$3 AND attempt=$4`, op.ID, string(in.Phase), in.StepKey, attempt).Scan(&sequence); err != nil {
			return err
		}
		now := utcNow(s.now)
		evidenceID := s.id("evd")
		location := in.Location
		if location == "" {
			location = fmt.Sprintf("authority://operations/%s/steps/%s/%s/attempts/%d/evidence/%s", op.ID, strings.ToLower(string(in.Phase)), in.StepKey, attempt, evidenceID)
		}
		trace := controlplane.OperationStepTrace{ResourceMeta: controlplane.ResourceMeta{ID: s.id("trc"), Revision: 1, CreatedAt: now, UpdatedAt: now}, OperationID: op.ID, Phase: in.Phase, StepKey: in.StepKey, Attempt: attempt, Sequence: sequence, TraceKey: in.TraceKey, Level: in.Level, EventType: in.EventType, Message: in.Message, EvidenceID: evidenceID, EvidenceDigest: digest}
		evidence := controlplane.EvidenceMetadata{ResourceMeta: controlplane.ResourceMeta{ID: evidenceID, Revision: 1, CreatedAt: now, UpdatedAt: now}, OperationID: op.ID, Phase: in.Phase, StepKey: in.StepKey, Attempt: attempt, TraceID: trace.ID, Kind: in.EvidenceKind, Digest: digest, MediaType: in.MediaType, Location: location, Size: int64(len(in.Payload)), HasPayload: true, Sealed: true}
		if _, err = tx.ExecContext(ctx, `INSERT INTO evidence_metadata(id,operation_id,revision,step_phase,step_key,attempt,trace_id,kind,digest,media_type,location,size_bytes,has_payload,sealed,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,true,true,$12,$12)`, evidence.ID, evidence.OperationID, string(evidence.Phase), evidence.StepKey, evidence.Attempt, evidence.TraceID, evidence.Kind, evidence.Digest, evidence.MediaType, evidence.Location, evidence.Size, now); err != nil {
			return mapDBError(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO operation_evidence_payloads(evidence_id,payload,digest,size_bytes,created_at) VALUES($1,$2,$3,$4,$5)`, evidence.ID, in.Payload, evidence.Digest, evidence.Size, now); err != nil {
			return mapDBError(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO operation_step_traces(id,operation_id,revision,step_phase,step_key,attempt,sequence,trace_key,level,event_type,message,evidence_id,evidence_digest,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)`, trace.ID, trace.OperationID, string(trace.Phase), trace.StepKey, trace.Attempt, trace.Sequence, trace.TraceKey, string(trace.Level), trace.EventType, trace.Message, trace.EvidenceID, trace.EvidenceDigest, now); err != nil {
			return mapDBError(err)
		}
		metadata := map[string]any{"method": controlplane.OperationStepTraceMethod, "operationId": op.ID, "phase": trace.Phase, "stepKey": trace.StepKey, "attempt": trace.Attempt, "sequence": trace.Sequence, "traceId": trace.ID, "traceKey": trace.TraceKey, "eventType": trace.EventType, "level": trace.Level, "evidenceId": evidence.ID, "evidenceDigest": evidence.Digest}
		if err = s.appendAuditTx(ctx, tx, actor, "operation_step.trace_sealed", "operationStepTrace", trace.ID, 1, "", metadata); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operationStepTrace", trace.ID, "operation_step.trace_sealed", trace); err != nil {
			return err
		}
		outTrace, outEvidence = trace, evidence
		return nil
	})
	return outTrace, outEvidence, err
}

func (s *PostgresStore) ListOperationStepTraces(ctx context.Context, operationID string) ([]controlplane.OperationStepTrace, error) {
	query := `SELECT ` + operationStepTraceColumns + ` FROM operation_step_traces`
	args := []any{}
	if strings.TrimSpace(operationID) != "" {
		query += ` WHERE operation_id=$1`
		args = append(args, strings.TrimSpace(operationID))
	}
	query += ` ORDER BY attempt,step_phase,step_key,sequence,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []controlplane.OperationStepTrace
	for rows.Next() {
		v, e := scanOperationStepTrace(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetEvidencePayload(ctx context.Context, evidenceID string) (controlplane.EvidenceMetadata, []byte, error) {
	evidence, err := scanEvidence(s.db.QueryRowContext(ctx, `SELECT `+evidenceColumns+` FROM evidence_metadata WHERE id=$1`, strings.TrimSpace(evidenceID)))
	if err != nil {
		return controlplane.EvidenceMetadata{}, nil, mapDBError(err)
	}
	if !evidence.HasPayload {
		return controlplane.EvidenceMetadata{}, nil, controlplane.ErrNotFound
	}
	var payload []byte
	var digest string
	var size int64
	if err = s.db.QueryRowContext(ctx, `SELECT payload,digest,size_bytes FROM operation_evidence_payloads WHERE evidence_id=$1`, evidence.ID).Scan(&payload, &digest, &size); err != nil {
		return controlplane.EvidenceMetadata{}, nil, mapDBError(err)
	}
	if digest != evidence.Digest || size != evidence.Size || int64(len(payload)) != evidence.Size || tracePayloadDigest(payload) != evidence.Digest {
		return controlplane.EvidenceMetadata{}, nil, fmt.Errorf("%w: sealed evidence payload integrity mismatch", controlplane.ErrConflict)
	}
	return evidence, append([]byte(nil), payload...), nil
}
