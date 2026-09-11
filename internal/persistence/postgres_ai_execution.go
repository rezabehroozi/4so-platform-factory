package persistence

import (
	"context"
	"database/sql"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const aiExecutionColumns = `id,project_id,revision,purpose,idempotency_key,request_digest,state,ai_run_id,failure_code,requested_by,created_at,updated_at`

func scanAIExecution(row interface{ Scan(...any) error }) (controlplane.AIExecutionClaim, error) {
	var v controlplane.AIExecutionClaim
	err := row.Scan(&v.ID, &v.ProjectID, &v.Revision, &v.Purpose, &v.IdempotencyKey, &v.RequestDigest, &v.State, &v.AIRunID, &v.FailureCode, &v.RequestedBy, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	if err = controlplane.ValidateAIExecutionClaim(&v); err != nil {
		return controlplane.AIExecutionClaim{}, err
	}
	return v, nil
}

func (s *PostgresStore) ClaimAIExecution(ctx context.Context, v controlplane.AIExecutionClaim, actor string) (controlplane.AIExecutionClaim, bool, error) {
	v.State = controlplane.AIExecutionDispatched
	v.AIRunID = ""
	v.FailureCode = ""
	if err := controlplane.ValidateAIExecutionClaim(&v); err != nil {
		return controlplane.AIExecutionClaim{}, false, err
	}
	var out controlplane.AIExecutionClaim
	acquired := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		acquired = false
		now := utcNow(s.now)
		candidate := v
		candidate.ResourceMeta = controlplane.ResourceMeta{ID: s.id("aic"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		candidate.RequestedBy = strings.TrimSpace(actor)
		result, e := tx.ExecContext(ctx, `INSERT INTO ai_execution_claims(id,project_id,revision,purpose,idempotency_key,request_digest,state,ai_run_id,failure_code,requested_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,'DISPATCHED','','',$6,$7,$7) ON CONFLICT(project_id,idempotency_key) DO NOTHING`, candidate.ID, candidate.ProjectID, candidate.Purpose, candidate.IdempotencyKey, candidate.RequestDigest, candidate.RequestedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		rows, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if rows == 1 {
			out = candidate
			acquired = true
			return s.appendAuditTx(ctx, tx, actor, "ai_execution.dispatched", "aiExecutionClaim", out.ID, out.Revision, "", map[string]any{"projectId": out.ProjectID, "purpose": out.Purpose})
		}
		existing, e := scanAIExecution(tx.QueryRowContext(ctx, `SELECT `+aiExecutionColumns+` FROM ai_execution_claims WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
		if e != nil {
			return mapDBError(e)
		}
		if existing.RequestDigest != v.RequestDigest || existing.Purpose != v.Purpose {
			return controlplane.ErrIdempotencyConflict
		}
		out = existing
		return nil
	})
	return out, acquired, err
}

func (s *PostgresStore) FinalizeAIExecution(ctx context.Context, run controlplane.AIRun, actor string) (controlplane.AIRun, bool, controlplane.AIExecutionClaim, error) {
	if err := controlplane.ValidateAIRun(&run); err != nil {
		return controlplane.AIRun{}, false, controlplane.AIExecutionClaim{}, err
	}
	var outRun controlplane.AIRun
	var outClaim controlplane.AIExecutionClaim
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		claim, e := scanAIExecution(tx.QueryRowContext(ctx, `SELECT `+aiExecutionColumns+` FROM ai_execution_claims WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, run.ProjectID, run.IdempotencyKey))
		if e != nil {
			return mapDBError(e)
		}
		if claim.RequestDigest != run.RequestDigest || claim.Purpose != run.Purpose {
			return controlplane.ErrIdempotencyConflict
		}
		if claim.State == controlplane.AIExecutionFailed {
			return controlplane.ErrIdempotencyConflict
		}
		if claim.State == controlplane.AIExecutionCompleted {
			existing, e := scanAIRun(tx.QueryRowContext(ctx, `SELECT `+aiRunColumns+` FROM ai_runs WHERE id=$1 FOR UPDATE`, claim.AIRunID))
			if e != nil {
				return mapDBError(e)
			}
			if existing.ProjectID != claim.ProjectID || existing.IdempotencyKey != claim.IdempotencyKey || existing.RequestDigest != claim.RequestDigest {
				return controlplane.ErrValidation
			}
			outRun, outClaim, replay = existing, claim, true
			return nil
		}
		if claim.State != controlplane.AIExecutionDispatched {
			return controlplane.ErrIdempotencyConflict
		}

		existing, e := scanAIRun(tx.QueryRowContext(ctx, `SELECT `+aiRunColumns+` FROM ai_runs WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, run.ProjectID, run.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != run.RequestDigest || existing.Purpose != run.Purpose {
				return controlplane.ErrIdempotencyConflict
			}
			outRun = existing
			replay = true
		} else if e != sql.ErrNoRows {
			return e
		} else {
			var exists bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, run.ProjectID).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				return controlplane.ErrNotFound
			}
			if run.LinkedResourceType != "" {
				table := ""
				switch run.LinkedResourceType {
				case "operation":
					table = "operations"
				case "managedCluster":
					table = "managed_clusters"
				default:
					return controlplane.ErrValidation
				}
				var linkedProject string
				if e = tx.QueryRowContext(ctx, `SELECT project_id FROM `+table+` WHERE id=$1`, run.LinkedResourceID).Scan(&linkedProject); e != nil {
					return mapDBError(e)
				}
				if linkedProject != run.ProjectID {
					return controlplane.ErrNotFound
				}
			}
			now := utcNow(s.now)
			run.ResourceMeta = controlplane.ResourceMeta{ID: s.id("air"), Revision: 1, CreatedAt: now, UpdatedAt: now}
			run.RequestedBy = strings.TrimSpace(actor)
			run.AdvisoryOnly = true
			if _, e = tx.ExecContext(ctx, `INSERT INTO ai_runs(id,project_id,revision,purpose,provider,model,prompt_id,prompt_digest,context_digest,output_digest,redaction_count,input_bytes,input_tokens,cached_tokens,output_tokens,output,linked_resource_type,linked_resource_id,requested_by,idempotency_key,request_digest,advisory_only,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,$18,$19,$20,true,$21,$21)`, run.ID, run.ProjectID, run.Purpose, run.Provider, run.Model, run.PromptID, run.PromptDigest, run.ContextDigest, run.OutputDigest, run.RedactionCount, run.InputBytes, run.InputTokens, run.CachedTokens, run.OutputTokens, []byte(run.Output), run.LinkedResourceType, run.LinkedResourceID, run.RequestedBy, run.IdempotencyKey, run.RequestDigest, now); e != nil {
				return mapDBError(e)
			}
			if e = s.appendAuditTx(ctx, tx, actor, "ai_run.created", "aiRun", run.ID, run.Revision, "", map[string]any{"projectId": run.ProjectID, "purpose": run.Purpose, "provider": run.Provider, "model": run.Model, "redactionCount": run.RedactionCount, "linkedResourceType": run.LinkedResourceType, "linkedResourceId": run.LinkedResourceID}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "aiRun", run.ID, "ai_run.created", run); e != nil {
				return e
			}
			outRun = run
		}

		now := utcNow(s.now)
		claim.State = controlplane.AIExecutionCompleted
		claim.AIRunID = outRun.ID
		claim.FailureCode = ""
		claim.Revision++
		claim.UpdatedAt = now
		if e = controlplane.ValidateAIExecutionClaim(&claim); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE ai_execution_claims SET revision=$3,state='COMPLETED',ai_run_id=$4,failure_code='',updated_at=$5 WHERE project_id=$1 AND idempotency_key=$2`, claim.ProjectID, claim.IdempotencyKey, claim.Revision, claim.AIRunID, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "ai_execution.completed", "aiExecutionClaim", claim.ID, claim.Revision, "", map[string]any{"projectId": claim.ProjectID, "aiRunId": claim.AIRunID}); e != nil {
			return e
		}
		outClaim = claim
		return nil
	})
	return outRun, replay, outClaim, err
}

func (s *PostgresStore) FailAIExecution(ctx context.Context, projectID, key, requestDigest, failureCode, actor string) (controlplane.AIExecutionClaim, error) {
	var out controlplane.AIExecutionClaim
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanAIExecution(tx.QueryRowContext(ctx, `SELECT `+aiExecutionColumns+` FROM ai_execution_claims WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, strings.TrimSpace(projectID), strings.TrimSpace(key)))
		if e != nil {
			return mapDBError(e)
		}
		if v.RequestDigest != strings.TrimSpace(requestDigest) {
			return controlplane.ErrIdempotencyConflict
		}
		if v.State == controlplane.AIExecutionFailed {
			out = v
			return nil
		}
		if v.State != controlplane.AIExecutionDispatched {
			return controlplane.ErrIdempotencyConflict
		}
		v.State = controlplane.AIExecutionFailed
		v.AIRunID = ""
		v.FailureCode = strings.TrimSpace(failureCode)
		v.Revision++
		v.UpdatedAt = utcNow(s.now)
		if err := controlplane.ValidateAIExecutionClaim(&v); err != nil {
			return err
		}
		if _, e = tx.ExecContext(ctx, `UPDATE ai_execution_claims SET revision=$3,state='FAILED',ai_run_id='',failure_code=$4,updated_at=$5 WHERE project_id=$1 AND idempotency_key=$2`, v.ProjectID, v.IdempotencyKey, v.Revision, v.FailureCode, v.UpdatedAt); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "ai_execution.failed", "aiExecutionClaim", v.ID, v.Revision, "", map[string]any{"projectId": v.ProjectID, "failureCode": v.FailureCode}); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) listAIExecutionClaims(ctx context.Context) ([]controlplane.AIExecutionClaim, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+aiExecutionColumns+` FROM ai_execution_claims ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.AIExecutionClaim{}
	for rows.Next() {
		v, e := scanAIExecution(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
