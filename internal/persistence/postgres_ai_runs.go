package persistence

import (
	"context"
	"database/sql"
	"fmt"

	"platform.4so.io/factory/internal/controlplane"
)

const aiRunColumns = `id,project_id,revision,purpose,provider,model,prompt_id,prompt_digest,context_digest,output_digest,redaction_count,input_bytes,input_tokens,cached_tokens,output_tokens,output,linked_resource_type,linked_resource_id,requested_by,idempotency_key,request_digest,advisory_only,created_at,updated_at`

func scanAIRun(row interface{ Scan(...any) error }) (controlplane.AIRun, error) {
	var v controlplane.AIRun
	var output []byte
	err := row.Scan(&v.ID, &v.ProjectID, &v.Revision, &v.Purpose, &v.Provider, &v.Model, &v.PromptID, &v.PromptDigest, &v.ContextDigest, &v.OutputDigest, &v.RedactionCount, &v.InputBytes, &v.InputTokens, &v.CachedTokens, &v.OutputTokens, &output, &v.LinkedResourceType, &v.LinkedResourceID, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest, &v.AdvisoryOnly, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	v.Output = append(v.Output[:0], output...)
	if err = controlplane.ValidateAIRun(&v); err != nil {
		return controlplane.AIRun{}, err
	}
	return v, nil
}

func (s *PostgresStore) CreateAIRun(ctx context.Context, v controlplane.AIRun, actor string) (controlplane.AIRun, bool, error) {
	if err := controlplane.ValidateAIRun(&v); err != nil {
		return controlplane.AIRun{}, false, err
	}
	var out controlplane.AIRun
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanAIRun(tx.QueryRowContext(ctx, `SELECT `+aiRunColumns+` FROM ai_runs WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != v.RequestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			out = existing
			replay = true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		var exists bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)`, v.ProjectID).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return controlplane.ErrNotFound
		}
		if v.LinkedResourceType != "" {
			table := ""
			switch v.LinkedResourceType {
			case "operation":
				table = "operations"
			case "managedCluster":
				table = "managed_clusters"
			default:
				return controlplane.ErrValidation
			}
			var linkedProject string
			if e = tx.QueryRowContext(ctx, `SELECT project_id FROM `+table+` WHERE id=$1`, v.LinkedResourceID).Scan(&linkedProject); e != nil {
				return mapDBError(e)
			}
			if linkedProject != v.ProjectID {
				return controlplane.ErrNotFound
			}
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("air"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.RequestedBy = actor
		v.AdvisoryOnly = true
		_, e = tx.ExecContext(ctx, `INSERT INTO ai_runs(id,project_id,revision,purpose,provider,model,prompt_id,prompt_digest,context_digest,output_digest,redaction_count,input_bytes,input_tokens,cached_tokens,output_tokens,output,linked_resource_type,linked_resource_id,requested_by,idempotency_key,request_digest,advisory_only,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,$18,$19,$20,true,$21,$21)`, v.ID, v.ProjectID, v.Purpose, v.Provider, v.Model, v.PromptID, v.PromptDigest, v.ContextDigest, v.OutputDigest, v.RedactionCount, v.InputBytes, v.InputTokens, v.CachedTokens, v.OutputTokens, []byte(v.Output), v.LinkedResourceType, v.LinkedResourceID, actor, v.IdempotencyKey, v.RequestDigest, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "ai_run.created", "aiRun", v.ID, v.Revision, "", map[string]any{"projectId": v.ProjectID, "purpose": v.Purpose, "provider": v.Provider, "model": v.Model, "redactionCount": v.RedactionCount, "linkedResourceType": v.LinkedResourceType, "linkedResourceId": v.LinkedResourceID}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "aiRun", v.ID, "ai_run.created", v)
	})
	return out, replay, err
}

func (s *PostgresStore) GetAIRun(ctx context.Context, id string) (controlplane.AIRun, error) {
	v, err := scanAIRun(s.db.QueryRowContext(ctx, `SELECT `+aiRunColumns+` FROM ai_runs WHERE id=$1`, id))
	return v, mapDBError(err)
}
func (s *PostgresStore) GetAIRunByIdempotencyKey(ctx context.Context, projectID, key string) (controlplane.AIRun, error) {
	v, err := scanAIRun(s.db.QueryRowContext(ctx, `SELECT `+aiRunColumns+` FROM ai_runs WHERE project_id=$1 AND idempotency_key=$2`, projectID, key))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListAIRuns(ctx context.Context, projectID string) ([]controlplane.AIRun, error) {
	q := `SELECT ` + aiRunColumns + ` FROM ai_runs WHERE 1=1`
	args := []any{}
	if projectID != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.AIRun{}
	for rows.Next() {
		v, e := scanAIRun(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
