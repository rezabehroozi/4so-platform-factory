package persistence

import (
	"context"
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
