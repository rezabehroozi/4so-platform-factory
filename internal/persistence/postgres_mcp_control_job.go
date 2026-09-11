package persistence

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const mcpControlJobColumns = `id,revision,tool_name,family,action,method,route,state,risk,actor_id,authentication,oauth_client_id,delegation_profile,organization_id,project_id,request_id,idempotency_key,request_digest,attempt,lease_owner,lease_expires_at,fence_token,COALESCE(status_code,0),COALESCE(response_digest,''),response,error_code,COALESCE(recovery_resolution,''),COALESCE(recovery_readback_digest,''),COALESCE(recovery_evidence_digest,''),COALESCE(recovered_by,''),recovered_at,created_at,updated_at`

func scanMCPControlJob(row interface{ Scan(...any) error }) (controlplane.MCPControlJob, error) {
	var v controlplane.MCPControlJob
	err := row.Scan(&v.ID, &v.Revision, &v.ToolName, &v.Family, &v.Action, &v.Method, &v.Route, &v.State, &v.Risk, &v.ActorID, &v.Authentication, &v.OAuthClientID, &v.DelegationProfile, &v.OrganizationID, &v.ProjectID, &v.RequestID, &v.IdempotencyKey, &v.RequestDigest, &v.Attempt, &v.LeaseOwner, &v.LeaseExpiresAt, &v.FenceToken, &v.StatusCode, &v.ResponseDigest, &v.Response, &v.ErrorCode, &v.RecoveryResolution, &v.RecoveryReadbackDigest, &v.RecoveryEvidenceDigest, &v.RecoveredBy, &v.RecoveredAt, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func (s *PostgresStore) CreateMCPControlJob(ctx context.Context, input controlplane.MCPControlJob, lease time.Duration, now time.Time) (controlplane.MCPControlJob, bool, error) {
	v, err := controlplane.NormalizeMCPControlJob(input, lease, now.UTC())
	if err != nil {
		return controlplane.MCPControlJob{}, false, err
	}
	var out controlplane.MCPControlJob
	replay := false
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		existing, e := scanMCPControlJob(tx.QueryRowContext(ctx, `SELECT `+mcpControlJobColumns+` FROM mcp_control_jobs WHERE actor_id=$1 AND oauth_client_id=$2 AND delegation_profile=$3 AND organization_id=$4 AND project_id=$5 AND tool_name=$6 AND idempotency_key=$7 FOR UPDATE`, v.ActorID, v.OAuthClientID, v.DelegationProfile, v.OrganizationID, v.ProjectID, v.ToolName, v.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != v.RequestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			if existing.State == controlplane.MCPControlJobRunning && !existing.LeaseExpiresAt.After(now.UTC()) {
				existing, e = scanMCPControlJob(tx.QueryRowContext(ctx, `UPDATE mcp_control_jobs SET revision=revision+1,state='RECOVERY_REQUIRED',error_code='MCP_CONTROL_JOB_OUTCOME_INDETERMINATE',lease_expires_at=NULL,updated_at=$2 WHERE id=$1 RETURNING `+mcpControlJobColumns, existing.ID, utcNow(s.now)))
				if e != nil {
					return mapDBError(e)
				}
				if e = s.appendAuditTx(ctx, tx, v.ActorID, "mcp.control_job.recovery_required", "mcp-control-job", existing.ID, existing.Revision, "", map[string]any{"authority": controlplane.MCPDurableControlJobAuthority, "requestDigest": existing.RequestDigest}); e != nil {
					return e
				}
			} else if e != nil {
				return e
			}
			out = existing
			replay = true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		v.ID = s.id("mcpjob")
		stamp := utcNow(s.now)
		v.CreatedAt = stamp
		v.UpdatedAt = stamp
		v.Revision = 1
		out, e = scanMCPControlJob(tx.QueryRowContext(ctx, `INSERT INTO mcp_control_jobs(id,revision,tool_name,family,action,method,route,state,risk,actor_id,authentication,oauth_client_id,delegation_profile,organization_id,project_id,request_id,idempotency_key,request_digest,attempt,lease_owner,lease_expires_at,fence_token,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,'RUNNING',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,1,$17,$18,1,$19,$19) RETURNING `+mcpControlJobColumns, v.ID, v.ToolName, v.Family, v.Action, v.Method, v.Route, v.Risk, v.ActorID, v.Authentication, v.OAuthClientID, v.DelegationProfile, v.OrganizationID, v.ProjectID, v.RequestID, v.IdempotencyKey, v.RequestDigest, v.LeaseOwner, v.LeaseExpiresAt, stamp))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, v.ActorID, "mcp.control_job.created", "mcp-control-job", out.ID, out.Revision, "", map[string]any{"authority": controlplane.MCPDurableControlJobAuthority, "tool": out.ToolName, "requestDigest": out.RequestDigest, "oauthClientId": out.OAuthClientID, "delegationProfile": out.DelegationProfile})
	})
	return out, replay, err
}

func (s *PostgresStore) CompleteMCPControlJob(ctx context.Context, id string, expected, fence int64, status int, response []byte, actor string) (controlplane.MCPControlJob, error) {
	if len(response) > 65536 {
		return controlplane.MCPControlJob{}, controlplane.ErrValidation
	}
	state := "FAILED"
	if status >= 200 && status < 400 {
		state = "SUCCEEDED"
	}
	digest := controlplane.OperationRequestPayloadDigest(response)
	var out controlplane.MCPControlJob
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		out, e = scanMCPControlJob(tx.QueryRowContext(ctx, `UPDATE mcp_control_jobs SET revision=revision+1,state=$4,status_code=$5,response=$6,response_digest=$7,lease_expires_at=NULL,updated_at=$8 WHERE id=$1 AND revision=$2 AND fence_token=$3 AND state='RUNNING' RETURNING `+mcpControlJobColumns, strings.TrimSpace(id), expected, fence, state, status, response, digest, utcNow(s.now)))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, strings.TrimSpace(actor), "mcp.control_job.completed", "mcp-control-job", out.ID, out.Revision, "", map[string]any{"authority": controlplane.MCPDurableControlJobAuthority, "state": out.State, "statusCode": status, "responseDigest": out.ResponseDigest})
	})
	return out, err
}
func (s *PostgresStore) MarkMCPControlJobRecoveryRequired(ctx context.Context, id string, expected int64, actor string) (controlplane.MCPControlJob, error) {
	var out controlplane.MCPControlJob
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		out, e = scanMCPControlJob(tx.QueryRowContext(ctx, `UPDATE mcp_control_jobs SET revision=revision+1,state='RECOVERY_REQUIRED',error_code='MCP_CONTROL_JOB_OUTCOME_INDETERMINATE',lease_expires_at=NULL,updated_at=$3 WHERE id=$1 AND revision=$2 AND state='RUNNING' RETURNING `+mcpControlJobColumns, strings.TrimSpace(id), expected, utcNow(s.now)))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, strings.TrimSpace(actor), "mcp.control_job.recovery_required", "mcp-control-job", out.ID, out.Revision, "", map[string]any{"authority": controlplane.MCPDurableControlJobAuthority, "requestDigest": out.RequestDigest})
	})
	return out, err
}
func (s *PostgresStore) ResolveMCPControlJobRecovery(ctx context.Context, id string, expected int64, resolution controlplane.MCPControlJobRecoveryResolution, readbackDigest, evidenceDigest, actor string) (controlplane.MCPControlJob, error) {
	id = strings.TrimSpace(id)
	var out controlplane.MCPControlJob
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, e := scanMCPControlJob(tx.QueryRowContext(ctx, `SELECT `+mcpControlJobColumns+` FROM mcp_control_jobs WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		resolved, e := controlplane.ApplyMCPControlJobRecoveryResolution(current, expected, resolution, readbackDigest, evidenceDigest, actor, utcNow(s.now))
		if e != nil {
			return e
		}
		out, e = scanMCPControlJob(tx.QueryRowContext(ctx, `UPDATE mcp_control_jobs SET revision=$2,state=$3,status_code=$4,response=$5,response_digest=$6,error_code=$7,lease_expires_at=NULL,recovery_resolution=$8,recovery_readback_digest=$9,recovery_evidence_digest=$10,recovered_by=$11,recovered_at=$12,updated_at=$13 WHERE id=$1 AND revision=$14 AND state='RECOVERY_REQUIRED' RETURNING `+mcpControlJobColumns, id, resolved.Revision, resolved.State, resolved.StatusCode, resolved.Response, resolved.ResponseDigest, resolved.ErrorCode, resolved.RecoveryResolution, resolved.RecoveryReadbackDigest, resolved.RecoveryEvidenceDigest, resolved.RecoveredBy, resolved.RecoveredAt, resolved.UpdatedAt, expected))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, strings.TrimSpace(actor), "mcp.control_job.recovery_resolved", "mcp-control-job", out.ID, out.Revision, "", map[string]any{"authority": controlplane.MCPControlJobRecoveryAuthority, "resolution": out.RecoveryResolution, "readbackDigest": out.RecoveryReadbackDigest, "evidenceDigest": out.RecoveryEvidenceDigest, "automaticRedispatch": false})
	})
	return out, err
}

func (s *PostgresStore) GetMCPControlJob(ctx context.Context, id string) (controlplane.MCPControlJob, error) {
	v, err := scanMCPControlJob(s.db.QueryRowContext(ctx, `SELECT `+mcpControlJobColumns+` FROM mcp_control_jobs WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}
func (s *PostgresStore) ListMCPControlJobs(ctx context.Context, org, project string, limit int) ([]controlplane.MCPControlJob, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + mcpControlJobColumns + ` FROM mcp_control_jobs WHERE 1=1`
	args := []any{}
	n := 1
	if strings.TrimSpace(org) != "" {
		q += ` AND organization_id=$` + strconv.Itoa(n)
		args = append(args, strings.TrimSpace(org))
		n++
	}
	if strings.TrimSpace(project) != "" {
		q += ` AND project_id=$` + strconv.Itoa(n)
		args = append(args, strings.TrimSpace(project))
		n++
	}
	q += ` ORDER BY created_at DESC,id LIMIT $` + strconv.Itoa(n)
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.MCPControlJob{}
	for rows.Next() {
		v, e := scanMCPControlJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
