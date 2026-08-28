package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const runtimeClosureColumns = `id,project_id,cluster_id,baseline_deployment_id,COALESCE(runtime_verification_id,''),revision,state::text,desired_digest,observed_digest,evidence_digest,next_action,summary,last_error,requested_by,idempotency_key,request_digest,started_at,finished_at,created_at,updated_at`

func scanRuntimeClosureCampaign(row interface{ Scan(...any) error }) (controlplane.RuntimeClosureCampaign, error) {
	var v controlplane.RuntimeClosureCampaign
	var state string
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.BaselineDeploymentID, &v.RuntimeVerificationID, &v.Revision, &state, &v.DesiredDigest, &v.ObservedDigest, &v.EvidenceDigest, &v.NextAction, &v.Summary, &v.LastError, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest, &v.StartedAt, &v.FinishedAt, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.RuntimeClosureCampaignState(state)
	return v, err
}

func postgresRuntimeClosureTransitionAllowed(from, to controlplane.RuntimeClosureCampaignState) bool {
	if from == to {
		return true
	}
	switch from {
	case controlplane.RuntimeClosureWaitingBaseline:
		return to == controlplane.RuntimeClosureWaitingApproval || to == controlplane.RuntimeClosureWaitingVerification || to == controlplane.RuntimeClosureFailed
	case controlplane.RuntimeClosureWaitingApproval:
		return to == controlplane.RuntimeClosureWaitingBaseline || to == controlplane.RuntimeClosureWaitingVerification || to == controlplane.RuntimeClosureFailed
	case controlplane.RuntimeClosureWaitingVerification:
		return to == controlplane.RuntimeClosureSucceeded || to == controlplane.RuntimeClosureFailed
	case controlplane.RuntimeClosureFailed:
		return to == controlplane.RuntimeClosureWaitingBaseline || to == controlplane.RuntimeClosureWaitingApproval || to == controlplane.RuntimeClosureWaitingVerification
	default:
		return false
	}
}

func (s *PostgresStore) CreateRuntimeClosureCampaign(ctx context.Context, v controlplane.RuntimeClosureCampaign, actor string) (controlplane.RuntimeClosureCampaign, bool, error) {
	if err := controlplane.ValidateRuntimeClosureCampaign(&v); err != nil {
		return controlplane.RuntimeClosureCampaign{}, false, err
	}
	var out controlplane.RuntimeClosureCampaign
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanRuntimeClosureCampaign(tx.QueryRowContext(ctx, `SELECT `+runtimeClosureColumns+` FROM runtime_closure_campaigns WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != v.RequestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			out, replay = existing, true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		var projectID, clusterID, desired string
		if e = tx.QueryRowContext(ctx, `SELECT project_id,cluster_id,desired_digest FROM baseline_deployments WHERE id=$1`, v.BaselineDeploymentID).Scan(&projectID, &clusterID, &desired); e != nil {
			return mapDBError(e)
		}
		if projectID != v.ProjectID || clusterID != v.ClusterID || desired != v.DesiredDigest {
			return controlplane.ErrNotFound
		}
		var clusterProject string
		if e = tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1`, v.ClusterID).Scan(&clusterProject); e != nil {
			return mapDBError(e)
		}
		if clusterProject != v.ProjectID {
			return controlplane.ErrNotFound
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("rcc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.RequestedBy = actor
		v.StartedAt = &now
		if v.State == controlplane.RuntimeClosureFailed {
			v.FinishedAt = &now
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO runtime_closure_campaigns(id,project_id,cluster_id,baseline_deployment_id,revision,state,desired_digest,observed_digest,evidence_digest,next_action,summary,last_error,requested_by,idempotency_key,request_digest,started_at,finished_at,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17)`, v.ID, v.ProjectID, v.ClusterID, v.BaselineDeploymentID, string(v.State), v.DesiredDigest, v.ObservedDigest, v.EvidenceDigest, v.NextAction, v.Summary, v.LastError, actor, v.IdempotencyKey, v.RequestDigest, v.StartedAt, v.FinishedAt, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "runtime_closure.created", "runtimeClosureCampaign", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "baselineDeploymentId": v.BaselineDeploymentID, "state": v.State}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "runtimeClosureCampaign", v.ID, "runtime_closure.created", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}

func (s *PostgresStore) GetRuntimeClosureCampaign(ctx context.Context, id string) (controlplane.RuntimeClosureCampaign, error) {
	v, err := scanRuntimeClosureCampaign(s.db.QueryRowContext(ctx, `SELECT `+runtimeClosureColumns+` FROM runtime_closure_campaigns WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListRuntimeClosureCampaigns(ctx context.Context, projectID, clusterID string) ([]controlplane.RuntimeClosureCampaign, error) {
	query := `SELECT ` + runtimeClosureColumns + ` FROM runtime_closure_campaigns WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(projectID) != "" {
		args = append(args, strings.TrimSpace(projectID))
		query += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	if strings.TrimSpace(clusterID) != "" {
		args = append(args, strings.TrimSpace(clusterID))
		query += fmt.Sprintf(" AND cluster_id=$%d", len(args))
	}
	query += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.RuntimeClosureCampaign{}
	for rows.Next() {
		v, err := scanRuntimeClosureCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateRuntimeClosureCampaign(ctx context.Context, id string, expected int64, update controlplane.RuntimeClosureCampaignUpdate, actor string) (controlplane.RuntimeClosureCampaign, error) {
	var out controlplane.RuntimeClosureCampaign
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanRuntimeClosureCampaign(tx.QueryRowContext(ctx, `SELECT `+runtimeClosureColumns+` FROM runtime_closure_campaigns WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if !postgresRuntimeClosureTransitionAllowed(v.State, update.State) {
			return controlplane.ErrInvalidTransition
		}
		update.RuntimeVerificationID = strings.TrimSpace(update.RuntimeVerificationID)
		if v.RuntimeVerificationID != "" && update.RuntimeVerificationID != "" && v.RuntimeVerificationID != update.RuntimeVerificationID {
			return controlplane.ErrValidation
		}
		if update.RuntimeVerificationID != "" {
			var projectID, clusterID, baselineID string
			if e = tx.QueryRowContext(ctx, `SELECT project_id,cluster_id,baseline_deployment_id FROM runtime_verifications WHERE id=$1`, update.RuntimeVerificationID).Scan(&projectID, &clusterID, &baselineID); e != nil {
				return mapDBError(e)
			}
			if projectID != v.ProjectID || clusterID != v.ClusterID || baselineID != v.BaselineDeploymentID {
				return controlplane.ErrNotFound
			}
			v.RuntimeVerificationID = update.RuntimeVerificationID
		}
		if update.State == controlplane.RuntimeClosureSucceeded {
			var state, desired, observed string
			if v.RuntimeVerificationID == "" {
				return controlplane.ErrInvalidTransition
			}
			if e = tx.QueryRowContext(ctx, `SELECT state::text,desired_digest,observed_digest FROM runtime_verifications WHERE id=$1`, v.RuntimeVerificationID).Scan(&state, &desired, &observed); e != nil {
				return mapDBError(e)
			}
			if state != string(controlplane.RuntimeVerificationSucceeded) || desired != observed || desired != v.DesiredDigest || !strings.HasPrefix(strings.TrimSpace(update.EvidenceDigest), "sha256:") {
				return controlplane.ErrInvalidTransition
			}
		}
		if update.State == controlplane.RuntimeClosureFailed && strings.TrimSpace(update.LastError) == "" {
			return controlplane.ErrValidation
		}
		if strings.TrimSpace(update.NextAction) == "" {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		v.State = update.State
		v.ObservedDigest = strings.TrimSpace(update.ObservedDigest)
		v.EvidenceDigest = strings.TrimSpace(update.EvidenceDigest)
		v.NextAction = strings.TrimSpace(update.NextAction)
		v.Summary = strings.TrimSpace(update.Summary)
		v.LastError = strings.TrimSpace(update.LastError)
		if v.State == controlplane.RuntimeClosureSucceeded || v.State == controlplane.RuntimeClosureFailed {
			v.FinishedAt = &now
		} else {
			v.FinishedAt = nil
		}
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE runtime_closure_campaigns SET runtime_verification_id=NULLIF($2,''),revision=$3,state=$4,observed_digest=$5,evidence_digest=$6,next_action=$7,summary=$8,last_error=$9,finished_at=$10,updated_at=$11 WHERE id=$1`, v.ID, v.RuntimeVerificationID, v.Revision, string(v.State), v.ObservedDigest, v.EvidenceDigest, v.NextAction, v.Summary, v.LastError, v.FinishedAt, now)
		if e != nil {
			return mapDBError(e)
		}
		action := "runtime_closure." + strings.ToLower(string(v.State))
		if e = s.appendAuditTx(ctx, tx, actor, action, "runtimeClosureCampaign", v.ID, v.Revision, "", map[string]any{"nextAction": v.NextAction, "runtimeVerificationId": v.RuntimeVerificationID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "runtimeClosureCampaign", v.ID, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
