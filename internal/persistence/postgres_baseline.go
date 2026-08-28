package persistence

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
)

const baselineDeploymentColumns = `id,project_id,cluster_id,revision,baseline_id,baseline_version,target_namespace,state::text,risk,desired_digest,observed_digest,previous_digest,request_digest,idempotency_key,requested_by,approved_by,approved_at,started_at,finished_at,plan,plan_created_at,plan_expires_at,plan_inventory_digest,plan_impact,plan_impact_digest,plan_context_digest,evidence,evidence_digest,plan_revalidation_count,last_error,task_attempt,task_fence_token,task_lease_expires_at,pending_action,COALESCE(destructive_operation_id,''),source_type,source_id,source_version,created_at,updated_at`

func scanBaselineDeployment(row interface{ Scan(...any) error }) (controlplane.BaselineDeployment, error) {
	var v controlplane.BaselineDeployment
	var state string
	var planRaw, impactRaw, evidenceRaw []byte
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.Revision, &v.BaselineID, &v.BaselineVersion, &v.TargetNamespace, &state, &v.Risk, &v.DesiredDigest, &v.ObservedDigest, &v.PreviousDigest, &v.RequestDigest, &v.IdempotencyKey, &v.RequestedBy, &v.ApprovedBy, &v.ApprovedAt, &v.StartedAt, &v.FinishedAt, &planRaw, &v.PlanCreatedAt, &v.PlanExpiresAt, &v.PlanInventoryDigest, &impactRaw, &v.PlanImpactDigest, &v.PlanContextDigest, &evidenceRaw, &v.EvidenceDigest, &v.PlanRevalidationCount, &v.LastError, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskLeaseExpiresAt, &v.PendingAction, &v.DestructiveOperationID, &v.SourceType, &v.SourceID, &v.SourceVersion, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.BaselineDeploymentState(state)
	if len(planRaw) > 0 {
		if decodeErr := decodeJSONColumn(planRaw, &v.Plan, "postgres_baseline.Plan"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(impactRaw) > 0 {
		if decodeErr := decodeJSONColumn(impactRaw, &v.PlanImpact, "postgres_baseline.PlanImpact"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(evidenceRaw) > 0 {
		if decodeErr := decodeJSONColumn(evidenceRaw, &v.Evidence, "postgres_baseline.Evidence"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}

func secureTokenEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *PostgresStore) CreateBaselineDeployment(ctx context.Context, v controlplane.BaselineDeployment, actor string) (controlplane.BaselineDeployment, bool, error) {
	if err := controlplane.ValidateBaselineDeploymentCreate(&v); err != nil {
		return controlplane.BaselineDeployment{}, false, err
	}
	var out controlplane.BaselineDeployment
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
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
		var clusterProject string
		if e = tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1`, v.ClusterID).Scan(&clusterProject); e != nil {
			return mapDBError(e)
		}
		if clusterProject != v.ProjectID {
			return controlplane.ErrNotFound
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("bld"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.BaselineDeploymentPlanning
		v.PendingAction = "PLAN"
		v.RequestedBy = actor
		v.Plan = nil
		_, e = tx.ExecContext(ctx, `INSERT INTO baseline_deployments(id,project_id,cluster_id,revision,baseline_id,baseline_version,target_namespace,state,risk,desired_digest,request_digest,idempotency_key,requested_by,pending_action,source_type,source_id,source_version,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17)`, v.ID, v.ProjectID, v.ClusterID, v.BaselineID, v.BaselineVersion, v.TargetNamespace, string(v.State), v.Risk, v.DesiredDigest, v.RequestDigest, v.IdempotencyKey, actor, v.PendingAction, v.SourceType, v.SourceID, v.SourceVersion, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "baseline_deployment.created", "baselineDeployment", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "baselineId": v.BaselineID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "baselineDeployment", v.ID, "baseline_deployment.planning_requested", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}

func (s *PostgresStore) GetBaselineDeployment(ctx context.Context, id string) (controlplane.BaselineDeployment, error) {
	v, e := scanBaselineDeployment(s.db.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListBaselineDeployments(ctx context.Context, projectID, clusterID string) ([]controlplane.BaselineDeployment, error) {
	q := `SELECT ` + baselineDeploymentColumns + ` FROM baseline_deployments WHERE 1=1`
	args := []any{}
	if projectID != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	if clusterID != "" {
		args = append(args, clusterID)
		q += fmt.Sprintf(" AND cluster_id=$%d", len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.BaselineDeployment{}
	for rows.Next() {
		v, e := scanBaselineDeployment(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ApproveBaselineDeployment(ctx context.Context, id string, expected int64, actor string) (controlplane.BaselineDeployment, error) {
	var out controlplane.BaselineDeployment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.BaselineDeploymentAwaitingApproval {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		var inventoryDigest string
		if e = tx.QueryRowContext(ctx, `SELECT inventory_digest FROM managed_clusters WHERE id=$1 FOR SHARE`, v.ClusterID).Scan(&inventoryDigest); e != nil {
			return mapDBError(e)
		}
		if !v.PlanImpact.ApprovalReady {
			return fmt.Errorf("%w: plan impact has approval blockers", controlplane.ErrPrerequisite)
		}
		if !controlplane.BaselinePlanFresh(v, controlplane.ManagedCluster{InventoryDigest: inventoryDigest}, now) {
			return controlplane.ErrPlanStale
		}
		v.State = controlplane.BaselineDeploymentQueued
		v.PendingAction = "APPLY"
		v.ApprovedBy = actor
		v.ApprovedAt = &now
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE baseline_deployments SET revision=$2,state=$3,pending_action='APPLY',approved_by=$4,approved_at=$5,updated_at=$5 WHERE id=$1`, id, v.Revision, string(v.State), actor, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "baseline_deployment.approved", "baselineDeployment", id, v.Revision, "", map[string]any{"desiredDigest": v.DesiredDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "baselineDeployment", id, "baseline_deployment.queued", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) RevalidateBaselineDeployment(ctx context.Context, id string, expected int64, actor string) (controlplane.BaselineDeployment, error) {
	var out controlplane.BaselineDeployment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.BaselineDeploymentAwaitingApproval && v.State != controlplane.BaselineDeploymentQueued {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.State = controlplane.BaselineDeploymentPlanning
		v.PendingAction = "PLAN"
		v.ApprovedBy = ""
		v.ApprovedAt = nil
		v.Plan = nil
		v.PlanCreatedAt = nil
		v.PlanExpiresAt = nil
		v.PlanInventoryDigest = ""
		v.PlanImpact = controlplane.BaselinePlanImpact{}
		v.PlanImpactDigest = ""
		v.PlanContextDigest = ""
		v.PlanRevalidationCount++
		v.LastError = "plan revalidation requested"
		v.FinishedAt = nil
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE baseline_deployments SET revision=$2,state='PLANNING',pending_action='PLAN',approved_by='',approved_at=NULL,plan='[]'::jsonb,plan_created_at=NULL,plan_expires_at=NULL,plan_inventory_digest='',plan_impact='{}'::jsonb,plan_impact_digest='',plan_context_digest='',evidence='[]'::jsonb,evidence_digest='',plan_revalidation_count=$3,last_error=$4,finished_at=NULL,updated_at=$5 WHERE id=$1`, id, v.Revision, v.PlanRevalidationCount, v.LastError, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "baseline_deployment.revalidation_requested", "baselineDeployment", id, v.Revision, "", map[string]any{"revalidationCount": v.PlanRevalidationCount}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "baselineDeployment", id, "baseline_deployment.planning_requested", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) RetryBaselineDeployment(ctx context.Context, id string, expected int64, actor string) (controlplane.BaselineDeployment, error) {
	var out controlplane.BaselineDeployment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.BaselineDeploymentFailed {
			return controlplane.ErrInvalidTransition
		}
		switch v.PendingAction {
		case "PLAN":
			v.State = controlplane.BaselineDeploymentPlanning
		case "APPLY":
			v.State = controlplane.BaselineDeploymentQueued
		case "ROLLBACK":
			return fmt.Errorf("%w: destructive rollback retry requires a fresh recovery-bound request", controlplane.ErrPrerequisite)
		default:
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		v.LastError, v.FinishedAt, v.Revision, v.UpdatedAt = "", nil, v.Revision+1, now
		_, e = tx.ExecContext(ctx, `UPDATE baseline_deployments SET revision=$2,state=$3,last_error='',finished_at=NULL,updated_at=$4 WHERE id=$1`, id, v.Revision, string(v.State), now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "baseline_deployment.retry_queued", "baselineDeployment", id, v.Revision, "", map[string]any{"action": v.PendingAction}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "baselineDeployment", id, "baseline_deployment.retry_queued", v)
	})
	return out, err
}

func (s *PostgresStore) QueueBaselineRollback(ctx context.Context, id string, expected int64, actor, recoveryCheckpointID, requestDigest string) (controlplane.BaselineDeployment, error) {
	var out controlplane.BaselineDeployment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.BaselineDeploymentSucceeded && v.State != controlplane.BaselineDeploymentFailed && v.State != controlplane.BaselineDeploymentRollbackQueued {
			return controlplane.ErrInvalidTransition
		}
		if v.State == controlplane.BaselineDeploymentRollbackQueued {
			if e = s.cancelOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, actor, "recovery checkpoint superseded before rollback claim"); e != nil {
				return e
			}
		}
		op, e := s.createOwnerDestructiveOperationTx(ctx, tx, v.ProjectID, v.ClusterID, controlplane.OwnerOperationBaselineRollback, v.ID, v.Revision, v.DesiredDigest, recoveryCheckpointID, actor, requestDigest, false)
		if e != nil {
			return e
		}
		v.DestructiveOperationID = op.ID
		now := utcNow(s.now)
		v.State = controlplane.BaselineDeploymentRollbackQueued
		v.PendingAction = "ROLLBACK"
		v.LastError = ""
		v.FinishedAt = nil
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE baseline_deployments SET revision=$2,state=$3,pending_action='ROLLBACK',destructive_operation_id=$4,last_error='',finished_at=NULL,updated_at=$5 WHERE id=$1`, id, v.Revision, string(v.State), v.DestructiveOperationID, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "baseline_deployment.rollback_queued", "baselineDeployment", id, v.Revision, "", nil); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "baselineDeployment", id, "baseline_deployment.rollback_queued", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) NextBaselineTask(ctx context.Context, clusterID, tokenDigest string) (controlplane.BaselineDeployment, error) {
	var out controlplane.BaselineDeployment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		now := utcNow(s.now)
		v, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE cluster_id=$1 AND (state IN ('QUEUED','ROLLBACK_QUEUED') OR (state IN ('PLANNING','APPLYING','ROLLING_BACK') AND (task_lease_expires_at IS NULL OR task_lease_expires_at<=$2))) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, clusterID, now))
		if e != nil {
			return mapDBError(e)
		}
		if v.State == controlplane.BaselineDeploymentRollingBack && v.TaskLeaseExpiresAt != nil {
			message := "baseline rollback task lease expired; explicit recovery-bound retry is required"
			if _, e = s.finishOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, false, message, "cluster-agent"); e != nil {
				return e
			}
			v.State, v.LastError, v.TaskLeaseExpiresAt = controlplane.BaselineDeploymentFailed, message, nil
			v.FinishedAt = &now
			v.Revision++
			v.UpdatedAt = now
			if _, e = tx.ExecContext(ctx, `UPDATE baseline_deployments SET revision=$2,state='FAILED',last_error=$3,task_lease_expires_at=NULL,finished_at=$4,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, message, now); e != nil {
				return e
			}
			if e = s.appendAuditTx(ctx, tx, "cluster-agent", "baseline_deployment.task.lease_expired", "baselineDeployment", v.ID, v.Revision, "", map[string]any{"action": "ROLLBACK", "taskFenceToken": v.TaskFenceToken}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "baselineDeployment", v.ID, "baseline_deployment.failed", v); e != nil {
				return e
			}
			return controlplane.ErrNotFound
		}
		if v.State == controlplane.BaselineDeploymentQueued {
			var inventoryDigest string
			if e = tx.QueryRowContext(ctx, `SELECT inventory_digest FROM managed_clusters WHERE id=$1 FOR SHARE`, v.ClusterID).Scan(&inventoryDigest); e != nil {
				return mapDBError(e)
			}
			if !controlplane.BaselinePlanFresh(v, controlplane.ManagedCluster{InventoryDigest: inventoryDigest}, now) {
				v.State = controlplane.BaselineDeploymentPlanning
				v.PendingAction = "PLAN"
				v.ApprovedBy, v.ApprovedAt = "", nil
				v.Plan, v.PlanCreatedAt, v.PlanExpiresAt = nil, nil, nil
				v.PlanInventoryDigest = ""
				v.PlanImpact = controlplane.BaselinePlanImpact{}
				v.PlanImpactDigest, v.PlanContextDigest = "", ""
				v.PlanRevalidationCount++
				v.LastError = "approved plan became stale before apply; a fresh read-only plan is required"
				v.FinishedAt = nil
				v.TaskLeaseExpiresAt = nil
				v.Revision++
				v.UpdatedAt = now
				if _, e = tx.ExecContext(ctx, `UPDATE baseline_deployments SET revision=$2,state='PLANNING',pending_action='PLAN',approved_by='',approved_at=NULL,plan='[]'::jsonb,plan_created_at=NULL,plan_expires_at=NULL,plan_inventory_digest='',plan_impact='{}'::jsonb,plan_impact_digest='',plan_context_digest='',evidence='[]'::jsonb,evidence_digest='',plan_revalidation_count=$3,last_error=$4,finished_at=NULL,task_lease_expires_at=NULL,updated_at=$5 WHERE id=$1`, v.ID, v.Revision, v.PlanRevalidationCount, v.LastError, now); e != nil {
					return e
				}
				if e = s.appendAuditTx(ctx, tx, "cluster-agent", "baseline_deployment.plan_stale", "baselineDeployment", v.ID, v.Revision, "", map[string]any{"inventoryDigest": inventoryDigest}); e != nil {
					return e
				}
				if e = s.appendOutboxTx(ctx, tx, "baselineDeployment", v.ID, "baseline_deployment.planning_requested", v); e != nil {
					return e
				}
			}
		}
		action := "PLAN"
		switch v.State {
		case controlplane.BaselineDeploymentQueued:
			action = "APPLY"
			v.State = controlplane.BaselineDeploymentApplying
			if v.StartedAt == nil {
				v.StartedAt = &now
			}
		case controlplane.BaselineDeploymentApplying:
			action = "APPLY"
		case controlplane.BaselineDeploymentRollbackQueued:
			action = "ROLLBACK"
			if _, e = s.startOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, v.ProjectID, v.ClusterID, "cluster-agent"); e != nil {
				return e
			}
			v.State = controlplane.BaselineDeploymentRollingBack
			if v.StartedAt == nil {
				v.StartedAt = &now
			}
		case controlplane.BaselineDeploymentRollingBack:
			action = "ROLLBACK"
		}
		lease := now.Add(controlplane.AgentTaskLeaseDuration)
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseExpiresAt = &lease
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE baseline_deployments SET revision=$2,state=$3,task_attempt=$4,task_fence_token=$5,task_lease_expires_at=$6,started_at=$7,updated_at=$8 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.TaskAttempt, v.TaskFenceToken, lease, v.StartedAt, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "baseline_deployment.task_claimed", "baselineDeployment", v.ID, v.Revision, "", map[string]any{"action": action, "attempt": v.TaskAttempt, "taskFenceToken": v.TaskFenceToken, "leaseExpiresAt": lease}); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) ReportBaselineTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result controlplane.BaselineTaskResult) (controlplane.BaselineDeployment, error) {
	var out controlplane.BaselineDeployment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		v, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1 FOR UPDATE`, result.DeploymentID))
		if e != nil {
			return mapDBError(e)
		}
		if v.ClusterID != clusterID {
			return controlplane.ErrNotFound
		}
		now := utcNow(s.now)
		if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
			return controlplane.ErrConflict
		}
		switch strings.ToUpper(result.Action) {
		case "PLAN":
			if v.State != controlplane.BaselineDeploymentPlanning {
				return controlplane.ErrInvalidTransition
			}
			if !result.Success {
				v.State = controlplane.BaselineDeploymentFailed
				v.LastError = strings.TrimSpace(result.Error)
				v.FinishedAt = &now
			} else {
				v.Plan = append([]controlplane.BaselinePlanChange(nil), result.Changes...)
				v.PreviousDigest = result.ObservedDigest
				v.ObservedDigest = result.ObservedDigest
				var inventoryDigest string
				if e = tx.QueryRowContext(ctx, `SELECT inventory_digest FROM managed_clusters WHERE id=$1 FOR SHARE`, v.ClusterID).Scan(&inventoryDigest); e != nil {
					return mapDBError(e)
				}
				if strings.TrimSpace(inventoryDigest) == "" || !strings.HasPrefix(inventoryDigest, "sha256:") {
					return fmt.Errorf("%w: cluster inventory is required before a plan can be approved", controlplane.ErrPrerequisite)
				}
				if e = controlplane.ValidatePlanningImpact(result.Impact, inventoryDigest, result.Changes); e != nil {
					return e
				}
				v.PlanImpact = result.Impact
				v.PlanImpactDigest = result.Impact.Digest
				v.PlanCreatedAt = &now
				expires := now.Add(controlplane.ExecutionPlanTTL)
				v.PlanExpiresAt = &expires
				v.PlanInventoryDigest = inventoryDigest
				v.PlanContextDigest = controlplane.ExecutionPlanContextDigest(v.DesiredDigest, v.ObservedDigest, inventoryDigest, v.PlanImpactDigest)
				v.State = controlplane.BaselineDeploymentAwaitingApproval
				v.PendingAction = ""
				v.LastError = ""
			}
		case "APPLY":
			if v.State != controlplane.BaselineDeploymentApplying {
				return controlplane.ErrInvalidTransition
			}
			if !result.Success || result.ObservedDigest != v.DesiredDigest {
				v.State = controlplane.BaselineDeploymentFailed
				v.LastError = strings.TrimSpace(result.Error)
				if v.LastError == "" {
					v.LastError = "observed digest does not match desired digest"
				}
			} else {
				sealed, evidenceDigest, evidenceErr := controlplane.SealBaselineEvidence(v.PlanImpact.Evidence, v.ID, result.Evidence, now)
				if evidenceErr != nil {
					return fmt.Errorf("%w: baseline completion evidence invalid: %v", controlplane.ErrValidation, evidenceErr)
				}
				v.State = controlplane.BaselineDeploymentSucceeded
				v.PendingAction = ""
				v.ObservedDigest = result.ObservedDigest
				v.Evidence = sealed
				v.EvidenceDigest = evidenceDigest
				v.LastError = ""
			}
			v.FinishedAt = &now
		case "ROLLBACK":
			if v.State != controlplane.BaselineDeploymentRollingBack {
				return controlplane.ErrInvalidTransition
			}
			if !result.Success {
				v.State = controlplane.BaselineDeploymentFailed
				v.LastError = strings.TrimSpace(result.Error)
			} else {
				v.State = controlplane.BaselineDeploymentRolledBack
				v.PendingAction = ""
				v.ObservedDigest = result.ObservedDigest
				v.LastError = ""
			}
			v.FinishedAt = &now
			if _, e = s.finishOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, result.Success, v.LastError, "cluster-agent"); e != nil {
				return e
			}
		default:
			return controlplane.ErrValidation
		}
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		planRaw, _ := json.Marshal(v.Plan)
		impactRaw, _ := json.Marshal(v.PlanImpact)
		evidenceRaw, _ := json.Marshal(v.Evidence)
		_, e = tx.ExecContext(ctx, `UPDATE baseline_deployments SET revision=$2,state=$3,observed_digest=$4,previous_digest=$5,plan=$6::jsonb,plan_created_at=$7,plan_expires_at=$8,plan_inventory_digest=$9,plan_impact=$10::jsonb,plan_impact_digest=$11,plan_context_digest=$12,evidence=$13::jsonb,evidence_digest=$14,plan_revalidation_count=$15,last_error=$16,finished_at=$17,pending_action=$18,task_lease_expires_at=NULL,updated_at=$19 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.ObservedDigest, v.PreviousDigest, planRaw, v.PlanCreatedAt, v.PlanExpiresAt, v.PlanInventoryDigest, impactRaw, v.PlanImpactDigest, v.PlanContextDigest, evidenceRaw, v.EvidenceDigest, v.PlanRevalidationCount, v.LastError, v.FinishedAt, v.PendingAction, now)
		if e != nil {
			return e
		}
		action := "baseline_deployment." + strings.ToLower(string(v.State))
		auditPayload := map[string]any{"observedDigest": result.ObservedDigest, "taskFenceToken": result.TaskFenceToken}
		if strings.EqualFold(result.Action, "PLAN") && result.Success {
			auditPayload["planImpactDigest"] = v.PlanImpactDigest
			auditPayload["approvalReady"] = v.PlanImpact.ApprovalReady
			auditPayload["disruption"] = v.PlanImpact.Disruption.Level
			auditPayload["maintenance"] = v.PlanImpact.Disruption.MaintenanceRecommendation
			auditPayload["apiImpactCount"] = len(v.PlanImpact.API)
			auditPayload["capacityCeilingCheck"] = v.PlanImpact.Capacity.CeilingCheck
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", action, "baselineDeployment", v.ID, v.Revision, "", auditPayload); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "baselineDeployment", v.ID, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
