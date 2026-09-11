package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const backupPolicyColumns = `id,revision,project_id,cluster_id,name,provider,backup_storage_location,credential_ref,schedule,retention,included_namespaces,desired_digest,state,requested_by,created_at,updated_at`
const dataProtectionRunColumns = `id,revision,kind,state,project_id,cluster_id,policy_id,COALESCE(backup_run_id,''),COALESCE(recovery_checkpoint_id,''),inventory_digest,policy_digest,source_backup_name,target_namespace,velero_name,reference,evidence_digest,checks,rpo_seconds,rto_seconds,idempotency_key,request_digest,requested_by,approved_by,approved_at,task_attempt,task_fence_token,task_lease_expires_at,started_at,finished_at,last_error,created_at,updated_at`

func scanBackupPolicy(row interface{ Scan(...any) error }) (controlplane.BackupPolicy, error) {
	var v controlplane.BackupPolicy
	var namespaces []byte
	var state string
	err := row.Scan(&v.ID, &v.Revision, &v.ProjectID, &v.ClusterID, &v.Name, &v.Provider, &v.BackupStorageLocation, &v.CredentialRef, &v.Schedule, &v.Retention, &namespaces, &v.DesiredDigest, &state, &v.RequestedBy, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	v.State = controlplane.BackupPolicyState(state)
	if err := decodeJSONColumn(namespaces, &v.IncludedNamespaces, "backup_policies.included_namespaces"); err != nil {
		return v, err
	}
	return v, nil
}

func scanDataProtectionRun(row interface{ Scan(...any) error }) (controlplane.DataProtectionRun, error) {
	var v controlplane.DataProtectionRun
	var kind, state string
	var checks []byte
	err := row.Scan(&v.ID, &v.Revision, &kind, &state, &v.ProjectID, &v.ClusterID, &v.PolicyID, &v.BackupRunID, &v.RecoveryCheckpointID, &v.InventoryDigest, &v.PolicyDigest, &v.SourceBackupName, &v.TargetNamespace, &v.VeleroName, &v.Reference, &v.EvidenceDigest, &checks, &v.RPOSeconds, &v.RTOSeconds, &v.IdempotencyKey, &v.RequestDigest, &v.RequestedBy, &v.ApprovedBy, &v.ApprovedAt, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskLeaseExpiresAt, &v.StartedAt, &v.FinishedAt, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	v.Kind = controlplane.DataProtectionRunKind(kind)
	v.State = controlplane.DataProtectionRunState(state)
	if err := decodeJSONColumn(checks, &v.Checks, "data_protection_runs.checks"); err != nil {
		return v, err
	}
	return v, nil
}

func clusterHasDataProtectionCapability(cluster controlplane.ManagedCluster) bool {
	for _, capability := range cluster.Capabilities {
		if strings.TrimSpace(capability) == controlplane.DataProtectionAgentCapability {
			return true
		}
	}
	return false
}

func (s *PostgresStore) UpsertBackupPolicy(ctx context.Context, v controlplane.BackupPolicy, expected int64, actor string) (controlplane.BackupPolicy, error) {
	var out controlplane.BackupPolicy
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cluster, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR SHARE`, v.ClusterID))
		if e != nil {
			return mapDBError(e)
		}
		if e = controlplane.ValidateBackupPolicy(&v, cluster); e != nil {
			return e
		}
		now := utcNow(s.now)
		if strings.TrimSpace(v.ID) == "" {
			v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("bkp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
			v.State = controlplane.BackupPolicyActive
			v.RequestedBy = strings.TrimSpace(actor)
			ns, _ := json.Marshal(v.IncludedNamespaces)
			_, e = tx.ExecContext(ctx, `INSERT INTO backup_policies(id,revision,project_id,cluster_id,name,provider,backup_storage_location,credential_ref,schedule,retention,included_namespaces,desired_digest,state,requested_by,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`, v.ID, v.ProjectID, v.ClusterID, v.Name, v.Provider, v.BackupStorageLocation, v.CredentialRef, v.Schedule, v.Retention, ns, v.DesiredDigest, string(v.State), v.RequestedBy, now)
			if e != nil {
				return mapDBError(e)
			}
			if e = s.appendAuditTx(ctx, tx, actor, "backup_policy.created", "backupPolicy", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "desiredDigest": v.DesiredDigest}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "backupPolicy", v.ID, "backup_policy.created", v); e != nil {
				return e
			}
			out = v
			return nil
		}
		current, e := scanBackupPolicy(tx.QueryRowContext(ctx, `SELECT `+backupPolicyColumns+` FROM backup_policies WHERE id=$1 FOR UPDATE`, v.ID))
		if e != nil {
			return mapDBError(e)
		}
		if current.Revision != expected || current.ProjectID != v.ProjectID || current.ClusterID != v.ClusterID {
			return controlplane.ErrConflict
		}
		v.ResourceMeta = current.ResourceMeta
		v.Revision++
		v.UpdatedAt = now
		v.State = current.State
		v.RequestedBy = current.RequestedBy
		ns, _ := json.Marshal(v.IncludedNamespaces)
		_, e = tx.ExecContext(ctx, `UPDATE backup_policies SET revision=$2,name=$3,provider=$4,backup_storage_location=$5,credential_ref=$6,schedule=$7,retention=$8,included_namespaces=$9,desired_digest=$10,updated_at=$11 WHERE id=$1`, v.ID, v.Revision, v.Name, v.Provider, v.BackupStorageLocation, v.CredentialRef, v.Schedule, v.Retention, ns, v.DesiredDigest, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "backup_policy.updated", "backupPolicy", v.ID, v.Revision, "", map[string]any{"desiredDigest": v.DesiredDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "backupPolicy", v.ID, "backup_policy.updated", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) SetBackupPolicyState(ctx context.Context, id string, expected int64, state controlplane.BackupPolicyState, actor string) (controlplane.BackupPolicy, error) {
	var out controlplane.BackupPolicy
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanBackupPolicy(tx.QueryRowContext(ctx, `SELECT `+backupPolicyColumns+` FROM backup_policies WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if state != controlplane.BackupPolicyActive && state != controlplane.BackupPolicyDisabled {
			return controlplane.ErrValidation
		}
		if v.State == state {
			out = v
			return nil
		}
		now := utcNow(s.now)
		v.State = state
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE backup_policies SET revision=$2,state=$3,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, string(state), now); e != nil {
			return e
		}
		action := "backup_policy.enabled"
		if state == controlplane.BackupPolicyDisabled {
			action = "backup_policy.disabled"
		}
		if e = s.appendAuditTx(ctx, tx, actor, action, "backupPolicy", v.ID, v.Revision, "", map[string]any{"state": state}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "backupPolicy", v.ID, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) GetBackupPolicy(ctx context.Context, id string) (controlplane.BackupPolicy, error) {
	v, err := scanBackupPolicy(s.db.QueryRowContext(ctx, `SELECT `+backupPolicyColumns+` FROM backup_policies WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListBackupPolicies(ctx context.Context, projectID, clusterID string) ([]controlplane.BackupPolicy, error) {
	q := `SELECT ` + backupPolicyColumns + ` FROM backup_policies WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(projectID) != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	if strings.TrimSpace(clusterID) != "" {
		args = append(args, clusterID)
		q += fmt.Sprintf(" AND cluster_id=$%d", len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.BackupPolicy{}
	for rows.Next() {
		v, e := scanBackupPolicy(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateDataProtectionRun(ctx context.Context, v controlplane.DataProtectionRun, actor string) (controlplane.DataProtectionRun, bool, error) {
	var out controlplane.DataProtectionRun
	var replay bool
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		policy, e := scanBackupPolicy(tx.QueryRowContext(ctx, `SELECT `+backupPolicyColumns+` FROM backup_policies WHERE id=$1 FOR SHARE`, strings.TrimSpace(v.PolicyID)))
		if e != nil {
			return mapDBError(e)
		}
		if policy.State != controlplane.BackupPolicyActive {
			return controlplane.ErrPrerequisite
		}
		cluster, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR SHARE`, policy.ClusterID))
		if e != nil {
			return mapDBError(e)
		}
		if !controlplane.ClusterTaskAdmitted(cluster) || !clusterHasDataProtectionCapability(cluster) {
			return fmt.Errorf("%w: cluster data-protection mutation authority is not active", controlplane.ErrPrerequisite)
		}
		if v.ProjectID != policy.ProjectID || v.ClusterID != policy.ClusterID || !strings.HasPrefix(cluster.InventoryDigest, "sha256:") {
			return controlplane.ErrPrerequisite
		}
		v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
		v.RequestDigest = strings.TrimSpace(v.RequestDigest)
		if v.IdempotencyKey == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") {
			return fmt.Errorf("%w: idempotency key and request digest are required", controlplane.ErrValidation)
		}
		current, e := scanDataProtectionRun(tx.QueryRowContext(ctx, `SELECT `+dataProtectionRunColumns+` FROM data_protection_runs WHERE project_id=$1 AND idempotency_key=$2`, v.ProjectID, v.IdempotencyKey))
		if e == nil {
			if current.RequestDigest != v.RequestDigest {
				return controlplane.ErrConflict
			}
			out, replay = current, true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		if v.Kind != controlplane.DataProtectionBackup && v.Kind != controlplane.DataProtectionRestore && v.Kind != controlplane.DataProtectionRestoreDrill {
			return fmt.Errorf("%w: unsupported data protection run kind", controlplane.ErrValidation)
		}
		now := utcNow(s.now)
		if v.Kind != controlplane.DataProtectionBackup {
			backup, e := scanDataProtectionRun(tx.QueryRowContext(ctx, `SELECT `+dataProtectionRunColumns+` FROM data_protection_runs WHERE id=$1 FOR SHARE`, strings.TrimSpace(v.BackupRunID)))
			if e != nil {
				return mapDBError(e)
			}
			if backup.Kind != controlplane.DataProtectionBackup || backup.State != controlplane.DataProtectionSucceeded || backup.ClusterID != v.ClusterID || backup.PolicyID != v.PolicyID || backup.RecoveryCheckpointID == "" {
				return fmt.Errorf("%w: restore requires a successful backup run with recovery checkpoint", controlplane.ErrPrerequisite)
			}
			cp, e := scanRecoveryCheckpoint(tx.QueryRowContext(ctx, `SELECT `+recoveryCheckpointColumns+` FROM recovery_checkpoints WHERE id=$1 FOR SHARE`, backup.RecoveryCheckpointID))
			if e != nil {
				return mapDBError(e)
			}
			if cp.State != controlplane.RecoveryCheckpointVerified || !cp.ExpiresAt.After(now) || cp.InventoryDigest != backup.InventoryDigest {
				return fmt.Errorf("%w: source backup recovery checkpoint is unavailable or stale", controlplane.ErrPrerequisite)
			}
			v.SourceBackupName, v.RecoveryCheckpointID = backup.VeleroName, cp.ID
			if v.Kind == controlplane.DataProtectionRestoreDrill && len(policy.IncludedNamespaces) != 1 {
				return fmt.Errorf("%w: V1 restore drill requires exactly one included namespace", controlplane.ErrPrerequisite)
			}
		}
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("dpr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.InventoryDigest, v.PolicyDigest, v.RequestedBy = cluster.InventoryDigest, policy.DesiredDigest, strings.TrimSpace(actor)
		v.VeleroName = strings.ToLower(string(v.Kind)) + "-" + strings.TrimPrefix(v.ID, "dpr_")
		if len(v.VeleroName) > 63 {
			v.VeleroName = v.VeleroName[:63]
		}
		if v.Kind == controlplane.DataProtectionRestoreDrill {
			v.TargetNamespace = "restore-drill-" + strings.TrimPrefix(v.ID, "dpr_")
			if len(v.TargetNamespace) > 63 {
				v.TargetNamespace = v.TargetNamespace[:63]
			}
		}
		if v.Kind == controlplane.DataProtectionRestore {
			v.State = controlplane.DataProtectionAwaitingApproval
		} else {
			v.State = controlplane.DataProtectionQueued
		}
		checks, _ := json.Marshal([]controlplane.RuntimeCheck{})
		var insertedID string
		e = tx.QueryRowContext(ctx, `INSERT INTO data_protection_runs(id,revision,kind,state,project_id,cluster_id,policy_id,backup_run_id,recovery_checkpoint_id,inventory_digest,policy_digest,source_backup_name,target_namespace,velero_name,reference,evidence_digest,checks,rpo_seconds,rto_seconds,idempotency_key,request_digest,requested_by,approved_by,task_attempt,task_fence_token,last_error,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),$9,$10,$11,$12,$13,'','',$14,0,0,$15,$16,$17,'',0,0,'',$18,$18) ON CONFLICT(project_id,idempotency_key) DO NOTHING RETURNING id`, v.ID, string(v.Kind), string(v.State), v.ProjectID, v.ClusterID, v.PolicyID, v.BackupRunID, v.RecoveryCheckpointID, v.InventoryDigest, v.PolicyDigest, v.SourceBackupName, v.TargetNamespace, v.VeleroName, checks, v.IdempotencyKey, v.RequestDigest, v.RequestedBy, now).Scan(&insertedID)
		if e == sql.ErrNoRows {
			current, lookupErr := scanDataProtectionRun(tx.QueryRowContext(ctx, `SELECT `+dataProtectionRunColumns+` FROM data_protection_runs WHERE project_id=$1 AND idempotency_key=$2`, v.ProjectID, v.IdempotencyKey))
			if lookupErr != nil {
				return mapDBError(lookupErr)
			}
			if current.RequestDigest != v.RequestDigest {
				return controlplane.ErrConflict
			}
			out, replay = current, true
			return nil
		}
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "data_protection_run.created", "dataProtectionRun", v.ID, v.Revision, "", map[string]any{"kind": v.Kind, "clusterId": v.ClusterID, "policyId": v.PolicyID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "dataProtectionRun", v.ID, "data_protection_run.created", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}

func (s *PostgresStore) GetDataProtectionRun(ctx context.Context, id string) (controlplane.DataProtectionRun, error) {
	v, err := scanDataProtectionRun(s.db.QueryRowContext(ctx, `SELECT `+dataProtectionRunColumns+` FROM data_protection_runs WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListDataProtectionRuns(ctx context.Context, projectID, clusterID string, kind controlplane.DataProtectionRunKind) ([]controlplane.DataProtectionRun, error) {
	q := `SELECT ` + dataProtectionRunColumns + ` FROM data_protection_runs WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(projectID) != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	if strings.TrimSpace(clusterID) != "" {
		args = append(args, clusterID)
		q += fmt.Sprintf(" AND cluster_id=$%d", len(args))
	}
	if kind != "" {
		args = append(args, string(kind))
		q += fmt.Sprintf(" AND kind=$%d", len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.DataProtectionRun{}
	for rows.Next() {
		v, e := scanDataProtectionRun(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ApproveDataProtectionRun(ctx context.Context, id string, expected int64, actor string) (controlplane.DataProtectionRun, error) {
	var out controlplane.DataProtectionRun
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanDataProtectionRun(tx.QueryRowContext(ctx, `SELECT `+dataProtectionRunColumns+` FROM data_protection_runs WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		actor = strings.TrimSpace(actor)
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.Kind != controlplane.DataProtectionRestore || v.State != controlplane.DataProtectionAwaitingApproval || actor == "" || actor == v.RequestedBy {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.State, v.ApprovedBy, v.ApprovedAt, v.Revision, v.UpdatedAt = controlplane.DataProtectionQueued, actor, &now, v.Revision+1, now
		_, e = tx.ExecContext(ctx, `UPDATE data_protection_runs SET revision=$2,state=$3,approved_by=$4,approved_at=$5,updated_at=$5 WHERE id=$1`, v.ID, v.Revision, string(v.State), actor, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "data_protection_run.approved", "dataProtectionRun", v.ID, v.Revision, "", map[string]any{"kind": v.Kind}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "dataProtectionRun", v.ID, "data_protection_run.approved", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) NextDataProtectionTask(ctx context.Context, clusterID, tokenDigest string) (controlplane.DataProtectionRun, controlplane.BackupPolicy, error) {
	var out controlplane.DataProtectionRun
	var policyOut controlplane.BackupPolicy
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		now := utcNow(s.now)
		v, e := scanDataProtectionRun(tx.QueryRowContext(ctx, `SELECT `+dataProtectionRunColumns+` FROM data_protection_runs WHERE cluster_id=$1 AND (state='QUEUED' OR (state='RUNNING' AND (task_lease_expires_at IS NULL OR task_lease_expires_at <= $2))) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, clusterID, now))
		if e != nil {
			return mapDBError(e)
		}
		policy, e := scanBackupPolicy(tx.QueryRowContext(ctx, `SELECT `+backupPolicyColumns+` FROM backup_policies WHERE id=$1 FOR SHARE`, v.PolicyID))
		if e != nil {
			return mapDBError(e)
		}
		cluster, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR SHARE`, clusterID))
		if e != nil {
			return mapDBError(e)
		}
		if policy.State != controlplane.BackupPolicyActive || policy.DesiredDigest != v.PolicyDigest || cluster.InventoryDigest != v.InventoryDigest || !clusterHasDataProtectionCapability(cluster) {
			v.State, v.LastError, v.FinishedAt, v.TaskLeaseExpiresAt, v.Revision, v.UpdatedAt = controlplane.DataProtectionFailed, "data-protection context changed after run was queued", &now, nil, v.Revision+1, now
			_, e = tx.ExecContext(ctx, `UPDATE data_protection_runs SET revision=$2,state='FAILED',last_error=$3,finished_at=$4,task_lease_expires_at=NULL,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, v.LastError, now)
			if e != nil {
				return e
			}
			if e = s.appendAuditTx(ctx, tx, "system", "data_protection_run.context_invalidated", "dataProtectionRun", v.ID, v.Revision, "", map[string]any{"kind": v.Kind}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "dataProtectionRun", v.ID, "data_protection_run.failed", v); e != nil {
				return e
			}
			out = v
			return nil
		}
		if v.State == controlplane.DataProtectionQueued {
			v.State = controlplane.DataProtectionRunning
			v.StartedAt = &now
		}
		lease := now.Add(controlplane.AgentTaskLeaseDuration)
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseExpiresAt = &lease
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE data_protection_runs SET revision=$2,state=$3,task_attempt=$4,task_fence_token=$5,task_lease_expires_at=$6,started_at=COALESCE(started_at,$7),updated_at=$7 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.TaskAttempt, v.TaskFenceToken, lease, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "data_protection_run.task_claimed", "dataProtectionRun", v.ID, v.Revision, "", map[string]any{"kind": v.Kind, "attempt": v.TaskAttempt, "taskFenceToken": v.TaskFenceToken}); e != nil {
			return e
		}
		out, policyOut = v, policy
		return nil
	})
	return out, policyOut, err
}

func (s *PostgresStore) ReportDataProtectionTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result controlplane.DataProtectionTaskResult) (controlplane.DataProtectionRun, error) {
	var out controlplane.DataProtectionRun
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		v, e := scanDataProtectionRun(tx.QueryRowContext(ctx, `SELECT `+dataProtectionRunColumns+` FROM data_protection_runs WHERE id=$1 FOR UPDATE`, result.RunID))
		if e != nil {
			return mapDBError(e)
		}
		now := utcNow(s.now)
		if v.ClusterID != clusterID {
			return controlplane.ErrNotFound
		}
		if v.Revision != expected || v.State != controlplane.DataProtectionRunning || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
			return controlplane.ErrConflict
		}
		if len(result.Checks) == 0 {
			return fmt.Errorf("%w: data protection result requires checks", controlplane.ErrValidation)
		}
		allPass := result.Success
		for _, check := range result.Checks {
			if strings.TrimSpace(check.Key) == "" || check.Status != "PASS" {
				allPass = false
			}
		}
		v.Checks = append([]controlplane.RuntimeCheck(nil), result.Checks...)
		v.Reference = strings.TrimSpace(result.Reference)
		v.RPOSeconds, v.RTOSeconds = result.RPOSeconds, result.RTOSeconds
		if !allPass {
			v.State = controlplane.DataProtectionFailed
			v.LastError = strings.TrimSpace(result.Error)
			if v.LastError == "" {
				v.LastError = "data protection task checks failed"
			}
		} else {
			if e := controlplane.ValidateDataProtectionSuccessfulResult(v, result); e != nil {
				return e
			}
			expectedEvidence := controlplane.DataProtectionEvidenceDigest(v, result)
			if strings.TrimSpace(result.EvidenceDigest) != expectedEvidence || v.Reference == "" {
				return fmt.Errorf("%w: evidence digest/reference mismatch", controlplane.ErrValidation)
			}
			v.State, v.EvidenceDigest, v.LastError = controlplane.DataProtectionSucceeded, expectedEvidence, ""
			if v.Kind == controlplane.DataProtectionBackup || v.Kind == controlplane.DataProtectionRestoreDrill {
				policy, e := scanBackupPolicy(tx.QueryRowContext(ctx, `SELECT `+backupPolicyColumns+` FROM backup_policies WHERE id=$1 FOR SHARE`, v.PolicyID))
				if e != nil {
					return mapDBError(e)
				}
				retention, e := time.ParseDuration(policy.Retention)
				if e != nil {
					return e
				}
				cp := controlplane.RecoveryCheckpoint{ProjectID: v.ProjectID, ClusterID: v.ClusterID, Provider: "velero", Reference: v.Reference, EvidenceDigest: v.EvidenceDigest, InventoryDigest: v.InventoryDigest, CompletedAt: now, ExpiresAt: now.Add(retention), State: controlplane.RecoveryCheckpointVerified, RequestedBy: "cluster-agent"}
				cp.ResourceMeta = controlplane.ResourceMeta{ID: s.id("rcp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
				_, e = tx.ExecContext(ctx, `INSERT INTO recovery_checkpoints(id,project_id,cluster_id,revision,provider,reference,evidence_digest,inventory_digest,completed_at,expires_at,state,requested_by,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, cp.ID, cp.ProjectID, cp.ClusterID, cp.Provider, cp.Reference, cp.EvidenceDigest, cp.InventoryDigest, cp.CompletedAt, cp.ExpiresAt, string(cp.State), cp.RequestedBy, now)
				if e != nil {
					return mapDBError(e)
				}
				v.RecoveryCheckpointID = cp.ID
				if e = s.appendAuditTx(ctx, tx, "cluster-agent", "recovery_checkpoint.produced", "recoveryCheckpoint", cp.ID, cp.Revision, "", map[string]any{"dataProtectionRunId": v.ID, "kind": v.Kind, "evidenceDigest": cp.EvidenceDigest}); e != nil {
					return e
				}
				if e = s.appendOutboxTx(ctx, tx, "recoveryCheckpoint", cp.ID, "recovery_checkpoint.verified", cp); e != nil {
					return e
				}
			}
		}
		v.FinishedAt, v.TaskLeaseExpiresAt, v.Revision, v.UpdatedAt = &now, nil, v.Revision+1, now
		checks, _ := json.Marshal(v.Checks)
		_, e = tx.ExecContext(ctx, `UPDATE data_protection_runs SET revision=$2,state=$3,recovery_checkpoint_id=NULLIF($4,''),reference=$5,evidence_digest=$6,checks=$7,rpo_seconds=$8,rto_seconds=$9,finished_at=$10,task_lease_expires_at=NULL,last_error=$11,updated_at=$10 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.RecoveryCheckpointID, v.Reference, v.EvidenceDigest, checks, v.RPOSeconds, v.RTOSeconds, now, v.LastError)
		if e != nil {
			return e
		}
		action := "data_protection_run.failed"
		if v.State == controlplane.DataProtectionSucceeded {
			action = "data_protection_run.succeeded"
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", action, "dataProtectionRun", v.ID, v.Revision, "", map[string]any{"kind": v.Kind, "evidenceDigest": v.EvidenceDigest, "taskFenceToken": result.TaskFenceToken}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "dataProtectionRun", v.ID, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

var _ = sort.Strings
