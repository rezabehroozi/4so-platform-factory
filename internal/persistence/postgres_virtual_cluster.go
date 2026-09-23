package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/virtualcluster"
)

const virtualClusterColumns = `id,project_id,workspace_id,workspace_binding_id,workspace_binding_revision,host_cluster_id,host_namespace,revision,name,profile,developer_mode,kubernetes_version,cpu_milli,memory_mib,storage_gib,max_namespaces,sleep_after_minutes,desired_digest,state,pending_action,requested_by,idempotency_key,request_digest,observed_digest,phase,runtime_source_digest,task_attempt,task_fence_token,task_action,task_lease_expires_at,task_dispatched_at,lifecycle_action,lifecycle_idempotency_key,lifecycle_request_digest,last_error,created_at,updated_at`

func scanVirtualCluster(row interface{ Scan(...any) error }) (controlplane.VirtualCluster, error) {
	var v controlplane.VirtualCluster
	var profile, state, action, lifecycleAction string
	err := row.Scan(
		&v.ID, &v.ProjectID, &v.WorkspaceID, &v.WorkspaceBindingID, &v.WorkspaceBindingRevision, &v.HostClusterID, &v.HostNamespace,
		&v.Revision, &v.Name, &profile, &v.DeveloperMode, &v.KubernetesVersion,
		&v.CPUMilli, &v.MemoryMiB, &v.StorageGiB, &v.MaxNamespaces, &v.SleepAfterMinutes,
		&v.DesiredDigest, &state, &action, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest,
		&v.ObservedDigest, &v.Phase, &v.RuntimeSourceDigest, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskAction, &v.TaskLeaseExpiresAt,
		&v.TaskDispatchedAt, &lifecycleAction, &v.LifecycleIdempotencyKey, &v.LifecycleRequestDigest,
		&v.LastError, &v.CreatedAt, &v.UpdatedAt,
	)
	v.Profile = virtualcluster.ProfileID(profile)
	v.State = virtualcluster.State(state)
	v.PendingAction = virtualcluster.Action(action)
	v.LifecycleAction = virtualcluster.Action(lifecycleAction)
	return v, err
}

func (s *PostgresStore) CreateVirtualCluster(ctx context.Context, request controlplane.VirtualClusterCreateRequest, actor string) (controlplane.VirtualCluster, bool, error) {
	var out controlplane.VirtualCluster
	replay := false
	request.WorkspaceID = strings.TrimSpace(request.WorkspaceID)
	request.WorkspaceBindingID = strings.TrimSpace(request.WorkspaceBindingID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.RequestDigest = strings.TrimSpace(request.RequestDigest)
	if request.WorkspaceID == "" || request.WorkspaceBindingID == "" || request.IdempotencyKey == "" || request.RequestDigest == "" {
		return out, false, controlplane.ErrValidation
	}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		workspace, e := scanWorkspace(tx.QueryRowContext(ctx, `SELECT `+workspaceColumns+` FROM workspaces WHERE id=$1 FOR SHARE`, request.WorkspaceID))
		if e != nil { return mapDBError(e) }
		binding, e := scanWorkspaceBinding(tx.QueryRowContext(ctx, `SELECT `+workspaceBindingColumns+` FROM workspace_bindings WHERE id=$1 FOR SHARE`, request.WorkspaceBindingID))
		if e != nil { return mapDBError(e) }
		if binding.WorkspaceID != workspace.ID || binding.ProjectID != workspace.ProjectID {
			return controlplane.ErrNotFound
		}
		existing, e := scanVirtualCluster(tx.QueryRowContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, workspace.ProjectID, request.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != request.RequestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			out, replay = existing, true
			return nil
		}
		if e != sql.ErrNoRows {
			return mapDBError(e)
		}
		authority, e := controlplane.VirtualClusterWorkspaceAuthorityForPersistence(workspace, binding)
		if e != nil { return e }
		plan, e := virtualcluster.BuildPlan(authority, request.Spec)
		if e != nil { return fmt.Errorf("%w: %v", controlplane.ErrValidation, e) }
		var duplicate string
		e = tx.QueryRowContext(ctx, `SELECT id FROM virtual_clusters WHERE workspace_id=$1 AND name=$2 AND state<>'DELETED' LIMIT 1`, workspace.ID, plan.Name).Scan(&duplicate)
		if e == nil { return controlplane.ErrDuplicateName }
		if e != sql.ErrNoRows { return e }
		now := utcNow(s.now)
		out = controlplane.VirtualClusterFromPlanForPersistence(plan, request, actor, controlplane.ResourceMeta{ID: s.id("vcl"), Revision: 1, CreatedAt: now, UpdatedAt: now})
		_, e = tx.ExecContext(ctx, `INSERT INTO virtual_clusters(
			id,project_id,workspace_id,workspace_binding_id,workspace_binding_revision,host_cluster_id,host_namespace,revision,name,profile,developer_mode,kubernetes_version,
			cpu_milli,memory_mib,storage_gib,max_namespaces,sleep_after_minutes,desired_digest,state,pending_action,requested_by,idempotency_key,request_digest,
			observed_digest,phase,runtime_source_digest,task_attempt,task_fence_token,task_action,task_lease_expires_at,last_error,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,'','','',0,0,'',NULL,'',$23,$23)`,
			out.ID, out.ProjectID, out.WorkspaceID, out.WorkspaceBindingID, out.WorkspaceBindingRevision, out.HostClusterID, out.HostNamespace,
			out.Name, string(out.Profile), out.DeveloperMode, out.KubernetesVersion, out.CPUMilli, out.MemoryMiB, out.StorageGiB,
			out.MaxNamespaces, out.SleepAfterMinutes, out.DesiredDigest, string(out.State), string(out.PendingAction), out.RequestedBy,
			out.IdempotencyKey, out.RequestDigest, now)
		if e != nil { return mapDBError(e) }
		if e = s.appendAuditTx(ctx, tx, actor, "virtual_cluster.created", "virtualCluster", out.ID, out.Revision, "", map[string]any{
			"projectId": out.ProjectID, "workspaceId": out.WorkspaceID, "workspaceBindingId": out.WorkspaceBindingID,
			"hostClusterId": out.HostClusterID, "hostNamespace": out.HostNamespace, "profile": out.Profile, "desiredDigest": out.DesiredDigest,
		}); e != nil { return e }
		return s.appendOutboxTx(ctx, tx, "virtualCluster", out.ID, "virtual_cluster.created", out)
	})
	return out, replay, err
}

func (s *PostgresStore) GetVirtualCluster(ctx context.Context, id string) (controlplane.VirtualCluster, error) {
	v, err := scanVirtualCluster(s.db.QueryRowContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListVirtualClusters(ctx context.Context, projectID, workspaceID string) ([]controlplane.VirtualCluster, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters WHERE ($1='' OR project_id=$1) AND ($2='' OR workspace_id=$2) ORDER BY workspace_id,lower(name),id`, strings.TrimSpace(projectID), strings.TrimSpace(workspaceID))
	if err != nil { return nil, err }
	defer rows.Close()
	out := []controlplane.VirtualCluster{}
	for rows.Next() {
		v, e := scanVirtualCluster(rows)
		if e != nil { return nil, e }
		out = append(out, v)
	}
	return out, rows.Err()
}


func (s *PostgresStore) NextVirtualClusterTask(ctx context.Context, clusterID, tokenDigest, runtimeSourceDigest string) (controlplane.VirtualClusterTask, error) {
	var task controlplane.VirtualClusterTask
	noTask := false
	runtimeSourceDigest = strings.TrimSpace(runtimeSourceDigest)
	if err := controlplane.ValidateVirtualClusterRuntimeSourceDigest(runtimeSourceDigest); err != nil {
		return task, err
	}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if err := s.validateFreshClusterAgentTx(ctx, tx, clusterID, tokenDigest); err != nil {
			return err
		}
		now := utcNow(s.now)
		v, err := scanVirtualCluster(tx.QueryRowContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters
			WHERE host_cluster_id=$1 AND (
				state='REQUESTED'
				OR (state IN ('PROVISIONING','SUSPENDING','RESUMING','DELETING') AND (task_lease_expires_at IS NULL OR task_lease_expires_at<=$2))
			)
			ORDER BY updated_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, strings.TrimSpace(clusterID), now))
		if err != nil {
			return mapDBError(err)
		}
		if v.State == virtualcluster.StateProvisioning && v.TaskAction == "APPLY" && v.TaskLeaseExpiresAt != nil && !controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
			v.State, v.Phase = virtualcluster.StateRecoveryRequired, "RecoveryRequired"
			v.LastError = "virtual cluster APPLY lease expired; mutation outcome is ambiguous and automatic replay is forbidden"
			v.TaskAction = ""
			v.TaskLeaseExpiresAt = nil
			v.Revision++
			v.UpdatedAt = now
			if _, err = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,phase=$4,last_error=$5,task_action='',task_lease_expires_at=NULL,updated_at=$6 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.Phase, v.LastError, now); err != nil { return err }
			if err = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.apply.lease_expired_recovery_required", "virtualCluster", v.ID, v.Revision, "", map[string]any{"taskFenceToken": v.TaskFenceToken}); err != nil { return err }
			if err = s.appendOutboxTx(ctx, tx, "virtualCluster", v.ID, "virtual_cluster.state.changed", v); err != nil { return err }
			noTask = true
			return nil
		}
		if controlplane.VirtualClusterExpiredDispatchedMutation(v, now) {
			v.State, v.Phase = virtualcluster.StateRecoveryRequired, "RecoveryRequired"
			v.LastError = "virtual cluster lifecycle mutation lease expired after durable dispatch acknowledgement; automatic replay is forbidden"
			v.TaskAction = ""
			v.TaskLeaseExpiresAt = nil
			v.TaskDispatchedAt = nil
			v.Revision++
			v.UpdatedAt = now
			if _, err = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,phase=$4,last_error=$5,task_action='',task_lease_expires_at=NULL,task_dispatched_at=NULL,updated_at=$6 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.Phase, v.LastError, now); err != nil { return err }
			if err = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.lifecycle.lease_expired_recovery_required", "virtualCluster", v.ID, v.Revision, "", map[string]any{"taskFenceToken": v.TaskFenceToken, "lifecycleAction": v.PendingAction}); err != nil { return err }
			if err = s.appendOutboxTx(ctx, tx, "virtualCluster", v.ID, "virtual_cluster.state.changed", v); err != nil { return err }
			noTask = true
			return nil
		}
		binding, err := scanWorkspaceBinding(tx.QueryRowContext(ctx, `SELECT `+workspaceBindingColumns+` FROM workspace_bindings WHERE id=$1 FOR SHARE`, v.WorkspaceBindingID))
		if err != nil { return mapDBError(err) }
		bindingCurrent := binding.WorkspaceID == v.WorkspaceID && binding.ProjectID == v.ProjectID && binding.ClusterID == v.HostClusterID && binding.Namespace == v.HostNamespace && binding.Revision == v.WorkspaceBindingRevision && binding.State == controlplane.WorkspaceBindingActive
		if !bindingCurrent {
			if v.State == virtualcluster.StateRequested {
				v.State, v.Phase = virtualcluster.StateFailed, "BindingFenceRejected"
			} else {
				v.State, v.Phase = virtualcluster.StateRecoveryRequired, "RecoveryRequired"
			}
			v.LastError = "workspace binding revision/state changed before virtual cluster runtime claim"
			v.TaskAction = ""
			v.TaskLeaseExpiresAt = nil
			v.TaskDispatchedAt = nil
			v.Revision++
			v.UpdatedAt = now
			if _, err = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,phase=$4,last_error=$5,task_action='',task_lease_expires_at=NULL,task_dispatched_at=NULL,updated_at=$6 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.Phase, v.LastError, now); err != nil { return err }
			if err = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.binding_fence.rejected", "virtualCluster", v.ID, v.Revision, "", map[string]any{"workspaceBindingId": v.WorkspaceBindingID, "workspaceBindingRevision": v.WorkspaceBindingRevision}); err != nil { return err }
			if err = s.appendOutboxTx(ctx, tx, "virtualCluster", v.ID, "virtual_cluster.state.changed", v); err != nil { return err }
			noTask = true
			return nil
		}
		claimed, claimedTask, err := controlplane.PrepareVirtualClusterTaskClaim(v, runtimeSourceDigest, now)
		if err != nil { return err }
		if _, err = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,runtime_source_digest=$4,task_attempt=$5,task_fence_token=$6,task_action=$7,task_lease_expires_at=$8,task_dispatched_at=NULL,phase=$9,last_error='',updated_at=$10 WHERE id=$1`,
			claimed.ID, claimed.Revision, string(claimed.State), claimed.RuntimeSourceDigest, claimed.TaskAttempt, claimed.TaskFenceToken, claimed.TaskAction, claimed.TaskLeaseExpiresAt, claimed.Phase, claimed.UpdatedAt); err != nil { return err }
		if err = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.task.claimed", "virtualCluster", claimed.ID, claimed.Revision, "", map[string]any{"action": claimedTask.Action, "lifecycleAction": claimedTask.LifecycleAction, "taskFenceToken": claimed.TaskFenceToken}); err != nil { return err }
		if err = s.appendOutboxTx(ctx, tx, "virtualCluster", claimed.ID, "virtual_cluster.state.changed", claimed); err != nil { return err }
		task = claimedTask
		return nil
	})
	if err == nil && noTask {
		return controlplane.VirtualClusterTask{}, controlplane.ErrNotFound
	}
	return task, err
}

func (s *PostgresStore) ReportVirtualClusterTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result controlplane.VirtualClusterTaskResult) (controlplane.VirtualCluster, error) {
	var out controlplane.VirtualCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if err := s.validateClusterAgentTx(ctx, tx, clusterID, tokenDigest); err != nil { return err }
		v, err := scanVirtualCluster(tx.QueryRowContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters WHERE id=$1 FOR UPDATE`, strings.TrimSpace(result.VirtualClusterID)))
		if err != nil { return mapDBError(err) }
		if v.HostClusterID != strings.TrimSpace(clusterID) { return controlplane.ErrNotFound }
		now := utcNow(s.now)
		action := strings.ToUpper(strings.TrimSpace(result.Action))
		if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) || action != v.TaskAction {
			return controlplane.ErrConflict
		}
		updated, err := controlplane.ApplyVirtualClusterTaskResult(v, result, now)
		if err != nil { return err }
		if _, err = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,observed_digest=$4,pending_action=$5,phase=$6,last_error=$7,task_action=$8,task_lease_expires_at=NULL,task_dispatched_at=NULL,updated_at=$9 WHERE id=$1`,
			updated.ID, updated.Revision, string(updated.State), updated.ObservedDigest, string(updated.PendingAction), updated.Phase, updated.LastError, updated.TaskAction, updated.UpdatedAt); err != nil { return err }
		if err = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.task.reported", "virtualCluster", updated.ID, updated.Revision, "", map[string]any{"action": action, "lifecycleAction": result.LifecycleAction, "success": result.Success, "ready": result.Ready, "recoveryRequired": result.RecoveryRequired, "taskFenceToken": result.TaskFenceToken}); err != nil { return err }
		if err = s.appendOutboxTx(ctx, tx, "virtualCluster", updated.ID, "virtual_cluster.state.changed", updated); err != nil { return err }
		out = updated
		return nil
	})
	return out, err
}
