package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/virtualcluster"
)

const virtualClusterColumns = `id,project_id,workspace_id,workspace_binding_id,workspace_binding_revision,host_cluster_id,host_namespace,revision,name,profile,developer_mode,kubernetes_version,cpu_milli,memory_mib,storage_gib,max_namespaces,sleep_after_minutes,desired_digest,state,pending_action,requested_by,idempotency_key,request_digest,observed_digest,phase,runtime_source_digest,task_attempt,task_fence_token,task_action,task_lease_expires_at,last_error,created_at,updated_at`

func scanVirtualCluster(row interface{ Scan(...any) error }) (controlplane.VirtualCluster, error) {
	var v controlplane.VirtualCluster
	var profile, state, action string
	err := row.Scan(
		&v.ID, &v.ProjectID, &v.WorkspaceID, &v.WorkspaceBindingID, &v.WorkspaceBindingRevision, &v.HostClusterID, &v.HostNamespace,
		&v.Revision, &v.Name, &profile, &v.DeveloperMode, &v.KubernetesVersion,
		&v.CPUMilli, &v.MemoryMiB, &v.StorageGiB, &v.MaxNamespaces, &v.SleepAfterMinutes,
		&v.DesiredDigest, &state, &action, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest,
		&v.ObservedDigest, &v.Phase, &v.RuntimeSourceDigest, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskAction, &v.TaskLeaseExpiresAt,
		&v.LastError, &v.CreatedAt, &v.UpdatedAt,
	)
	v.Profile = virtualcluster.ProfileID(profile)
	v.State = virtualcluster.State(state)
	v.PendingAction = virtualcluster.Action(action)
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
		noTask = false
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		now := utcNow(s.now)
		v, e := scanVirtualCluster(tx.QueryRowContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters
			WHERE host_cluster_id=$1 AND (state='REQUESTED' OR (state='PROVISIONING' AND (task_lease_expires_at IS NULL OR task_lease_expires_at<=$2)))
			ORDER BY updated_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, clusterID, now))
		if e != nil {
			return mapDBError(e)
		}
		if v.State == virtualcluster.StateProvisioning && v.TaskAction == "APPLY" && v.TaskLeaseExpiresAt != nil && !controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
			v.State, v.Phase = virtualcluster.StateRecoveryRequired, "RecoveryRequired"
			v.LastError = "virtual cluster APPLY lease expired; mutation outcome is ambiguous and automatic replay is forbidden"
			v.TaskLeaseExpiresAt = nil
			v.Revision++
			v.UpdatedAt = now
			if _, e = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,phase=$4,last_error=$5,task_lease_expires_at=NULL,updated_at=$6 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.Phase, v.LastError, now); e != nil {
				return e
			}
			if e = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.apply.lease_expired_recovery_required", "virtualCluster", v.ID, v.Revision, "", map[string]any{"taskFenceToken": v.TaskFenceToken, "runtimeSourceDigest": v.RuntimeSourceDigest}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "virtualCluster", v.ID, "virtual_cluster.state.changed", v); e != nil {
				return e
			}
			noTask = true
			return nil
		}
		binding, e := scanWorkspaceBinding(tx.QueryRowContext(ctx, `SELECT `+workspaceBindingColumns+` FROM workspace_bindings WHERE id=$1 FOR SHARE`, v.WorkspaceBindingID))
		if e != nil {
			return mapDBError(e)
		}
		bindingCurrent := binding.WorkspaceID == v.WorkspaceID && binding.ProjectID == v.ProjectID &&
			binding.ClusterID == v.HostClusterID && binding.Namespace == v.HostNamespace &&
			binding.Revision == v.WorkspaceBindingRevision && binding.State == controlplane.WorkspaceBindingActive
		if !bindingCurrent {
			if v.State == virtualcluster.StateRequested {
				v.State, v.Phase = virtualcluster.StateFailed, "BindingFenceRejected"
			} else {
				v.State, v.Phase = virtualcluster.StateRecoveryRequired, "RecoveryRequired"
			}
			v.LastError = "workspace binding revision/state changed before virtual cluster runtime claim"
			v.TaskLeaseExpiresAt = nil
			v.Revision++
			v.UpdatedAt = now
			if _, e = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,phase=$4,last_error=$5,task_lease_expires_at=NULL,updated_at=$6 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.Phase, v.LastError, now); e != nil {
				return e
			}
			if e = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.binding_fence.rejected", "virtualCluster", v.ID, v.Revision, "", map[string]any{"workspaceBindingId": v.WorkspaceBindingID, "workspaceBindingRevision": v.WorkspaceBindingRevision}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "virtualCluster", v.ID, "virtual_cluster.state.changed", v); e != nil {
				return e
			}
			noTask = true
			return nil
		}
		if v.RuntimeSourceDigest != "" && v.RuntimeSourceDigest != runtimeSourceDigest {
			return controlplane.ErrConflict
		}
		action := "APPLY"
		if v.State == virtualcluster.StateProvisioning {
			action = "INSPECT"
		}
		if v.RuntimeSourceDigest == "" {
			v.RuntimeSourceDigest = runtimeSourceDigest
		}
		lease := now.Add(controlplane.AgentTaskLeaseDuration)
		v.State = virtualcluster.StateProvisioning
		v.TaskAction = action
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseExpiresAt = &lease
		v.Phase = action + "Claimed"
		v.LastError = ""
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,runtime_source_digest=$4,task_attempt=$5,task_fence_token=$6,task_action=$7,task_lease_expires_at=$8,phase=$9,last_error='',updated_at=$10 WHERE id=$1`,
			v.ID, v.Revision, string(v.State), v.RuntimeSourceDigest, v.TaskAttempt, v.TaskFenceToken, v.TaskAction, lease, v.Phase, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.task.claimed", "virtualCluster", v.ID, v.Revision, "", map[string]any{"action": action, "taskFenceToken": v.TaskFenceToken, "runtimeSourceDigest": v.RuntimeSourceDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "virtualCluster", v.ID, "virtual_cluster.state.changed", v); e != nil {
			return e
		}
		task = controlplane.VirtualClusterTaskFromRecord(v)
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
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		v, e := scanVirtualCluster(tx.QueryRowContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters WHERE id=$1 FOR UPDATE`, result.VirtualClusterID))
		if e != nil {
			return mapDBError(e)
		}
		if v.HostClusterID != strings.TrimSpace(clusterID) {
			return controlplane.ErrNotFound
		}
		now := utcNow(s.now)
		action := strings.ToUpper(strings.TrimSpace(result.Action))
		if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken ||
			!controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) || action != v.TaskAction {
			return controlplane.ErrConflict
		}
		if action != "APPLY" && action != "INSPECT" {
			return controlplane.ErrValidation
		}
		if result.RecoveryRequired && result.Success {
			return controlplane.ErrValidation
		}
		result.ObservedDigest = strings.TrimSpace(result.ObservedDigest)
		result.Phase = strings.TrimSpace(result.Phase)
		result.Error = strings.TrimSpace(result.Error)

		if !result.Success {
			if result.RecoveryRequired {
				v.State, v.Phase = virtualcluster.StateRecoveryRequired, "RecoveryRequired"
				v.LastError = result.Error
				if v.LastError == "" {
					v.LastError = "virtual cluster runtime outcome requires authoritative recovery"
				}
				v.TaskAction = ""
			} else if action == "APPLY" {
				v.State, v.Phase = virtualcluster.StateFailed, "ApplyFailed"
				v.LastError = result.Error
				if v.LastError == "" {
					v.LastError = "virtual cluster apply failed before mutation convergence"
				}
				v.TaskAction = ""
			} else {
				v.State, v.Phase, v.TaskAction = virtualcluster.StateProvisioning, "InspectRetry", "INSPECT"
				v.LastError = result.Error
				if v.LastError == "" {
					v.LastError = "virtual cluster authoritative readback failed"
				}
			}
		} else if result.ObservedDigest != v.DesiredDigest {
			v.State, v.Phase, v.TaskAction = virtualcluster.StateRecoveryRequired, "RecoveryRequired", ""
			v.LastError = "virtual cluster authoritative readback digest does not match desired state"
		} else if result.Ready {
			v.State, v.ObservedDigest = virtualcluster.StateActive, result.ObservedDigest
			v.Phase = result.Phase
			if v.Phase == "" {
				v.Phase = "Ready"
			}
			v.PendingAction, v.TaskAction, v.LastError = "", "", ""
		} else {
			v.State, v.ObservedDigest, v.TaskAction = virtualcluster.StateProvisioning, result.ObservedDigest, "INSPECT"
			v.Phase = result.Phase
			if v.Phase == "" {
				v.Phase = "Reconciling"
			}
			v.LastError = ""
		}
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,observed_digest=$4,pending_action=$5,phase=$6,last_error=$7,task_action=$8,task_lease_expires_at=NULL,updated_at=$9 WHERE id=$1`,
			v.ID, v.Revision, string(v.State), v.ObservedDigest, string(v.PendingAction), v.Phase, v.LastError, v.TaskAction, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.task.reported", "virtualCluster", v.ID, v.Revision, "", map[string]any{"action": action, "success": result.Success, "ready": result.Ready, "recoveryRequired": result.RecoveryRequired, "taskFenceToken": result.TaskFenceToken}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "virtualCluster", v.ID, "virtual_cluster.state.changed", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
