package persistence

import (
	"context"
	"database/sql"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/virtualcluster"
)

func (s *PostgresStore) RequestVirtualClusterLifecycle(ctx context.Context, id string, expected int64, action, idempotencyKey, requestDigest, actor string) (controlplane.VirtualCluster, bool, error) {
	var out controlplane.VirtualCluster
	replay := false
	id = strings.TrimSpace(id)
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	requestDigest = strings.TrimSpace(requestDigest)
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, err := scanVirtualCluster(tx.QueryRowContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if idempotencyKey != "" && v.LifecycleIdempotencyKey == idempotencyKey {
			updated, exactReplay, err := controlplane.PrepareVirtualClusterLifecycleRequest(v, expected, virtualcluster.Action(action), idempotencyKey, requestDigest, utcNow(s.now))
			if err != nil { return err }
			out, replay = updated, exactReplay
			return nil
		}
		binding, err := scanWorkspaceBinding(tx.QueryRowContext(ctx, `SELECT `+workspaceBindingColumns+` FROM workspace_bindings WHERE id=$1 FOR SHARE`, v.WorkspaceBindingID))
		if err != nil { return mapDBError(err) }
		if binding.WorkspaceID != v.WorkspaceID || binding.ProjectID != v.ProjectID || binding.ClusterID != v.HostClusterID || binding.Namespace != v.HostNamespace || binding.Revision != v.WorkspaceBindingRevision || binding.State != controlplane.WorkspaceBindingActive {
			return controlplane.ErrPrerequisite
		}
		updated, exactReplay, err := controlplane.PrepareVirtualClusterLifecycleRequest(v, expected, virtualcluster.Action(action), idempotencyKey, requestDigest, utcNow(s.now))
		if err != nil { return err }
		if exactReplay { out, replay = updated, true; return nil }
		_, err = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,state=$3,pending_action=$4,lifecycle_action=$5,lifecycle_idempotency_key=$6,lifecycle_request_digest=$7,task_action='',task_lease_expires_at=NULL,task_dispatched_at=NULL,phase=$8,last_error='',updated_at=$9 WHERE id=$1`,
			updated.ID, updated.Revision, string(updated.State), string(updated.PendingAction), string(updated.LifecycleAction), updated.LifecycleIdempotencyKey, updated.LifecycleRequestDigest, updated.Phase, updated.UpdatedAt)
		if err != nil { return mapDBError(err) }
		if err = s.appendAuditTx(ctx, tx, actor, "virtual_cluster.lifecycle.requested", "virtualCluster", updated.ID, updated.Revision, "", map[string]any{"action": updated.LifecycleAction, "workspaceId": updated.WorkspaceID, "hostClusterId": updated.HostClusterID}); err != nil { return err }
		if err = s.appendOutboxTx(ctx, tx, "virtualCluster", updated.ID, "virtual_cluster.state.changed", updated); err != nil { return err }
		out = updated
		return nil
	})
	return out, replay, err
}

func (s *PostgresStore) DispatchVirtualClusterTask(ctx context.Context, clusterID, tokenDigest, virtualClusterID string, expected, fence int64, action string) (controlplane.VirtualClusterTask, bool, error) {
	var out controlplane.VirtualClusterTask
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if err := s.validateFreshClusterAgentTx(ctx, tx, clusterID, tokenDigest); err != nil { return err }
		v, err := scanVirtualCluster(tx.QueryRowContext(ctx, `SELECT `+virtualClusterColumns+` FROM virtual_clusters WHERE id=$1 FOR UPDATE`, strings.TrimSpace(virtualClusterID)))
		if err != nil { return mapDBError(err) }
		if v.HostClusterID != strings.TrimSpace(clusterID) { return controlplane.ErrNotFound }
		updated, exactReplay, err := controlplane.ApplyVirtualClusterTaskDispatch(v, expected, fence, action, utcNow(s.now))
		if err != nil { return err }
		if exactReplay { out, replay = controlplane.VirtualClusterTaskFromRecord(updated), true; return nil }
		_, err = tx.ExecContext(ctx, `UPDATE virtual_clusters SET revision=$2,task_dispatched_at=$3,phase=$4,updated_at=$5 WHERE id=$1`, updated.ID, updated.Revision, updated.TaskDispatchedAt, updated.Phase, updated.UpdatedAt)
		if err != nil { return mapDBError(err) }
		if err = s.appendAuditTx(ctx, tx, "cluster-agent", "virtual_cluster.task.dispatched", "virtualCluster", updated.ID, updated.Revision, "", map[string]any{"action": updated.TaskAction, "taskFenceToken": updated.TaskFenceToken}); err != nil { return err }
		if err = s.appendOutboxTx(ctx, tx, "virtualCluster", updated.ID, "virtual_cluster.state.changed", updated); err != nil { return err }
		out = controlplane.VirtualClusterTaskFromRecord(updated)
		return nil
	})
	return out, replay, err
}
