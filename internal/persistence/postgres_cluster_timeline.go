package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

// ListClusterTimelineAuditPage builds the cluster resource set inside
// PostgreSQL and applies LIMIT only after cluster scoping. This is the bounded
// production path used by timeline and support-bundle diagnostics.
func (s *PostgresStore) ListClusterTimelineAuditPage(ctx context.Context, clusterID string, limit int) ([]controlplane.AuditEvent, error) {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return nil, controlplane.ErrValidation
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM managed_clusters WHERE id=$1)`, clusterID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, controlplane.ErrNotFound
	}
	clusterArray, _ := json.Marshal([]string{clusterID})
	targetNeedle, _ := json.Marshal([]map[string]string{{"clusterId": clusterID}})
	q := `WITH cluster_scope AS (
        SELECT id,project_id,import_id FROM managed_clusters WHERE id=$1
    ), related_operations AS (
        SELECT id FROM operations WHERE project_id=(SELECT project_id FROM cluster_scope) AND (target_ref=$1 OR target_ref='cluster/'||$1)
        UNION
        SELECT operation_id FROM cluster_maintenance_runs WHERE cluster_id=$1 AND operation_id <> ''
    ), allowed_resources(id) AS (
        SELECT id FROM cluster_scope
        UNION SELECT import_id FROM cluster_scope
        UNION SELECT id FROM related_operations
        UNION SELECT s.id FROM operation_steps s JOIN related_operations o ON o.id=s.operation_id
        UNION SELECT t.id FROM operation_step_traces t JOIN related_operations o ON o.id=t.operation_id
        UNION SELECT c.id FROM operation_compensation_steps c JOIN related_operations o ON o.id=c.operation_id
        UNION SELECT e.id FROM evidence_metadata e JOIN related_operations o ON o.id=e.operation_id
        UNION SELECT id FROM cluster_inventory_snapshots WHERE cluster_id=$1
        UNION SELECT id FROM agent_certificates WHERE cluster_id=$1
        UNION SELECT id FROM cluster_maintenance_profiles WHERE cluster_id=$1
        UNION SELECT id FROM cluster_maintenance_windows WHERE cluster_id=$1
        UNION SELECT id FROM cluster_maintenance_runs WHERE cluster_id=$1
        UNION SELECT id FROM baseline_deployments WHERE cluster_id=$1
        UNION SELECT id FROM runtime_verifications WHERE cluster_id=$1
        UNION SELECT id FROM runtime_certification_runs WHERE cluster_id=$1
        UNION SELECT id FROM runtime_closure_campaigns WHERE cluster_id=$1
        UNION SELECT id FROM recovery_checkpoints WHERE cluster_id=$1
        UNION SELECT id FROM tenant_environments WHERE cluster_id=$1
        UNION SELECT id FROM provider_profiles WHERE management_cluster_id=$1
        UNION SELECT id FROM provider_clusters WHERE management_cluster_id=$1
        UNION SELECT id FROM marketplace_recommendations WHERE cluster_id=$1
        UNION SELECT id FROM workspace_bindings WHERE cluster_id=$1
        UNION SELECT workspace_id FROM workspace_bindings WHERE cluster_id=$1
        UNION SELECT id FROM fleet_groups WHERE cluster_ids @> $2::jsonb
        UNION SELECT id FROM drift_scans WHERE targets @> $3::jsonb
        UNION SELECT id FROM upgrade_campaigns WHERE targets @> $3::jsonb
    )
    SELECT a.id,a.occurred_at,a.actor_id,a.action,a.resource_type,a.resource_id,a.resource_revision,COALESCE(a.request_id,''),a.metadata
    FROM audit_events a
    WHERE a.resource_id IN (SELECT id FROM allowed_resources) OR a.metadata->>'clusterId'=$1
    ORDER BY a.occurred_at DESC,a.id DESC LIMIT $4`
	rows, err := s.db.QueryContext(ctx, q, clusterID, string(clusterArray), string(targetNeedle), limit)
	if err != nil {
		return nil, fmt.Errorf("cluster timeline query: %w", err)
	}
	defer rows.Close()
	out := []controlplane.AuditEvent{}
	for rows.Next() {
		var v controlplane.AuditEvent
		var metadata []byte
		if err := rows.Scan(&v.ID, &v.OccurredAt, &v.ActorID, &v.Action, &v.ResourceType, &v.ResourceID, &v.Revision, &v.RequestID, &metadata); err != nil {
			return nil, err
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &v.Metadata); err != nil {
				return nil, err
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
