package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

// ListAuditPageByScopes resolves audit resource ownership inside PostgreSQL and
// applies authorization before LIMIT. This avoids the historical scoped API
// path that materialized a complete control-plane Snapshot and only then
// filtered audit rows in process.
func (s *PostgresStore) ListAuditPageByScopes(ctx context.Context, organizationIDs, projectIDs []string, limit int) ([]controlplane.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	organizations := normalizedScopeIDs(organizationIDs)
	projects := normalizedScopeIDs(projectIDs)
	if len(organizations) == 0 && len(projects) == 0 {
		return []controlplane.AuditEvent{}, nil
	}

	args := make([]any, 0, 3)
	orgArg, projectArg := 0, 0
	const separator = "\x1f"
	if len(organizations) > 0 {
		args = append(args, strings.Join(organizations, separator))
		orgArg = len(args)
	}
	if len(projects) > 0 {
		args = append(args, strings.Join(projects, separator))
		projectArg = len(args)
	}
	orgPredicate := func(column string) string {
		return fmt.Sprintf("%s = ANY(string_to_array($%d, chr(31)))", column, orgArg)
	}
	projectPredicate := func(column string) string {
		return fmt.Sprintf("%s = ANY(string_to_array($%d, chr(31)))", column, projectArg)
	}

	resourceQueries := make([]string, 0, 48)
	visibility := make([]string, 0, 3)
	if orgArg > 0 {
		resourceQueries = append(resourceQueries,
			"SELECT id FROM organizations WHERE "+orgPredicate("id"),
			"SELECT id FROM organization_memberships WHERE "+orgPredicate("organization_id"),
			"SELECT id FROM oidc_group_mappings WHERE project_id IS NULL AND "+orgPredicate("organization_id"),
			"SELECT id FROM service_accounts WHERE "+orgPredicate("organization_id"),
			"SELECT id FROM api_tokens WHERE "+orgPredicate("organization_id"),
			"SELECT id FROM catalog_trust_keys WHERE "+orgPredicate("organization_id"),
			"SELECT id FROM catalog_revisions WHERE "+orgPredicate("organization_id"),
			"SELECT id FROM catalog_releases WHERE "+orgPredicate("organization_id"),
			"SELECT id FROM notification_destinations WHERE "+orgPredicate("organization_id"),
			"SELECT id FROM notification_routes WHERE project_id IS NULL AND "+orgPredicate("organization_id"),
			"SELECT id FROM notification_events WHERE project_id IS NULL AND "+orgPredicate("organization_id"),
			"SELECT d.id FROM notification_deliveries d JOIN notification_events e ON e.id=d.event_id WHERE e.project_id IS NULL AND "+orgPredicate("e.organization_id"),
			"SELECT a.id FROM notification_delivery_attempts a JOIN notification_deliveries d ON d.id=a.delivery_id JOIN notification_events e ON e.id=d.event_id WHERE e.project_id IS NULL AND "+orgPredicate("e.organization_id"),
			"SELECT id FROM entitlements WHERE "+orgPredicate("organization_id"),
			"SELECT id FROM oem_profiles WHERE "+orgPredicate("organization_id"),
		)
		visibility = append(visibility, fmt.Sprintf("a.metadata->>'organizationId' = ANY(string_to_array($%d, chr(31)))", orgArg))
	}
	if projectArg > 0 {
		resourceQueries = append(resourceQueries,
			"SELECT id FROM projects WHERE "+projectPredicate("id"),
			"SELECT id FROM oidc_group_mappings WHERE "+projectPredicate("project_id"),
			"SELECT id FROM blueprint_overlays WHERE "+projectPredicate("project_id"),
			"SELECT id FROM blueprint_revisions WHERE "+projectPredicate("project_id"),
			"SELECT id FROM blueprint_releases WHERE "+projectPredicate("project_id"),
			"SELECT id FROM assignments WHERE "+projectPredicate("project_id"),
			"SELECT id FROM operations WHERE "+projectPredicate("project_id"),
			"SELECT s.id FROM operation_steps s JOIN operations o ON o.id=s.operation_id WHERE "+projectPredicate("o.project_id"),
			"SELECT t.id FROM operation_step_traces t JOIN operations o ON o.id=t.operation_id WHERE "+projectPredicate("o.project_id"),
			"SELECT c.id FROM operation_compensation_steps c JOIN operations o ON o.id=c.operation_id WHERE "+projectPredicate("o.project_id"),
			"SELECT e.id FROM evidence_metadata e JOIN operations o ON o.id=e.operation_id WHERE "+projectPredicate("o.project_id"),
			"SELECT id FROM notification_routes WHERE "+projectPredicate("project_id"),
			"SELECT id FROM notification_events WHERE "+projectPredicate("project_id"),
			"SELECT d.id FROM notification_deliveries d JOIN notification_events e ON e.id=d.event_id WHERE "+projectPredicate("e.project_id"),
			"SELECT a.id FROM notification_delivery_attempts a JOIN notification_deliveries d ON d.id=a.delivery_id JOIN notification_events e ON e.id=d.event_id WHERE "+projectPredicate("e.project_id"),
			"SELECT id FROM cluster_imports WHERE "+projectPredicate("project_id"),
			"SELECT id FROM managed_clusters WHERE "+projectPredicate("project_id"),
			"SELECT i.id FROM cluster_inventory_snapshots i JOIN managed_clusters c ON c.id=i.cluster_id WHERE "+projectPredicate("c.project_id"),
			"SELECT id FROM cluster_maintenance_profiles WHERE "+projectPredicate("project_id"),
			"SELECT id FROM cluster_maintenance_windows WHERE "+projectPredicate("project_id"),
			"SELECT id FROM cluster_maintenance_runs WHERE "+projectPredicate("project_id"),
			"SELECT a.id FROM agent_certificates a JOIN managed_clusters c ON c.id=a.cluster_id WHERE "+projectPredicate("c.project_id"),
			"SELECT id FROM baseline_deployments WHERE "+projectPredicate("project_id"),
			"SELECT id FROM runtime_verifications WHERE "+projectPredicate("project_id"),
			"SELECT id FROM runtime_certification_runs WHERE "+projectPredicate("project_id"),
			"SELECT id FROM recovery_checkpoints WHERE "+projectPredicate("project_id"),
			"SELECT id FROM fleet_groups WHERE "+projectPredicate("project_id"),
			"SELECT id FROM drift_scans WHERE "+projectPredicate("project_id"),
			"SELECT id FROM upgrade_campaigns WHERE "+projectPredicate("project_id"),
			"SELECT id FROM tenant_environments WHERE "+projectPredicate("project_id"),
			"SELECT id FROM provider_profiles WHERE "+projectPredicate("project_id"),
			"SELECT id FROM provider_clusters WHERE "+projectPredicate("project_id"),
			"SELECT id FROM marketplace_recommendations WHERE "+projectPredicate("project_id"),
			"SELECT id FROM runtime_closure_campaigns WHERE "+projectPredicate("project_id"),
		)
		visibility = append(visibility, fmt.Sprintf("a.metadata->>'projectId' = ANY(string_to_array($%d, chr(31)))", projectArg))
	}
	visibility = append([]string{"a.resource_id IN (SELECT id FROM allowed_resources)"}, visibility...)
	args = append(args, limit)
	limitArg := len(args)
	q := `WITH allowed_resources(id) AS (` + strings.Join(resourceQueries, ` UNION `) + `) ` +
		`SELECT a.id,a.occurred_at,a.actor_id,a.action,a.resource_type,a.resource_id,a.resource_revision,COALESCE(a.request_id,''),a.metadata ` +
		`FROM audit_events a WHERE (` + strings.Join(visibility, ` OR `) + `) ` +
		`ORDER BY a.occurred_at DESC,a.id DESC LIMIT $` + fmt.Sprint(limitArg)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.AuditEvent{}
	for rows.Next() {
		var value controlplane.AuditEvent
		var metadata []byte
		if err := rows.Scan(&value.ID, &value.OccurredAt, &value.ActorID, &value.Action, &value.ResourceType, &value.ResourceID, &value.Revision, &value.RequestID, &metadata); err != nil {
			return nil, err
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &value.Metadata); err != nil {
				return nil, err
			}
		}
		out = append(out, value)
	}
	return out, rows.Err()
}


func (s *PostgresStore) ListAuditPageByResource(ctx context.Context, resourceType, resourceID string, limit int) ([]controlplane.AuditEvent, error) {
	resourceType = strings.TrimSpace(resourceType)
	resourceID = strings.TrimSpace(resourceID)
	if resourceType == "" || resourceID == "" {
		return []controlplane.AuditEvent{}, controlplane.ErrValidation
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,occurred_at,actor_id,action,resource_type,resource_id,resource_revision,COALESCE(request_id,''),metadata
		 FROM audit_events
		 WHERE resource_type=$1 AND resource_id=$2
		 ORDER BY occurred_at DESC,id DESC LIMIT $3`,
		resourceType, resourceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.AuditEvent{}
	for rows.Next() {
		var value controlplane.AuditEvent
		var metadata []byte
		if err := rows.Scan(&value.ID, &value.OccurredAt, &value.ActorID, &value.Action, &value.ResourceType, &value.ResourceID, &value.Revision, &value.RequestID, &metadata); err != nil {
			return nil, err
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &value.Metadata); err != nil {
				return nil, err
			}
		}
		out = append(out, value)
	}
	return out, rows.Err()
}
