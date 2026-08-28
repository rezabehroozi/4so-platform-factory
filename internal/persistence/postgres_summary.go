package persistence

import (
	"context"
	"encoding/json"
	"fmt"

	"platform.4so.io/factory/internal/controlplane"
)

// ControlPlaneSummaryCounts returns the dashboard aggregate directly from
// PostgreSQL. It intentionally does not call Snapshot(): Snapshot is a backup /
// diagnostics authority and materializes append-only history and evidence
// payloads, which is not an acceptable hot-path dependency for a polled UI.
func (s *PostgresStore) ControlPlaneSummaryCounts(ctx context.Context, organizationIDs, projectIDs, resourceOrganizationIDs []string, allOrganizationsAndProjects, allResourceOrganizations bool) (controlplane.ControlPlaneSummaryCounts, error) {
	if allOrganizationsAndProjects && allResourceOrganizations {
		return s.globalControlPlaneSummaryCounts(ctx)
	}
	orgJSON, err := json.Marshal(organizationIDs)
	if err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, err
	}
	projectJSON, err := json.Marshal(projectIDs)
	if err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, err
	}
	resourceOrgJSON, err := json.Marshal(resourceOrganizationIDs)
	if err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, err
	}

	// visible_resources mirrors api.buildScopeIndex for the resource families
	// that can own audit/outbox rows. Organization resources are deliberately
	// separate from selected_orgs because project-scoped API tokens may see the
	// containing organization in the summary without gaining organization-wide
	// audit/outbox visibility.
	const query = `
WITH
selected_orgs AS (
  SELECT id FROM organizations
  WHERE $4::boolean OR id IN (SELECT jsonb_array_elements_text($1::jsonb))
),
selected_projects AS (
  SELECT id FROM projects
  WHERE $4::boolean OR id IN (SELECT jsonb_array_elements_text($2::jsonb))
),
resource_orgs AS (
  SELECT id FROM organizations
  WHERE $5::boolean OR id IN (SELECT jsonb_array_elements_text($3::jsonb))
),
operation_scope AS (
  SELECT id,state FROM operations WHERE project_id IN (SELECT id FROM selected_projects)
),
visible_resources(id) AS (
  SELECT id FROM resource_orgs
  UNION SELECT id FROM selected_projects
  UNION SELECT id FROM organization_memberships WHERE organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM oidc_group_mappings WHERE (project_id IS NOT NULL AND project_id IN (SELECT id FROM selected_projects)) OR (project_id IS NULL AND organization_id IN (SELECT id FROM resource_orgs))
  UNION SELECT id FROM service_accounts WHERE organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM api_tokens WHERE organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM blueprint_overlays WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM blueprint_revisions WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM blueprint_releases WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM catalog_trust_keys WHERE organization_id IS NOT NULL AND organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM catalog_revisions WHERE organization_id IS NOT NULL AND organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM catalog_releases WHERE organization_id IS NOT NULL AND organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM assignments WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM operation_scope
  UNION SELECT s.id FROM operation_steps s JOIN operation_scope o ON o.id=s.operation_id
  UNION SELECT t.id FROM operation_step_traces t JOIN operation_scope o ON o.id=t.operation_id
  UNION SELECT c.id FROM operation_compensation_steps c JOIN operation_scope o ON o.id=c.operation_id
  UNION SELECT e.id FROM evidence_metadata e JOIN operation_scope o ON o.id=e.operation_id
  UNION SELECT id FROM notification_destinations WHERE organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM notification_routes WHERE (project_id IS NOT NULL AND project_id IN (SELECT id FROM selected_projects)) OR (project_id IS NULL AND organization_id IN (SELECT id FROM resource_orgs))
  UNION SELECT id FROM notification_events WHERE (project_id IS NOT NULL AND project_id IN (SELECT id FROM selected_projects)) OR (project_id IS NULL AND organization_id IN (SELECT id FROM resource_orgs))
  UNION SELECT d.id FROM notification_deliveries d JOIN notification_events e ON e.id=d.event_id WHERE (e.project_id IS NOT NULL AND e.project_id IN (SELECT id FROM selected_projects)) OR (e.project_id IS NULL AND e.organization_id IN (SELECT id FROM resource_orgs))
  UNION SELECT a.id FROM notification_delivery_attempts a JOIN notification_deliveries d ON d.id=a.delivery_id JOIN notification_events e ON e.id=d.event_id WHERE (e.project_id IS NOT NULL AND e.project_id IN (SELECT id FROM selected_projects)) OR (e.project_id IS NULL AND e.organization_id IN (SELECT id FROM resource_orgs))
  UNION SELECT id FROM cluster_imports WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM managed_clusters WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT i.id FROM cluster_inventory_snapshots i JOIN managed_clusters c ON c.id=i.cluster_id WHERE c.project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM cluster_maintenance_profiles WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM cluster_maintenance_windows WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM cluster_maintenance_runs WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT a.id FROM agent_certificates a JOIN managed_clusters c ON c.id=a.cluster_id WHERE c.project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM baseline_deployments WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM runtime_verifications WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM runtime_certification_runs WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM recovery_checkpoints WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM fleet_groups WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM drift_scans WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM upgrade_campaigns WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM entitlements WHERE organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM oem_profiles WHERE organization_id IN (SELECT id FROM resource_orgs)
  UNION SELECT id FROM tenant_environments WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM provider_profiles WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM provider_clusters WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM marketplace_recommendations WHERE project_id IN (SELECT id FROM selected_projects)
  UNION SELECT id FROM runtime_closure_campaigns WHERE project_id IN (SELECT id FROM selected_projects)
)
SELECT
  (SELECT count(*) FROM selected_orgs),
  (SELECT count(*) FROM selected_projects),
  (SELECT count(*) FROM blueprint_revisions WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM assignments WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM operation_scope),
  (SELECT count(*) FROM outbox_events WHERE published_at IS NULL AND aggregate_id IN (SELECT id FROM visible_resources)),
  (SELECT count(*) FROM audit_events WHERE resource_id IN (SELECT id FROM visible_resources) OR COALESCE(metadata->>'organizationId','') IN (SELECT id FROM resource_orgs) OR COALESCE(metadata->>'projectId','') IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM evidence_metadata e JOIN operation_scope o ON o.id=e.operation_id),
  (SELECT count(*) FROM cluster_imports WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM managed_clusters WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM baseline_deployments WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM runtime_verifications WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM runtime_closure_campaigns WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM entitlements WHERE organization_id IN (SELECT id FROM resource_orgs)),
  (SELECT count(*) FROM oem_profiles WHERE organization_id IN (SELECT id FROM resource_orgs)),
  (SELECT count(*) FROM tenant_environments WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM provider_profiles WHERE project_id IN (SELECT id FROM selected_projects)),
  (SELECT count(*) FROM provider_clusters WHERE project_id IN (SELECT id FROM selected_projects))`

	var out controlplane.ControlPlaneSummaryCounts
	err = s.db.QueryRowContext(ctx, query, string(orgJSON), string(projectJSON), string(resourceOrgJSON), allOrganizationsAndProjects, allResourceOrganizations).Scan(
		&out.Organizations, &out.Projects, &out.BlueprintRevisions, &out.Assignments, &out.Operations,
		&out.UnpublishedOutbox, &out.AuditEvents, &out.Evidence, &out.ClusterImports, &out.ManagedClusters,
		&out.BaselineDeployments, &out.RuntimeVerifications, &out.RuntimeClosureCampaigns, &out.Entitlements,
		&out.OEMProfiles, &out.Tenants, &out.ProviderProfiles, &out.ProviderClusters,
	)
	if err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, fmt.Errorf("control-plane summary aggregates: %w", err)
	}
	out.OperationStates = map[controlplane.OperationState]int{}
	rows, err := s.db.QueryContext(ctx, `
WITH selected_projects AS (
  SELECT id FROM projects
  WHERE $2::boolean OR id IN (SELECT jsonb_array_elements_text($1::jsonb))
)
SELECT state,count(*) FROM operations WHERE project_id IN (SELECT id FROM selected_projects) GROUP BY state`, string(projectJSON), allOrganizationsAndProjects)
	if err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, fmt.Errorf("control-plane operation-state aggregates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int
		if scanErr := rows.Scan(&state, &count); scanErr != nil {
			return controlplane.ControlPlaneSummaryCounts{}, scanErr
		}
		out.OperationStates[controlplane.OperationState(state)] = count
	}
	if err = rows.Err(); err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, err
	}
	return out, nil
}

func (s *PostgresStore) globalControlPlaneSummaryCounts(ctx context.Context) (controlplane.ControlPlaneSummaryCounts, error) {
	const query = `SELECT
  (SELECT count(*) FROM organizations),
  (SELECT count(*) FROM projects),
  (SELECT count(*) FROM blueprint_revisions),
  (SELECT count(*) FROM assignments),
  (SELECT count(*) FROM operations),
  (SELECT count(*) FROM outbox_events WHERE published_at IS NULL),
  (SELECT count(*) FROM audit_events),
  (SELECT count(*) FROM evidence_metadata),
  (SELECT count(*) FROM cluster_imports),
  (SELECT count(*) FROM managed_clusters),
  (SELECT count(*) FROM baseline_deployments),
  (SELECT count(*) FROM runtime_verifications),
  (SELECT count(*) FROM runtime_closure_campaigns),
  (SELECT count(*) FROM entitlements),
  (SELECT count(*) FROM oem_profiles),
  (SELECT count(*) FROM tenant_environments),
  (SELECT count(*) FROM provider_profiles),
  (SELECT count(*) FROM provider_clusters)`
	var out controlplane.ControlPlaneSummaryCounts
	if err := s.db.QueryRowContext(ctx, query).Scan(
		&out.Organizations, &out.Projects, &out.BlueprintRevisions, &out.Assignments, &out.Operations,
		&out.UnpublishedOutbox, &out.AuditEvents, &out.Evidence, &out.ClusterImports, &out.ManagedClusters,
		&out.BaselineDeployments, &out.RuntimeVerifications, &out.RuntimeClosureCampaigns, &out.Entitlements,
		&out.OEMProfiles, &out.Tenants, &out.ProviderProfiles, &out.ProviderClusters,
	); err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, fmt.Errorf("global control-plane summary aggregates: %w", err)
	}
	out.OperationStates = map[controlplane.OperationState]int{}
	rows, err := s.db.QueryContext(ctx, `SELECT state,count(*) FROM operations GROUP BY state`)
	if err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, fmt.Errorf("global operation-state aggregates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int
		if scanErr := rows.Scan(&state, &count); scanErr != nil {
			return controlplane.ControlPlaneSummaryCounts{}, scanErr
		}
		out.OperationStates[controlplane.OperationState(state)] = count
	}
	if err = rows.Err(); err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, err
	}
	return out, nil
}
