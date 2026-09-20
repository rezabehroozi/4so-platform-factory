package persistence

import (
	"context"
	"encoding/json"
	"fmt"

	"platform.4so.io/factory/internal/controlplane"
)

// ControlPlaneAttention returns the newest urgent operator items from PostgreSQL
// with project authorization applied before LIMIT. It is intentionally a small
// cross-resource projection rather than a materialization of each owning table.
func (s *PostgresStore) ControlPlaneAttention(ctx context.Context, projectIDs []string, allProjects bool, limit int) ([]controlplane.OperatorAttentionItem, error) {
	if limit <= 0 || limit > 50 {
		return nil, fmt.Errorf("attention limit must be between 1 and 50")
	}
	projectJSON, err := json.Marshal(projectIDs)
	if err != nil {
		return nil, err
	}
	const query = `
WITH selected_projects AS (
  SELECT id FROM projects
  WHERE $2::boolean OR id IN (SELECT jsonb_array_elements_text($1::jsonb))
), attention AS (
  SELECT 'baseline-deployment'::text kind,id,project_id,(baseline_id || '@' || baseline_version)::text display_name,state::text,
         COALESCE(NULLIF(last_error,''),'Baseline deployment failed and can be inspected from its record.')::text message,
         'baselines'::text page,updated_at
    FROM baseline_deployments WHERE project_id IN (SELECT id FROM selected_projects) AND state='FAILED'
  UNION ALL
  SELECT 'runtime-verification',id,project_id,id,state::text,
         COALESCE(NULLIF(last_error,''),'Runtime verification failed and can be retried from its record.'),
         'verification',updated_at
    FROM runtime_verifications WHERE project_id IN (SELECT id FROM selected_projects) AND state='FAILED'
  UNION ALL
  SELECT 'runtime-closure',id,project_id,id,state::text,
         COALESCE(NULLIF(last_error,''),'Runtime closure failed and requires operator review.'),
         'verification',updated_at
    FROM runtime_closure_campaigns WHERE project_id IN (SELECT id FROM selected_projects) AND state='FAILED'
  UNION ALL
  SELECT 'tenant',id,project_id,display_name,state::text,
         COALESCE(NULLIF(last_error,''),'Tenant workflow failed and requires operator review.'),
         'tenants',updated_at
    FROM tenant_environments WHERE project_id IN (SELECT id FROM selected_projects) AND state='FAILED'
  UNION ALL
  SELECT 'provider-profile',id,project_id,display_name,state::text,
         COALESCE(NULLIF(last_error,''),'Provider profile verification failed.'),
         'providers',updated_at
    FROM provider_profiles WHERE project_id IN (SELECT id FROM selected_projects) AND state='FAILED'
  UNION ALL
  SELECT 'provider-cluster',id,project_id,display_name,state::text,
         COALESCE(NULLIF(last_error,''),'Provider cluster workflow failed.'),
         'providers',updated_at
    FROM provider_clusters WHERE project_id IN (SELECT id FROM selected_projects) AND state IN ('FAILED','RECOVERY_REQUIRED')
  UNION ALL
  SELECT 'managed-cluster',id,project_id,display_name,'OFFLINE'::text,
         'Cluster heartbeat or inventory is stale.'::text,
         'clusters'::text,updated_at
    FROM managed_clusters
   WHERE project_id IN (SELECT id FROM selected_projects)
     AND connection_state <> 'REVOKED'
     AND (last_seen_at IS NULL OR last_seen_at < now() - interval '3 minutes')
)
SELECT kind,id,project_id,display_name,state,message,page,updated_at
  FROM attention
 ORDER BY updated_at DESC,id DESC
 LIMIT $3`
	rows, err := s.db.QueryContext(ctx, query, string(projectJSON), allProjects, limit)
	if err != nil {
		return nil, fmt.Errorf("control-plane attention query: %w", err)
	}
	defer rows.Close()
	out := make([]controlplane.OperatorAttentionItem, 0, limit)
	for rows.Next() {
		var item controlplane.OperatorAttentionItem
		if err := rows.Scan(&item.Kind, &item.ID, &item.ProjectID, &item.DisplayName, &item.State, &item.Message, &item.Page, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
