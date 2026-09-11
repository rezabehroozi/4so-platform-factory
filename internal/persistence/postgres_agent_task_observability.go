package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

// AgentTaskQueueCounts keeps Queue Center agent-task health on a bounded SQL
// aggregate path. It never materializes the canonical snapshot or task payloads.
func (s *PostgresStore) AgentTaskQueueCounts(ctx context.Context, projectIDs []string, allProjects bool) (controlplane.AgentTaskQueueCounts, error) {
	projectJSON, err := json.Marshal(projectIDs)
	if err != nil {
		return controlplane.AgentTaskQueueCounts{}, err
	}
	const query = `
WITH selected_projects AS (
  SELECT id FROM projects
  WHERE $2::boolean OR id IN (SELECT jsonb_array_elements_text($1::jsonb))
), tasks AS (
  SELECT 'baseline'::text AS family, state::text, task_lease_expires_at AS lease_expires_at, task_attempt, updated_at
    FROM baseline_deployments WHERE project_id IN (SELECT id FROM selected_projects)
  UNION ALL
  SELECT 'runtime-verification', state::text, task_lease_expires_at, task_attempt, updated_at
    FROM runtime_verifications WHERE project_id IN (SELECT id FROM selected_projects)
  UNION ALL
  SELECT 'runtime-certification', state::text, task_lease_expires_at, task_attempt, updated_at
    FROM runtime_certification_runs WHERE project_id IN (SELECT id FROM selected_projects)
  UNION ALL
  SELECT 'tenant', state::text, task_lease_expires_at, task_attempt, updated_at
    FROM tenant_environments WHERE project_id IN (SELECT id FROM selected_projects)
  UNION ALL
  SELECT 'provider-profile', state::text, task_lease_expires_at, task_attempt, updated_at
    FROM provider_profiles WHERE project_id IN (SELECT id FROM selected_projects)
  UNION ALL
  SELECT 'provider-cluster', state::text, task_lease_expires_at, task_attempt, updated_at
    FROM provider_clusters WHERE project_id IN (SELECT id FROM selected_projects)
)
SELECT family, state, count(*) AS total,
       count(*) FILTER (WHERE lease_expires_at IS NOT NULL AND lease_expires_at > now()) AS active_leases,
       count(*) FILTER (WHERE lease_expires_at IS NOT NULL AND lease_expires_at <= now()) AS expired_leases,
       count(*) FILTER (WHERE task_attempt > 1) AS retried,
       COALESCE(max(task_attempt), 0) AS max_attempt,
       min(updated_at) FILTER (WHERE lease_expires_at IS NULL OR lease_expires_at <= now()) AS oldest_pending_at,
       min(updated_at) FILTER (WHERE lease_expires_at IS NOT NULL AND lease_expires_at > now()) AS oldest_executing_at
FROM tasks
GROUP BY family,state
ORDER BY family,state`
	rows, err := s.db.QueryContext(ctx, query, string(projectJSON), allProjects)
	if err != nil {
		return controlplane.AgentTaskQueueCounts{}, fmt.Errorf("agent-task queue aggregates: %w", err)
	}
	defer rows.Close()
	out := controlplane.AgentTaskQueueCounts{States: map[string]int{}}
	for rows.Next() {
		var family, state string
		var total, active, expired, retried, maxAttempt int
		var oldestPending, oldestExecuting sql.NullTime
		if err := rows.Scan(&family, &state, &total, &active, &expired, &retried, &maxAttempt, &oldestPending, &oldestExecuting); err != nil {
			return controlplane.AgentTaskQueueCounts{}, err
		}
		var pendingPtr, executingPtr *time.Time
		if oldestPending.Valid {
			v := oldestPending.Time.UTC()
			pendingPtr = &v
		}
		if oldestExecuting.Valid {
			v := oldestExecuting.Time.UTC()
			executingPtr = &v
		}
		controlplane.AddAgentTaskQueueState(&out, family, state, total, active, expired, retried, maxAttempt, pendingPtr, executingPtr)
	}
	if err := rows.Err(); err != nil {
		return controlplane.AgentTaskQueueCounts{}, err
	}
	return out, nil
}
