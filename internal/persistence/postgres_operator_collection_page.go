package persistence

import (
	"context"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
)

func consoleLimit(limit int) int {
	if limit < 1 {
		return 1
	}
	// API callers may request maxLimit+1 internally to detect whether a
	// continuation cursor is required. The public maximum remains 200.
	if limit > 201 {
		return 201
	}
	return limit
}
func appendConsoleProjectScope(q string, args *[]any, ids []string, all bool) string {
	if all {
		return q
	}
	clean := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			clean = append(clean, id)
		}
	}
	if len(clean) == 0 {
		return q + " AND FALSE"
	}
	q += " AND project_id IN ("
	for i, id := range clean {
		if i > 0 {
			q += ","
		}
		*args = append(*args, id)
		q += fmt.Sprintf("$%d", len(*args))
	}
	return q + ")"
}
func appendConsoleFilter(q string, args *[]any, column, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return q
	}
	*args = append(*args, value)
	return q + fmt.Sprintf(" AND %s=$%d", column, len(*args))
}
func appendConsoleLimit(q string, args *[]any, cursor *controlplane.CollectionCursor, limit int) string {
	if cursor != nil {
		*args = append(*args, cursor.UpdatedAt.UTC(), cursor.ID)
		updatedArg, idArg := len(*args)-1, len(*args)
		q += fmt.Sprintf(" AND (updated_at < $%d OR (updated_at = $%d AND id < $%d))", updatedArg, updatedArg, idArg)
	}
	*args = append(*args, consoleLimit(limit))
	return q + fmt.Sprintf(" ORDER BY updated_at DESC,id DESC LIMIT $%d", len(*args))
}

func (s *PostgresStore) ListManagedClustersPage(ctx context.Context, ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ManagedCluster, error) {
	q := `SELECT ` + managedClusterColumns + ` FROM managed_clusters WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.ManagedCluster{}
	for rows.Next() {
		v, e := scanManagedCluster(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListClusterImportsPage(ctx context.Context, ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ClusterImport, error) {
	q := `SELECT ` + clusterImportColumns + ` FROM cluster_imports WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	now := utcNow(s.now)
	out := []controlplane.ClusterImport{}
	for rows.Next() {
		v, e := scanClusterImport(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, effectivePostgresClusterImport(v, now))
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListBaselineDeploymentsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.BaselineDeployment, error) {
	q := `SELECT ` + baselineDeploymentColumns + ` FROM baseline_deployments WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "cluster_id", cluster)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
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
func (s *PostgresStore) ListRuntimeVerificationsPage(ctx context.Context, ids []string, all bool, cluster, baseline string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.RuntimeVerification, error) {
	q := `SELECT ` + runtimeVerificationColumns + ` FROM runtime_verifications WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "cluster_id", cluster)
	q = appendConsoleFilter(q, &a, "baseline_deployment_id", baseline)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.RuntimeVerification{}
	for rows.Next() {
		v, e := scanRuntimeVerification(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListRuntimeClosureCampaignsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.RuntimeClosureCampaign, error) {
	q := `SELECT ` + runtimeClosureColumns + ` FROM runtime_closure_campaigns WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "cluster_id", cluster)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.RuntimeClosureCampaign{}
	for rows.Next() {
		v, e := scanRuntimeClosureCampaign(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListRuntimeCertificationsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.RuntimeCertificationRun, error) {
	q := `SELECT ` + runtimeCertificationColumns + ` FROM runtime_certification_runs WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "cluster_id", cluster)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.RuntimeCertificationRun{}
	for rows.Next() {
		v, e := scanRuntimeCertification(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListProviderProfilesPage(ctx context.Context, ids []string, all bool, cluster string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ProviderProfile, error) {
	q := `SELECT ` + providerProfileColumns + ` FROM provider_profiles WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "management_cluster_id", cluster)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.ProviderProfile{}
	for rows.Next() {
		v, e := scanProviderProfile(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListProviderClustersPage(ctx context.Context, ids []string, all bool, profile string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ProviderCluster, error) {
	q := `SELECT ` + providerClusterColumns + ` FROM provider_clusters WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "provider_profile_id", profile)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.ProviderCluster{}
	for rows.Next() {
		v, e := scanProviderCluster(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListDriftScansPage(ctx context.Context, ids []string, all bool, group string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.DriftScan, error) {
	q := `SELECT ` + driftScanColumns + ` FROM drift_scans WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "fleet_group_id", group)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.DriftScan{}
	for rows.Next() {
		v, e := scanDriftScan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListTenantsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.TenantEnvironment, error) {
	q := `SELECT ` + tenantColumns + ` FROM tenant_environments WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "cluster_id", cluster)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.TenantEnvironment{}
	for rows.Next() {
		v, e := scanTenant(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListAIRunsPage(ctx context.Context, ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.AIRun, error) {
	q := `SELECT ` + aiRunColumns + ` FROM ai_runs WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.AIRun{}
	for rows.Next() {
		v, e := scanAIRun(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListBlueprintReleasesPage(ctx context.Context, ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.BlueprintRelease, error) {
	q := `SELECT ` + blueprintReleaseColumns + ` FROM blueprint_releases WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.BlueprintRelease{}
	for rows.Next() {
		v, e := scanBlueprintRelease(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListPlatformTemplatesPage(ctx context.Context, ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.PlatformTemplate, error) {
	q := `SELECT ` + platformTemplateColumns + ` FROM platform_templates WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.PlatformTemplate{}
	for rows.Next() {
		v, e := scanPlatformTemplate(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListWorkspacesPage(ctx context.Context, ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.Workspace, error) {
	q := `SELECT ` + workspaceColumns + ` FROM workspaces WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.Workspace{}
	for rows.Next() {
		v, e := scanWorkspace(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListRecoveryCheckpointsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.RecoveryCheckpoint, error) {
	q := `SELECT ` + recoveryCheckpointColumns + ` FROM recovery_checkpoints WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "cluster_id", cluster)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.RecoveryCheckpoint{}
	for rows.Next() {
		v, e := scanRecoveryCheckpoint(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListFleetGroupsPage(ctx context.Context, ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.FleetGroup, error) {
	q := `SELECT ` + fleetGroupColumns + ` FROM fleet_groups WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.FleetGroup{}
	for rows.Next() {
		v, e := scanFleetGroup(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListUpgradeCampaignsPage(ctx context.Context, ids []string, all bool, group string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.UpgradeCampaign, error) {
	q := `SELECT ` + upgradeCampaignColumns + ` FROM upgrade_campaigns WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "fleet_group_id", group)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.UpgradeCampaign{}
	for rows.Next() {
		v, e := scanUpgradeCampaign(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ListMarketplaceInstallationsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.BaselineDeployment, error) {
	q := `SELECT ` + baselineDeploymentColumns + ` FROM baseline_deployments WHERE source_type=$1`
	a := []any{controlplane.BaselineSourceMarketplace}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "cluster_id", cluster)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
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
func (s *PostgresStore) ListMarketplaceRecommendationsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.MarketplaceRecommendation, error) {
	q := `SELECT ` + marketplaceRecommendationColumns + ` FROM marketplace_recommendations WHERE 1=1`
	a := []any{}
	q = appendConsoleProjectScope(q, &a, ids, all)
	q = appendConsoleFilter(q, &a, "cluster_id", cluster)
	q = appendConsoleLimit(q, &a, cursor, limit)
	rows, e := s.db.QueryContext(ctx, q, a...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.MarketplaceRecommendation{}
	for rows.Next() {
		v, e := scanMarketplaceRecommendation(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
