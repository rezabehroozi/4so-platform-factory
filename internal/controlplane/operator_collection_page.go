package controlplane

import (
	"context"
	"sort"
	"time"
)

// CollectionCursor is the stable continuation boundary for operator collections.
// The next page contains resources strictly older than this (updated_at,id) tuple.
type CollectionCursor struct {
	UpdatedAt time.Time
	ID        string
}

type CollectionItem interface {
	CollectionMeta() ResourceMeta
}

// CollectionMeta is promoted by every resource that embeds ResourceMeta, which
// keeps pagination generic without a central type switch or transport-owned
// knowledge of every product resource type.
func (m ResourceMeta) CollectionMeta() ResourceMeta { return m }

func boundedNewest[T any](items []T, limit int, updated func(T) ResourceMeta) []T {
	out := append([]T(nil), items...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := updated(out[i]), updated(out[j])
		if a.UpdatedAt.Equal(b.UpdatedAt) {
			return a.ID > b.ID
		}
		return a.UpdatedAt.After(b.UpdatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
func projectAllowed(id string, ids []string, all bool) bool {
	if all {
		return true
	}
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func filterProjectNewest[T any](items []T, ids []string, all bool, cursor *CollectionCursor, limit int, project func(T) string, meta func(T) ResourceMeta) []T {
	allowed := make([]T, 0, len(items))
	for _, item := range items {
		if !projectAllowed(project(item), ids, all) {
			continue
		}
		resource := meta(item)
		if cursor != nil && !(resource.UpdatedAt.Before(cursor.UpdatedAt) || (resource.UpdatedAt.Equal(cursor.UpdatedAt) && resource.ID < cursor.ID)) {
			continue
		}
		allowed = append(allowed, item)
	}
	return boundedNewest(allowed, limit, meta)
}

func (s *MemoryStore) ListManagedClustersPage(ctx context.Context, ids []string, all bool, cursor *CollectionCursor, limit int) ([]ManagedCluster, error) {
	v, e := s.ListManagedClusters(ctx, "")
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x ManagedCluster) string { return x.ProjectID }, func(x ManagedCluster) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListClusterImportsPage(ctx context.Context, ids []string, all bool, cursor *CollectionCursor, limit int) ([]ClusterImport, error) {
	v, e := s.ListClusterImports(ctx, "")
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x ClusterImport) string { return x.ProjectID }, func(x ClusterImport) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListBaselineDeploymentsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *CollectionCursor, limit int) ([]BaselineDeployment, error) {
	v, e := s.ListBaselineDeployments(ctx, "", cluster)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x BaselineDeployment) string { return x.ProjectID }, func(x BaselineDeployment) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListRuntimeVerificationsPage(ctx context.Context, ids []string, all bool, cluster, baseline string, cursor *CollectionCursor, limit int) ([]RuntimeVerification, error) {
	v, e := s.ListRuntimeVerifications(ctx, "", cluster, baseline)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x RuntimeVerification) string { return x.ProjectID }, func(x RuntimeVerification) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListRuntimeClosureCampaignsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *CollectionCursor, limit int) ([]RuntimeClosureCampaign, error) {
	v, e := s.ListRuntimeClosureCampaigns(ctx, "", cluster)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x RuntimeClosureCampaign) string { return x.ProjectID }, func(x RuntimeClosureCampaign) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListRuntimeCertificationsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *CollectionCursor, limit int) ([]RuntimeCertificationRun, error) {
	v, e := s.ListRuntimeCertifications(ctx, "", cluster)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x RuntimeCertificationRun) string { return x.ProjectID }, func(x RuntimeCertificationRun) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListProviderProfilesPage(ctx context.Context, ids []string, all bool, cluster string, cursor *CollectionCursor, limit int) ([]ProviderProfile, error) {
	v, e := s.ListProviderProfiles(ctx, "", cluster)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x ProviderProfile) string { return x.ProjectID }, func(x ProviderProfile) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListProviderClustersPage(ctx context.Context, ids []string, all bool, profile string, cursor *CollectionCursor, limit int) ([]ProviderCluster, error) {
	v, e := s.ListProviderClusters(ctx, "", profile)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x ProviderCluster) string { return x.ProjectID }, func(x ProviderCluster) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListDriftScansPage(ctx context.Context, ids []string, all bool, group string, cursor *CollectionCursor, limit int) ([]DriftScan, error) {
	v, e := s.ListDriftScans(ctx, "", group)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x DriftScan) string { return x.ProjectID }, func(x DriftScan) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListTenantsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *CollectionCursor, limit int) ([]TenantEnvironment, error) {
	v, e := s.ListTenants(ctx, "", cluster)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x TenantEnvironment) string { return x.ProjectID }, func(x TenantEnvironment) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListAIRunsPage(ctx context.Context, ids []string, all bool, cursor *CollectionCursor, limit int) ([]AIRun, error) {
	v, e := s.ListAIRuns(ctx, "")
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x AIRun) string { return x.ProjectID }, func(x AIRun) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListBlueprintReleasesPage(ctx context.Context, ids []string, all bool, cursor *CollectionCursor, limit int) ([]BlueprintRelease, error) {
	v, e := s.ListBlueprintReleases(ctx, "")
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x BlueprintRelease) string { return x.ProjectID }, func(x BlueprintRelease) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListPlatformTemplatesPage(ctx context.Context, ids []string, all bool, cursor *CollectionCursor, limit int) ([]PlatformTemplate, error) {
	v, e := s.ListPlatformTemplates(ctx, "")
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x PlatformTemplate) string { return x.ProjectID }, func(x PlatformTemplate) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListWorkspacesPage(ctx context.Context, ids []string, all bool, cursor *CollectionCursor, limit int) ([]Workspace, error) {
	v, e := s.ListWorkspaces(ctx, "")
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x Workspace) string { return x.ProjectID }, func(x Workspace) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListRecoveryCheckpointsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *CollectionCursor, limit int) ([]RecoveryCheckpoint, error) {
	v, e := s.ListRecoveryCheckpoints(ctx, "", cluster)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x RecoveryCheckpoint) string { return x.ProjectID }, func(x RecoveryCheckpoint) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListFleetGroupsPage(ctx context.Context, ids []string, all bool, cursor *CollectionCursor, limit int) ([]FleetGroup, error) {
	v, e := s.ListFleetGroups(ctx, "")
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x FleetGroup) string { return x.ProjectID }, func(x FleetGroup) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListUpgradeCampaignsPage(ctx context.Context, ids []string, all bool, group string, cursor *CollectionCursor, limit int) ([]UpgradeCampaign, error) {
	v, e := s.ListUpgradeCampaigns(ctx, "", group)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x UpgradeCampaign) string { return x.ProjectID }, func(x UpgradeCampaign) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListMarketplaceInstallationsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *CollectionCursor, limit int) ([]BaselineDeployment, error) {
	v, e := s.ListBaselineDeployments(ctx, "", cluster)
	if e != nil {
		return nil, e
	}
	filtered := make([]BaselineDeployment, 0, len(v))
	for _, item := range v {
		if item.SourceType == BaselineSourceMarketplace {
			filtered = append(filtered, item)
		}
	}
	return filterProjectNewest(filtered, ids, all, cursor, limit, func(x BaselineDeployment) string { return x.ProjectID }, func(x BaselineDeployment) ResourceMeta { return x.ResourceMeta }), nil
}
func (s *MemoryStore) ListMarketplaceRecommendationsPage(ctx context.Context, ids []string, all bool, cluster string, cursor *CollectionCursor, limit int) ([]MarketplaceRecommendation, error) {
	v, e := s.ListMarketplaceRecommendations(ctx, "", cluster)
	if e != nil {
		return nil, e
	}
	return filterProjectNewest(v, ids, all, cursor, limit, func(x MarketplaceRecommendation) string { return x.ProjectID }, func(x MarketplaceRecommendation) ResourceMeta { return x.ResourceMeta }), nil
}
