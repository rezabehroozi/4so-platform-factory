package controlplane

import "context"

func (f *FileStore) UpsertEntitlement(ctx context.Context, v Entitlement, expected int64, actor string) (Entitlement, error) {
	return mutate(f, ctx, func() (Entitlement, error) { return f.MemoryStore.UpsertEntitlement(ctx, v, expected, actor) })
}
func (f *FileStore) UpsertOEMProfile(ctx context.Context, v OEMProfile, expected int64, actor string) (OEMProfile, error) {
	return mutate(f, ctx, func() (OEMProfile, error) { return f.MemoryStore.UpsertOEMProfile(ctx, v, expected, actor) })
}
func (f *FileStore) CreateTenant(ctx context.Context, v TenantEnvironment, actor string) (TenantEnvironment, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return TenantEnvironment{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateTenant(ctx, v, actor)
	if err != nil {
		return out, replay, err
	}
	if !replay {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
		}
	}
	return out, replay, err
}
func (f *FileStore) QueueTenantResize(ctx context.Context, id string, rev int64, planName string, quota map[string]string, desiredDigest, actor, requestDigest string) (TenantEnvironment, error) {
	return mutate(f, ctx, func() (TenantEnvironment, error) {
		return f.MemoryStore.QueueTenantResize(ctx, id, rev, planName, quota, desiredDigest, actor, requestDigest)
	})
}
func (f *FileStore) QueueTenantAction(ctx context.Context, id string, rev int64, action, actor, recoveryCheckpointID, requestDigest string) (TenantEnvironment, error) {
	return mutate(f, ctx, func() (TenantEnvironment, error) {
		return f.MemoryStore.QueueTenantAction(ctx, id, rev, action, actor, recoveryCheckpointID, requestDigest)
	})
}
func (f *FileStore) ApproveTenantAction(ctx context.Context, id string, rev int64, actor string) (TenantEnvironment, error) {
	return mutate(f, ctx, func() (TenantEnvironment, error) { return f.MemoryStore.ApproveTenantAction(ctx, id, rev, actor) })
}
func (f *FileStore) NextTenantTask(ctx context.Context, clusterID, token string) (TenantEnvironment, error) {
	return mutate(f, ctx, func() (TenantEnvironment, error) { return f.MemoryStore.NextTenantTask(ctx, clusterID, token) })
}
func (f *FileStore) ReportTenantTask(ctx context.Context, clusterID, token string, rev int64, result TenantTaskResult) (TenantEnvironment, error) {
	return mutate(f, ctx, func() (TenantEnvironment, error) {
		return f.MemoryStore.ReportTenantTask(ctx, clusterID, token, rev, result)
	})
}
