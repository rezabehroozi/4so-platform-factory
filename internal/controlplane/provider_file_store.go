package controlplane

import "context"

func (f *FileStore) CreateProviderProfile(ctx context.Context, v ProviderProfile, actor string) (ProviderProfile, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return ProviderProfile{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateProviderProfile(ctx, v, actor)
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

func (f *FileStore) RetryProviderProfile(ctx context.Context, id string, rev int64, actor string) (ProviderProfile, error) {
	return mutate(f, ctx, func() (ProviderProfile, error) { return f.MemoryStore.RetryProviderProfile(ctx, id, rev, actor) })
}

func (f *FileStore) NextProviderProfileTask(ctx context.Context, clusterID, token string) (ProviderProfile, error) {
	return mutate(f, ctx, func() (ProviderProfile, error) { return f.MemoryStore.NextProviderProfileTask(ctx, clusterID, token) })
}

func (f *FileStore) ReportProviderProfileTask(ctx context.Context, clusterID, token string, rev int64, result ProviderProfileTaskResult) (ProviderProfile, error) {
	return mutate(f, ctx, func() (ProviderProfile, error) {
		return f.MemoryStore.ReportProviderProfileTask(ctx, clusterID, token, rev, result)
	})
}

func (f *FileStore) CreateProviderCluster(ctx context.Context, v ProviderCluster, actor string) (ProviderCluster, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return ProviderCluster{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateProviderCluster(ctx, v, actor)
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

func (f *FileStore) QueueProviderClusterChange(ctx context.Context, id string, rev int64, action string, desired ProviderClusterSpec, desiredDigest, actor, requestDigest, recoveryCheckpointID string) (ProviderCluster, error) {
	return mutate(f, ctx, func() (ProviderCluster, error) {
		return f.MemoryStore.QueueProviderClusterChange(ctx, id, rev, action, desired, desiredDigest, actor, requestDigest, recoveryCheckpointID)
	})
}

func (f *FileStore) ApproveProviderCluster(ctx context.Context, id string, rev int64, actor string) (ProviderCluster, error) {
	return mutate(f, ctx, func() (ProviderCluster, error) { return f.MemoryStore.ApproveProviderCluster(ctx, id, rev, actor) })
}

func (f *FileStore) RetryProviderCluster(ctx context.Context, id string, rev int64, actor string) (ProviderCluster, error) {
	return mutate(f, ctx, func() (ProviderCluster, error) { return f.MemoryStore.RetryProviderCluster(ctx, id, rev, actor) })
}

func (f *FileStore) NextProviderClusterTask(ctx context.Context, clusterID, token string) (ProviderCluster, ProviderProfile, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return ProviderCluster{}, ProviderProfile{}, err
	}
	cluster, profile, err := f.MemoryStore.NextProviderClusterTask(ctx, clusterID, token)
	if err != nil {
		return cluster, profile, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
	}
	return cluster, profile, err
}

func (f *FileStore) ReportProviderClusterTask(ctx context.Context, clusterID, token string, rev int64, result ProviderClusterTaskResult) (ProviderCluster, error) {
	return mutate(f, ctx, func() (ProviderCluster, error) {
		return f.MemoryStore.ReportProviderClusterTask(ctx, clusterID, token, rev, result)
	})
}
