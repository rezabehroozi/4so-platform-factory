package controlplane

import "context"

func (f *FileStore) CreateClusterImport(ctx context.Context, v ClusterImport, a string) (ClusterImport, error) {
	return mutate(f, ctx, func() (ClusterImport, error) { return f.MemoryStore.CreateClusterImport(ctx, v, a) })
}
func (f *FileStore) ApproveClusterImport(ctx context.Context, id string, rev int64, a string) (ClusterImport, error) {
	return mutate(f, ctx, func() (ClusterImport, error) { return f.MemoryStore.ApproveClusterImport(ctx, id, rev, a) })
}
func (f *FileStore) RevokeClusterImport(ctx context.Context, id string, rev int64, a string) (ClusterImport, error) {
	return mutate(f, ctx, func() (ClusterImport, error) { return f.MemoryStore.RevokeClusterImport(ctx, id, rev, a) })
}
func (f *FileStore) ClaimClusterImport(ctx context.Context, id, t, at, u, av string) (ClusterImport, ManagedCluster, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, e := f.MemoryStore.Snapshot(ctx)
	if e != nil {
		return ClusterImport{}, ManagedCluster{}, e
	}
	i, c, e := f.MemoryStore.ClaimClusterImport(ctx, id, t, at, u, av)
	if e != nil {
		return i, c, e
	}
	if e = f.persist(ctx); e != nil {
		_ = f.MemoryStore.Restore(before)
	}
	return i, c, e
}
func (f *FileStore) UpsertClusterInventory(ctx context.Context, id, t, u string, v ClusterInventory) (ManagedCluster, ClusterInventory, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, e := f.MemoryStore.Snapshot(ctx)
	if e != nil {
		return ManagedCluster{}, ClusterInventory{}, e
	}
	c, i, e := f.MemoryStore.UpsertClusterInventory(ctx, id, t, u, v)
	if e != nil {
		return c, i, e
	}
	if e = f.persist(ctx); e != nil {
		_ = f.MemoryStore.Restore(before)
	}
	return c, i, e
}
func (f *FileStore) AuthorizeClusterMutationRBACActivation(ctx context.Context, id, actor string) (ManagedCluster, ClusterImport, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, e := f.MemoryStore.Snapshot(ctx)
	if e != nil {
		return ManagedCluster{}, ClusterImport{}, e
	}
	c, imp, e := f.MemoryStore.AuthorizeClusterMutationRBACActivation(ctx, id, actor)
	if e != nil {
		return c, imp, e
	}
	if e = f.persist(ctx); e != nil {
		_ = f.MemoryStore.Restore(before)
	}
	return c, imp, e
}

func (f *FileStore) HeartbeatCluster(ctx context.Context, id, t, u, av string) (ManagedCluster, error) {
	return mutate(f, ctx, func() (ManagedCluster, error) { return f.MemoryStore.HeartbeatCluster(ctx, id, t, u, av) })
}

func (f *FileStore) RevokeManagedCluster(ctx context.Context, id string, rev int64, actor string) (ManagedCluster, ClusterImport, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, e := f.MemoryStore.Snapshot(ctx)
	if e != nil {
		return ManagedCluster{}, ClusterImport{}, e
	}
	c, imp, e := f.MemoryStore.RevokeManagedCluster(ctx, id, rev, actor)
	if e != nil {
		return c, imp, e
	}
	if e = f.persist(ctx); e != nil {
		_ = f.MemoryStore.Restore(before)
	}
	return c, imp, e
}

func (f *FileStore) AcknowledgeManagedClusterTargetRBACRevocation(ctx context.Context, id string, rev int64, digest, actor string) (ManagedCluster, error) {
	return mutate(f, ctx, func() (ManagedCluster, error) {
		return f.MemoryStore.AcknowledgeManagedClusterTargetRBACRevocation(ctx, id, rev, digest, actor)
	})
}

func (f *FileStore) BindManagedClusterProvider(ctx context.Context, id string, rev int64, providerClusterID, actor string) (ManagedCluster, error) {
	return mutate(f, ctx, func() (ManagedCluster, error) {
		return f.MemoryStore.BindManagedClusterProvider(ctx, id, rev, providerClusterID, actor)
	})
}
