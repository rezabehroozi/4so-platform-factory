package controlplane

import "context"

func (f *FileStore) NextVirtualClusterTask(ctx context.Context, clusterID, tokenDigest, runtimeSourceDigest string) (VirtualClusterTask, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return VirtualClusterTask{}, err
	}
	task, err := f.MemoryStore.NextVirtualClusterTask(ctx, clusterID, tokenDigest, runtimeSourceDigest)
	if err != nil {
		after, snapshotErr := f.MemoryStore.Snapshot(ctx)
		if snapshotErr == nil && len(after.VirtualClusters) > 0 {
			// Some fail-closed claim paths intentionally persist RECOVERY_REQUIRED
			// or FAILED before returning ErrNotFound. Preserve that durable state.
			if persistErr := f.persist(ctx); persistErr != nil {
				_ = f.MemoryStore.Restore(before)
				return VirtualClusterTask{}, persistErr
			}
		}
		return task, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
	}
	return task, err
}

func (f *FileStore) ReportVirtualClusterTask(ctx context.Context, clusterID, tokenDigest string, rev int64, result VirtualClusterTaskResult) (VirtualCluster, error) {
	return mutate(f, ctx, func() (VirtualCluster, error) {
		return f.MemoryStore.ReportVirtualClusterTask(ctx, clusterID, tokenDigest, rev, result)
	})
}
