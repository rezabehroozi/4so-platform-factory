package controlplane

import "context"

func (f *FileStore) RequestVirtualClusterLifecycle(ctx context.Context, id string, expected int64, action, idempotencyKey, requestDigest, actor string) (VirtualCluster, bool, error) {
	return mutate2(f, ctx, func() (VirtualCluster, bool, error) {
		return f.MemoryStore.RequestVirtualClusterLifecycle(ctx, id, expected, action, idempotencyKey, requestDigest, actor)
	})
}

func (f *FileStore) DispatchVirtualClusterTask(ctx context.Context, clusterID, tokenDigest, virtualClusterID string, expected, fence int64, action string) (VirtualClusterTask, bool, error) {
	return mutate2(f, ctx, func() (VirtualClusterTask, bool, error) {
		return f.MemoryStore.DispatchVirtualClusterTask(ctx, clusterID, tokenDigest, virtualClusterID, expected, fence, action)
	})
}
