package controlplane

import (
	"context"
	"fmt"
)

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


func (f *FileStore) NextVirtualClusterTask(ctx context.Context, clusterID, tokenDigest, runtimeSourceDigest string) (VirtualClusterTask, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return VirtualClusterTask{}, err
	}
	task, taskErr := f.MemoryStore.NextVirtualClusterTask(ctx, clusterID, tokenDigest, runtimeSourceDigest)
	if taskErr != nil && taskErr != ErrNotFound {
		return task, taskErr
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return task, fmt.Errorf("persist authoritative snapshot: %w", err)
	}
	return task, taskErr
}

func (f *FileStore) ReportVirtualClusterTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result VirtualClusterTaskResult) (VirtualCluster, error) {
	return mutate(f, ctx, func() (VirtualCluster, error) {
		return f.MemoryStore.ReportVirtualClusterTask(ctx, clusterID, tokenDigest, expected, result)
	})
}
