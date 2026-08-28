package controlplane

import "context"

func (f *FileStore) UpsertClusterMaintenanceProfile(ctx context.Context, v ClusterMaintenanceProfile, expected int64, actor string) (ClusterMaintenanceProfile, error) {
	return mutate(f, ctx, func() (ClusterMaintenanceProfile, error) {
		return f.MemoryStore.UpsertClusterMaintenanceProfile(ctx, v, expected, actor)
	})
}

func (f *FileStore) CreateClusterMaintenanceWindow(ctx context.Context, v ClusterMaintenanceWindow, actor string) (ClusterMaintenanceWindow, error) {
	return mutate(f, ctx, func() (ClusterMaintenanceWindow, error) {
		return f.MemoryStore.CreateClusterMaintenanceWindow(ctx, v, actor)
	})
}

func (f *FileStore) CancelClusterMaintenanceWindow(ctx context.Context, id string, expected int64, actor string) (ClusterMaintenanceWindow, error) {
	return mutate(f, ctx, func() (ClusterMaintenanceWindow, error) {
		return f.MemoryStore.CancelClusterMaintenanceWindow(ctx, id, expected, actor)
	})
}

func (f *FileStore) CreateClusterMaintenanceRun(ctx context.Context, v ClusterMaintenanceRun, actor string) (ClusterMaintenanceRun, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return ClusterMaintenanceRun{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateClusterMaintenanceRun(ctx, v, actor)
	if err != nil {
		return out, replay, err
	}
	if !replay {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
			return out, replay, err
		}
	}
	return out, replay, nil
}

func (f *FileStore) CreateClusterMaintenanceRunRequest(ctx context.Context, v ClusterMaintenanceRun, opRequest OperationRequest, opKey, actor, requestID string) (ClusterMaintenanceRun, Operation, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return ClusterMaintenanceRun{}, Operation{}, false, err
	}
	run, op, replay, err := f.MemoryStore.CreateClusterMaintenanceRunRequest(ctx, v, opRequest, opKey, actor, requestID)
	if err != nil {
		_ = f.MemoryStore.Restore(before)
		return run, op, replay, err
	}
	if !replay {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
			return run, op, replay, err
		}
	}
	return run, op, replay, nil
}

func (f *FileStore) ApproveClusterMaintenanceRun(ctx context.Context, id string, expected int64, actor string) (ClusterMaintenanceRun, error) {
	return mutate(f, ctx, func() (ClusterMaintenanceRun, error) {
		return f.MemoryStore.ApproveClusterMaintenanceRun(ctx, id, expected, actor)
	})
}

func (f *FileStore) NextClusterMaintenanceTask(ctx context.Context, clusterID, token string) (ClusterMaintenanceRun, Operation, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return ClusterMaintenanceRun{}, Operation{}, err
	}
	run, op, err := f.MemoryStore.NextClusterMaintenanceTask(ctx, clusterID, token)
	if err != nil {
		// Next may fail stale queued runs before returning ErrNotFound. Persist that
		// authoritative failure transition instead of losing it on restart.
		if err == ErrNotFound {
			if persistErr := f.persist(ctx); persistErr != nil {
				_ = f.MemoryStore.Restore(before)
				return run, op, persistErr
			}
		}
		return run, op, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return run, op, err
	}
	return run, op, nil
}

func (f *FileStore) ReportClusterMaintenanceTask(ctx context.Context, clusterID, runID string, expected int64, result ClusterMaintenanceTaskResult) (ClusterMaintenanceRun, Operation, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return ClusterMaintenanceRun{}, Operation{}, err
	}
	run, op, err := f.MemoryStore.ReportClusterMaintenanceTask(ctx, clusterID, runID, expected, result)
	if err != nil {
		return run, op, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return run, op, err
	}
	return run, op, nil
}
