package controlplane

import "context"

func (f *FileStore) CreateBaselineDeployment(ctx context.Context, v BaselineDeployment, a string) (BaselineDeployment, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return BaselineDeployment{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateBaselineDeployment(ctx, v, a)
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
func (f *FileStore) ApproveBaselineDeployment(ctx context.Context, id string, rev int64, a string) (BaselineDeployment, error) {
	return mutate(f, ctx, func() (BaselineDeployment, error) { return f.MemoryStore.ApproveBaselineDeployment(ctx, id, rev, a) })
}
func (f *FileStore) RevalidateBaselineDeployment(ctx context.Context, id string, rev int64, a string) (BaselineDeployment, error) {
	return mutate(f, ctx, func() (BaselineDeployment, error) { return f.MemoryStore.RevalidateBaselineDeployment(ctx, id, rev, a) })
}
func (f *FileStore) RetryBaselineDeployment(ctx context.Context, id string, rev int64, a string) (BaselineDeployment, error) {
	return mutate(f, ctx, func() (BaselineDeployment, error) { return f.MemoryStore.RetryBaselineDeployment(ctx, id, rev, a) })
}
func (f *FileStore) QueueBaselineRollback(ctx context.Context, id string, rev int64, actor, recoveryCheckpointID, requestDigest string) (BaselineDeployment, error) {
	return mutate(f, ctx, func() (BaselineDeployment, error) {
		return f.MemoryStore.QueueBaselineRollback(ctx, id, rev, actor, recoveryCheckpointID, requestDigest)
	})
}
func (f *FileStore) NextBaselineTask(ctx context.Context, clusterID, token string) (BaselineDeployment, error) {
	return mutate(f, ctx, func() (BaselineDeployment, error) { return f.MemoryStore.NextBaselineTask(ctx, clusterID, token) })
}
func (f *FileStore) ReportBaselineTask(ctx context.Context, clusterID, token string, rev int64, result BaselineTaskResult) (BaselineDeployment, error) {
	return mutate(f, ctx, func() (BaselineDeployment, error) {
		return f.MemoryStore.ReportBaselineTask(ctx, clusterID, token, rev, result)
	})
}

func (f *FileStore) CreateRuntimeVerification(ctx context.Context, v RuntimeVerification, a string) (RuntimeVerification, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return RuntimeVerification{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateRuntimeVerification(ctx, v, a)
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
func (f *FileStore) GetRuntimeVerification(ctx context.Context, id string) (RuntimeVerification, error) {
	return f.MemoryStore.GetRuntimeVerification(ctx, id)
}
func (f *FileStore) ListRuntimeVerifications(ctx context.Context, p, c, b string) ([]RuntimeVerification, error) {
	return f.MemoryStore.ListRuntimeVerifications(ctx, p, c, b)
}
func (f *FileStore) RetryRuntimeVerification(ctx context.Context, id string, rev int64, actor string) (RuntimeVerification, error) {
	return mutate(f, ctx, func() (RuntimeVerification, error) {
		return f.MemoryStore.RetryRuntimeVerification(ctx, id, rev, actor)
	})
}
func (f *FileStore) NextRuntimeVerificationTask(ctx context.Context, c, t string) (RuntimeVerification, error) {
	return mutate(f, ctx, func() (RuntimeVerification, error) { return f.MemoryStore.NextRuntimeVerificationTask(ctx, c, t) })
}
func (f *FileStore) ReportRuntimeVerificationTask(ctx context.Context, c, t string, rev int64, result RuntimeVerificationResult) (RuntimeVerification, error) {
	return mutate(f, ctx, func() (RuntimeVerification, error) {
		return f.MemoryStore.ReportRuntimeVerificationTask(ctx, c, t, rev, result)
	})
}
