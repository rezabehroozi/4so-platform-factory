package controlplane

import "context"

func (f *FileStore) CreateRuntimeCertification(ctx context.Context, v RuntimeCertificationRun, actor string) (RuntimeCertificationRun, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return RuntimeCertificationRun{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateRuntimeCertification(ctx, v, actor)
	if err != nil {
		return out, replay, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return out, replay, err
	}
	return out, replay, nil
}

func (f *FileStore) GetRuntimeCertification(ctx context.Context, id string) (RuntimeCertificationRun, error) {
	return f.MemoryStore.GetRuntimeCertification(ctx, id)
}
func (f *FileStore) ListRuntimeCertifications(ctx context.Context, projectID, clusterID string) ([]RuntimeCertificationRun, error) {
	return f.MemoryStore.ListRuntimeCertifications(ctx, projectID, clusterID)
}
func (f *FileStore) NextRuntimeCertificationTask(ctx context.Context, clusterID, tokenDigest string) (RuntimeCertificationRun, error) {
	return mutate(f, ctx, func() (RuntimeCertificationRun, error) {
		return f.MemoryStore.NextRuntimeCertificationTask(ctx, clusterID, tokenDigest)
	})
}
func (f *FileStore) ReportRuntimeCertificationTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result RuntimeCertificationResult) (RuntimeCertificationRun, error) {
	return mutate(f, ctx, func() (RuntimeCertificationRun, error) {
		return f.MemoryStore.ReportRuntimeCertificationTask(ctx, clusterID, tokenDigest, expected, result)
	})
}
func (f *FileStore) RevokeRuntimeCertification(ctx context.Context, id string, expected int64, actor string) (RuntimeCertificationRun, error) {
	return mutate(f, ctx, func() (RuntimeCertificationRun, error) {
		return f.MemoryStore.RevokeRuntimeCertification(ctx, id, expected, actor)
	})
}
