package controlplane

import "context"

func (f *FileStore) UpsertBackupPolicy(ctx context.Context, v BackupPolicy, expected int64, actor string) (BackupPolicy, error) {
	return mutate(f, ctx, func() (BackupPolicy, error) { return f.MemoryStore.UpsertBackupPolicy(ctx, v, expected, actor) })
}
func (f *FileStore) SetBackupPolicyState(ctx context.Context, id string, expected int64, state BackupPolicyState, actor string) (BackupPolicy, error) {
	return mutate(f, ctx, func() (BackupPolicy, error) {
		return f.MemoryStore.SetBackupPolicyState(ctx, id, expected, state, actor)
	})
}

func (f *FileStore) GetBackupPolicy(ctx context.Context, id string) (BackupPolicy, error) {
	return f.MemoryStore.GetBackupPolicy(ctx, id)
}
func (f *FileStore) ListBackupPolicies(ctx context.Context, projectID, clusterID string) ([]BackupPolicy, error) {
	return f.MemoryStore.ListBackupPolicies(ctx, projectID, clusterID)
}
func (f *FileStore) CreateDataProtectionRun(ctx context.Context, v DataProtectionRun, actor string) (DataProtectionRun, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return DataProtectionRun{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateDataProtectionRun(ctx, v, actor)
	if err != nil {
		return out, replay, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return out, replay, err
	}
	return out, replay, nil
}
func (f *FileStore) GetDataProtectionRun(ctx context.Context, id string) (DataProtectionRun, error) {
	return f.MemoryStore.GetDataProtectionRun(ctx, id)
}
func (f *FileStore) ListDataProtectionRuns(ctx context.Context, projectID, clusterID string, kind DataProtectionRunKind) ([]DataProtectionRun, error) {
	return f.MemoryStore.ListDataProtectionRuns(ctx, projectID, clusterID, kind)
}
func (f *FileStore) ApproveDataProtectionRun(ctx context.Context, id string, expected int64, actor string) (DataProtectionRun, error) {
	return mutate(f, ctx, func() (DataProtectionRun, error) {
		return f.MemoryStore.ApproveDataProtectionRun(ctx, id, expected, actor)
	})
}
func (f *FileStore) NextDataProtectionTask(ctx context.Context, clusterID, tokenDigest string) (DataProtectionRun, BackupPolicy, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return DataProtectionRun{}, BackupPolicy{}, err
	}
	run, policy, err := f.MemoryStore.NextDataProtectionTask(ctx, clusterID, tokenDigest)
	if err != nil {
		return run, policy, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return run, policy, err
	}
	return run, policy, nil
}
func (f *FileStore) ReportDataProtectionTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result DataProtectionTaskResult) (DataProtectionRun, error) {
	return mutate(f, ctx, func() (DataProtectionRun, error) {
		return f.MemoryStore.ReportDataProtectionTask(ctx, clusterID, tokenDigest, expected, result)
	})
}
