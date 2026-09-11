package controlplane

import (
	"context"
	"time"
)

func (f *FileStore) CreateMCPControlJob(ctx context.Context, v MCPControlJob, lease time.Duration, now time.Time) (MCPControlJob, bool, error) {
	return mutate2(f, ctx, func() (MCPControlJob, bool, error) { return f.MemoryStore.CreateMCPControlJob(ctx, v, lease, now) })
}
func (f *FileStore) CompleteMCPControlJob(ctx context.Context, id string, expected, fence int64, status int, response []byte, actor string) (MCPControlJob, error) {
	return mutate(f, ctx, func() (MCPControlJob, error) {
		return f.MemoryStore.CompleteMCPControlJob(ctx, id, expected, fence, status, response, actor)
	})
}
func (f *FileStore) MarkMCPControlJobRecoveryRequired(ctx context.Context, id string, expected int64, actor string) (MCPControlJob, error) {
	return mutate(f, ctx, func() (MCPControlJob, error) {
		return f.MemoryStore.MarkMCPControlJobRecoveryRequired(ctx, id, expected, actor)
	})
}
func (f *FileStore) ResolveMCPControlJobRecovery(ctx context.Context, id string, expected int64, resolution MCPControlJobRecoveryResolution, readbackDigest, evidenceDigest, actor string) (MCPControlJob, error) {
	return mutate(f, ctx, func() (MCPControlJob, error) {
		return f.MemoryStore.ResolveMCPControlJobRecovery(ctx, id, expected, resolution, readbackDigest, evidenceDigest, actor)
	})
}
func (f *FileStore) GetMCPControlJob(ctx context.Context, id string) (MCPControlJob, error) {
	return f.MemoryStore.GetMCPControlJob(ctx, id)
}
func (f *FileStore) ListMCPControlJobs(ctx context.Context, org, project string, limit int) ([]MCPControlJob, error) {
	return f.MemoryStore.ListMCPControlJobs(ctx, org, project, limit)
}
