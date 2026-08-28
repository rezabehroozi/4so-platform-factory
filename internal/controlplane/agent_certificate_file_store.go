package controlplane

import "context"

func (f *FileStore) CreateAgentCertificate(ctx context.Context, v AgentCertificate, a string) (AgentCertificate, error) {
	return mutate(f, ctx, func() (AgentCertificate, error) { return f.MemoryStore.CreateAgentCertificate(ctx, v, a) })
}
func (f *FileStore) RotateAgentCertificate(ctx context.Context, id string, v AgentCertificate, a string) (AgentCertificate, AgentCertificate, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, e := f.MemoryStore.Snapshot(ctx)
	if e != nil {
		return AgentCertificate{}, AgentCertificate{}, e
	}
	old, n, e := f.MemoryStore.RotateAgentCertificate(ctx, id, v, a)
	if e != nil {
		return old, n, e
	}
	if e = f.persist(ctx); e != nil {
		_ = f.MemoryStore.Restore(before)
	}
	return old, n, e
}
func (f *FileStore) RevokeAgentCertificate(ctx context.Context, id string, rev int64, a string) (AgentCertificate, error) {
	return mutate(f, ctx, func() (AgentCertificate, error) { return f.MemoryStore.RevokeAgentCertificate(ctx, id, rev, a) })
}
