package controlplane

import (
	"context"
	"time"
)

func (f *FileStore) CreateMCPTrustedClient(ctx context.Context, v MCPTrustedClient, actor string) (MCPTrustedClient, error) {
	return mutate(f, ctx, func() (MCPTrustedClient, error) { return f.MemoryStore.CreateMCPTrustedClient(ctx, v, actor) })
}
func (f *FileStore) ListMCPTrustedClients(ctx context.Context) ([]MCPTrustedClient, error) {
	return f.MemoryStore.ListMCPTrustedClients(ctx)
}
func (f *FileStore) GetMCPTrustedClientByClientID(ctx context.Context, clientID string) (MCPTrustedClient, error) {
	return f.MemoryStore.GetMCPTrustedClientByClientID(ctx, clientID)
}
func (f *FileStore) RevokeMCPTrustedClient(ctx context.Context, id string, expected int64, actor string) (MCPTrustedClient, error) {
	return mutate(f, ctx, func() (MCPTrustedClient, error) {
		return f.MemoryStore.RevokeMCPTrustedClient(ctx, id, expected, actor)
	})
}
func (f *FileStore) CreateMCPDelegationGrant(ctx context.Context, v MCPDelegationGrant, actor string) (MCPDelegationGrant, error) {
	return mutate(f, ctx, func() (MCPDelegationGrant, error) { return f.MemoryStore.CreateMCPDelegationGrant(ctx, v, actor) })
}
func (f *FileStore) ListMCPDelegationGrants(ctx context.Context, subject string) ([]MCPDelegationGrant, error) {
	return f.MemoryStore.ListMCPDelegationGrants(ctx, subject)
}
func (f *FileStore) GetActiveMCPDelegationGrant(ctx context.Context, issuer, subject, clientID string, now time.Time) (MCPDelegationGrant, error) {
	return f.MemoryStore.GetActiveMCPDelegationGrant(ctx, issuer, subject, clientID, now)
}
func (f *FileStore) RevokeMCPDelegationGrant(ctx context.Context, id string, expected int64, actor string) (MCPDelegationGrant, error) {
	return mutate(f, ctx, func() (MCPDelegationGrant, error) {
		return f.MemoryStore.RevokeMCPDelegationGrant(ctx, id, expected, actor)
	})
}
