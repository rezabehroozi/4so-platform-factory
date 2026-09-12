package controlplane

import (
	"context"

	"platform.4so.io/factory/internal/reliability"
)

func (f *FileStore) CreateHealthObservation(ctx context.Context, v reliability.HealthObservation) (reliability.HealthObservation, bool, error) {
	return mutate2(f, ctx, func() (reliability.HealthObservation, bool, error) {
		return f.MemoryStore.CreateHealthObservation(ctx, v)
	})
}

func (f *FileStore) CreateIncident(ctx context.Context, v reliability.Incident, actor string) (reliability.Incident, error) {
	return mutate(f, ctx, func() (reliability.Incident, error) { return f.MemoryStore.CreateIncident(ctx, v, actor) })
}

func (f *FileStore) TransitionIncident(ctx context.Context, id string, expected int64, action, actor, summary string) (reliability.Incident, error) {
	return mutate(f, ctx, func() (reliability.Incident, error) {
		return f.MemoryStore.TransitionIncident(ctx, id, expected, action, actor, summary)
	})
}

func (f *FileStore) CreateSLOPolicy(ctx context.Context, v reliability.SLOPolicy, actor string) (reliability.SLOPolicy, error) {
	return mutate(f, ctx, func() (reliability.SLOPolicy, error) { return f.MemoryStore.CreateSLOPolicy(ctx, v, actor) })
}

func (f *FileStore) CreateSLOPolicyRevision(ctx context.Context, predecessor string, expected int64, next reliability.SLOPolicy, actor string) (reliability.SLOPolicy, error) {
	return mutate(f, ctx, func() (reliability.SLOPolicy, error) {
		return f.MemoryStore.CreateSLOPolicyRevision(ctx, predecessor, expected, next, actor)
	})
}

var _ ReliabilityStore = (*FileStore)(nil)
