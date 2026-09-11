package controlplane

import "context"

func (f *FileStore) CreateFinOpsBudgetPolicy(ctx context.Context, v FinOpsBudgetPolicy, actor string) (FinOpsBudgetPolicy, error) {
	return mutate(f, ctx, func() (FinOpsBudgetPolicy, error) { return f.MemoryStore.CreateFinOpsBudgetPolicy(ctx, v, actor) })
}
