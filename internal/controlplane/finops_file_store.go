package controlplane

import "context"

func (f *FileStore) CreateFinOpsRateCard(ctx context.Context, v FinOpsRateCard, actor string) (FinOpsRateCard, error) {
	return mutate(f, ctx, func() (FinOpsRateCard, error) { return f.MemoryStore.CreateFinOpsRateCard(ctx, v, actor) })
}
func (f *FileStore) CreateFinOpsUsageMeasurement(ctx context.Context, v FinOpsUsageMeasurement, actor string) (FinOpsUsageMeasurement, bool, error) {
	return mutate2(f, ctx, func() (FinOpsUsageMeasurement, bool, error) {
		return f.MemoryStore.CreateFinOpsUsageMeasurement(ctx, v, actor)
	})
}
func (f *FileStore) CreateFinOpsCapacityObservation(ctx context.Context, v FinOpsCapacityObservation, actor string) (FinOpsCapacityObservation, bool, error) {
	return mutate2(f, ctx, func() (FinOpsCapacityObservation, bool, error) {
		return f.MemoryStore.CreateFinOpsCapacityObservation(ctx, v, actor)
	})
}
