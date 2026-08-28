package controlplane

import "context"

func (f *FileStore) CreateMarketplaceRecommendation(ctx context.Context, v MarketplaceRecommendation, actor string) (MarketplaceRecommendation, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return MarketplaceRecommendation{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateMarketplaceRecommendation(ctx, v, actor)
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

func (f *FileStore) GetMarketplaceRecommendationByIdempotencyKey(ctx context.Context, projectID, key string) (MarketplaceRecommendation, error) {
	return f.MemoryStore.GetMarketplaceRecommendationByIdempotencyKey(ctx, projectID, key)
}
