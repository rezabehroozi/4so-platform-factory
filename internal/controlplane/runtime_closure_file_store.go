package controlplane

import "context"

func (f *FileStore) CreateRuntimeClosureCampaign(ctx context.Context, v RuntimeClosureCampaign, actor string) (RuntimeClosureCampaign, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return RuntimeClosureCampaign{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateRuntimeClosureCampaign(ctx, v, actor)
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

func (f *FileStore) UpdateRuntimeClosureCampaign(ctx context.Context, id string, expected int64, update RuntimeClosureCampaignUpdate, actor string) (RuntimeClosureCampaign, error) {
	return mutate(f, ctx, func() (RuntimeClosureCampaign, error) {
		return f.MemoryStore.UpdateRuntimeClosureCampaign(ctx, id, expected, update, actor)
	})
}
