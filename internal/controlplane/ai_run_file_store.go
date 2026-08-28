package controlplane

import "context"

func (f *FileStore) CreateAIRun(ctx context.Context, v AIRun, actor string) (AIRun, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return AIRun{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateAIRun(ctx, v, actor)
	if err != nil {
		return out, replay, err
	}
	if !replay {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
			return AIRun{}, false, err
		}
	}
	return out, replay, nil
}
