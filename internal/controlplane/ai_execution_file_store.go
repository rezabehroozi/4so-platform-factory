package controlplane

import "context"

func (f *FileStore) ClaimAIExecution(ctx context.Context, v AIExecutionClaim, actor string) (AIExecutionClaim, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return AIExecutionClaim{}, false, err
	}
	out, acquired, err := f.MemoryStore.ClaimAIExecution(ctx, v, actor)
	if err != nil {
		return out, acquired, err
	}
	if acquired {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
			return AIExecutionClaim{}, false, err
		}
	}
	return out, acquired, nil
}

func (f *FileStore) FinalizeAIExecution(ctx context.Context, run AIRun, actor string) (AIRun, bool, AIExecutionClaim, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return AIRun{}, false, AIExecutionClaim{}, err
	}
	out, replay, claim, err := f.MemoryStore.FinalizeAIExecution(ctx, run, actor)
	if err != nil {
		return out, replay, claim, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
		return AIRun{}, false, AIExecutionClaim{}, err
	}
	return out, replay, claim, nil
}

func (f *FileStore) FailAIExecution(ctx context.Context, projectID, key, requestDigest, failureCode, actor string) (AIExecutionClaim, error) {
	return mutate(f, ctx, func() (AIExecutionClaim, error) {
		return f.MemoryStore.FailAIExecution(ctx, projectID, key, requestDigest, failureCode, actor)
	})
}
