package controlplane

import "context"

func (f *FileStore) CreateFleetGroup(ctx context.Context, v FleetGroup, a string) (FleetGroup, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return FleetGroup{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateFleetGroup(ctx, v, a)
	if err != nil {
		return out, replay, err
	}
	if !replay {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
		}
	}
	return out, replay, err
}
func (f *FileStore) CreateDriftScan(ctx context.Context, v DriftScan, a string) (DriftScan, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return DriftScan{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateDriftScan(ctx, v, a)
	if err != nil {
		return out, replay, err
	}
	if !replay {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
		}
	}
	return out, replay, err
}
func (f *FileStore) NextDriftTask(ctx context.Context, clusterID, token string) (DriftScan, DriftScanTarget, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return DriftScan{}, DriftScanTarget{}, err
	}
	scan, target, err := f.MemoryStore.NextDriftTask(ctx, clusterID, token)
	if err != nil {
		return scan, target, err
	}
	if err = f.persist(ctx); err != nil {
		_ = f.MemoryStore.Restore(before)
	}
	return scan, target, err
}
func (f *FileStore) ReportDriftTask(ctx context.Context, clusterID, token string, rev int64, result DriftTaskResult) (DriftScan, error) {
	return mutate(f, ctx, func() (DriftScan, error) { return f.MemoryStore.ReportDriftTask(ctx, clusterID, token, rev, result) })
}
func (f *FileStore) CreateUpgradeCampaign(ctx context.Context, v UpgradeCampaign, a string) (UpgradeCampaign, bool, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	before, err := f.MemoryStore.Snapshot(ctx)
	if err != nil {
		return UpgradeCampaign{}, false, err
	}
	out, replay, err := f.MemoryStore.CreateUpgradeCampaign(ctx, v, a)
	if err != nil {
		return out, replay, err
	}
	if !replay {
		if err = f.persist(ctx); err != nil {
			_ = f.MemoryStore.Restore(before)
		}
	}
	return out, replay, err
}
func (f *FileStore) ApproveUpgradeCampaign(ctx context.Context, id string, rev int64, a string) (UpgradeCampaign, error) {
	return mutate(f, ctx, func() (UpgradeCampaign, error) { return f.MemoryStore.ApproveUpgradeCampaign(ctx, id, rev, a) })
}
func (f *FileStore) PauseUpgradeCampaign(ctx context.Context, id string, rev int64, a, reason string) (UpgradeCampaign, error) {
	return mutate(f, ctx, func() (UpgradeCampaign, error) { return f.MemoryStore.PauseUpgradeCampaign(ctx, id, rev, a, reason) })
}
func (f *FileStore) ResumeUpgradeCampaign(ctx context.Context, id string, rev int64, a string) (UpgradeCampaign, error) {
	return mutate(f, ctx, func() (UpgradeCampaign, error) { return f.MemoryStore.ResumeUpgradeCampaign(ctx, id, rev, a) })
}
func (f *FileStore) CancelUpgradeCampaign(ctx context.Context, id string, rev int64, a, reason string) (UpgradeCampaign, error) {
	return mutate(f, ctx, func() (UpgradeCampaign, error) { return f.MemoryStore.CancelUpgradeCampaign(ctx, id, rev, a, reason) })
}
func (f *FileStore) UpdateUpgradeCampaign(ctx context.Context, v UpgradeCampaign, rev int64, a string) (UpgradeCampaign, error) {
	return mutate(f, ctx, func() (UpgradeCampaign, error) { return f.MemoryStore.UpdateUpgradeCampaign(ctx, v, rev, a) })
}

func (f *FileStore) CreateRecoveryCheckpoint(ctx context.Context, v RecoveryCheckpoint, a string) (RecoveryCheckpoint, error) {
	return mutate(f, ctx, func() (RecoveryCheckpoint, error) { return f.MemoryStore.CreateRecoveryCheckpoint(ctx, v, a) })
}
func (f *FileStore) RevokeRecoveryCheckpoint(ctx context.Context, id string, rev int64, a string) (RecoveryCheckpoint, error) {
	return mutate(f, ctx, func() (RecoveryCheckpoint, error) { return f.MemoryStore.RevokeRecoveryCheckpoint(ctx, id, rev, a) })
}
func (f *FileStore) RevalidateUpgradeCampaign(ctx context.Context, id string, rev int64, input UpgradeCampaignRevalidation, a string) (UpgradeCampaign, error) {
	return mutate(f, ctx, func() (UpgradeCampaign, error) {
		return f.MemoryStore.RevalidateUpgradeCampaign(ctx, id, rev, input, a)
	})
}

func (f *FileStore) RecordManagedGitRevision(ctx context.Context, v ManagedGitRevision, actor string) (ManagedGitRevision, error) {
	return mutate(f, ctx, func() (ManagedGitRevision, error) { return f.MemoryStore.RecordManagedGitRevision(ctx, v, actor) })
}
func (f *FileStore) GetManagedGitRevision(ctx context.Context, id string) (ManagedGitRevision, error) {
	return f.MemoryStore.GetManagedGitRevision(ctx, id)
}

func (f *FileStore) GetLatestManagedGitRevision(ctx context.Context, organization, repository, branch string) (ManagedGitRevision, error) {
	return f.MemoryStore.GetLatestManagedGitRevision(ctx, organization, repository, branch)
}
func (f *FileStore) ListManagedGitRevisions(ctx context.Context, organization, repository string) ([]ManagedGitRevision, error) {
	return f.MemoryStore.ListManagedGitRevisions(ctx, organization, repository)
}

func (f *FileStore) CreateGitPullRequest(ctx context.Context, v GitPullRequest, actor string) (GitPullRequest, error) {
	return mutate(f, ctx, func() (GitPullRequest, error) { return f.MemoryStore.CreateGitPullRequest(ctx, v, actor) })
}
func (f *FileStore) FinalizeGitPullRequest(ctx context.Context, id string, expected int64, externalNumber int64, externalURL, candidateCommitSHA, actor string) (GitPullRequest, error) {
	return mutate(f, ctx, func() (GitPullRequest, error) {
		return f.MemoryStore.FinalizeGitPullRequest(ctx, id, expected, externalNumber, externalURL, candidateCommitSHA, actor)
	})
}
func (f *FileStore) GetGitPullRequest(ctx context.Context, id string) (GitPullRequest, error) {
	return f.MemoryStore.GetGitPullRequest(ctx, id)
}
func (f *FileStore) ListGitPullRequests(ctx context.Context, organization, repository string) ([]GitPullRequest, error) {
	return f.MemoryStore.ListGitPullRequests(ctx, organization, repository)
}
func (f *FileStore) ApproveGitPullRequest(ctx context.Context, id string, expected int64, approvedHeadCommitSHA, actor string) (GitPullRequest, error) {
	return mutate(f, ctx, func() (GitPullRequest, error) {
		return f.MemoryStore.ApproveGitPullRequest(ctx, id, expected, approvedHeadCommitSHA, actor)
	})
}
func (f *FileStore) CommitMergedGitPullRequest(ctx context.Context, id string, expected int64, commitSHA string, managed ManagedGitRevision, actor string) (GitPullRequest, ManagedGitRevision, error) {
	return mutate2(f, ctx, func() (GitPullRequest, ManagedGitRevision, error) {
		return f.MemoryStore.CommitMergedGitPullRequest(ctx, id, expected, commitSHA, managed, actor)
	})
}
func (f *FileStore) GetLastKnownGoodGitRevision(ctx context.Context, organization, repository, branch string) (ManagedGitRevision, error) {
	return f.MemoryStore.GetLastKnownGoodGitRevision(ctx, organization, repository, branch)
}
func (f *FileStore) MarkManagedGitRevisionSynchronized(ctx context.Context, id string, expected int64, observedDigest string, healthy bool, actor string) (ManagedGitRevision, error) {
	return mutate(f, ctx, func() (ManagedGitRevision, error) {
		return f.MemoryStore.MarkManagedGitRevisionSynchronized(ctx, id, expected, observedDigest, healthy, actor)
	})
}
