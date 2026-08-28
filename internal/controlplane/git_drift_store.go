package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/gitops"
)

func normalizeGitIdentity(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

func (s *MemoryStore) RecordManagedGitRevision(_ context.Context, v ManagedGitRevision, actor string) (ManagedGitRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Organization = normalizeGitIdentity(v.Organization)
	v.Repository = normalizeGitIdentity(v.Repository)
	v.Branch = strings.TrimSpace(v.Branch)
	if v.Branch == "" {
		v.Branch = "main"
	}
	v.RevisionID = strings.TrimSpace(v.RevisionID)
	v.Digest = strings.TrimSpace(v.Digest)
	v.CommitSHA = strings.TrimSpace(v.CommitSHA)
	v.PublicKeyFingerprint = strings.TrimSpace(v.PublicKeyFingerprint)
	v.Source = strings.TrimSpace(v.Source)
	if v.Source == "" {
		v.Source = "PLATFORM_PUBLISHED"
	}
	if v.DeliveryMode == "" {
		v.DeliveryMode = GitDeliveryDirectCommit
	}
	v.PullRequestID = strings.TrimSpace(v.PullRequestID)
	v.ObservedDigest = strings.TrimSpace(v.ObservedDigest)
	if v.DeliveryMode != GitDeliveryDirectCommit && v.DeliveryMode != GitDeliveryPullRequest {
		return ManagedGitRevision{}, fmt.Errorf("%w: delivery mode is invalid", ErrValidation)
	}
	if v.DeliveryMode == GitDeliveryPullRequest && v.PullRequestID == "" {
		return ManagedGitRevision{}, fmt.Errorf("%w: pullRequestId is required for pull-request revisions", ErrValidation)
	}
	if v.Organization == "" || v.Repository == "" || v.RevisionID == "" || !strings.HasPrefix(v.Digest, "sha256:") || !gitops.IsFullCommitSHA(v.CommitSHA) || !strings.HasPrefix(v.PublicKeyFingerprint, "sha256:") {
		return ManagedGitRevision{}, fmt.Errorf("%w: repository identity, revision, digest, commit and signing fingerprint are required", ErrValidation)
	}
	for _, existing := range s.managedGitRevisions {
		if existing.Organization == v.Organization && existing.Repository == v.Repository && existing.Branch == v.Branch && existing.CommitSHA == v.CommitSHA {
			if existing.Digest != v.Digest || existing.RevisionID != v.RevisionID || existing.PublicKeyFingerprint != v.PublicKeyFingerprint {
				return ManagedGitRevision{}, ErrConflict
			}
			return existing, nil
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("gtr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.RecordedBy = strings.TrimSpace(actor)
	s.managedGitRevisions[v.ID] = v
	s.appendAuditLocked(actor, "git_revision.recorded", "managedGitRevision", v.ID, v.Revision, map[string]any{"organization": v.Organization, "repository": v.Repository, "branch": v.Branch, "commitSha": v.CommitSHA, "source": v.Source, "deliveryMode": v.DeliveryMode, "pullRequestId": v.PullRequestID})
	s.appendOutboxLocked("managedGitRevision", v.ID, "git_revision.recorded", v)
	return v, nil
}

func (s *MemoryStore) GetManagedGitRevision(_ context.Context, id string) (ManagedGitRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.managedGitRevisions[strings.TrimSpace(id)]
	if !ok {
		return ManagedGitRevision{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) GetLatestManagedGitRevision(_ context.Context, organization, repository, branch string) (ManagedGitRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organization, repository = normalizeGitIdentity(organization), normalizeGitIdentity(repository)
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	var found ManagedGitRevision
	ok := false
	for _, v := range s.managedGitRevisions {
		if v.Organization == organization && v.Repository == repository && v.Branch == branch && (!ok || v.CreatedAt.After(found.CreatedAt) || (v.CreatedAt.Equal(found.CreatedAt) && v.ID > found.ID)) {
			found = v
			ok = true
		}
	}
	if !ok {
		return ManagedGitRevision{}, ErrNotFound
	}
	return found, nil
}

func (s *MemoryStore) GetLastKnownGoodGitRevision(_ context.Context, organization, repository, branch string) (ManagedGitRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organization, repository = normalizeGitIdentity(organization), normalizeGitIdentity(repository)
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	var found ManagedGitRevision
	ok := false
	for _, v := range s.managedGitRevisions {
		if v.Organization == organization && v.Repository == repository && v.Branch == branch && v.LastKnownGood && (!ok || v.UpdatedAt.After(found.UpdatedAt) || (v.UpdatedAt.Equal(found.UpdatedAt) && v.ID > found.ID)) {
			found = v
			ok = true
		}
	}
	if !ok {
		return ManagedGitRevision{}, ErrNotFound
	}
	return found, nil
}

func (s *MemoryStore) MarkManagedGitRevisionSynchronized(_ context.Context, id string, expected int64, observedDigest string, healthy bool, actor string) (ManagedGitRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.managedGitRevisions[strings.TrimSpace(id)]
	if !ok {
		return ManagedGitRevision{}, ErrNotFound
	}
	if v.Revision != expected {
		return ManagedGitRevision{}, ErrConflict
	}
	observedDigest = strings.TrimSpace(observedDigest)
	if !healthy || observedDigest == "" || observedDigest != v.Digest {
		return ManagedGitRevision{}, fmt.Errorf("%w: healthy sync with observed digest equal to managed revision is required", ErrValidation)
	}
	now := nowUTC(s.now)
	for key, other := range s.managedGitRevisions {
		if other.ID != v.ID && other.Organization == v.Organization && other.Repository == v.Repository && other.Branch == v.Branch && other.LastKnownGood {
			other.LastKnownGood = false
			other.Revision++
			other.UpdatedAt = now
			s.managedGitRevisions[key] = other
		}
	}
	v = s.managedGitRevisions[v.ID]
	v.Revision++
	v.SyncHealthy = true
	v.ObservedDigest = observedDigest
	v.LastKnownGood = true
	v.LastKnownGoodAt = &now
	v.UpdatedAt = now
	s.managedGitRevisions[v.ID] = v
	s.appendAuditLocked(actor, "git_revision.last_known_good", "managedGitRevision", v.ID, v.Revision, map[string]any{"organization": v.Organization, "repository": v.Repository, "branch": v.Branch, "commitSha": v.CommitSHA, "digest": v.Digest})
	s.appendOutboxLocked("managedGitRevision", v.ID, "git_revision.last_known_good", v)
	return v, nil
}

func (s *MemoryStore) ListManagedGitRevisions(_ context.Context, organization, repository string) ([]ManagedGitRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organization, repository = normalizeGitIdentity(organization), normalizeGitIdentity(repository)
	out := []ManagedGitRevision{}
	for _, v := range s.managedGitRevisions {
		if (organization == "" || v.Organization == organization) && (repository == "" || v.Repository == repository) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func ClassifyGitDrift(input *GitDriftEvidence, observedDigest string) *GitDriftEvidence {
	if input == nil {
		return nil
	}
	v := *input
	v.ChangedFiles = append([]string(nil), input.ChangedFiles...)
	v.ObservedDigest = strings.TrimSpace(observedDigest)
	v.Conflict = false
	v.Adoptable = false
	gitChanged := v.CurrentCommitSHA != v.BaseCommitSHA || v.CurrentDigest != v.BaseDigest
	if v.ObservedDigest == "" {
		v.Classification = GitDriftObservedUnknown
		v.Summary = "live GitOps revision could not be observed"
		return &v
	}
	if !gitChanged {
		if v.ObservedDigest == v.BaseDigest {
			v.Classification = GitDriftInSync
			v.Summary = "platform base, Git desired state and live state are in sync"
		} else {
			v.Classification = GitDriftLiveDrift
			v.Conflict = true
			v.Summary = "live state differs while Git still matches the platform-published base"
		}
		return &v
	}
	if !v.CurrentTrusted {
		v.Classification = GitDriftUntrustedChange
		v.Conflict = true
		v.Summary = "Git changed outside the trusted platform signing identity"
		return &v
	}
	if v.CurrentDigest == v.BaseDigest && v.CurrentCommitSHA != v.BaseCommitSHA {
		v.Classification = GitDriftCommitOnlyChange
		v.Summary = "Git commit changed but the signed desired-state digest is unchanged"
		return &v
	}
	switch v.ObservedDigest {
	case v.BaseDigest:
		v.Classification = GitDriftExternalChange
		v.Summary = "trusted Git desired state changed externally and has not been observed live"
	case v.CurrentDigest:
		v.Classification = GitDriftExternalApplied
		v.Adoptable = true
		v.Summary = "trusted external Git desired state is already observed live and may be adopted without overwrite"
	default:
		v.Classification = GitDriftThreeWayConflict
		v.Conflict = true
		v.Summary = "platform base, Git desired state and live observed state all diverge"
	}
	return &v
}
