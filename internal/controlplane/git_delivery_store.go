package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/gitops"
)

func normalizeGitPullRequest(v GitPullRequest) (GitPullRequest, error) {
	v.Organization = normalizeGitIdentity(v.Organization)
	v.Repository = normalizeGitIdentity(v.Repository)
	v.BaseBranch = strings.TrimSpace(v.BaseBranch)
	if v.BaseBranch == "" {
		v.BaseBranch = "main"
	}
	v.BaseCommitSHA = strings.TrimSpace(v.BaseCommitSHA)
	v.HeadBranch = strings.TrimSpace(v.HeadBranch)
	v.CandidateCommitSHA = strings.TrimSpace(v.CandidateCommitSHA)
	v.ApprovedHeadCommitSHA = strings.TrimSpace(v.ApprovedHeadCommitSHA)
	v.RevisionID = strings.TrimSpace(v.RevisionID)
	v.Digest = strings.TrimSpace(v.Digest)
	v.PublicKeyFingerprint = strings.TrimSpace(v.PublicKeyFingerprint)
	v.ExternalURL = strings.TrimSpace(v.ExternalURL)
	if v.Organization == "" || v.Repository == "" || v.HeadBranch == "" || v.RevisionID == "" || !strings.HasPrefix(v.Digest, "sha256:") || !strings.HasPrefix(v.PublicKeyFingerprint, "sha256:") || !gitops.IsFullCommitSHA(v.BaseCommitSHA) {
		return GitPullRequest{}, fmt.Errorf("%w: complete Git pull request intent identity is required", ErrValidation)
	}
	if v.State == "" {
		v.State = GitPullRequestRequested
	}
	if v.State != GitPullRequestRequested || v.ExternalNumber != 0 || v.CandidateCommitSHA != "" || v.ApprovedHeadCommitSHA != "" {
		return GitPullRequest{}, fmt.Errorf("%w: new pull request must be REQUESTED without external identity", ErrValidation)
	}
	return v, nil
}

func (s *MemoryStore) CreateGitPullRequest(_ context.Context, v GitPullRequest, actor string) (GitPullRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if v, err = normalizeGitPullRequest(v); err != nil {
		return GitPullRequest{}, err
	}
	for _, existing := range s.gitPullRequests {
		if existing.Organization == v.Organization && existing.Repository == v.Repository && existing.RevisionID == v.RevisionID && existing.State != GitPullRequestClosed {
			if existing.Digest != v.Digest || existing.HeadBranch != v.HeadBranch || existing.BaseBranch != v.BaseBranch || existing.BaseCommitSHA != v.BaseCommitSHA || existing.PublicKeyFingerprint != v.PublicKeyFingerprint {
				return GitPullRequest{}, ErrConflict
			}
			return existing, nil
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("gpr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.RequestedBy = strings.TrimSpace(actor)
	s.gitPullRequests[v.ID] = v
	s.appendAuditLocked(actor, "git_pull_request.requested", "gitPullRequest", v.ID, v.Revision, map[string]any{"organization": v.Organization, "repository": v.Repository, "revisionId": v.RevisionID, "headBranch": v.HeadBranch, "baseCommitSha": v.BaseCommitSHA})
	s.appendOutboxLocked("gitPullRequest", v.ID, "git_pull_request.requested", v)
	return v, nil
}

func (s *MemoryStore) FinalizeGitPullRequest(_ context.Context, id string, expected int64, externalNumber int64, externalURL, candidateCommitSHA, actor string) (GitPullRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.gitPullRequests[strings.TrimSpace(id)]
	if !ok {
		return GitPullRequest{}, ErrNotFound
	}
	candidateCommitSHA = strings.TrimSpace(candidateCommitSHA)
	externalURL = strings.TrimSpace(externalURL)
	if v.Revision != expected {
		return GitPullRequest{}, ErrConflict
	}
	if v.State == GitPullRequestOpen {
		if v.ExternalNumber == externalNumber && v.CandidateCommitSHA == candidateCommitSHA {
			return v, nil
		}
		return GitPullRequest{}, ErrConflict
	}
	if v.State != GitPullRequestRequested || externalNumber <= 0 || !gitops.IsFullCommitSHA(candidateCommitSHA) {
		return GitPullRequest{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	v.Revision++
	v.ExternalNumber = externalNumber
	v.ExternalURL = externalURL
	v.CandidateCommitSHA = candidateCommitSHA
	v.State = GitPullRequestOpen
	v.UpdatedAt = now
	s.gitPullRequests[v.ID] = v
	s.appendAuditLocked(actor, "git_pull_request.opened", "gitPullRequest", v.ID, v.Revision, map[string]any{"externalNumber": v.ExternalNumber, "revisionId": v.RevisionID, "candidateCommitSha": candidateCommitSHA})
	s.appendOutboxLocked("gitPullRequest", v.ID, "git_pull_request.opened", v)
	return v, nil
}

func (s *MemoryStore) GetGitPullRequest(_ context.Context, id string) (GitPullRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.gitPullRequests[strings.TrimSpace(id)]
	if !ok {
		return GitPullRequest{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListGitPullRequests(_ context.Context, organization, repository string) ([]GitPullRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organization, repository = normalizeGitIdentity(organization), normalizeGitIdentity(repository)
	out := []GitPullRequest{}
	for _, v := range s.gitPullRequests {
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

func (s *MemoryStore) ApproveGitPullRequest(_ context.Context, id string, expected int64, approvedHeadCommitSHA, actor string) (GitPullRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.gitPullRequests[strings.TrimSpace(id)]
	if !ok {
		return GitPullRequest{}, ErrNotFound
	}
	approvedHeadCommitSHA = strings.TrimSpace(approvedHeadCommitSHA)
	if v.Revision != expected {
		return GitPullRequest{}, ErrConflict
	}
	if v.State == GitPullRequestApproved {
		if v.ApprovedHeadCommitSHA == approvedHeadCommitSHA {
			return v, nil
		}
		return GitPullRequest{}, ErrConflict
	}
	if v.State != GitPullRequestOpen || !gitops.IsFullCommitSHA(approvedHeadCommitSHA) || approvedHeadCommitSHA != v.CandidateCommitSHA {
		return GitPullRequest{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	v.Revision++
	v.State = GitPullRequestApproved
	v.ApprovedHeadCommitSHA = approvedHeadCommitSHA
	v.ApprovedBy = strings.TrimSpace(actor)
	v.ApprovedAt = &now
	v.UpdatedAt = now
	s.gitPullRequests[v.ID] = v
	s.appendAuditLocked(actor, "git_pull_request.approved", "gitPullRequest", v.ID, v.Revision, map[string]any{"externalNumber": v.ExternalNumber, "revisionId": v.RevisionID, "approvedHeadCommitSha": approvedHeadCommitSHA})
	s.appendOutboxLocked("gitPullRequest", v.ID, "git_pull_request.approved", v)
	return v, nil
}

func normalizeManagedGitRevisionForInsert(v ManagedGitRevision) (ManagedGitRevision, error) {
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
	return v, nil
}

func (s *MemoryStore) CommitMergedGitPullRequest(_ context.Context, id string, expected int64, commitSHA string, managed ManagedGitRevision, actor string) (GitPullRequest, ManagedGitRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr, ok := s.gitPullRequests[strings.TrimSpace(id)]
	if !ok {
		return GitPullRequest{}, ManagedGitRevision{}, ErrNotFound
	}
	commitSHA = strings.TrimSpace(commitSHA)
	if pr.Revision != expected {
		return GitPullRequest{}, ManagedGitRevision{}, ErrConflict
	}
	if pr.State == GitPullRequestMerged {
		if pr.MergedCommitSHA != commitSHA {
			return GitPullRequest{}, ManagedGitRevision{}, ErrConflict
		}
		for _, existing := range s.managedGitRevisions {
			if existing.PullRequestID == pr.ID && existing.CommitSHA == commitSHA {
				return pr, existing, nil
			}
		}
		return GitPullRequest{}, ManagedGitRevision{}, ErrConflict
	}
	if pr.State != GitPullRequestApproved || pr.ApprovedHeadCommitSHA == "" || pr.ApprovedHeadCommitSHA != pr.CandidateCommitSHA || !gitops.IsFullCommitSHA(commitSHA) {
		return GitPullRequest{}, ManagedGitRevision{}, ErrInvalidTransition
	}
	managed.Organization, managed.Repository, managed.Branch = pr.Organization, pr.Repository, pr.BaseBranch
	managed.RevisionID, managed.Digest, managed.CommitSHA, managed.PublicKeyFingerprint = pr.RevisionID, pr.Digest, commitSHA, pr.PublicKeyFingerprint
	managed.DeliveryMode, managed.PullRequestID = GitDeliveryPullRequest, pr.ID
	var err error
	managed, err = normalizeManagedGitRevisionForInsert(managed)
	if err != nil {
		return GitPullRequest{}, ManagedGitRevision{}, err
	}
	for _, existing := range s.managedGitRevisions {
		if existing.Organization == managed.Organization && existing.Repository == managed.Repository && existing.Branch == managed.Branch && existing.CommitSHA == managed.CommitSHA {
			if existing.Digest != managed.Digest || existing.RevisionID != managed.RevisionID || existing.PublicKeyFingerprint != managed.PublicKeyFingerprint || existing.PullRequestID != pr.ID {
				return GitPullRequest{}, ManagedGitRevision{}, ErrConflict
			}
			managed = existing
			goto commitPR
		}
	}
	{
		now := nowUTC(s.now)
		managed.ResourceMeta = ResourceMeta{ID: s.id("gtr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		managed.RecordedBy = strings.TrimSpace(actor)
		s.managedGitRevisions[managed.ID] = managed
		s.appendAuditLocked(actor, "git_revision.recorded", "managedGitRevision", managed.ID, managed.Revision, map[string]any{"organization": managed.Organization, "repository": managed.Repository, "branch": managed.Branch, "commitSha": managed.CommitSHA, "source": managed.Source, "deliveryMode": managed.DeliveryMode, "pullRequestId": managed.PullRequestID})
		s.appendOutboxLocked("managedGitRevision", managed.ID, "git_revision.recorded", managed)
	}
commitPR:
	now := nowUTC(s.now)
	pr.Revision++
	pr.State = GitPullRequestMerged
	pr.MergedBy = strings.TrimSpace(actor)
	pr.MergedAt = &now
	pr.MergedCommitSHA = commitSHA
	pr.UpdatedAt = now
	s.gitPullRequests[pr.ID] = pr
	s.appendAuditLocked(actor, "git_pull_request.merged", "gitPullRequest", pr.ID, pr.Revision, map[string]any{"externalNumber": pr.ExternalNumber, "revisionId": pr.RevisionID, "commitSha": commitSHA})
	s.appendOutboxLocked("gitPullRequest", pr.ID, "git_pull_request.merged", pr)
	return pr, managed, nil
}
