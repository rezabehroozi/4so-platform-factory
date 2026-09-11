package api

import (
	"net/http"
	"strconv"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/integrations"
)

func (s *Server) listGitPullRequests(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireGitAdmin(w, r); !ok {
		return
	}
	items, err := s.store.ListGitPullRequests(r.Context(), r.URL.Query().Get("organization"), r.URL.Query().Get("repository"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) approveGitPullRequest(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	if s.services == nil {
		writeError(w, http.StatusServiceUnavailable, "GIT_AUTHORITY_UNAVAILABLE", "managed Forgejo integration is not configured")
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "REVISION_REQUIRED", err.Error())
		return
	}
	pr, err := s.store.GetGitPullRequest(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if pr.Revision != rev {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if pr.State != controlplane.GitPullRequestOpen && pr.State != controlplane.GitPullRequestApproved {
		writeStoreError(w, controlplane.ErrInvalidTransition)
		return
	}
	status, err := s.services.ValidatePullRequestCandidate(r.Context(), pr.Organization, pr.Repository, pr.ExternalNumber, pr.BaseBranch, pr.HeadBranch, pr.BaseCommitSHA, pr.CandidateCommitSHA, pr.RevisionID, pr.Digest, pr.PublicKeyFingerprint, false)
	if err != nil {
		writeError(w, http.StatusConflict, "GIT_PULL_REQUEST_AUTHORITY_CHANGED", err.Error())
		return
	}
	if status.Merged {
		writeError(w, http.StatusConflict, "GIT_PULL_REQUEST_ALREADY_MERGED", "pull request merged before local approval authority committed")
		return
	}
	if !status.Approved {
		if _, err = s.services.ApprovePullRequest(r.Context(), pr.Organization, pr.Repository, pr.ExternalNumber); err != nil {
			writeError(w, http.StatusBadGateway, "GIT_PULL_REQUEST_APPROVAL_FAILED", err.Error())
			return
		}
		if _, err = s.services.ValidatePullRequestCandidate(r.Context(), pr.Organization, pr.Repository, pr.ExternalNumber, pr.BaseBranch, pr.HeadBranch, pr.BaseCommitSHA, pr.CandidateCommitSHA, pr.RevisionID, pr.Digest, pr.PublicKeyFingerprint, true); err != nil {
			writeError(w, http.StatusBadGateway, "GIT_PULL_REQUEST_APPROVAL_NOT_OBSERVED", err.Error())
			return
		}
	}
	pr, err = s.store.ApproveGitPullRequest(r.Context(), pr.ID, rev, pr.CandidateCommitSHA, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, pr.Revision)
	writeJSON(w, http.StatusOK, pr)
}

func (s *Server) mergeGitPullRequest(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	if s.services == nil {
		writeError(w, http.StatusServiceUnavailable, "GIT_AUTHORITY_UNAVAILABLE", "managed Forgejo integration is not configured")
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "REVISION_REQUIRED", err.Error())
		return
	}
	pr, err := s.store.GetGitPullRequest(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if pr.Revision != rev {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if pr.State != controlplane.GitPullRequestApproved {
		writeStoreError(w, controlplane.ErrInvalidTransition)
		return
	}
	status, err := s.services.ValidatePullRequestCandidate(r.Context(), pr.Organization, pr.Repository, pr.ExternalNumber, pr.BaseBranch, pr.HeadBranch, pr.BaseCommitSHA, pr.ApprovedHeadCommitSHA, pr.RevisionID, pr.Digest, pr.PublicKeyFingerprint, true)
	if err != nil {
		writeError(w, http.StatusConflict, "GIT_PULL_REQUEST_AUTHORITY_CHANGED", err.Error())
		return
	}
	commitSHA := strings.TrimSpace(status.MergeCommitSHA)
	if !status.Merged {
		result, e := s.services.MergePullRequest(r.Context(), pr.Organization, pr.Repository, pr.ExternalNumber, pr.ApprovedHeadCommitSHA)
		if e != nil {
			writeError(w, http.StatusBadGateway, "GIT_PULL_REQUEST_MERGE_FAILED", e.Error())
			return
		}
		commitSHA = strings.TrimSpace(result.CommitSHA)
		status, e = s.services.InspectPullRequest(r.Context(), pr.Organization, pr.Repository, pr.ExternalNumber)
		if e != nil || !status.Merged {
			if e == nil {
				e = controlplane.ErrValidation
			}
			writeError(w, http.StatusBadGateway, "GIT_PULL_REQUEST_MERGE_NOT_OBSERVED", e.Error())
			return
		}
		if strings.TrimSpace(status.MergeCommitSHA) != "" {
			commitSHA = strings.TrimSpace(status.MergeCommitSHA)
		}
	}
	_, err = s.services.ValidateMergedPullRequestRevision(r.Context(), pr.Organization, pr.Repository, pr.BaseBranch, pr.BaseCommitSHA, commitSHA, pr.RevisionID, pr.Digest, pr.PublicKeyFingerprint)
	if err != nil {
		writeError(w, http.StatusBadGateway, "GIT_MERGED_REVISION_INVALID", err.Error())
		return
	}
	pr, managed, err := s.store.CommitMergedGitPullRequest(r.Context(), pr.ID, rev, commitSHA, controlplane.ManagedGitRevision{Source: "PLATFORM_PR_MERGED"}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, pr.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"pullRequest": pr, "managedRevision": managed, "mergeVerified": true})
}

func (s *Server) observeGitRevisionSynchronization(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 400, "REVISION_REQUIRED", err.Error())
		return
	}
	managed, err := s.store.GetManagedGitRevision(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if managed.Revision != rev {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if s.services == nil {
		writeError(w, 503, "GITOPS_AUTHORITY_UNAVAILABLE", "managed Argo CD integration is not configured")
		return
	}
	observation, err := s.services.ObserveGitOpsApplication(r.Context(), "platform-appliance")
	if err != nil {
		writeError(w, 502, "GITOPS_OBSERVATION_FAILED", err.Error())
		return
	}
	if observation.SyncStatus != "Synced" || observation.HealthStatus != "Healthy" || observation.Revision != managed.CommitSHA {
		writeError(w, 422, "GITOPS_REVISION_NOT_HEALTHY", "Argo CD must report the exact managed commit as Synced and Healthy")
		return
	}
	v, err := s.store.MarkManagedGitRevisionSynchronized(r.Context(), managed.ID, rev, managed.Digest, true, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, map[string]any{"revision": v, "lastKnownGood": true, "authority": "GIT_LAST_KNOWN_GOOD_REVISION_V1", "observationAuthority": "ARGOCD_APPLICATION_STATUS_V1", "application": observation})
}

func (s *Server) getLastKnownGoodGitRevision(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireGitAdmin(w, r); !ok {
		return
	}
	v, err := s.store.GetLastKnownGoodGitRevision(r.Context(), r.URL.Query().Get("organization"), r.URL.Query().Get("repository"), r.URL.Query().Get("branch"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"authority": "GIT_LAST_KNOWN_GOOD_REVISION_V1", "revision": v})
}

func (s *Server) rollbackLastKnownGoodGitRevision(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireGitAdmin(w, r)
	if !ok {
		return
	}
	if s.services == nil {
		writeError(w, http.StatusServiceUnavailable, "GIT_AUTHORITY_UNAVAILABLE", "managed Forgejo integration is not configured")
		return
	}
	var in struct {
		Organization string `json:"organization"`
		Repository   string `json:"repository"`
		Branch       string `json:"branch"`
		LKGID        string `json:"lkgId"`
		LKGRevision  int64  `json:"lkgRevision"`
		CommitSHA    string `json:"commitSha"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	in.Branch = strings.TrimSpace(in.Branch)
	if in.Branch == "" {
		in.Branch = "main"
	}
	in.LKGID, in.CommitSHA = strings.TrimSpace(in.LKGID), strings.TrimSpace(in.CommitSHA)
	if in.LKGID == "" || in.LKGRevision <= 0 || in.CommitSHA == "" {
		writeError(w, http.StatusBadRequest, "LKG_TARGET_REQUIRED", "lkgId, lkgRevision and commitSha are required")
		return
	}
	confirmation := "rollback:" + in.LKGID + ":" + strconv.FormatInt(in.LKGRevision, 10)
	if strings.TrimSpace(r.Header.Get("X-Confirm-Rollback")) != confirmation {
		writeError(w, http.StatusPreconditionRequired, "ROLLBACK_CONFIRMATION_REQUIRED", "X-Confirm-Rollback must bind the exact LKG id and revision")
		return
	}
	lkg, err := s.store.GetManagedGitRevision(r.Context(), in.LKGID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if lkg.Revision != in.LKGRevision || !lkg.LastKnownGood || lkg.Organization != strings.ToLower(strings.TrimSpace(in.Organization)) || lkg.Repository != strings.ToLower(strings.TrimSpace(in.Repository)) || lkg.Branch != in.Branch || lkg.CommitSHA != in.CommitSHA {
		writeError(w, http.StatusConflict, "LKG_TARGET_CHANGED", "the confirmed last-known-good authority changed; reload before rollback")
		return
	}
	if err = s.services.ValidateManagedRepositoryTree(r.Context(), lkg.Organization, lkg.Repository, lkg.CommitSHA); err != nil {
		writeError(w, http.StatusConflict, "LKG_TARGET_INVALID", err.Error())
		return
	}
	current, inspectErr := s.services.InspectGitRevision(r.Context(), lkg.Organization, lkg.Repository, lkg.Branch, "", lkg.PublicKeyFingerprint)
	currentSignedAsLKG := inspectErr == nil && current.Trusted && current.RevisionID == lkg.RevisionID && current.Digest == lkg.Digest && current.PublicKeyFingerprint == lkg.PublicKeyFingerprint
	treeMatchesLKG := false
	if currentSignedAsLKG {
		if treeErr := s.services.ValidateManagedRepositoryTree(r.Context(), lkg.Organization, lkg.Repository, current.CommitSHA); treeErr == nil {
			if current.CommitSHA == lkg.CommitSHA {
				treeMatchesLKG = true
			} else if diff, diffErr := s.services.CompareGitCommitFiles(r.Context(), lkg.Organization, lkg.Repository, lkg.CommitSHA, current.CommitSHA); diffErr == nil && len(diff) == 0 {
				treeMatchesLKG = true
			}
		}
	}
	// Response-loss recovery is accepted only when the live branch is the exact
	// signed LKG tree. Merely seeing the same signed descriptor is insufficient:
	// an unmanaged file must never be adopted as a successful rollback.
	alreadyRestored := currentSignedAsLKG && treeMatchesLKG
	var result integrations.RevisionResult
	if alreadyRestored {
		result = integrations.RevisionResult{Organization: lkg.Organization, Repository: lkg.Repository, RevisionID: current.RevisionID, Digest: current.Digest, CommitSHA: current.CommitSHA, PublicKeyFingerprint: current.PublicKeyFingerprint}
	} else {
		if inspectErr != nil || !current.Trusted {
			writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", "live Git branch is not a trusted managed authority; reconcile drift before rollback")
			return
		}
		latest, latestErr := s.store.GetLatestManagedGitRevision(r.Context(), lkg.Organization, lkg.Repository, lkg.Branch)
		if latestErr != nil {
			writeStoreError(w, latestErr)
			return
		}
		if current.CommitSHA != latest.CommitSHA || current.RevisionID != latest.RevisionID || current.Digest != latest.Digest || current.PublicKeyFingerprint != latest.PublicKeyFingerprint {
			writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", "live Git branch changed since the latest recorded authority; reconcile drift before rollback")
			return
		}
		if treeErr := s.services.ValidateManagedRepositoryTree(r.Context(), lkg.Organization, lkg.Repository, current.CommitSHA); treeErr != nil {
			writeError(w, http.StatusConflict, "GIT_BASE_AUTHORITY_CHANGED", treeErr.Error())
			return
		}
		result, err = s.services.RestoreRevision(r.Context(), lkg.Organization, lkg.Repository, lkg.CommitSHA, lkg.Branch, latest.CommitSHA, lkg.PublicKeyFingerprint)
		if err != nil {
			writeError(w, 502, "GIT_LKG_ROLLBACK_FAILED", err.Error())
			return
		}
		current, err = s.services.InspectGitRevision(r.Context(), lkg.Organization, lkg.Repository, lkg.Branch, "", lkg.PublicKeyFingerprint)
		if err != nil || !current.Trusted || current.RevisionID != lkg.RevisionID || current.Digest != lkg.Digest || current.CommitSHA != result.CommitSHA {
			if err == nil {
				err = controlplane.ErrValidation
			}
			writeError(w, http.StatusBadGateway, "GIT_LKG_ROLLBACK_NOT_OBSERVED", err.Error())
			return
		}
		if err = s.services.ValidateManagedRepositoryTree(r.Context(), lkg.Organization, lkg.Repository, current.CommitSHA); err != nil {
			writeError(w, http.StatusBadGateway, "GIT_LKG_ROLLBACK_NOT_OBSERVED", err.Error())
			return
		}
		diff, diffErr := s.services.CompareGitCommitFiles(r.Context(), lkg.Organization, lkg.Repository, lkg.CommitSHA, current.CommitSHA)
		if diffErr != nil || len(diff) != 0 {
			if diffErr == nil {
				diffErr = controlplane.ErrValidation
			}
			writeError(w, http.StatusBadGateway, "GIT_LKG_ROLLBACK_TREE_MISMATCH", diffErr.Error())
			return
		}
	}
	recorded, err := s.store.RecordManagedGitRevision(r.Context(), controlplane.ManagedGitRevision{Organization: result.Organization, Repository: result.Repository, Branch: lkg.Branch, RevisionID: result.RevisionID, Digest: result.Digest, CommitSHA: result.CommitSHA, PublicKeyFingerprint: result.PublicKeyFingerprint, Source: "PLATFORM_LKG_ROLLBACK", DeliveryMode: controlplane.GitDeliveryDirectCommit}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"authority": "GIT_LAST_KNOWN_GOOD_REVISION_V1", "restoredFrom": lkg, "rollbackRevision": recorded, "requiresSyncObservation": true, "changedFiles": result.ChangedFiles, "reconciledWithoutMutation": alreadyRestored})
}
