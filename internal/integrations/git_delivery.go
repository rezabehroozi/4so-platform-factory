package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/gitops"
)

type PullRequestRevisionResult struct {
	RevisionResult
	BaseBranch     string `json:"baseBranch"`
	HeadBranch     string `json:"headBranch"`
	ExternalNumber int64  `json:"externalNumber"`
	ExternalURL    string `json:"externalUrl,omitempty"`
}

type PullRequestReviewResult struct {
	ExternalNumber int64  `json:"externalNumber"`
	State          string `json:"state"`
}
type PullRequestMergeResult struct {
	ExternalNumber int64  `json:"externalNumber"`
	CommitSHA      string `json:"commitSha"`
}
type PullRequestStatus struct {
	ExternalNumber int64  `json:"externalNumber"`
	State          string `json:"state"`
	Merged         bool   `json:"merged"`
	MergeCommitSHA string `json:"mergeCommitSha,omitempty"`
	BaseBranch     string `json:"baseBranch"`
	BaseCommitSHA  string `json:"baseCommitSha"`
	HeadBranch     string `json:"headBranch"`
	HeadCommitSHA  string `json:"headCommitSha"`
	Approved       bool   `json:"approved"`
}

func managedBranchName(prefix, revisionID string) string {
	raw := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(revisionID), "_", "-"))
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	base := prefix + strings.Trim(b.String(), "-.")
	if base == prefix {
		base += "revision"
	}
	const maxBranchLen = 100
	if len(base) <= maxBranchLen {
		return base
	}
	sum := sha256.Sum256([]byte(base))
	suffix := "-" + hex.EncodeToString(sum[:6])
	return base[:maxBranchLen-len(suffix)] + suffix
}

func PullRequestHeadBranch(revisionID string) string {
	return managedBranchName("platform-", revisionID)
}

func directStageBranch(revisionID string) string {
	return managedBranchName("platform-direct-", revisionID)
}

func restoreStageBranch(revisionID string) string {
	return managedBranchName("platform-restore-", revisionID)
}

func validateRevisionRequest(input RevisionRequest) (revisionDescriptor, []string, error) {
	input.Organization = strings.TrimSpace(input.Organization)
	input.Repository = strings.TrimSpace(input.Repository)
	input.RevisionID = strings.TrimSpace(input.RevisionID)
	input.Digest = strings.TrimSpace(input.Digest)
	if !safeName(input.Organization) || !safeName(input.Repository) || input.RevisionID == "" || !strings.HasPrefix(input.Digest, "sha256:") {
		return revisionDescriptor{}, nil, errors.New("organization, repository, revisionId and sha256 digest are required")
	}
	if len(input.Files) == 0 {
		return revisionDescriptor{}, nil, errors.New("revision files are required")
	}
	d, err := verifyRevisionFiles(input.Files, "")
	if err != nil {
		return revisionDescriptor{}, nil, fmt.Errorf("verify signed revision: %w", err)
	}
	if d.Integrity.Digest != input.Digest || d.Metadata.ID != input.RevisionID {
		return revisionDescriptor{}, nil, errors.New("revisionId/digest do not match signed revision descriptor")
	}
	canonicalFiles := make(map[string][]byte, len(input.Files))
	for filePath, raw := range input.Files {
		canonicalFiles[filePath] = []byte(raw)
	}
	if err := gitops.ValidateCanonicalManagedFiles(canonicalFiles, d.Spec, d.Metadata.ID, d.Integrity.Digest, d.Integrity.Signature, d.Integrity.PublicKeyFingerprint); err != nil {
		return revisionDescriptor{}, nil, fmt.Errorf("verify canonical managed revision bundle: %w", err)
	}
	paths := make([]string, 0, len(input.Files))
	for filePath := range input.Files {
		clean := path.Clean("/" + filePath)
		if clean == "/" || strings.Contains(clean, "..") {
			return revisionDescriptor{}, nil, fmt.Errorf("unsafe repository path %q", filePath)
		}
		paths = append(paths, strings.TrimPrefix(clean, "/"))
	}
	sort.Strings(paths)
	for i, p := range paths {
		if p == "clusters/appliance/kustomization.yaml" {
			paths = append(append(paths[:i], paths[i+1:]...), p)
			break
		}
	}
	return d, paths, nil
}

func ValidatePullRequestRevisionIntent(input RevisionRequest) (string, error) {
	d, _, err := validateRevisionRequest(input)
	if err != nil {
		return "", err
	}
	return d.Integrity.PublicKeyFingerprint, nil
}

func (c *Client) CreatePullRequestRevision(ctx context.Context, input RevisionRequest, expectedBaseCommit string) (PullRequestRevisionResult, error) {
	if c == nil || c.config.GitConnectionResolver == nil {
		return PullRequestRevisionResult{}, errors.New("managed Forgejo integration is not configured")
	}
	descriptor, paths, err := validateRevisionRequest(input)
	if err != nil {
		return PullRequestRevisionResult{}, err
	}
	if _, err = c.EnsureRepository(ctx, RepositoryRequest{Organization: input.Organization, Name: input.Repository, Description: "Managed platform desired state", Private: true}); err != nil {
		return PullRequestRevisionResult{}, err
	}
	expectedBaseCommit = strings.TrimSpace(expectedBaseCommit)
	if !gitops.IsFullCommitSHA(expectedBaseCommit) {
		return PullRequestRevisionResult{}, errors.New("full immutable base commit is required for pull-request delivery")
	}
	currentBase, err := c.branchCommit(ctx, input.Organization, input.Repository, "main")
	if err != nil {
		return PullRequestRevisionResult{}, err
	}
	if currentBase != expectedBaseCommit {
		return PullRequestRevisionResult{}, errors.New("base branch changed before pull-request staging; create a new intent")
	}
	head := PullRequestHeadBranch(input.RevisionID)
	branchPayload := map[string]any{"new_branch_name": head, "old_branch_name": "main"}
	var branchResponse map[string]any
	err = c.forgejoJSON(ctx, http.MethodPost, "/api/v1/repos/"+url.PathEscape(input.Organization)+"/"+url.PathEscape(input.Repository)+"/branches", branchPayload, &branchResponse, http.StatusCreated)
	recoveredBranch := false
	if err != nil {
		var statusErr *httpStatusError
		if !errors.As(err, &statusErr) || statusErr.Status != http.StatusConflict {
			return PullRequestRevisionResult{}, err
		}
		recoveredBranch = true
	}
	changed := 0
	if recoveredBranch {
		headCommit, e := c.branchCommit(ctx, input.Organization, input.Repository, head)
		if e != nil {
			return PullRequestRevisionResult{}, e
		}
		for _, filePath := range paths {
			raw, e := c.repositoryFile(ctx, input.Organization, input.Repository, filePath, head)
			if e != nil || string(raw) != input.Files[filePath] {
				return PullRequestRevisionResult{}, errors.New("existing pull-request branch does not exactly match the signed revision intent")
			}
		}
		diff, e := c.compareFiles(ctx, input.Organization, input.Repository, expectedBaseCommit, headCommit)
		if e != nil {
			return PullRequestRevisionResult{}, e
		}
		allowed := map[string]bool{}
		for _, p := range paths {
			allowed[p] = true
		}
		for _, p := range diff {
			if !allowed[p] {
				return PullRequestRevisionResult{}, fmt.Errorf("existing pull-request branch contains unmanaged change %q", p)
			}
		}
	} else {
		for _, filePath := range paths {
			updated, e := c.putRepositoryFileOnBranch(ctx, input.Organization, input.Repository, head, filePath, []byte(input.Files[filePath]), "Stage "+input.RevisionID+" ("+input.Digest+")")
			if e != nil {
				return PullRequestRevisionResult{}, e
			}
			if updated {
				changed++
			}
		}
	}
	headCommit, err := c.branchCommit(ctx, input.Organization, input.Repository, head)
	if err != nil {
		return PullRequestRevisionResult{}, err
	}
	payload := map[string]any{"base": "main", "head": head, "title": "Platform revision " + input.RevisionID, "body": "Signed desired-state revision " + input.Digest + " staged by 4SO Platform Factory."}
	var pr struct {
		Number  int64  `json:"number"`
		HTMLURL string `json:"html_url"`
		State   string `json:"state"`
	}
	if err = c.forgejoJSON(ctx, http.MethodPost, "/api/v1/repos/"+url.PathEscape(input.Organization)+"/"+url.PathEscape(input.Repository)+"/pulls", payload, &pr, http.StatusCreated); err != nil {
		var statusErr *httpStatusError
		if !errors.As(err, &statusErr) || (statusErr.Status != http.StatusConflict && statusErr.Status != http.StatusUnprocessableEntity) {
			return PullRequestRevisionResult{}, err
		}
		existing, e := c.findPullRequestByHead(ctx, input.Organization, input.Repository, "main", head)
		if e != nil {
			return PullRequestRevisionResult{}, e
		}
		pr.Number, pr.HTMLURL = existing.ExternalNumber, existing.ExternalURL
	}
	if pr.Number <= 0 {
		return PullRequestRevisionResult{}, errors.New("Forgejo pull request response did not include a number")
	}
	return PullRequestRevisionResult{RevisionResult: RevisionResult{Organization: input.Organization, Repository: input.Repository, RevisionID: input.RevisionID, Digest: input.Digest, CommitSHA: headCommit, ChangedFiles: changed, PublicKeyFingerprint: descriptor.Integrity.PublicKeyFingerprint}, BaseBranch: "main", HeadBranch: head, ExternalNumber: pr.Number, ExternalURL: pr.HTMLURL}, nil
}

type pullRequestAPI struct {
	Number         int64  `json:"number"`
	HTMLURL        string `json:"html_url"`
	State          string `json:"state"`
	Merged         bool   `json:"merged"`
	MergeCommitSHA string `json:"merge_commit_sha"`
	Base           struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"base"`
	Head struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
}

func (c *Client) findPullRequestByHead(ctx context.Context, organization, repository, base, head string) (PullRequestRevisionResult, error) {
	var pulls []pullRequestAPI
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/pulls?state=all&limit=50"
	if err := c.forgejoJSON(ctx, http.MethodGet, endpoint, nil, &pulls, http.StatusOK); err != nil {
		return PullRequestRevisionResult{}, err
	}
	for _, pr := range pulls {
		if strings.TrimSpace(pr.Base.Ref) == base && strings.TrimSpace(pr.Head.Ref) == head && !pr.Merged && strings.EqualFold(strings.TrimSpace(pr.State), "open") {
			return PullRequestRevisionResult{BaseBranch: base, HeadBranch: head, ExternalNumber: pr.Number, ExternalURL: pr.HTMLURL}, nil
		}
	}
	return PullRequestRevisionResult{}, errors.New("existing pull-request branch has no recoverable exact pull request")
}

func (c *Client) InspectPullRequest(ctx context.Context, organization, repository string, number int64) (PullRequestStatus, error) {
	if number <= 0 {
		return PullRequestStatus{}, errors.New("pull request number is required")
	}
	var pr pullRequestAPI
	endpoint := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d", url.PathEscape(organization), url.PathEscape(repository), number)
	if err := c.forgejoJSON(ctx, http.MethodGet, endpoint, nil, &pr, http.StatusOK); err != nil {
		return PullRequestStatus{}, err
	}
	approved := false
	var reviews []struct {
		State     string `json:"state"`
		Dismissed bool   `json:"dismissed"`
	}
	if err := c.forgejoJSON(ctx, http.MethodGet, endpoint+"/reviews", nil, &reviews, http.StatusOK); err != nil {
		return PullRequestStatus{}, err
	}
	for _, review := range reviews {
		if !review.Dismissed && strings.EqualFold(strings.TrimSpace(review.State), "APPROVED") {
			approved = true
			break
		}
	}
	return PullRequestStatus{ExternalNumber: pr.Number, State: pr.State, Merged: pr.Merged, MergeCommitSHA: strings.TrimSpace(pr.MergeCommitSHA), BaseBranch: strings.TrimSpace(pr.Base.Ref), BaseCommitSHA: strings.TrimSpace(pr.Base.SHA), HeadBranch: strings.TrimSpace(pr.Head.Ref), HeadCommitSHA: strings.TrimSpace(pr.Head.SHA), Approved: approved}, nil
}

func (c *Client) ValidatePullRequestCandidate(ctx context.Context, organization, repository string, number int64, baseBranch, headBranch, expectedBaseCommit, expectedHeadCommit, revisionID, digest, fingerprint string, requireApproved bool) (PullRequestStatus, error) {
	status, err := c.InspectPullRequest(ctx, organization, repository, number)
	if err != nil {
		return PullRequestStatus{}, err
	}
	if status.BaseBranch != strings.TrimSpace(baseBranch) || status.HeadBranch != strings.TrimSpace(headBranch) || status.HeadCommitSHA != strings.TrimSpace(expectedHeadCommit) {
		return PullRequestStatus{}, errors.New("pull request identity/head changed after staging")
	}
	// Before merge, the base branch must still be exactly the commit that the PR
	// intent was planned against. After a remotely committed merge we deliberately
	// skip this live-base equality check so crash recovery can reconcile the exact
	// already-merged PR without attempting a second merge. The candidate head is
	// still verified below against the immutable persisted base commit.
	if !status.Merged {
		currentBase, err := c.branchCommit(ctx, organization, repository, baseBranch)
		if err != nil {
			return PullRequestStatus{}, err
		}
		if currentBase != strings.TrimSpace(expectedBaseCommit) {
			return PullRequestStatus{}, errors.New("base branch changed after pull-request intent; re-plan delivery")
		}
	}
	snapshot, err := c.InspectGitRevision(ctx, organization, repository, headBranch, expectedBaseCommit, fingerprint)
	if err != nil {
		return PullRequestStatus{}, err
	}
	if !snapshot.Trusted || snapshot.CommitSHA != strings.TrimSpace(expectedHeadCommit) || snapshot.RevisionID != strings.TrimSpace(revisionID) || snapshot.Digest != strings.TrimSpace(digest) || snapshot.PublicKeyFingerprint != strings.TrimSpace(fingerprint) {
		return PullRequestStatus{}, errors.New("pull request head no longer matches the signed revision intent")
	}
	if err := validateManagedRevisionChangedFiles(snapshot.ChangedFiles); err != nil {
		return PullRequestStatus{}, err
	}
	if err := c.ValidateManagedRepositoryTree(ctx, organization, repository, snapshot.CommitSHA); err != nil {
		return PullRequestStatus{}, fmt.Errorf("pull request candidate tree is not canonical managed authority: %w", err)
	}
	if requireApproved && !status.Approved {
		return PullRequestStatus{}, errors.New("pull request is not approved by the managed review authority")
	}
	return status, nil
}

func validateManagedRevisionChangedFiles(paths []string) error {
	allowed := map[string]bool{}
	for _, p := range managedRevisionPaths {
		allowed[p] = true
	}
	for _, p := range paths {
		if !allowed[p] {
			return fmt.Errorf("revision contains unmanaged change %q", p)
		}
	}
	return nil
}

// ValidateMergedPullRequestRevision proves that the resulting base branch is the
// exact merge commit of the signed candidate and that the complete diff from
// the persisted pre-merge base contains only product-managed paths. This closes
// the head-change race between pre-merge validation and the remote merge call.
func (c *Client) ValidateMergedPullRequestRevision(ctx context.Context, organization, repository, baseBranch, expectedBaseCommit, expectedMergeCommit, revisionID, digest, fingerprint string) (GitRevisionSnapshot, error) {
	snapshot, err := c.InspectGitRevision(ctx, organization, repository, baseBranch, expectedBaseCommit, fingerprint)
	if err != nil {
		return GitRevisionSnapshot{}, err
	}
	if !snapshot.Trusted || snapshot.CommitSHA != strings.TrimSpace(expectedMergeCommit) || snapshot.RevisionID != strings.TrimSpace(revisionID) || snapshot.Digest != strings.TrimSpace(digest) || snapshot.PublicKeyFingerprint != strings.TrimSpace(fingerprint) {
		return GitRevisionSnapshot{}, errors.New("merged base branch does not match the approved signed revision")
	}
	if err := validateManagedRevisionChangedFiles(snapshot.ChangedFiles); err != nil {
		return GitRevisionSnapshot{}, err
	}
	if err := c.ValidateManagedRepositoryTree(ctx, organization, repository, snapshot.CommitSHA); err != nil {
		return GitRevisionSnapshot{}, fmt.Errorf("merged pull request tree is not canonical managed authority: %w", err)
	}
	return snapshot, nil
}

func (c *Client) BranchCommit(ctx context.Context, organization, repository, branch string) (string, error) {
	return c.branchCommit(ctx, organization, repository, branch)
}

func (c *Client) ApprovePullRequest(ctx context.Context, organization, repository string, number int64) (PullRequestReviewResult, error) {
	if number <= 0 {
		return PullRequestReviewResult{}, errors.New("pull request number is required")
	}
	var out map[string]any
	payload := map[string]any{"event": "APPROVED", "body": "Approved by 4SO Platform Factory delivery authority"}
	if err := c.forgejoJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/reviews", url.PathEscape(organization), url.PathEscape(repository), number), payload, &out, http.StatusCreated); err != nil {
		return PullRequestReviewResult{}, err
	}
	return PullRequestReviewResult{ExternalNumber: number, State: "APPROVED"}, nil
}
func (c *Client) MergePullRequest(ctx context.Context, organization, repository string, number int64, expectedHeadCommit string) (PullRequestMergeResult, error) {
	if number <= 0 {
		return PullRequestMergeResult{}, errors.New("pull request number is required")
	}
	var out map[string]any
	expectedHeadCommit = strings.TrimSpace(expectedHeadCommit)
	if !gitops.IsFullCommitSHA(expectedHeadCommit) {
		return PullRequestMergeResult{}, errors.New("full immutable approved head commit is required")
	}
	payload := map[string]any{"Do": "merge", "head_commit_id": expectedHeadCommit, "delete_branch_after_merge": false}
	if err := c.forgejoJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/merge", url.PathEscape(organization), url.PathEscape(repository), number), payload, &out, http.StatusOK); err != nil {
		return PullRequestMergeResult{}, err
	}
	commit, err := c.branchCommit(ctx, organization, repository, "main")
	if err != nil {
		return PullRequestMergeResult{}, err
	}
	return PullRequestMergeResult{ExternalNumber: number, CommitSHA: commit}, nil
}

var managedRevisionPaths = gitops.ManagedRevisionPaths()

// CompareGitCommitFiles returns the complete changed-file set reported by the
// managed Forgejo compare API between two immutable commits. Callers use this
// to bind rollback/recovery decisions to the exact repository tree rather than
// trusting only the signed descriptor files.
func (c *Client) CompareGitCommitFiles(ctx context.Context, organization, repository, baseCommit, headCommit string) ([]string, error) {
	baseCommit = strings.TrimSpace(baseCommit)
	headCommit = strings.TrimSpace(headCommit)
	if !gitops.IsFullCommitSHA(baseCommit) || !gitops.IsFullCommitSHA(headCommit) {
		return nil, errors.New("full immutable base and head commits are required")
	}
	return c.compareFiles(ctx, organization, repository, baseCommit, headCommit)
}

// ValidateManagedRepositoryTree proves that an immutable managed commit contains
// exactly the product-owned repository tree. This prevents historical or
// concurrent unmanaged files from being silently promoted into ManagedGitRevision
// authority simply because the signed descriptor files themselves still verify.
func (c *Client) ValidateManagedRepositoryTree(ctx context.Context, organization, repository, commit string) error {
	commit = strings.TrimSpace(commit)
	if !gitops.IsFullCommitSHA(commit) {
		return errors.New("full immutable commit is required for managed repository tree validation")
	}
	allowedFiles := map[string]bool{"README.md": true}
	allowedDirs := map[string]bool{}
	for _, managedPath := range managedRevisionPaths {
		clean := strings.TrimPrefix(path.Clean("/"+managedPath), "/")
		allowedFiles[clean] = true
		parts := strings.Split(clean, "/")
		for i := 1; i < len(parts); i++ {
			allowedDirs[strings.Join(parts[:i], "/")] = true
		}
	}
	type entry struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}
	seen := map[string]bool{}
	queue := []string{""}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/contents"
		if dir != "" {
			endpoint += "/" + strings.Join(escapePathSegments(dir), "/")
		}
		endpoint += "?ref=" + url.QueryEscape(commit)
		var entries []entry
		if err := c.forgejoJSON(ctx, http.MethodGet, endpoint, nil, &entries, http.StatusOK); err != nil {
			return fmt.Errorf("inspect managed repository tree %q: %w", dir, err)
		}
		for _, item := range entries {
			clean := strings.TrimPrefix(path.Clean("/"+strings.TrimSpace(item.Path)), "/")
			if clean == "" || strings.Contains(clean, "..") {
				return fmt.Errorf("managed repository returned unsafe tree path %q", item.Path)
			}
			switch strings.ToLower(strings.TrimSpace(item.Type)) {
			case "dir", "tree":
				if !allowedDirs[clean] {
					return fmt.Errorf("unmanaged repository directory %q is present in managed Git authority", clean)
				}
				queue = append(queue, clean)
			case "file", "blob", "":
				if !allowedFiles[clean] {
					return fmt.Errorf("unmanaged repository path %q is present in managed Git authority", clean)
				}
				seen[clean] = true
			default:
				return fmt.Errorf("unsupported repository object %q at managed path %q", item.Type, clean)
			}
		}
	}
	for expected := range allowedFiles {
		if !seen[expected] {
			return fmt.Errorf("required managed repository path %q is missing", expected)
		}
	}
	readme, err := c.repositoryFile(ctx, organization, repository, "README.md", commit)
	if err != nil {
		return fmt.Errorf("read managed repository bootstrap README: %w", err)
	}
	if string(readme) != managedRepositorySeedReadme {
		return errors.New("managed repository bootstrap README differs from canonical product seed")
	}
	return nil
}

func (c *Client) RestoreRevision(ctx context.Context, organization, repository, sourceCommit, targetBranch, expectedBaseCommit, expectedFingerprint string) (RevisionResult, error) {
	organization = strings.TrimSpace(organization)
	repository = strings.TrimSpace(repository)
	sourceCommit = strings.TrimSpace(sourceCommit)
	targetBranch = strings.TrimSpace(targetBranch)
	expectedBaseCommit = strings.TrimSpace(expectedBaseCommit)
	if targetBranch == "" {
		targetBranch = "main"
	}
	if !safeName(organization) || !safeName(repository) || !gitops.IsFullCommitSHA(sourceCommit) || !gitops.IsFullCommitSHA(expectedBaseCommit) {
		return RevisionResult{}, errors.New("repository, source commit and full immutable target base commit are required")
	}
	files := map[string]string{}
	for _, p := range managedRevisionPaths {
		raw, err := c.repositoryFile(ctx, organization, repository, p, sourceCommit)
		if err != nil {
			return RevisionResult{}, fmt.Errorf("read last-known-good %s: %w", p, err)
		}
		files[p] = string(raw)
	}
	d, err := verifyRevisionFiles(files, expectedFingerprint)
	if err != nil {
		return RevisionResult{}, fmt.Errorf("verify last-known-good revision: %w", err)
	}
	canonicalFiles := make(map[string][]byte, len(files))
	for filePath, raw := range files {
		canonicalFiles[filePath] = []byte(raw)
	}
	if err = gitops.ValidateCanonicalManagedFiles(canonicalFiles, d.Spec, d.Metadata.ID, d.Integrity.Digest, d.Integrity.Signature, d.Integrity.PublicKeyFingerprint); err != nil {
		return RevisionResult{}, fmt.Errorf("verify canonical last-known-good revision bundle: %w", err)
	}
	atomicFiles := make(map[string][]byte, len(managedRevisionPaths))
	for _, p := range managedRevisionPaths {
		atomicFiles[p] = []byte(files[p])
	}
	if err = c.requireForgejoAtomicPublicationCapability(ctx); err != nil {
		return RevisionResult{}, err
	}
	changed, commit, err := c.commitManagedFilesWithBranchCAS(ctx, organization, repository, targetBranch, expectedBaseCommit, restoreStageBranch(d.Metadata.ID), atomicFiles, "Rollback to last-known-good "+d.Metadata.ID+" ("+d.Integrity.Digest+")")
	if err != nil {
		return RevisionResult{}, err
	}
	snapshot, err := c.InspectGitRevision(ctx, organization, repository, targetBranch, expectedBaseCommit, expectedFingerprint)
	if err != nil {
		return RevisionResult{}, err
	}
	if !snapshot.Trusted || snapshot.CommitSHA != commit || snapshot.RevisionID != d.Metadata.ID || snapshot.Digest != d.Integrity.Digest || snapshot.PublicKeyFingerprint != d.Integrity.PublicKeyFingerprint {
		return RevisionResult{}, errors.New("restored branch does not match the exact signed last-known-good revision")
	}
	if err := validateManagedRevisionChangedFiles(snapshot.ChangedFiles); err != nil {
		return RevisionResult{}, err
	}
	if err := c.ValidateManagedRepositoryTree(ctx, organization, repository, commit); err != nil {
		return RevisionResult{}, err
	}
	return RevisionResult{Organization: organization, Repository: repository, RevisionID: d.Metadata.ID, Digest: d.Integrity.Digest, CommitSHA: commit, ChangedFiles: changed, PublicKeyFingerprint: d.Integrity.PublicKeyFingerprint}, nil
}

func (c *Client) commitManagedFilesWithBranchCAS(ctx context.Context, organization, repository, targetBranch, expectedBaseCommit, stageBranch string, files map[string][]byte, message string) (int, string, error) {
	expectedBaseCommit = strings.TrimSpace(expectedBaseCommit)
	if !gitops.IsFullCommitSHA(expectedBaseCommit) {
		return 0, "", errors.New("full immutable base commit is required for managed branch mutation")
	}
	// Prove the exact Forgejo repository capability before creating a staging
	// branch or writing any managed revision file. Compatibility failures must
	// never leave partial publication side effects behind.
	if err := c.ensureFastForwardOnlyMergeAllowed(ctx, organization, repository); err != nil {
		return 0, "", err
	}
	current, err := c.branchCommit(ctx, organization, repository, targetBranch)
	if err != nil {
		return 0, "", err
	}
	if current != expectedBaseCommit {
		return 0, "", errors.New("target branch changed before managed mutation; re-read authority and retry")
	}
	if !safeName(stageBranch) || len(stageBranch) > 100 {
		return 0, "", errors.New("managed staging branch name is invalid")
	}
	branchPayload := map[string]any{"new_branch_name": stageBranch, "old_branch_name": targetBranch}
	var branchResponse map[string]any
	err = c.forgejoJSON(ctx, http.MethodPost, "/api/v1/repos/"+url.PathEscape(organization)+"/"+url.PathEscape(repository)+"/branches", branchPayload, &branchResponse, http.StatusCreated)
	recovered := false
	if err != nil {
		var statusErr *httpStatusError
		if !errors.As(err, &statusErr) || statusErr.Status != http.StatusConflict {
			return 0, "", err
		}
		recovered = true
	}
	stageCommit, err := c.branchCommit(ctx, organization, repository, stageBranch)
	if err != nil {
		return 0, "", err
	}
	changed := 0
	if stageCommit == expectedBaseCommit {
		changed, stageCommit, err = c.changeRepositoryFilesAtomic(ctx, organization, repository, stageBranch, files, message)
		if err != nil {
			return 0, "", err
		}
	} else {
		if !recovered {
			return 0, "", errors.New("new staging branch was not created from the expected base commit")
		}
		for p, expected := range files {
			raw, e := c.repositoryFile(ctx, organization, repository, p, stageBranch)
			if e != nil || !bytes.Equal(raw, expected) {
				return 0, "", errors.New("existing staging branch does not exactly match the managed mutation intent")
			}
		}
	}
	diff, err := c.compareFiles(ctx, organization, repository, expectedBaseCommit, stageCommit)
	if err != nil {
		return 0, "", err
	}
	if err = validateManagedRevisionChangedFiles(diff); err != nil {
		return 0, "", err
	}
	changed = len(diff)
	if stageCommit == expectedBaseCommit {
		return 0, stageCommit, nil
	}
	// Forgejo 16.x does not expose Gitea's newer branch-ref update API. Use
	// Forgejo's native fast-forward-only pull-request merge as the branch CAS:
	// the staging commit is a descendant of expectedBaseCommit, so any forward
	// movement of the target branch makes --ff-only fail instead of folding
	// concurrent/unmanaged state into the managed authority. The exact staged
	// head is also bound through head_commit_id.
	if err = c.mergeStagedBranchFastForward(ctx, organization, repository, targetBranch, stageBranch, expectedBaseCommit, stageCommit); err != nil {
		return 0, "", err
	}
	return changed, stageCommit, nil
}

func (c *Client) ensureFastForwardOnlyMergeAllowed(ctx context.Context, organization, repository string) error {
	payload := map[string]any{"allow_fast_forward_only_merge": true}
	var updated struct {
		AllowFastForwardOnly bool `json:"allow_fast_forward_only_merge"`
	}
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository)
	if err := c.forgejoJSON(ctx, http.MethodPatch, endpoint, payload, &updated, http.StatusOK); err != nil {
		return fmt.Errorf("enable Forgejo fast-forward-only merge capability: %w", err)
	}
	if !updated.AllowFastForwardOnly {
		var observed struct {
			AllowFastForwardOnly bool `json:"allow_fast_forward_only_merge"`
		}
		if err := c.forgejoJSON(ctx, http.MethodGet, endpoint, nil, &observed, http.StatusOK); err != nil {
			return fmt.Errorf("verify Forgejo fast-forward-only merge capability: %w", err)
		}
		if !observed.AllowFastForwardOnly {
			return errors.New("Forgejo repository does not expose fast-forward-only merge capability required for managed branch compare-and-swap")
		}
	}
	return nil
}

func (c *Client) mergeStagedBranchFastForward(ctx context.Context, organization, repository, targetBranch, stageBranch, expectedBaseCommit, stageCommit string) error {
	current, err := c.branchCommit(ctx, organization, repository, targetBranch)
	if err != nil {
		return err
	}
	if current != expectedBaseCommit {
		return errors.New("target branch changed before fast-forward compare-and-swap; re-plan managed mutation")
	}
	payload := map[string]any{
		"base":  targetBranch,
		"head":  stageBranch,
		"title": "Managed fast-forward " + stageBranch,
		"body":  "Internal 4SO Platform Factory compare-and-swap delivery. This pull request is merged only with fast-forward-only semantics.",
	}
	var pr struct {
		Number int64 `json:"number"`
	}
	endpoint := "/api/v1/repos/" + url.PathEscape(organization) + "/" + url.PathEscape(repository) + "/pulls"
	if err = c.forgejoJSON(ctx, http.MethodPost, endpoint, payload, &pr, http.StatusCreated); err != nil {
		var statusErr *httpStatusError
		if !errors.As(err, &statusErr) || (statusErr.Status != http.StatusConflict && statusErr.Status != http.StatusUnprocessableEntity) {
			return err
		}
		existing, findErr := c.findPullRequestByHead(ctx, organization, repository, targetBranch, stageBranch)
		if findErr != nil {
			return findErr
		}
		pr.Number = existing.ExternalNumber
	}
	if pr.Number <= 0 {
		return errors.New("Forgejo staging pull request response did not include a number")
	}
	status, err := c.InspectPullRequest(ctx, organization, repository, pr.Number)
	if err != nil {
		return err
	}
	if status.Merged || status.BaseBranch != targetBranch || status.HeadBranch != stageBranch || status.HeadCommitSHA != stageCommit {
		return errors.New("Forgejo staging pull request identity/head does not match managed branch intent")
	}
	current, err = c.branchCommit(ctx, organization, repository, targetBranch)
	if err != nil {
		return err
	}
	if current != expectedBaseCommit {
		return errors.New("target branch changed before fast-forward merge; re-plan managed mutation")
	}
	mergePayload := map[string]any{"Do": "fast-forward-only", "head_commit_id": stageCommit, "delete_branch_after_merge": false}
	mergeEndpoint := fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/merge", url.PathEscape(organization), url.PathEscape(repository), pr.Number)
	if err = c.forgejoJSON(ctx, http.MethodPost, mergeEndpoint, mergePayload, nil, http.StatusOK); err != nil {
		// A lost HTTP response after a successful FF merge is recoverable only if
		// the target branch is already the exact staged commit. Otherwise preserve
		// the original error and never retry the remote mutation blindly.
		observed, observeErr := c.branchCommit(ctx, organization, repository, targetBranch)
		if observeErr == nil && observed == stageCommit {
			return nil
		}
		return err
	}
	current, err = c.branchCommit(ctx, organization, repository, targetBranch)
	if err != nil {
		return err
	}
	if current != stageCommit {
		return errors.New("managed fast-forward compare-and-swap result was not observed")
	}
	return nil
}
