package persistence

import (
	"context"
	"database/sql"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/gitops"
)

const gitPullRequestColumns = `id,revision,organization,repository,base_branch,base_commit_sha,head_branch,candidate_commit_sha,approved_head_commit_sha,revision_id,digest,public_key_fingerprint,external_number,external_url,state,requested_by,approved_by,approved_at,merged_by,merged_at,merged_commit_sha,created_at,updated_at`

func scanGitPullRequest(row interface{ Scan(...any) error }) (controlplane.GitPullRequest, error) {
	var v controlplane.GitPullRequest
	err := row.Scan(&v.ID, &v.Revision, &v.Organization, &v.Repository, &v.BaseBranch, &v.BaseCommitSHA, &v.HeadBranch, &v.CandidateCommitSHA, &v.ApprovedHeadCommitSHA, &v.RevisionID, &v.Digest, &v.PublicKeyFingerprint, &v.ExternalNumber, &v.ExternalURL, &v.State, &v.RequestedBy, &v.ApprovedBy, &v.ApprovedAt, &v.MergedBy, &v.MergedAt, &v.MergedCommitSHA, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func normalizePGPull(v controlplane.GitPullRequest) (controlplane.GitPullRequest, error) {
	v.Organization = strings.ToLower(strings.TrimSpace(v.Organization))
	v.Repository = strings.ToLower(strings.TrimSpace(v.Repository))
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
		return controlplane.GitPullRequest{}, controlplane.ErrValidation
	}
	if v.State == "" {
		v.State = controlplane.GitPullRequestRequested
	}
	if v.State != controlplane.GitPullRequestRequested || v.ExternalNumber != 0 || v.CandidateCommitSHA != "" || v.ApprovedHeadCommitSHA != "" {
		return controlplane.GitPullRequest{}, controlplane.ErrValidation
	}
	return v, nil
}

func (s *PostgresStore) CreateGitPullRequest(ctx context.Context, v controlplane.GitPullRequest, actor string) (controlplane.GitPullRequest, error) {
	var out controlplane.GitPullRequest
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		if v, e = normalizePGPull(v); e != nil {
			return e
		}
		existing, e := scanGitPullRequest(tx.QueryRowContext(ctx, `SELECT `+gitPullRequestColumns+` FROM git_pull_requests WHERE organization=$1 AND repository=$2 AND revision_id=$3 AND state<>'CLOSED' FOR SHARE`, v.Organization, v.Repository, v.RevisionID))
		if e == nil {
			if existing.Digest != v.Digest || existing.HeadBranch != v.HeadBranch || existing.BaseBranch != v.BaseBranch || existing.BaseCommitSHA != v.BaseCommitSHA || existing.PublicKeyFingerprint != v.PublicKeyFingerprint {
				return controlplane.ErrConflict
			}
			out = existing
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("gpr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.RequestedBy = strings.TrimSpace(actor)
		_, e = tx.ExecContext(ctx, `INSERT INTO git_pull_requests(id,revision,organization,repository,base_branch,base_commit_sha,head_branch,candidate_commit_sha,approved_head_commit_sha,revision_id,digest,public_key_fingerprint,external_number,external_url,state,requested_by,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,'','',$7,$8,$9,0,'','REQUESTED',$10,$11,$11)`, v.ID, v.Organization, v.Repository, v.BaseBranch, v.BaseCommitSHA, v.HeadBranch, v.RevisionID, v.Digest, v.PublicKeyFingerprint, v.RequestedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_pull_request.requested", "gitPullRequest", v.ID, 1, "", map[string]any{"organization": v.Organization, "repository": v.Repository, "revisionId": v.RevisionID, "headBranch": v.HeadBranch, "baseCommitSha": v.BaseCommitSHA}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitPullRequest", v.ID, "git_pull_request.requested", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) FinalizeGitPullRequest(ctx context.Context, id string, expected int64, externalNumber int64, externalURL, candidateCommitSHA, actor string) (controlplane.GitPullRequest, error) {
	var out controlplane.GitPullRequest
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanGitPullRequest(tx.QueryRowContext(ctx, `SELECT `+gitPullRequestColumns+` FROM git_pull_requests WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		candidateCommitSHA = strings.TrimSpace(candidateCommitSHA)
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State == controlplane.GitPullRequestOpen {
			if v.ExternalNumber == externalNumber && v.CandidateCommitSHA == candidateCommitSHA {
				out = v
				return nil
			}
			return controlplane.ErrConflict
		}
		if v.State != controlplane.GitPullRequestRequested || externalNumber <= 0 || !gitops.IsFullCommitSHA(candidateCommitSHA) {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.Revision++
		v.ExternalNumber = externalNumber
		v.ExternalURL = strings.TrimSpace(externalURL)
		v.CandidateCommitSHA = candidateCommitSHA
		v.State = controlplane.GitPullRequestOpen
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE git_pull_requests SET revision=$2,external_number=$3,external_url=$4,candidate_commit_sha=$5,state='OPEN',updated_at=$6 WHERE id=$1`, v.ID, v.Revision, v.ExternalNumber, v.ExternalURL, v.CandidateCommitSHA, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_pull_request.opened", "gitPullRequest", v.ID, v.Revision, "", map[string]any{"externalNumber": v.ExternalNumber, "revisionId": v.RevisionID, "candidateCommitSha": candidateCommitSHA}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitPullRequest", v.ID, "git_pull_request.opened", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) GetGitPullRequest(ctx context.Context, id string) (controlplane.GitPullRequest, error) {
	v, e := scanGitPullRequest(s.db.QueryRowContext(ctx, `SELECT `+gitPullRequestColumns+` FROM git_pull_requests WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(e)
}

func (s *PostgresStore) ListGitPullRequests(ctx context.Context, organization, repository string) ([]controlplane.GitPullRequest, error) {
	q := `SELECT ` + gitPullRequestColumns + ` FROM git_pull_requests WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(organization) != "" {
		args = append(args, strings.ToLower(strings.TrimSpace(organization)))
		q += ` AND organization=$1`
	}
	if strings.TrimSpace(repository) != "" {
		args = append(args, strings.ToLower(strings.TrimSpace(repository)))
		q += ` AND repository=$` + itoa(len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.GitPullRequest{}
	for rows.Next() {
		v, e := scanGitPullRequest(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ApproveGitPullRequest(ctx context.Context, id string, expected int64, approvedHeadCommitSHA, actor string) (controlplane.GitPullRequest, error) {
	var out controlplane.GitPullRequest
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanGitPullRequest(tx.QueryRowContext(ctx, `SELECT `+gitPullRequestColumns+` FROM git_pull_requests WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		approvedHeadCommitSHA = strings.TrimSpace(approvedHeadCommitSHA)
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State == controlplane.GitPullRequestApproved {
			if v.ApprovedHeadCommitSHA == approvedHeadCommitSHA {
				out = v
				return nil
			}
			return controlplane.ErrConflict
		}
		if v.State != controlplane.GitPullRequestOpen || !gitops.IsFullCommitSHA(approvedHeadCommitSHA) || approvedHeadCommitSHA != v.CandidateCommitSHA {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.Revision++
		v.State = controlplane.GitPullRequestApproved
		v.ApprovedHeadCommitSHA = approvedHeadCommitSHA
		v.ApprovedBy = strings.TrimSpace(actor)
		v.ApprovedAt = &now
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE git_pull_requests SET revision=$2,state='APPROVED',approved_head_commit_sha=$3,approved_by=$4,approved_at=$5,updated_at=$5 WHERE id=$1`, v.ID, v.Revision, v.ApprovedHeadCommitSHA, v.ApprovedBy, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_pull_request.approved", "gitPullRequest", v.ID, v.Revision, "", map[string]any{"externalNumber": v.ExternalNumber, "revisionId": v.RevisionID, "approvedHeadCommitSha": approvedHeadCommitSHA}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitPullRequest", v.ID, "git_pull_request.approved", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func normalizeManagedForTx(v controlplane.ManagedGitRevision) (controlplane.ManagedGitRevision, error) {
	v.Organization = strings.ToLower(strings.TrimSpace(v.Organization))
	v.Repository = strings.ToLower(strings.TrimSpace(v.Repository))
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
		v.Source = "PLATFORM_PR_MERGED"
	}
	v.PullRequestID = strings.TrimSpace(v.PullRequestID)
	if v.Organization == "" || v.Repository == "" || v.RevisionID == "" || !strings.HasPrefix(v.Digest, "sha256:") || !gitops.IsFullCommitSHA(v.CommitSHA) || !strings.HasPrefix(v.PublicKeyFingerprint, "sha256:") || v.PullRequestID == "" {
		return controlplane.ManagedGitRevision{}, controlplane.ErrValidation
	}
	v.DeliveryMode = controlplane.GitDeliveryPullRequest
	return v, nil
}

func (s *PostgresStore) CommitMergedGitPullRequest(ctx context.Context, id string, expected int64, commitSHA string, managed controlplane.ManagedGitRevision, actor string) (controlplane.GitPullRequest, controlplane.ManagedGitRevision, error) {
	var outPR controlplane.GitPullRequest
	var outManaged controlplane.ManagedGitRevision
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		pr, e := scanGitPullRequest(tx.QueryRowContext(ctx, `SELECT `+gitPullRequestColumns+` FROM git_pull_requests WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		commitSHA = strings.TrimSpace(commitSHA)
		if pr.Revision != expected {
			return controlplane.ErrConflict
		}
		if pr.State == controlplane.GitPullRequestMerged {
			if pr.MergedCommitSHA != commitSHA {
				return controlplane.ErrConflict
			}
			mr, e := scanManagedGitRevision(tx.QueryRowContext(ctx, `SELECT `+managedGitRevisionColumns+` FROM managed_git_revisions WHERE pull_request_id=$1 AND commit_sha=$2 FOR SHARE`, pr.ID, commitSHA))
			if e != nil {
				return mapDBError(e)
			}
			outPR, outManaged = pr, mr
			return nil
		}
		if pr.State != controlplane.GitPullRequestApproved || pr.ApprovedHeadCommitSHA == "" || pr.ApprovedHeadCommitSHA != pr.CandidateCommitSHA || !gitops.IsFullCommitSHA(commitSHA) {
			return controlplane.ErrInvalidTransition
		}
		managed.Organization, managed.Repository, managed.Branch = pr.Organization, pr.Repository, pr.BaseBranch
		managed.RevisionID, managed.Digest, managed.CommitSHA, managed.PublicKeyFingerprint = pr.RevisionID, pr.Digest, commitSHA, pr.PublicKeyFingerprint
		managed.PullRequestID = pr.ID
		managed, e = normalizeManagedForTx(managed)
		if e != nil {
			return e
		}
		existing, e := scanManagedGitRevision(tx.QueryRowContext(ctx, `SELECT `+managedGitRevisionColumns+` FROM managed_git_revisions WHERE organization=$1 AND repository=$2 AND branch=$3 AND commit_sha=$4 FOR SHARE`, managed.Organization, managed.Repository, managed.Branch, managed.CommitSHA))
		if e == nil {
			if existing.Digest != managed.Digest || existing.RevisionID != managed.RevisionID || existing.PublicKeyFingerprint != managed.PublicKeyFingerprint || existing.PullRequestID != pr.ID {
				return controlplane.ErrConflict
			}
			outManaged = existing
		} else if e == sql.ErrNoRows {
			now := utcNow(s.now)
			managed.ResourceMeta = controlplane.ResourceMeta{ID: s.id("gtr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
			managed.RecordedBy = strings.TrimSpace(actor)
			_, e = tx.ExecContext(ctx, `INSERT INTO managed_git_revisions(id,revision,organization,repository,branch,revision_id,digest,commit_sha,public_key_fingerprint,source,delivery_mode,pull_request_id,sync_healthy,observed_digest,last_known_good,last_known_good_at,recorded_by,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,'PULL_REQUEST',$10,false,'',false,NULL,$11,$12,$12)`, managed.ID, managed.Organization, managed.Repository, managed.Branch, managed.RevisionID, managed.Digest, managed.CommitSHA, managed.PublicKeyFingerprint, managed.Source, managed.PullRequestID, managed.RecordedBy, now)
			if e != nil {
				return mapDBError(e)
			}
			if e = s.appendAuditTx(ctx, tx, actor, "git_revision.recorded", "managedGitRevision", managed.ID, 1, "", map[string]any{"organization": managed.Organization, "repository": managed.Repository, "branch": managed.Branch, "commitSha": managed.CommitSHA, "source": managed.Source, "deliveryMode": managed.DeliveryMode, "pullRequestId": managed.PullRequestID}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "managedGitRevision", managed.ID, "git_revision.recorded", managed); e != nil {
				return e
			}
			outManaged = managed
		} else {
			return e
		}
		now := utcNow(s.now)
		pr.Revision++
		pr.State = controlplane.GitPullRequestMerged
		pr.MergedBy = strings.TrimSpace(actor)
		pr.MergedAt = &now
		pr.MergedCommitSHA = commitSHA
		pr.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE git_pull_requests SET revision=$2,state='MERGED',merged_by=$3,merged_at=$4,merged_commit_sha=$5,updated_at=$4 WHERE id=$1`, pr.ID, pr.Revision, pr.MergedBy, now, commitSHA)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_pull_request.merged", "gitPullRequest", pr.ID, pr.Revision, "", map[string]any{"externalNumber": pr.ExternalNumber, "revisionId": pr.RevisionID, "commitSha": commitSHA}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitPullRequest", pr.ID, "git_pull_request.merged", pr); e != nil {
			return e
		}
		outPR = pr
		return nil
	})
	return outPR, outManaged, err
}

func itoa(v int) string {
	if v == 1 {
		return "1"
	}
	if v == 2 {
		return "2"
	}
	if v == 3 {
		return "3"
	}
	return "4"
}
