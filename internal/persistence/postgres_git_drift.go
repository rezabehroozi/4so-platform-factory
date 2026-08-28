package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/gitops"
)

const managedGitRevisionColumns = `id,revision,organization,repository,branch,revision_id,digest,commit_sha,public_key_fingerprint,source,delivery_mode,COALESCE(pull_request_id,''),sync_healthy,observed_digest,last_known_good,last_known_good_at,recorded_by,created_at,updated_at`

func scanManagedGitRevision(row interface{ Scan(...any) error }) (controlplane.ManagedGitRevision, error) {
	var v controlplane.ManagedGitRevision
	err := row.Scan(&v.ID, &v.Revision, &v.Organization, &v.Repository, &v.Branch, &v.RevisionID, &v.Digest, &v.CommitSHA, &v.PublicKeyFingerprint, &v.Source, &v.DeliveryMode, &v.PullRequestID, &v.SyncHealthy, &v.ObservedDigest, &v.LastKnownGood, &v.LastKnownGoodAt, &v.RecordedBy, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func (s *PostgresStore) RecordManagedGitRevision(ctx context.Context, v controlplane.ManagedGitRevision, actor string) (controlplane.ManagedGitRevision, error) {
	var out controlplane.ManagedGitRevision
	err := s.serializable(ctx, func(tx *sql.Tx) error {
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
			v.Source = "PLATFORM_PUBLISHED"
		}
		if v.DeliveryMode == "" {
			v.DeliveryMode = controlplane.GitDeliveryDirectCommit
		}
		v.PullRequestID = strings.TrimSpace(v.PullRequestID)
		v.ObservedDigest = strings.TrimSpace(v.ObservedDigest)
		if v.DeliveryMode != controlplane.GitDeliveryDirectCommit && v.DeliveryMode != controlplane.GitDeliveryPullRequest {
			return controlplane.ErrValidation
		}
		if v.DeliveryMode == controlplane.GitDeliveryPullRequest && v.PullRequestID == "" {
			return controlplane.ErrValidation
		}
		if v.Organization == "" || v.Repository == "" || v.RevisionID == "" || !strings.HasPrefix(v.Digest, "sha256:") || !gitops.IsFullCommitSHA(v.CommitSHA) || !strings.HasPrefix(v.PublicKeyFingerprint, "sha256:") {
			return controlplane.ErrValidation
		}
		existing, e := scanManagedGitRevision(tx.QueryRowContext(ctx, `SELECT `+managedGitRevisionColumns+` FROM managed_git_revisions WHERE organization=$1 AND repository=$2 AND branch=$3 AND commit_sha=$4 FOR SHARE`, v.Organization, v.Repository, v.Branch, v.CommitSHA))
		if e == nil {
			if existing.Digest != v.Digest || existing.RevisionID != v.RevisionID || existing.PublicKeyFingerprint != v.PublicKeyFingerprint {
				return controlplane.ErrConflict
			}
			out = existing
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("gtr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.RecordedBy = strings.TrimSpace(actor)
		if _, e = tx.ExecContext(ctx, `INSERT INTO managed_git_revisions(id,revision,organization,repository,branch,revision_id,digest,commit_sha,public_key_fingerprint,source,delivery_mode,pull_request_id,sync_healthy,observed_digest,last_known_good,last_known_good_at,recorded_by,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),$12,$13,$14,$15,$16,$17,$17)`, v.ID, v.Organization, v.Repository, v.Branch, v.RevisionID, v.Digest, v.CommitSHA, v.PublicKeyFingerprint, v.Source, v.DeliveryMode, v.PullRequestID, v.SyncHealthy, v.ObservedDigest, v.LastKnownGood, v.LastKnownGoodAt, v.RecordedBy, now); e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_revision.recorded", "managedGitRevision", v.ID, v.Revision, "", map[string]any{"organization": v.Organization, "repository": v.Repository, "branch": v.Branch, "commitSha": v.CommitSHA, "source": v.Source, "deliveryMode": v.DeliveryMode, "pullRequestId": v.PullRequestID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "managedGitRevision", v.ID, "git_revision.recorded", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) GetManagedGitRevision(ctx context.Context, id string) (controlplane.ManagedGitRevision, error) {
	v, e := scanManagedGitRevision(s.db.QueryRowContext(ctx, `SELECT `+managedGitRevisionColumns+` FROM managed_git_revisions WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(e)
}

func (s *PostgresStore) GetLatestManagedGitRevision(ctx context.Context, organization, repository, branch string) (controlplane.ManagedGitRevision, error) {
	organization = strings.ToLower(strings.TrimSpace(organization))
	repository = strings.ToLower(strings.TrimSpace(repository))
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	v, e := scanManagedGitRevision(s.db.QueryRowContext(ctx, `SELECT `+managedGitRevisionColumns+` FROM managed_git_revisions WHERE organization=$1 AND repository=$2 AND branch=$3 ORDER BY created_at DESC,id DESC LIMIT 1`, organization, repository, branch))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListManagedGitRevisions(ctx context.Context, organization, repository string) ([]controlplane.ManagedGitRevision, error) {
	q := `SELECT ` + managedGitRevisionColumns + ` FROM managed_git_revisions WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(organization) != "" {
		args = append(args, strings.ToLower(strings.TrimSpace(organization)))
		q += ` AND organization=$1`
	}
	if strings.TrimSpace(repository) != "" {
		args = append(args, strings.ToLower(strings.TrimSpace(repository)))
		q += fmt.Sprintf(` AND repository=$%d`, len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.ManagedGitRevision{}
	for rows.Next() {
		v, e := scanManagedGitRevision(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetLastKnownGoodGitRevision(ctx context.Context, organization, repository, branch string) (controlplane.ManagedGitRevision, error) {
	organization = strings.ToLower(strings.TrimSpace(organization))
	repository = strings.ToLower(strings.TrimSpace(repository))
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	v, e := scanManagedGitRevision(s.db.QueryRowContext(ctx, `SELECT `+managedGitRevisionColumns+` FROM managed_git_revisions WHERE organization=$1 AND repository=$2 AND branch=$3 AND last_known_good=true LIMIT 1`, organization, repository, branch))
	return v, mapDBError(e)
}

func (s *PostgresStore) MarkManagedGitRevisionSynchronized(ctx context.Context, id string, expected int64, observedDigest string, healthy bool, actor string) (controlplane.ManagedGitRevision, error) {
	var out controlplane.ManagedGitRevision
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanManagedGitRevision(tx.QueryRowContext(ctx, `SELECT `+managedGitRevisionColumns+` FROM managed_git_revisions WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		observedDigest = strings.TrimSpace(observedDigest)
		if !healthy || observedDigest == "" || observedDigest != v.Digest {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		if _, e = tx.ExecContext(ctx, `UPDATE managed_git_revisions SET revision=revision+1,last_known_good=false,updated_at=$4 WHERE organization=$1 AND repository=$2 AND branch=$3 AND last_known_good=true AND id<>$5`, v.Organization, v.Repository, v.Branch, now, v.ID); e != nil {
			return e
		}
		v.Revision++
		v.SyncHealthy = true
		v.ObservedDigest = observedDigest
		v.LastKnownGood = true
		v.LastKnownGoodAt = &now
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE managed_git_revisions SET revision=$2,sync_healthy=true,observed_digest=$3,last_known_good=true,last_known_good_at=$4,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, observedDigest, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_revision.last_known_good", "managedGitRevision", v.ID, v.Revision, "", map[string]any{"organization": v.Organization, "repository": v.Repository, "branch": v.Branch, "commitSha": v.CommitSHA, "digest": v.Digest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "managedGitRevision", v.ID, "git_revision.last_known_good", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
