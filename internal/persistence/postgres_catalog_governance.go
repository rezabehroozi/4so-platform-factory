package persistence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const catalogTrustKeyColumns = `id,COALESCE(organization_id,''),revision,name,algorithm,public_key,fingerprint,state,created_by,COALESCE(revoked_by,''),revoked_at,created_at,updated_at`
const catalogRevisionColumns = `id,COALESCE(organization_id,''),revision,catalog_name,catalog_version,manifest_digest,payload,created_at,updated_at`
const catalogReleaseColumns = `id,COALESCE(organization_id,''),revision,catalog_name,catalog_version,visibility,state,channel,current_revision_id,manifest_digest,COALESCE(source_release_id,''),COALESCE(signing_key_id,''),COALESCE(signing_key_fingerprint,''),COALESCE(signature,''),requested_by,review_requested_at,COALESCE(published_by,''),published_at,COALESCE(deprecated_by,''),deprecated_at,COALESCE(revoked_by,''),revoked_at,created_at,updated_at`

func scanCatalogTrustKey(row interface{ Scan(...any) error }) (controlplane.CatalogTrustKey, error) {
	var value controlplane.CatalogTrustKey
	var state string
	err := row.Scan(&value.ID, &value.OrganizationID, &value.Revision, &value.Name, &value.Algorithm, &value.PublicKey, &value.Fingerprint, &state, &value.CreatedBy, &value.RevokedBy, &value.RevokedAt, &value.CreatedAt, &value.UpdatedAt)
	value.State = controlplane.CatalogTrustKeyState(state)
	return value, err
}

func scanCatalogRevision(row interface{ Scan(...any) error }) (controlplane.CatalogRevision, error) {
	var value controlplane.CatalogRevision
	err := row.Scan(&value.ID, &value.OrganizationID, &value.Revision, &value.CatalogName, &value.CatalogVersion, &value.ManifestDigest, &value.Payload, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

func scanCatalogRelease(row interface{ Scan(...any) error }) (controlplane.CatalogRelease, error) {
	var value controlplane.CatalogRelease
	var visibility, state, channel string
	err := row.Scan(
		&value.ID, &value.OrganizationID, &value.Revision, &value.CatalogName, &value.CatalogVersion, &visibility, &state, &channel,
		&value.CurrentRevisionID, &value.ManifestDigest, &value.SourceReleaseID, &value.SigningKeyID, &value.SigningKeyFingerprint, &value.Signature,
		&value.RequestedBy, &value.ReviewRequestedAt, &value.PublishedBy, &value.PublishedAt, &value.DeprecatedBy, &value.DeprecatedAt, &value.RevokedBy, &value.RevokedAt, &value.CreatedAt, &value.UpdatedAt,
	)
	value.Visibility = controlplane.CatalogVisibility(visibility)
	value.State = controlplane.CatalogLifecycleState(state)
	value.Channel = controlplane.CatalogChannel(channel)
	return value, err
}

func postgresPayloadDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func nextCatalogChannelDB(channel controlplane.CatalogChannel) controlplane.CatalogChannel {
	switch channel {
	case controlplane.CatalogChannelCandidate:
		return controlplane.CatalogChannelRender
	case controlplane.CatalogChannelRender:
		return controlplane.CatalogChannelRuntime
	case controlplane.CatalogChannelRuntime:
		return controlplane.CatalogChannelProduction
	default:
		return ""
	}
}

func validCatalogTransitionDB(from, to controlplane.CatalogLifecycleState) bool {
	switch from {
	case controlplane.CatalogDraft:
		return to == controlplane.CatalogReview
	case controlplane.CatalogReview:
		return to == controlplane.CatalogDraft || to == controlplane.CatalogPublished
	case controlplane.CatalogPublished:
		return to == controlplane.CatalogDeprecated || to == controlplane.CatalogRevoked
	case controlplane.CatalogDeprecated:
		return to == controlplane.CatalogRevoked
	default:
		return false
	}
}

func (s *PostgresStore) CreateCatalogTrustKey(ctx context.Context, key controlplane.CatalogTrustKey, actor string) (controlplane.CatalogTrustKey, error) {
	key.OrganizationID = strings.TrimSpace(key.OrganizationID)
	key.Name = normalizedName(key.Name)
	if key.Name == "" || strings.TrimSpace(actor) == "" {
		return controlplane.CatalogTrustKey{}, fmt.Errorf("%w: trust key name and actor are required", controlplane.ErrValidation)
	}
	fingerprint, err := controlplane.CatalogKeyFingerprint(key.PublicKey)
	if err != nil {
		return controlplane.CatalogTrustKey{}, err
	}
	key.Algorithm, key.Fingerprint, key.State, key.CreatedBy = "Ed25519", fingerprint, controlplane.CatalogTrustKeyActive, strings.TrimSpace(actor)
	now := utcNow(s.now)
	key.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ctk"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var org any
		if key.OrganizationID != "" {
			org = key.OrganizationID
		}
		created, scanErr := scanCatalogTrustKey(tx.QueryRowContext(ctx, `INSERT INTO catalog_trust_keys(id,organization_id,revision,name,algorithm,public_key,fingerprint,state,created_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING `+catalogTrustKeyColumns, key.ID, org, key.Name, key.Algorithm, key.PublicKey, key.Fingerprint, string(key.State), key.CreatedBy, now))
		if scanErr != nil {
			return mapDBError(scanErr)
		}
		key = created
		if err := s.appendAuditTx(ctx, tx, actor, "catalog_trust_key.created", "catalogTrustKey", key.ID, 1, "", map[string]any{"organizationId": key.OrganizationID, "fingerprint": key.Fingerprint}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "catalogTrustKey", key.ID, "catalog_trust_key.created", key)
	})
	return key, err
}

func (s *PostgresStore) GetCatalogTrustKey(ctx context.Context, id string) (controlplane.CatalogTrustKey, error) {
	value, err := scanCatalogTrustKey(s.db.QueryRowContext(ctx, `SELECT `+catalogTrustKeyColumns+` FROM catalog_trust_keys WHERE id=$1`, id))
	return value, mapDBError(err)
}

func (s *PostgresStore) ListCatalogTrustKeys(ctx context.Context, organizationID string) ([]controlplane.CatalogTrustKey, error) {
	query := `SELECT ` + catalogTrustKeyColumns + ` FROM catalog_trust_keys`
	args := []any{}
	if strings.TrimSpace(organizationID) != "" {
		query += ` WHERE organization_id=$1`
		args = append(args, strings.TrimSpace(organizationID))
	}
	query += ` ORDER BY COALESCE(organization_id,''),name,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.CatalogTrustKey{}
	for rows.Next() {
		value, scanErr := scanCatalogTrustKey(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeCatalogTrustKey(ctx context.Context, id string, expected int64, actor string) (controlplane.CatalogTrustKey, error) {
	var updated controlplane.CatalogTrustKey
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanCatalogTrustKey(tx.QueryRowContext(ctx, `SELECT `+catalogTrustKeyColumns+` FROM catalog_trust_keys WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if current.State == controlplane.CatalogTrustKeyRevoked {
			updated = current
			return nil
		}
		now := utcNow(s.now)
		current.State, current.RevokedBy, current.RevokedAt = controlplane.CatalogTrustKeyRevoked, strings.TrimSpace(actor), &now
		current.Revision++
		current.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE catalog_trust_keys SET revision=$2,state='REVOKED',revoked_by=NULLIF($3,''),revoked_at=$4,updated_at=$4 WHERE id=$1 AND revision=$5`, id, current.Revision, current.RevokedBy, now, expected); err != nil {
			return mapDBError(err)
		}
		if err = s.appendAuditTx(ctx, tx, actor, "catalog_trust_key.revoked", "catalogTrustKey", id, current.Revision, "", map[string]any{"fingerprint": current.Fingerprint}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "catalogTrustKey", id, "catalog_trust_key.revoked", current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}

func prepareCatalogRevisionDB(revision controlplane.CatalogRevision) (controlplane.CatalogRevision, error) {
	revision.OrganizationID = strings.TrimSpace(revision.OrganizationID)
	revision.CatalogName = normalizedName(revision.CatalogName)
	revision.CatalogVersion = strings.TrimSpace(revision.CatalogVersion)
	if revision.CatalogName == "" || revision.CatalogVersion == "" || !json.Valid(revision.Payload) || postgresPayloadDigest(revision.Payload) != strings.TrimSpace(revision.ManifestDigest) {
		return controlplane.CatalogRevision{}, fmt.Errorf("%w: catalog revision identity, JSON payload and matching sha256 digest are required", controlplane.ErrValidation)
	}
	return revision, nil
}

func (s *PostgresStore) createCatalogRevisionTx(ctx context.Context, tx *sql.Tx, revision controlplane.CatalogRevision, actor string) (controlplane.CatalogRevision, bool, error) {
	var org any
	if revision.OrganizationID != "" {
		org = revision.OrganizationID
	}
	existing, scanErr := scanCatalogRevision(tx.QueryRowContext(ctx, `SELECT `+catalogRevisionColumns+` FROM catalog_revisions WHERE COALESCE(organization_id,'')=$1 AND lower(catalog_name)=$2 AND catalog_version=$3 AND manifest_digest=$4`, revision.OrganizationID, revision.CatalogName, revision.CatalogVersion, revision.ManifestDigest))
	if scanErr == nil {
		return existing, false, nil
	}
	if scanErr != sql.ErrNoRows {
		return controlplane.CatalogRevision{}, false, mapDBError(scanErr)
	}
	now := utcNow(s.now)
	revision.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ctr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := tx.ExecContext(ctx, `INSERT INTO catalog_revisions(id,organization_id,revision,catalog_name,catalog_version,manifest_digest,payload,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6::jsonb,$7,$7)`, revision.ID, org, revision.CatalogName, revision.CatalogVersion, revision.ManifestDigest, revision.Payload, now); err != nil {
		return controlplane.CatalogRevision{}, false, mapDBError(err)
	}
	if err := s.appendAuditTx(ctx, tx, actor, "catalog_revision.created", "catalogRevision", revision.ID, 1, "", map[string]any{"organizationId": revision.OrganizationID, "manifestDigest": revision.ManifestDigest}); err != nil {
		return controlplane.CatalogRevision{}, false, err
	}
	if err := s.appendOutboxTx(ctx, tx, "catalogRevision", revision.ID, "catalog_revision.created", revision); err != nil {
		return controlplane.CatalogRevision{}, false, err
	}
	return revision, true, nil
}

func (s *PostgresStore) CreateCatalogRevision(ctx context.Context, revision controlplane.CatalogRevision, actor string) (controlplane.CatalogRevision, error) {
	prepared, err := prepareCatalogRevisionDB(revision)
	if err != nil {
		return controlplane.CatalogRevision{}, err
	}
	var created controlplane.CatalogRevision
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		created, _, e = s.createCatalogRevisionTx(ctx, tx, prepared, actor)
		return e
	})
	return created, err
}

func (s *PostgresStore) GetCatalogRevision(ctx context.Context, id string) (controlplane.CatalogRevision, error) {
	value, err := scanCatalogRevision(s.db.QueryRowContext(ctx, `SELECT `+catalogRevisionColumns+` FROM catalog_revisions WHERE id=$1`, id))
	return value, mapDBError(err)
}

func validateCatalogReleaseIdentityDB(release controlplane.CatalogRelease) error {
	if normalizedName(release.CatalogName) == "" || strings.TrimSpace(release.CatalogVersion) == "" || strings.TrimSpace(release.CurrentRevisionID) == "" || !strings.HasPrefix(strings.TrimSpace(release.ManifestDigest), "sha256:") {
		return fmt.Errorf("%w: catalog release identity, revision and sha256 digest are required", controlplane.ErrValidation)
	}
	if release.Visibility == controlplane.CatalogVisibilityPrivate && strings.TrimSpace(release.OrganizationID) == "" {
		return fmt.Errorf("%w: private catalog requires organizationId", controlplane.ErrValidation)
	}
	if release.Visibility == controlplane.CatalogVisibilityPlatform && strings.TrimSpace(release.OrganizationID) != "" {
		return fmt.Errorf("%w: platform catalog cannot have organizationId", controlplane.ErrValidation)
	}
	if release.Visibility != controlplane.CatalogVisibilityPrivate && release.Visibility != controlplane.CatalogVisibilityPlatform {
		return fmt.Errorf("%w: invalid catalog visibility", controlplane.ErrValidation)
	}
	switch release.Channel {
	case controlplane.CatalogChannelCandidate, controlplane.CatalogChannelRender, controlplane.CatalogChannelRuntime, controlplane.CatalogChannelProduction:
	default:
		return fmt.Errorf("%w: invalid catalog channel", controlplane.ErrValidation)
	}
	return nil
}

func validateCatalogPromotionTx(ctx context.Context, tx *sql.Tx, release controlplane.CatalogRelease) error {
	if strings.TrimSpace(release.SourceReleaseID) == "" {
		return nil
	}
	source, err := scanCatalogRelease(tx.QueryRowContext(ctx, `SELECT `+catalogReleaseColumns+` FROM catalog_releases WHERE id=$1`, release.SourceReleaseID))
	if err != nil {
		return mapDBError(err)
	}
	if source.OrganizationID != release.OrganizationID || normalizedName(source.CatalogName) != normalizedName(release.CatalogName) || source.CatalogVersion != release.CatalogVersion || (source.State != controlplane.CatalogPublished && source.State != controlplane.CatalogDeprecated) || nextCatalogChannelDB(source.Channel) != release.Channel || source.ManifestDigest != release.ManifestDigest {
		return fmt.Errorf("%w: promotion source must be previous published/deprecated channel with the same manifest", controlplane.ErrValidation)
	}
	return nil
}

func prepareCatalogReleaseDB(release controlplane.CatalogRelease) (controlplane.CatalogRelease, error) {
	release.OrganizationID = strings.TrimSpace(release.OrganizationID)
	release.CatalogName = normalizedName(release.CatalogName)
	release.CatalogVersion = strings.TrimSpace(release.CatalogVersion)
	release.SourceReleaseID = strings.TrimSpace(release.SourceReleaseID)
	if err := validateCatalogReleaseIdentityDB(release); err != nil {
		return controlplane.CatalogRelease{}, err
	}
	return release, nil
}

func (s *PostgresStore) createCatalogReleaseTx(ctx context.Context, tx *sql.Tx, release controlplane.CatalogRelease, actor string) (controlplane.CatalogRelease, error) {
	revision, err := scanCatalogRevision(tx.QueryRowContext(ctx, `SELECT `+catalogRevisionColumns+` FROM catalog_revisions WHERE id=$1`, release.CurrentRevisionID))
	if err != nil {
		return controlplane.CatalogRelease{}, mapDBError(err)
	}
	if revision.OrganizationID != release.OrganizationID || normalizedName(revision.CatalogName) != release.CatalogName || revision.CatalogVersion != release.CatalogVersion || revision.ManifestDigest != release.ManifestDigest {
		return controlplane.CatalogRelease{}, fmt.Errorf("%w: catalog revision does not match release identity", controlplane.ErrValidation)
	}
	if err = validateCatalogPromotionTx(ctx, tx, release); err != nil {
		return controlplane.CatalogRelease{}, err
	}
	now := utcNow(s.now)
	release.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ctl"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	release.State = controlplane.CatalogDraft
	release.RequestedBy = strings.TrimSpace(actor)
	var org, source any
	if release.OrganizationID != "" {
		org = release.OrganizationID
	}
	if release.SourceReleaseID != "" {
		source = release.SourceReleaseID
	}
	createdRow, err := scanCatalogRelease(tx.QueryRowContext(ctx, `INSERT INTO catalog_releases(id,organization_id,revision,catalog_name,catalog_version,visibility,channel,state,current_revision_id,manifest_digest,source_release_id,requested_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,'DRAFT',$7,$8,$9,$10,$11,$11) RETURNING `+catalogReleaseColumns, release.ID, org, release.CatalogName, release.CatalogVersion, string(release.Visibility), string(release.Channel), release.CurrentRevisionID, release.ManifestDigest, source, release.RequestedBy, now))
	if err != nil {
		return controlplane.CatalogRelease{}, mapDBError(err)
	}
	release = createdRow
	if err = s.appendAuditTx(ctx, tx, actor, "catalog_release.created", "catalogRelease", release.ID, 1, "", map[string]any{"organizationId": release.OrganizationID, "channel": release.Channel, "manifestDigest": release.ManifestDigest}); err != nil {
		return controlplane.CatalogRelease{}, err
	}
	if err = s.appendOutboxTx(ctx, tx, "catalogRelease", release.ID, "catalog_release.created", release); err != nil {
		return controlplane.CatalogRelease{}, err
	}
	return release, nil
}

func (s *PostgresStore) CreateCatalogRelease(ctx context.Context, release controlplane.CatalogRelease, actor string) (controlplane.CatalogRelease, error) {
	prepared, err := prepareCatalogReleaseDB(release)
	if err != nil {
		return controlplane.CatalogRelease{}, err
	}
	var created controlplane.CatalogRelease
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		created, e = s.createCatalogReleaseTx(ctx, tx, prepared, actor)
		return e
	})
	return created, err
}

func (s *PostgresStore) CreateCatalogReleaseWithRevision(ctx context.Context, revision controlplane.CatalogRevision, release controlplane.CatalogRelease, actor string) (controlplane.CatalogRevision, controlplane.CatalogRelease, error) {
	preparedRevision, err := prepareCatalogRevisionDB(revision)
	if err != nil {
		return controlplane.CatalogRevision{}, controlplane.CatalogRelease{}, err
	}
	var createdRevision controlplane.CatalogRevision
	var createdRelease controlplane.CatalogRelease
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		createdRevision, _, e = s.createCatalogRevisionTx(ctx, tx, preparedRevision, actor)
		if e != nil {
			return e
		}
		release.OrganizationID = createdRevision.OrganizationID
		release.CatalogName = createdRevision.CatalogName
		release.CatalogVersion = createdRevision.CatalogVersion
		release.CurrentRevisionID = createdRevision.ID
		release.ManifestDigest = createdRevision.ManifestDigest
		preparedRelease, e := prepareCatalogReleaseDB(release)
		if e != nil {
			return e
		}
		createdRelease, e = s.createCatalogReleaseTx(ctx, tx, preparedRelease, actor)
		return e
	})
	return createdRevision, createdRelease, err
}

func (s *PostgresStore) GetCatalogRelease(ctx context.Context, id string) (controlplane.CatalogRelease, error) {
	value, err := scanCatalogRelease(s.db.QueryRowContext(ctx, `SELECT `+catalogReleaseColumns+` FROM catalog_releases WHERE id=$1`, id))
	return value, mapDBError(err)
}

func (s *PostgresStore) ListCatalogReleases(ctx context.Context, organizationID string) ([]controlplane.CatalogRelease, error) {
	query := `SELECT ` + catalogReleaseColumns + ` FROM catalog_releases`
	args := []any{}
	if strings.TrimSpace(organizationID) != "" {
		query += ` WHERE organization_id=$1`
		args = append(args, strings.TrimSpace(organizationID))
	}
	query += ` ORDER BY COALESCE(organization_id,''),catalog_name,catalog_version,channel,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.CatalogRelease{}
	for rows.Next() {
		v, e := scanCatalogRelease(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateCatalogReleaseDraft(ctx context.Context, id string, expected int64, revisionID, manifestDigest, actor string) (controlplane.CatalogRelease, error) {
	var updated controlplane.CatalogRelease
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanCatalogRelease(tx.QueryRowContext(ctx, `SELECT `+catalogReleaseColumns+` FROM catalog_releases WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if current.State != controlplane.CatalogDraft {
			return controlplane.ErrImmutable
		}
		revision, err := scanCatalogRevision(tx.QueryRowContext(ctx, `SELECT `+catalogRevisionColumns+` FROM catalog_revisions WHERE id=$1`, revisionID))
		if err != nil {
			return mapDBError(err)
		}
		if revision.OrganizationID != current.OrganizationID || normalizedName(revision.CatalogName) != normalizedName(current.CatalogName) || revision.CatalogVersion != current.CatalogVersion || revision.ManifestDigest != manifestDigest {
			return fmt.Errorf("%w: draft catalog revision does not match release identity", controlplane.ErrValidation)
		}
		current.CurrentRevisionID = revisionID
		current.ManifestDigest = manifestDigest
		current.SigningKeyID = ""
		current.SigningKeyFingerprint = ""
		current.Signature = ""
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if _, err = tx.ExecContext(ctx, `UPDATE catalog_releases SET revision=$2,current_revision_id=$3,manifest_digest=$4,signing_key_id=NULL,signing_key_fingerprint=NULL,signature=NULL,updated_at=$5 WHERE id=$1 AND revision=$6`, id, current.Revision, revisionID, manifestDigest, current.UpdatedAt, expected); err != nil {
			return mapDBError(err)
		}
		if err = s.appendAuditTx(ctx, tx, actor, "catalog_release.draft_updated", "catalogRelease", id, current.Revision, "", map[string]any{"revisionId": revisionID, "manifestDigest": manifestDigest}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "catalogRelease", id, "catalog_release.draft_updated", current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}

func (s *PostgresStore) UpdateCatalogReleaseDraftWithRevision(ctx context.Context, id string, expected int64, revision controlplane.CatalogRevision, actor string) (controlplane.CatalogRevision, controlplane.CatalogRelease, error) {
	preparedRevision, err := prepareCatalogRevisionDB(revision)
	if err != nil {
		return controlplane.CatalogRevision{}, controlplane.CatalogRelease{}, err
	}
	var createdRevision controlplane.CatalogRevision
	var updated controlplane.CatalogRelease
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		current, e := scanCatalogRelease(tx.QueryRowContext(ctx, `SELECT `+catalogReleaseColumns+` FROM catalog_releases WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if current.State != controlplane.CatalogDraft {
			return controlplane.ErrImmutable
		}
		createdRevision, _, e = s.createCatalogRevisionTx(ctx, tx, preparedRevision, actor)
		if e != nil {
			return e
		}
		if createdRevision.OrganizationID != current.OrganizationID || normalizedName(createdRevision.CatalogName) != normalizedName(current.CatalogName) || createdRevision.CatalogVersion != current.CatalogVersion {
			return fmt.Errorf("%w: draft catalog revision does not match release identity", controlplane.ErrValidation)
		}
		current.CurrentRevisionID = createdRevision.ID
		current.ManifestDigest = createdRevision.ManifestDigest
		current.SigningKeyID = ""
		current.SigningKeyFingerprint = ""
		current.Signature = ""
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if _, e = tx.ExecContext(ctx, `UPDATE catalog_releases SET revision=$2,current_revision_id=$3,manifest_digest=$4,signing_key_id=NULL,signing_key_fingerprint=NULL,signature=NULL,updated_at=$5 WHERE id=$1 AND revision=$6`, id, current.Revision, createdRevision.ID, createdRevision.ManifestDigest, current.UpdatedAt, expected); e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "catalog_release.draft_updated", "catalogRelease", id, current.Revision, "", map[string]any{"revisionId": createdRevision.ID, "manifestDigest": createdRevision.ManifestDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "catalogRelease", id, "catalog_release.draft_updated", current); e != nil {
			return e
		}
		updated = current
		return nil
	})
	return createdRevision, updated, err
}

func (s *PostgresStore) SubmitCatalogReleaseReview(ctx context.Context, id string, expected int64, keyID, fingerprint, signature, actor string) (controlplane.CatalogRelease, error) {
	var updated controlplane.CatalogRelease
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanCatalogRelease(tx.QueryRowContext(ctx, `SELECT `+catalogReleaseColumns+` FROM catalog_releases WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if current.State != controlplane.CatalogDraft {
			return controlplane.ErrInvalidTransition
		}
		key, err := scanCatalogTrustKey(tx.QueryRowContext(ctx, `SELECT `+catalogTrustKeyColumns+` FROM catalog_trust_keys WHERE id=$1`, strings.TrimSpace(keyID)))
		if err != nil {
			return mapDBError(err)
		}
		current.SigningKeyID = strings.TrimSpace(keyID)
		current.SigningKeyFingerprint = strings.TrimSpace(fingerprint)
		current.Signature = strings.TrimSpace(signature)
		if err = controlplane.VerifyCatalogReleaseSignature(current, key); err != nil {
			return err
		}
		now := utcNow(s.now)
		current.State = controlplane.CatalogReview
		current.RequestedBy = strings.TrimSpace(actor)
		current.ReviewRequestedAt = &now
		current.Revision++
		current.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE catalog_releases SET revision=$2,state='REVIEW',signing_key_id=$3,signing_key_fingerprint=$4,signature=$5,requested_by=$6,review_requested_at=$7,updated_at=$7 WHERE id=$1 AND revision=$8`, id, current.Revision, current.SigningKeyID, current.SigningKeyFingerprint, current.Signature, current.RequestedBy, now, expected); err != nil {
			return mapDBError(err)
		}
		if err = s.appendAuditTx(ctx, tx, actor, "catalog_release.review", "catalogRelease", id, current.Revision, "", map[string]any{"signingKeyId": key.ID, "fingerprint": key.Fingerprint}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "catalogRelease", id, "catalog_release.review", current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}

func (s *PostgresStore) TransitionCatalogRelease(ctx context.Context, id string, expected int64, to controlplane.CatalogLifecycleState, actor string) (controlplane.CatalogRelease, error) {
	var updated controlplane.CatalogRelease
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanCatalogRelease(tx.QueryRowContext(ctx, `SELECT `+catalogReleaseColumns+` FROM catalog_releases WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if !validCatalogTransitionDB(current.State, to) {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		from := current.State
		if from == controlplane.CatalogReview && to == controlplane.CatalogDraft {
			current.ReviewRequestedAt = nil
			current.SigningKeyID = ""
			current.SigningKeyFingerprint = ""
			current.Signature = ""
		}
		if to == controlplane.CatalogPublished {
			key, err := scanCatalogTrustKey(tx.QueryRowContext(ctx, `SELECT `+catalogTrustKeyColumns+` FROM catalog_trust_keys WHERE id=$1`, current.SigningKeyID))
			if err != nil {
				return mapDBError(err)
			}
			if err = controlplane.VerifyCatalogReleaseSignature(current, key); err != nil {
				return err
			}
			current.PublishedBy = strings.TrimSpace(actor)
			current.PublishedAt = &now
		}
		if to == controlplane.CatalogDeprecated {
			current.DeprecatedBy = strings.TrimSpace(actor)
			current.DeprecatedAt = &now
		}
		if to == controlplane.CatalogRevoked {
			current.RevokedBy = strings.TrimSpace(actor)
			current.RevokedAt = &now
		}
		current.State = to
		current.Revision++
		current.UpdatedAt = now
		var keyID, keyFP, sig any
		if current.SigningKeyID != "" {
			keyID = current.SigningKeyID
			keyFP = current.SigningKeyFingerprint
			sig = current.Signature
		}
		if _, err = tx.ExecContext(ctx, `UPDATE catalog_releases SET revision=$2,state=$3,signing_key_id=$4,signing_key_fingerprint=$5,signature=$6,review_requested_at=$7,published_by=NULLIF($8,''),published_at=$9,deprecated_by=NULLIF($10,''),deprecated_at=$11,revoked_by=NULLIF($12,''),revoked_at=$13,updated_at=$14 WHERE id=$1 AND revision=$15`, id, current.Revision, string(current.State), keyID, keyFP, sig, current.ReviewRequestedAt, current.PublishedBy, current.PublishedAt, current.DeprecatedBy, current.DeprecatedAt, current.RevokedBy, current.RevokedAt, now, expected); err != nil {
			return mapDBError(err)
		}
		action := "catalog_release." + strings.ToLower(string(to))
		if err = s.appendAuditTx(ctx, tx, actor, action, "catalogRelease", id, current.Revision, "", map[string]any{"from": from, "to": to, "channel": current.Channel}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "catalogRelease", id, action, current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}
