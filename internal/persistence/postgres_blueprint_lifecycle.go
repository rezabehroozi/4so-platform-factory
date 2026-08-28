package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const blueprintReleaseColumns = `id,project_id,revision,blueprint_name,blueprint_version,state,current_revision_id,current_blueprint_digest,catalog_digest,COALESCE(catalog_release_id,''),COALESCE(source_release_id,''),upgrade_from_ids,execution_ready,plan_status,requested_by,review_requested_at,COALESCE(published_by,''),published_at,COALESCE(deprecated_by,''),deprecated_at,COALESCE(revoked_by,''),revoked_at,created_at,updated_at`

func scanBlueprintRelease(row interface{ Scan(...any) error }) (controlplane.BlueprintRelease, error) {
	var value controlplane.BlueprintRelease
	var state string
	var upgradeRaw []byte
	err := row.Scan(
		&value.ID, &value.ProjectID, &value.Revision, &value.BlueprintName, &value.BlueprintVersion, &state,
		&value.CurrentRevisionID, &value.CurrentBlueprintDigest, &value.CatalogDigest, &value.CatalogReleaseID, &value.SourceReleaseID,
		&upgradeRaw, &value.ExecutionReady, &value.PlanStatus, &value.RequestedBy, &value.ReviewRequestedAt,
		&value.PublishedBy, &value.PublishedAt, &value.DeprecatedBy, &value.DeprecatedAt, &value.RevokedBy, &value.RevokedAt,
		&value.CreatedAt, &value.UpdatedAt,
	)
	if err != nil {
		return value, err
	}
	value.State = controlplane.BlueprintLifecycleState(state)
	if len(upgradeRaw) != 0 {
		if err := json.Unmarshal(upgradeRaw, &value.UpgradeFromIDs); err != nil {
			return value, fmt.Errorf("decode blueprint upgrade edges: %w", err)
		}
	}
	return value, nil
}

func validateBlueprintReleaseIdentity(release controlplane.BlueprintRelease) error {
	if strings.TrimSpace(release.ProjectID) == "" || strings.TrimSpace(release.BlueprintName) == "" || strings.TrimSpace(release.BlueprintVersion) == "" || strings.TrimSpace(release.CurrentRevisionID) == "" || !strings.HasPrefix(release.CurrentBlueprintDigest, "sha256:") || !strings.HasPrefix(release.CatalogDigest, "sha256:") {
		return fmt.Errorf("%w: project, blueprint identity, immutable revision and sha256 digests are required", controlplane.ErrValidation)
	}
	return nil
}

func validateUpgradeSourcesTx(ctx context.Context, tx *sql.Tx, projectID, blueprintName, selfID string, ids []string) error {
	seen := map[string]bool{}
	for _, sourceID := range ids {
		sourceID = strings.TrimSpace(sourceID)
		if sourceID == "" || sourceID == selfID || seen[sourceID] {
			return fmt.Errorf("%w: upgradeFromIds must contain unique non-self release IDs", controlplane.ErrValidation)
		}
		seen[sourceID] = true
		var sourceProject, sourceName, sourceState string
		if err := tx.QueryRowContext(ctx, `SELECT project_id,blueprint_name,state FROM blueprint_releases WHERE id=$1`, sourceID).Scan(&sourceProject, &sourceName, &sourceState); err != nil {
			return mapDBError(err)
		}
		if sourceProject != projectID || normalizedName(sourceName) != normalizedName(blueprintName) || (sourceState != string(controlplane.BlueprintPublished) && sourceState != string(controlplane.BlueprintDeprecated)) {
			return fmt.Errorf("%w: upgrade source must be a published or deprecated release of the same blueprint", controlplane.ErrValidation)
		}
	}
	return nil
}

func validateBlueprintCatalogBindingTx(ctx context.Context, tx *sql.Tx, release controlplane.BlueprintRelease) error {
	if strings.TrimSpace(release.CatalogReleaseID) == "" {
		return nil
	}
	catalogRelease, err := scanCatalogRelease(tx.QueryRowContext(ctx, `SELECT `+catalogReleaseColumns+` FROM catalog_releases WHERE id=$1`, release.CatalogReleaseID))
	if err != nil {
		return mapDBError(err)
	}
	var projectOrg string
	if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1`, release.ProjectID).Scan(&projectOrg); err != nil {
		return mapDBError(err)
	}
	if catalogRelease.State != controlplane.CatalogPublished || catalogRelease.ManifestDigest != release.CatalogDigest || (catalogRelease.Visibility == controlplane.CatalogVisibilityPrivate && catalogRelease.OrganizationID != projectOrg) {
		return fmt.Errorf("%w: blueprint catalog release must be published, digest-matched and visible to the project", controlplane.ErrValidation)
	}
	key, err := scanCatalogTrustKey(tx.QueryRowContext(ctx, `SELECT `+catalogTrustKeyColumns+` FROM catalog_trust_keys WHERE id=$1`, catalogRelease.SigningKeyID))
	if err != nil {
		return mapDBError(err)
	}
	return controlplane.VerifyCatalogReleaseSignature(catalogRelease, key)
}

func prepareBlueprintReleaseDB(release controlplane.BlueprintRelease, actor string) (controlplane.BlueprintRelease, error) {
	if err := validateBlueprintReleaseIdentity(release); err != nil {
		return controlplane.BlueprintRelease{}, err
	}
	if strings.TrimSpace(actor) == "" {
		return controlplane.BlueprintRelease{}, fmt.Errorf("%w: actor is required", controlplane.ErrValidation)
	}
	return release, nil
}

func (s *PostgresStore) createBlueprintReleaseTx(ctx context.Context, tx *sql.Tx, release controlplane.BlueprintRelease, actor string) (controlplane.BlueprintRelease, error) {
	revision, err := scanBlueprintRevision(tx.QueryRowContext(ctx, `SELECT `+blueprintRevisionColumns+` FROM blueprint_revisions WHERE id=$1`, release.CurrentRevisionID))
	if err != nil {
		return controlplane.BlueprintRelease{}, mapDBError(err)
	}
	if revision.ProjectID != release.ProjectID || normalizedName(revision.BlueprintName) != normalizedName(release.BlueprintName) || revision.BlueprintVersion != release.BlueprintVersion || revision.BlueprintDigest != release.CurrentBlueprintDigest || revision.CatalogDigest != release.CatalogDigest {
		return controlplane.BlueprintRelease{}, fmt.Errorf("%w: current revision does not match release identity", controlplane.ErrValidation)
	}
	if err := validateBlueprintCatalogBindingTx(ctx, tx, release); err != nil {
		return controlplane.BlueprintRelease{}, err
	}
	if err := validateUpgradeSourcesTx(ctx, tx, release.ProjectID, release.BlueprintName, "", release.UpgradeFromIDs); err != nil {
		return controlplane.BlueprintRelease{}, err
	}
	now := utcNow(s.now)
	release.ResourceMeta = controlplane.ResourceMeta{ID: s.id("bpl"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	release.BlueprintName = normalizedName(release.BlueprintName)
	release.State = controlplane.BlueprintDraft
	release.RequestedBy = strings.TrimSpace(actor)
	release.UpgradeFromIDs = append([]string(nil), release.UpgradeFromIDs...)
	sort.Strings(release.UpgradeFromIDs)
	upgrades, _ := json.Marshal(release.UpgradeFromIDs)
	if _, err := tx.ExecContext(ctx, `INSERT INTO blueprint_releases(id,project_id,revision,blueprint_name,blueprint_version,state,current_revision_id,current_blueprint_digest,catalog_digest,catalog_release_id,source_release_id,upgrade_from_ids,execution_ready,plan_status,requested_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,'DRAFT',$5,$6,$7,NULLIF($8,''),NULLIF($9,''),$10::jsonb,$11,$12,$13,$14,$14)`,
		release.ID, release.ProjectID, release.BlueprintName, release.BlueprintVersion, release.CurrentRevisionID, release.CurrentBlueprintDigest, release.CatalogDigest, release.CatalogReleaseID, release.SourceReleaseID, upgrades, release.ExecutionReady, release.PlanStatus, release.RequestedBy, now); err != nil {
		return controlplane.BlueprintRelease{}, mapDBError(err)
	}
	if err := s.appendAuditTx(ctx, tx, actor, "blueprint_release.created", "blueprintRelease", release.ID, 1, "", map[string]any{"projectId": release.ProjectID, "blueprintName": release.BlueprintName, "blueprintVersion": release.BlueprintVersion}); err != nil {
		return controlplane.BlueprintRelease{}, err
	}
	if err := s.appendOutboxTx(ctx, tx, "blueprintRelease", release.ID, "blueprint_release.created", release); err != nil {
		return controlplane.BlueprintRelease{}, err
	}
	return release, nil
}

func (s *PostgresStore) CreateBlueprintRelease(ctx context.Context, release controlplane.BlueprintRelease, actor string) (controlplane.BlueprintRelease, error) {
	prepared, err := prepareBlueprintReleaseDB(release, actor)
	if err != nil {
		return controlplane.BlueprintRelease{}, err
	}
	var created controlplane.BlueprintRelease
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		created, e = s.createBlueprintReleaseTx(ctx, tx, prepared, actor)
		return e
	})
	return created, err
}

func (s *PostgresStore) CreateBlueprintReleaseWithRevision(ctx context.Context, revision controlplane.BlueprintRevision, release controlplane.BlueprintRelease, actor string) (controlplane.BlueprintRevision, controlplane.BlueprintRelease, error) {
	preparedRevision, err := prepareBlueprintRevisionDB(revision)
	if err != nil {
		return controlplane.BlueprintRevision{}, controlplane.BlueprintRelease{}, err
	}
	var createdRevision controlplane.BlueprintRevision
	var createdRelease controlplane.BlueprintRelease
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		createdRevision, _, e = s.createBlueprintRevisionTx(ctx, tx, preparedRevision, actor)
		if e != nil {
			return e
		}
		release.ProjectID = createdRevision.ProjectID
		release.BlueprintName = createdRevision.BlueprintName
		release.BlueprintVersion = createdRevision.BlueprintVersion
		release.CurrentRevisionID = createdRevision.ID
		release.CurrentBlueprintDigest = createdRevision.BlueprintDigest
		release.CatalogDigest = createdRevision.CatalogDigest
		preparedRelease, e := prepareBlueprintReleaseDB(release, actor)
		if e != nil {
			return e
		}
		createdRelease, e = s.createBlueprintReleaseTx(ctx, tx, preparedRelease, actor)
		return e
	})
	return createdRevision, createdRelease, err
}

func (s *PostgresStore) GetBlueprintRelease(ctx context.Context, id string) (controlplane.BlueprintRelease, error) {
	value, err := scanBlueprintRelease(s.db.QueryRowContext(ctx, `SELECT `+blueprintReleaseColumns+` FROM blueprint_releases WHERE id=$1`, id))
	return value, mapDBError(err)
}

func (s *PostgresStore) ListBlueprintReleases(ctx context.Context, projectID string) ([]controlplane.BlueprintRelease, error) {
	query := `SELECT ` + blueprintReleaseColumns + ` FROM blueprint_releases`
	args := []any{}
	if strings.TrimSpace(projectID) != "" {
		query += ` WHERE project_id=$1`
		args = append(args, strings.TrimSpace(projectID))
	}
	query += ` ORDER BY blueprint_name,blueprint_version,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.BlueprintRelease{}
	for rows.Next() {
		value, err := scanBlueprintRelease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateBlueprintReleaseDraft(ctx context.Context, id string, expected int64, revisionID, blueprintDigest, catalogDigest string, executionReady bool, planStatus string, upgradeFromIDs []string, actor string) (controlplane.BlueprintRelease, error) {
	var updated controlplane.BlueprintRelease
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanBlueprintRelease(tx.QueryRowContext(ctx, `SELECT `+blueprintReleaseColumns+` FROM blueprint_releases WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if current.State != controlplane.BlueprintDraft {
			return controlplane.ErrImmutable
		}
		revision, err := scanBlueprintRevision(tx.QueryRowContext(ctx, `SELECT `+blueprintRevisionColumns+` FROM blueprint_revisions WHERE id=$1`, revisionID))
		if err != nil {
			return mapDBError(err)
		}
		if revision.ProjectID != current.ProjectID || normalizedName(revision.BlueprintName) != normalizedName(current.BlueprintName) || revision.BlueprintVersion != current.BlueprintVersion || revision.BlueprintDigest != blueprintDigest || revision.CatalogDigest != catalogDigest {
			return fmt.Errorf("%w: draft revision does not match release identity", controlplane.ErrValidation)
		}
		if err := validateUpgradeSourcesTx(ctx, tx, current.ProjectID, current.BlueprintName, id, upgradeFromIDs); err != nil {
			return err
		}
		upgrades := append([]string(nil), upgradeFromIDs...)
		sort.Strings(upgrades)
		upgradeRaw, _ := json.Marshal(upgrades)
		current.CurrentRevisionID, current.CurrentBlueprintDigest, current.CatalogDigest = revisionID, blueprintDigest, catalogDigest
		current.ExecutionReady, current.PlanStatus, current.UpgradeFromIDs = executionReady, strings.TrimSpace(planStatus), upgrades
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if _, err := tx.ExecContext(ctx, `UPDATE blueprint_releases SET revision=$2,current_revision_id=$3,current_blueprint_digest=$4,catalog_digest=$5,execution_ready=$6,plan_status=$7,upgrade_from_ids=$8::jsonb,updated_at=$9 WHERE id=$1 AND revision=$10`, id, current.Revision, revisionID, blueprintDigest, catalogDigest, executionReady, current.PlanStatus, upgradeRaw, current.UpdatedAt, expected); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "blueprint_release.draft_updated", "blueprintRelease", id, current.Revision, "", map[string]any{"revisionId": revisionID, "blueprintDigest": blueprintDigest}); err != nil {
			return err
		}
		if err := s.appendOutboxTx(ctx, tx, "blueprintRelease", id, "blueprint_release.draft_updated", current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}

func (s *PostgresStore) UpdateBlueprintReleaseDraftWithRevision(ctx context.Context, id string, expected int64, revision controlplane.BlueprintRevision, executionReady bool, planStatus string, upgradeFromIDs []string, actor string) (controlplane.BlueprintRevision, controlplane.BlueprintRelease, error) {
	preparedRevision, err := prepareBlueprintRevisionDB(revision)
	if err != nil {
		return controlplane.BlueprintRevision{}, controlplane.BlueprintRelease{}, err
	}
	var createdRevision controlplane.BlueprintRevision
	var updated controlplane.BlueprintRelease
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		current, e := scanBlueprintRelease(tx.QueryRowContext(ctx, `SELECT `+blueprintReleaseColumns+` FROM blueprint_releases WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if current.State != controlplane.BlueprintDraft {
			return controlplane.ErrImmutable
		}
		createdRevision, _, e = s.createBlueprintRevisionTx(ctx, tx, preparedRevision, actor)
		if e != nil {
			return e
		}
		if createdRevision.ProjectID != current.ProjectID || normalizedName(createdRevision.BlueprintName) != normalizedName(current.BlueprintName) || createdRevision.BlueprintVersion != current.BlueprintVersion {
			return fmt.Errorf("%w: draft revision does not match release identity", controlplane.ErrValidation)
		}
		if e = validateUpgradeSourcesTx(ctx, tx, current.ProjectID, current.BlueprintName, id, upgradeFromIDs); e != nil {
			return e
		}
		upgrades := append([]string(nil), upgradeFromIDs...)
		sort.Strings(upgrades)
		upgradeRaw, _ := json.Marshal(upgrades)
		current.CurrentRevisionID = createdRevision.ID
		current.CurrentBlueprintDigest = createdRevision.BlueprintDigest
		current.CatalogDigest = createdRevision.CatalogDigest
		current.ExecutionReady = executionReady
		current.PlanStatus = strings.TrimSpace(planStatus)
		current.UpgradeFromIDs = upgrades
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if _, e = tx.ExecContext(ctx, `UPDATE blueprint_releases SET revision=$2,current_revision_id=$3,current_blueprint_digest=$4,catalog_digest=$5,execution_ready=$6,plan_status=$7,upgrade_from_ids=$8::jsonb,updated_at=$9 WHERE id=$1 AND revision=$10`, id, current.Revision, createdRevision.ID, createdRevision.BlueprintDigest, createdRevision.CatalogDigest, executionReady, current.PlanStatus, upgradeRaw, current.UpdatedAt, expected); e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "blueprint_release.draft_updated", "blueprintRelease", id, current.Revision, "", map[string]any{"revisionId": createdRevision.ID, "blueprintDigest": createdRevision.BlueprintDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "blueprintRelease", id, "blueprint_release.draft_updated", current); e != nil {
			return e
		}
		updated = current
		return nil
	})
	return createdRevision, updated, err
}

func (s *PostgresStore) TransitionBlueprintRelease(ctx context.Context, id string, expected int64, to controlplane.BlueprintLifecycleState, actor string) (controlplane.BlueprintRelease, error) {
	var updated controlplane.BlueprintRelease
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanBlueprintRelease(tx.QueryRowContext(ctx, `SELECT `+blueprintReleaseColumns+` FROM blueprint_releases WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if !validBlueprintLifecycleTransition(current.State, to) {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		from := current.State
		if to == controlplane.BlueprintPublished {
			if strings.TrimSpace(actor) == "" {
				return fmt.Errorf("%w: publish approver is required", controlplane.ErrValidation)
			}
			if err := validateBlueprintCatalogBindingTx(ctx, tx, current); err != nil {
				return err
			}
			if err := validateUpgradeSourcesTx(ctx, tx, current.ProjectID, current.BlueprintName, id, current.UpgradeFromIDs); err != nil {
				return err
			}
			current.PublishedBy, current.PublishedAt = actor, &now
		}
		if to == controlplane.BlueprintReview {
			current.RequestedBy, current.ReviewRequestedAt = actor, &now
		}
		if from == controlplane.BlueprintReview && to == controlplane.BlueprintDraft {
			current.ReviewRequestedAt = nil
		}
		if to == controlplane.BlueprintDeprecated {
			current.DeprecatedBy, current.DeprecatedAt = actor, &now
		}
		if to == controlplane.BlueprintRevoked {
			current.RevokedBy, current.RevokedAt = actor, &now
		}
		current.State = to
		current.Revision++
		current.UpdatedAt = now
		if _, err := tx.ExecContext(ctx, `UPDATE blueprint_releases SET revision=$2,state=$3,requested_by=$4,review_requested_at=$5,published_by=NULLIF($6,''),published_at=$7,deprecated_by=NULLIF($8,''),deprecated_at=$9,revoked_by=NULLIF($10,''),revoked_at=$11,updated_at=$12 WHERE id=$1 AND revision=$13`,
			id, current.Revision, string(current.State), current.RequestedBy, current.ReviewRequestedAt, current.PublishedBy, current.PublishedAt, current.DeprecatedBy, current.DeprecatedAt, current.RevokedBy, current.RevokedAt, current.UpdatedAt, expected); err != nil {
			return mapDBError(err)
		}
		action := "blueprint_release." + strings.ToLower(string(to))
		if err := s.appendAuditTx(ctx, tx, actor, action, "blueprintRelease", id, current.Revision, "", map[string]any{"from": from, "to": to}); err != nil {
			return err
		}
		if err := s.appendOutboxTx(ctx, tx, "blueprintRelease", id, action, current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}

func validBlueprintLifecycleTransition(from, to controlplane.BlueprintLifecycleState) bool {
	switch from {
	case controlplane.BlueprintDraft:
		return to == controlplane.BlueprintReview
	case controlplane.BlueprintReview:
		return to == controlplane.BlueprintDraft || to == controlplane.BlueprintPublished
	case controlplane.BlueprintPublished:
		return to == controlplane.BlueprintDeprecated || to == controlplane.BlueprintRevoked
	case controlplane.BlueprintDeprecated:
		return to == controlplane.BlueprintRevoked
	default:
		return false
	}
}

var _ = errors.Is
