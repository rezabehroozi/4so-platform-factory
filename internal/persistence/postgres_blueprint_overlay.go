package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const blueprintOverlayColumns = `id,project_id,revision,name,version,scope::text,scope_key,digest,changes,created_by,created_at,updated_at`

func scanBlueprintOverlay(row interface{ Scan(...any) error }) (controlplane.BlueprintOverlay, error) {
	var v controlplane.BlueprintOverlay
	var scope string
	var changes []byte
	if err := row.Scan(&v.ID, &v.ProjectID, &v.Revision, &v.Name, &v.Version, &scope, &v.ScopeKey, &v.Digest, &changes, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return v, err
	}
	v.Scope = controlplane.BlueprintOverlayScope(scope)
	if err := json.Unmarshal(changes, &v.Changes); err != nil {
		return v, fmt.Errorf("decode blueprint overlay changes: %w", err)
	}
	return v, nil
}

func (s *PostgresStore) CreateBlueprintOverlay(ctx context.Context, overlay controlplane.BlueprintOverlay, actor string) (controlplane.BlueprintOverlay, error) {
	var err error
	overlay, err = controlplane.NormalizeBlueprintOverlay(overlay)
	if err != nil {
		return controlplane.BlueprintOverlay{}, err
	}
	raw, err := json.Marshal(overlay.Changes)
	if err != nil {
		return controlplane.BlueprintOverlay{}, err
	}
	now := utcNow(s.now)
	overlay.ResourceMeta = controlplane.ResourceMeta{ID: s.id("bpo"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	overlay.CreatedBy = strings.TrimSpace(actor)
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO blueprint_overlays(id,project_id,revision,name,version,scope,scope_key,digest,changes,created_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$10)`, overlay.ID, overlay.ProjectID, overlay.Name, overlay.Version, string(overlay.Scope), overlay.ScopeKey, overlay.Digest, raw, overlay.CreatedBy, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "blueprint_overlay.created", "blueprintOverlay", overlay.ID, 1, "", map[string]any{"projectId": overlay.ProjectID, "scope": overlay.Scope, "scopeKey": overlay.ScopeKey, "digest": overlay.Digest}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "blueprintOverlay", overlay.ID, "blueprint_overlay.created", overlay)
	})
	return overlay, err
}
func (s *PostgresStore) GetBlueprintOverlay(ctx context.Context, id string) (controlplane.BlueprintOverlay, error) {
	v, err := scanBlueprintOverlay(s.db.QueryRowContext(ctx, `SELECT `+blueprintOverlayColumns+` FROM blueprint_overlays WHERE id=$1`, id))
	return v, mapDBError(err)
}
func (s *PostgresStore) ListBlueprintOverlays(ctx context.Context, projectID string, scope controlplane.BlueprintOverlayScope) ([]controlplane.BlueprintOverlay, error) {
	query := `SELECT ` + blueprintOverlayColumns + ` FROM blueprint_overlays WHERE ($1='' OR project_id=$1) AND ($2='' OR scope::text=$2) ORDER BY name,version,id`
	rows, err := s.db.QueryContext(ctx, query, strings.TrimSpace(projectID), string(scope))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.BlueprintOverlay{}
	for rows.Next() {
		v, e := scanBlueprintOverlay(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

var _ = errors.Is
