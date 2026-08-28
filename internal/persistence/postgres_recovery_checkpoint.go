package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
)

const recoveryCheckpointColumns = `id,project_id,cluster_id,revision,provider,reference,evidence_digest,inventory_digest,completed_at,expires_at,state::text,requested_by,revoked_by,revoked_at,created_at,updated_at`

func scanRecoveryCheckpoint(row interface{ Scan(...any) error }) (controlplane.RecoveryCheckpoint, error) {
	var v controlplane.RecoveryCheckpoint
	var state string
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.Revision, &v.Provider, &v.Reference, &v.EvidenceDigest, &v.InventoryDigest, &v.CompletedAt, &v.ExpiresAt, &state, &v.RequestedBy, &v.RevokedBy, &v.RevokedAt, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.RecoveryCheckpointState(state)
	return v, err
}

func (s *PostgresStore) CreateRecoveryCheckpoint(ctx context.Context, v controlplane.RecoveryCheckpoint, actor string) (controlplane.RecoveryCheckpoint, error) {
	var out controlplane.RecoveryCheckpoint
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var projectID, inventoryDigest string
		if e := tx.QueryRowContext(ctx, `SELECT project_id,inventory_digest FROM managed_clusters WHERE id=$1 FOR SHARE`, v.ClusterID).Scan(&projectID, &inventoryDigest); e != nil {
			return mapDBError(e)
		}
		cluster := controlplane.ManagedCluster{ResourceMeta: controlplane.ResourceMeta{ID: v.ClusterID}, ProjectID: projectID, InventoryDigest: inventoryDigest}
		now := utcNow(s.now)
		if e := controlplane.ValidateRecoveryCheckpointCreate(&v, cluster, now); e != nil {
			return e
		}
		var duplicate string
		e := tx.QueryRowContext(ctx, `SELECT id FROM recovery_checkpoints WHERE project_id=$1 AND cluster_id=$2 AND evidence_digest=$3 AND state='VERIFIED' LIMIT 1`, v.ProjectID, v.ClusterID, v.EvidenceDigest).Scan(&duplicate)
		if e == nil {
			return controlplane.ErrDuplicateName
		}
		if e != sql.ErrNoRows {
			return e
		}
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("rcp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.InventoryDigest = inventoryDigest
		v.State = controlplane.RecoveryCheckpointVerified
		v.RequestedBy = actor
		_, e = tx.ExecContext(ctx, `INSERT INTO recovery_checkpoints(id,project_id,cluster_id,revision,provider,reference,evidence_digest,inventory_digest,completed_at,expires_at,state,requested_by,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, v.ID, v.ProjectID, v.ClusterID, v.Provider, v.Reference, v.EvidenceDigest, v.InventoryDigest, v.CompletedAt, v.ExpiresAt, string(v.State), actor, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "recovery_checkpoint.registered", "recoveryCheckpoint", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "provider": v.Provider, "evidenceDigest": v.EvidenceDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "recoveryCheckpoint", v.ID, "recovery_checkpoint.verified", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) GetRecoveryCheckpoint(ctx context.Context, id string) (controlplane.RecoveryCheckpoint, error) {
	v, e := scanRecoveryCheckpoint(s.db.QueryRowContext(ctx, `SELECT `+recoveryCheckpointColumns+` FROM recovery_checkpoints WHERE id=$1`, id))
	return v, mapDBError(e)
}

func (s *PostgresStore) ListRecoveryCheckpoints(ctx context.Context, projectID, clusterID string) ([]controlplane.RecoveryCheckpoint, error) {
	q := `SELECT ` + recoveryCheckpointColumns + ` FROM recovery_checkpoints WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(projectID) != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	if strings.TrimSpace(clusterID) != "" {
		args = append(args, clusterID)
		q += fmt.Sprintf(" AND cluster_id=$%d", len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.RecoveryCheckpoint{}
	for rows.Next() {
		v, e := scanRecoveryCheckpoint(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeRecoveryCheckpoint(ctx context.Context, id string, expected int64, actor string) (controlplane.RecoveryCheckpoint, error) {
	var out controlplane.RecoveryCheckpoint
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanRecoveryCheckpoint(tx.QueryRowContext(ctx, `SELECT `+recoveryCheckpointColumns+` FROM recovery_checkpoints WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.RecoveryCheckpointVerified {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.State = controlplane.RecoveryCheckpointRevoked
		v.RevokedBy, v.RevokedAt = actor, &now
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE recovery_checkpoints SET revision=$2,state=$3,revoked_by=$4,revoked_at=$5,updated_at=$5 WHERE id=$1`, id, v.Revision, string(v.State), actor, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "recovery_checkpoint.revoked", "recoveryCheckpoint", id, v.Revision, "", nil); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "recoveryCheckpoint", id, "recovery_checkpoint.revoked", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
