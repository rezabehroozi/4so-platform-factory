package persistence

import (
	"context"
	"database/sql"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const agentCertificateColumns = `id,cluster_id,revision,serial_number,fingerprint,subject,state,not_before,not_after,issued_by,revoked_by,revoked_at,replaced_by_id,created_at,updated_at`

type rowScanner interface{ Scan(...any) error }

func scanAgentCertificate(row rowScanner) (controlplane.AgentCertificate, error) {
	var v controlplane.AgentCertificate
	var state string
	err := row.Scan(&v.ID, &v.ClusterID, &v.Revision, &v.SerialNumber, &v.Fingerprint, &v.Subject, &state, &v.NotBefore, &v.NotAfter, &v.IssuedBy, &v.RevokedBy, &v.RevokedAt, &v.ReplacedByID, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.AgentCertificateState(state)
	return v, err
}
func validateAgentCertPG(v controlplane.AgentCertificate) error {
	if strings.TrimSpace(v.ClusterID) == "" || strings.TrimSpace(v.SerialNumber) == "" || !strings.HasPrefix(v.Fingerprint, "sha256:") || v.NotBefore.IsZero() || v.NotAfter.IsZero() || !v.NotAfter.After(v.NotBefore) {
		return controlplane.ErrValidation
	}
	return nil
}
func (s *PostgresStore) CreateAgentCertificate(ctx context.Context, v controlplane.AgentCertificate, actor string) (controlplane.AgentCertificate, error) {
	if err := validateAgentCertPG(v); err != nil {
		return controlplane.AgentCertificate{}, err
	}
	var out controlplane.AgentCertificate
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var exists string
		if e := tx.QueryRowContext(ctx, `SELECT id FROM managed_clusters WHERE id=$1 FOR SHARE`, v.ClusterID).Scan(&exists); e != nil {
			return mapDBError(e)
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("acert"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.AgentCertificateActive
		v.IssuedBy = strings.TrimSpace(actor)
		_, e := tx.ExecContext(ctx, `INSERT INTO agent_certificates(id,cluster_id,revision,serial_number,fingerprint,subject,state,not_before,not_after,issued_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,'ACTIVE',$6,$7,$8,$9,$9)`, v.ID, v.ClusterID, v.SerialNumber, v.Fingerprint, v.Subject, v.NotBefore, v.NotAfter, v.IssuedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "agent_certificate.issued", "agentCertificate", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "serialNumber": v.SerialNumber, "fingerprint": v.Fingerprint, "notAfter": v.NotAfter}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "agentCertificate", v.ID, "agent_certificate.issued", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) GetAgentCertificate(ctx context.Context, id string) (controlplane.AgentCertificate, error) {
	v, e := scanAgentCertificate(s.db.QueryRowContext(ctx, `SELECT `+agentCertificateColumns+` FROM agent_certificates WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) GetAgentCertificateBySerial(ctx context.Context, serial string) (controlplane.AgentCertificate, error) {
	v, e := scanAgentCertificate(s.db.QueryRowContext(ctx, `SELECT `+agentCertificateColumns+` FROM agent_certificates WHERE serial_number=$1`, strings.ToLower(strings.TrimSpace(serial))))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListAgentCertificates(ctx context.Context, clusterID string) ([]controlplane.AgentCertificate, error) {
	q := `SELECT ` + agentCertificateColumns + ` FROM agent_certificates`
	args := []any{}
	if clusterID != "" {
		q += ` WHERE cluster_id=$1`
		args = append(args, clusterID)
	}
	q += ` ORDER BY created_at DESC,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.AgentCertificate{}
	for rows.Next() {
		v, e := scanAgentCertificate(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) RotateAgentCertificate(ctx context.Context, oldID string, next controlplane.AgentCertificate, actor string) (controlplane.AgentCertificate, controlplane.AgentCertificate, error) {
	if err := validateAgentCertPG(next); err != nil {
		return controlplane.AgentCertificate{}, controlplane.AgentCertificate{}, err
	}
	var old, out controlplane.AgentCertificate
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanAgentCertificate(tx.QueryRowContext(ctx, `SELECT `+agentCertificateColumns+` FROM agent_certificates WHERE id=$1 FOR UPDATE`, oldID))
		if e != nil {
			return mapDBError(e)
		}
		if v.State != controlplane.AgentCertificateActive {
			return controlplane.ErrInvalidTransition
		}
		if next.ClusterID != v.ClusterID {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		next.ResourceMeta = controlplane.ResourceMeta{ID: s.id("acert"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		next.State = controlplane.AgentCertificateActive
		next.IssuedBy = actor
		if _, e = tx.ExecContext(ctx, `INSERT INTO agent_certificates(id,cluster_id,revision,serial_number,fingerprint,subject,state,not_before,not_after,issued_by,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,'ACTIVE',$6,$7,$8,$9,$9)`, next.ID, next.ClusterID, next.SerialNumber, next.Fingerprint, next.Subject, next.NotBefore, next.NotAfter, actor, now); e != nil {
			return mapDBError(e)
		}
		v.State = controlplane.AgentCertificateRevoked
		v.RevokedBy = actor
		v.RevokedAt = &now
		v.ReplacedByID = next.ID
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE agent_certificates SET revision=$2,state='REVOKED',revoked_by=$3,revoked_at=$4,replaced_by_id=$5,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, actor, now, next.ID); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "agent_certificate.rotated", "agentCertificate", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "replacementId": next.ID, "replacementFingerprint": next.Fingerprint}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "agentCertificate", next.ID, "agent_certificate.rotated", map[string]any{"previous": v, "replacement": next}); e != nil {
			return e
		}
		old, out = v, next
		return nil
	})
	return old, out, err
}
func (s *PostgresStore) RevokeAgentCertificate(ctx context.Context, id string, rev int64, actor string) (controlplane.AgentCertificate, error) {
	var out controlplane.AgentCertificate
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanAgentCertificate(tx.QueryRowContext(ctx, `SELECT `+agentCertificateColumns+` FROM agent_certificates WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != rev {
			return controlplane.ErrConflict
		}
		if v.State == controlplane.AgentCertificateRevoked {
			out = v
			return nil
		}
		now := utcNow(s.now)
		v.State = controlplane.AgentCertificateRevoked
		v.RevokedBy = actor
		v.RevokedAt = &now
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE agent_certificates SET revision=$2,state='REVOKED',revoked_by=$3,revoked_at=$4,updated_at=$4 WHERE id=$1`, id, v.Revision, actor, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "agent_certificate.revoked", "agentCertificate", id, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "serialNumber": v.SerialNumber}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "agentCertificate", id, "agent_certificate.revoked", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
