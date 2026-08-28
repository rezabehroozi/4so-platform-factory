package persistence

import (
	"context"
	"database/sql"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const gitCredentialColumns = `id,revision,name,username,secret_ref,state,created_by,COALESCE(rotated_from_id,''),revoked_by,revoked_at,created_at,updated_at`
const gitProviderColumns = `id,revision,name,kind,base_url,credential_id,is_default,state,created_by,created_at,updated_at`

func scanGitCredential(row interface{ Scan(...any) error }) (controlplane.GitCredential, error) {
	var v controlplane.GitCredential
	err := row.Scan(&v.ID, &v.Revision, &v.Name, &v.Username, &v.SecretRef, &v.State, &v.CreatedBy, &v.RotatedFromID, &v.RevokedBy, &v.RevokedAt, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}
func scanGitProvider(row interface{ Scan(...any) error }) (controlplane.GitProvider, error) {
	var v controlplane.GitProvider
	err := row.Scan(&v.ID, &v.Revision, &v.Name, &v.Kind, &v.BaseURL, &v.CredentialID, &v.Default, &v.State, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func normalizePGSecretRef(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "env://") || strings.HasPrefix(v, "file:///")
}

func (s *PostgresStore) CreateGitCredential(ctx context.Context, v controlplane.GitCredential, actor string) (controlplane.GitCredential, error) {
	var out controlplane.GitCredential
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v.Name = strings.ToLower(strings.TrimSpace(v.Name))
		v.Username = strings.TrimSpace(v.Username)
		v.SecretRef = strings.TrimSpace(v.SecretRef)
		if v.Name == "" || v.Username == "" || !normalizePGSecretRef(v.SecretRef) {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("gitcred"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.GitCredentialActive
		v.CreatedBy = strings.TrimSpace(actor)
		_, e := tx.ExecContext(ctx, `INSERT INTO git_credentials(id,revision,name,username,secret_ref,state,created_by,rotated_from_id,revoked_by,revoked_at,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,NULL,'',NULL,$7,$7)`, v.ID, v.Name, v.Username, v.SecretRef, string(v.State), v.CreatedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_credential.created", "gitCredential", v.ID, 1, "", map[string]any{"name": v.Name, "username": v.Username, "secretRef": v.SecretRef, "secretMaterialPersisted": false}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitCredential", v.ID, "git_credential.created", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) GetGitCredential(ctx context.Context, id string) (controlplane.GitCredential, error) {
	v, e := scanGitCredential(s.db.QueryRowContext(ctx, `SELECT `+gitCredentialColumns+` FROM git_credentials WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListGitCredentials(ctx context.Context) ([]controlplane.GitCredential, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT `+gitCredentialColumns+` FROM git_credentials ORDER BY created_at,id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.GitCredential{}
	for rows.Next() {
		v, e := scanGitCredential(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) RotateGitCredential(ctx context.Context, id string, expected int64, repl controlplane.GitCredential, actor string) (controlplane.GitCredential, controlplane.GitCredential, error) {
	var old, out controlplane.GitCredential
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		old, e = scanGitCredential(tx.QueryRowContext(ctx, `SELECT `+gitCredentialColumns+` FROM git_credentials WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if old.Revision != expected {
			return controlplane.ErrConflict
		}
		if old.State != controlplane.GitCredentialActive {
			return controlplane.ErrValidation
		}
		repl.Name = strings.ToLower(strings.TrimSpace(repl.Name))
		if repl.Name == "" {
			repl.Name = old.Name
		}
		repl.Username = strings.TrimSpace(repl.Username)
		if repl.Username == "" {
			repl.Username = old.Username
		}
		repl.SecretRef = strings.TrimSpace(repl.SecretRef)
		if !normalizePGSecretRef(repl.SecretRef) {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		repl.ResourceMeta = controlplane.ResourceMeta{ID: s.id("gitcred"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		repl.State = controlplane.GitCredentialActive
		repl.CreatedBy = strings.TrimSpace(actor)
		repl.RotatedFromID = old.ID
		if _, e = tx.ExecContext(ctx, `UPDATE git_credentials SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE id=$1`, old.ID, actor, now); e != nil {
			return e
		}
		old.Revision++
		old.State = controlplane.GitCredentialRevoked
		old.RevokedBy = actor
		old.RevokedAt = &now
		old.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `INSERT INTO git_credentials(id,revision,name,username,secret_ref,state,created_by,rotated_from_id,revoked_by,revoked_at,created_at,updated_at) VALUES($1,1,$2,$3,$4,'ACTIVE',$5,$6,'',NULL,$7,$7)`, repl.ID, repl.Name, repl.Username, repl.SecretRef, repl.CreatedBy, old.ID, now); e != nil {
			return mapDBError(e)
		}
		res, e := tx.ExecContext(ctx, `UPDATE git_providers SET revision=revision+1,credential_id=$2,updated_at=$3 WHERE credential_id=$1`, old.ID, repl.ID, now)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if e = s.appendAuditTx(ctx, tx, actor, "git_credential.rotated", "gitCredential", repl.ID, 1, "", map[string]any{"rotatedFromId": old.ID, "providerBindingsRebound": n, "secretRef": repl.SecretRef, "secretMaterialPersisted": false}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitCredential", repl.ID, "git_credential.rotated", repl); e != nil {
			return e
		}
		out = repl
		return nil
	})
	return old, out, err
}
func (s *PostgresStore) RevokeGitCredential(ctx context.Context, id string, expected int64, actor string) (controlplane.GitCredential, error) {
	var out controlplane.GitCredential
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanGitCredential(tx.QueryRowContext(ctx, `SELECT `+gitCredentialColumns+` FROM git_credentials WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State == controlplane.GitCredentialRevoked {
			out = v
			return nil
		}
		now := utcNow(s.now)
		v.Revision++
		v.State = controlplane.GitCredentialRevoked
		v.RevokedBy = actor
		v.RevokedAt = &now
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE git_credentials SET revision=$2,state='REVOKED',revoked_by=$3,revoked_at=$4,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, actor, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_credential.revoked", "gitCredential", v.ID, v.Revision, "", map[string]any{"secretRef": v.SecretRef}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitCredential", v.ID, "git_credential.revoked", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) CreateGitProvider(ctx context.Context, v controlplane.GitProvider, actor string) (controlplane.GitProvider, error) {
	var out controlplane.GitProvider
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v.Name = strings.ToLower(strings.TrimSpace(v.Name))
		v.Kind = strings.ToUpper(strings.TrimSpace(v.Kind))
		if v.Kind == "" {
			v.Kind = "FORGEJO"
		}
		v.BaseURL = strings.TrimRight(strings.TrimSpace(v.BaseURL), "/")
		if v.Name == "" || v.Kind != "FORGEJO" || (!strings.HasPrefix(v.BaseURL, "https://") && !strings.HasPrefix(v.BaseURL, "http://")) {
			return controlplane.ErrValidation
		}
		cred, e := scanGitCredential(tx.QueryRowContext(ctx, `SELECT `+gitCredentialColumns+` FROM git_credentials WHERE id=$1 FOR SHARE`, strings.TrimSpace(v.CredentialID)))
		if e != nil {
			return mapDBError(e)
		}
		if cred.State != controlplane.GitCredentialActive {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		if v.Default {
			if _, e = tx.ExecContext(ctx, `UPDATE git_providers SET revision=revision+1,is_default=false,updated_at=$1 WHERE is_default=true AND state='ACTIVE'`, now); e != nil {
				return e
			}
		}
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("gitp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.GitProviderActive
		v.CreatedBy = actor
		if _, e = tx.ExecContext(ctx, `INSERT INTO git_providers(id,revision,name,kind,base_url,credential_id,is_default,state,created_by,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,'ACTIVE',$7,$8,$8)`, v.ID, v.Name, v.Kind, v.BaseURL, cred.ID, v.Default, actor, now); e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_provider.created", "gitProvider", v.ID, 1, "", map[string]any{"name": v.Name, "kind": v.Kind, "baseUrl": v.BaseURL, "credentialId": v.CredentialID, "default": v.Default}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitProvider", v.ID, "git_provider.created", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) GetGitProvider(ctx context.Context, id string) (controlplane.GitProvider, error) {
	v, e := scanGitProvider(s.db.QueryRowContext(ctx, `SELECT `+gitProviderColumns+` FROM git_providers WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListGitProviders(ctx context.Context) ([]controlplane.GitProvider, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT `+gitProviderColumns+` FROM git_providers ORDER BY is_default DESC,created_at,id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.GitProvider{}
	for rows.Next() {
		v, e := scanGitProvider(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) GetDefaultGitProvider(ctx context.Context) (controlplane.GitProvider, controlplane.GitCredential, error) {
	p, e := scanGitProvider(s.db.QueryRowContext(ctx, `SELECT `+gitProviderColumns+` FROM git_providers WHERE is_default=true AND state='ACTIVE' LIMIT 1`))
	if e != nil {
		return controlplane.GitProvider{}, controlplane.GitCredential{}, mapDBError(e)
	}
	c, e := s.GetGitCredential(ctx, p.CredentialID)
	if e != nil {
		return controlplane.GitProvider{}, controlplane.GitCredential{}, e
	}
	if c.State != controlplane.GitCredentialActive {
		return controlplane.GitProvider{}, controlplane.GitCredential{}, controlplane.ErrValidation
	}
	return p, c, nil
}
func (s *PostgresStore) UpdateGitProviderCredential(ctx context.Context, id string, expected int64, credentialID string, actor string) (controlplane.GitProvider, error) {
	var out controlplane.GitProvider
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		p, e := scanGitProvider(tx.QueryRowContext(ctx, `SELECT `+gitProviderColumns+` FROM git_providers WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if p.Revision != expected {
			return controlplane.ErrConflict
		}
		c, e := scanGitCredential(tx.QueryRowContext(ctx, `SELECT `+gitCredentialColumns+` FROM git_credentials WHERE id=$1 FOR SHARE`, strings.TrimSpace(credentialID)))
		if e != nil {
			return mapDBError(e)
		}
		if c.State != controlplane.GitCredentialActive {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		p.Revision++
		p.CredentialID = c.ID
		p.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE git_providers SET revision=$2,credential_id=$3,updated_at=$4 WHERE id=$1`, p.ID, p.Revision, c.ID, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "git_provider.credential_rebound", "gitProvider", p.ID, p.Revision, "", map[string]any{"credentialId": c.ID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "gitProvider", p.ID, "git_provider.credential_rebound", p); e != nil {
			return e
		}
		out = p
		return nil
	})
	return out, err
}
