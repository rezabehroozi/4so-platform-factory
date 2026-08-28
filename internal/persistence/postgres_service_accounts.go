package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const serviceAccountColumns = `id,organization_id,COALESCE(project_id,''),revision,name,display_name,product_role,state,created_by,revoked_by,revoked_at,created_at,updated_at`
const apiTokenColumns = `id,service_account_id,organization_id,COALESCE(project_id,''),revision,token_prefix,token_digest,idempotency_key,permissions,state,expires_at,created_by,COALESCE(rotated_from_id,''),revoked_by,revoked_at,created_at,updated_at`

func scanServiceAccount(row interface{ Scan(...any) error }) (controlplane.ServiceAccount, error) {
	var v controlplane.ServiceAccount
	err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.Revision, &v.Name, &v.DisplayName, &v.ProductRole, &v.State, &v.CreatedBy, &v.RevokedBy, &v.RevokedAt, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}
func scanAPIToken(row interface{ Scan(...any) error }) (controlplane.APIToken, error) {
	var v controlplane.APIToken
	var permissions []byte
	err := row.Scan(&v.ID, &v.ServiceAccountID, &v.OrganizationID, &v.ProjectID, &v.Revision, &v.TokenPrefix, &v.TokenDigest, &v.IdempotencyKey, &permissions, &v.State, &v.ExpiresAt, &v.CreatedBy, &v.RotatedFromID, &v.RevokedBy, &v.RevokedAt, &v.CreatedAt, &v.UpdatedAt)
	if err == nil {
		err = decodeJSONColumn(permissions, &v.Permissions, "api_tokens.permissions")
	}
	return v, err
}
func validServiceProductRole(role string) bool {
	return role == "platform-viewer" || role == "platform-operator"
}
func normalizeServiceTokenPermissions(role string, in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" || seen[p] {
			continue
		}
		switch p {
		case controlplane.APITokenPermissionRead, controlplane.APITokenPermissionMCPRead:
		case controlplane.APITokenPermissionOperate, controlplane.APITokenPermissionAIDiagnose:
			if role != "platform-operator" {
				return nil, fmt.Errorf("%w: %s permission requires platform-operator service account", controlplane.ErrValidation, p)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported API token permission %q", controlplane.ErrValidation, p)
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		out = append(out, controlplane.APITokenPermissionRead)
		seen[controlplane.APITokenPermissionRead] = true
	}
	if !seen[controlplane.APITokenPermissionRead] {
		out = append(out, controlplane.APITokenPermissionRead)
	}
	return out, nil
}

func (s *PostgresStore) CreateServiceAccount(ctx context.Context, account controlplane.ServiceAccount, actor string) (controlplane.ServiceAccount, error) {
	account.OrganizationID = strings.TrimSpace(account.OrganizationID)
	account.ProjectID = strings.TrimSpace(account.ProjectID)
	account.Name = normalizedName(account.Name)
	account.DisplayName = strings.TrimSpace(account.DisplayName)
	account.ProductRole = strings.TrimSpace(account.ProductRole)
	if account.OrganizationID == "" || account.Name == "" || account.DisplayName == "" || !validServiceProductRole(account.ProductRole) {
		return controlplane.ServiceAccount{}, fmt.Errorf("%w: organization, name, displayName and viewer/operator productRole are required", controlplane.ErrValidation)
	}
	var out controlplane.ServiceAccount
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if _, err := scanOrganization(tx.QueryRowContext(ctx, `SELECT `+organizationColumns+` FROM organizations WHERE id=$1 FOR SHARE`, account.OrganizationID)); err != nil {
			return mapDBError(err)
		}
		var project any = nil
		if account.ProjectID != "" {
			p, err := scanProject(tx.QueryRowContext(ctx, `SELECT `+projectColumns+` FROM projects WHERE id=$1 FOR SHARE`, account.ProjectID))
			if err != nil {
				return mapDBError(err)
			}
			if p.OrganizationID != account.OrganizationID {
				return fmt.Errorf("%w: project is outside service account organization", controlplane.ErrValidation)
			}
			project = account.ProjectID
		}
		now := utcNow(s.now)
		account.ResourceMeta = controlplane.ResourceMeta{ID: s.id("svc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		account.State = controlplane.ServiceAccountActive
		account.CreatedBy = strings.TrimSpace(actor)
		v, err := scanServiceAccount(tx.QueryRowContext(ctx, `INSERT INTO service_accounts(id,organization_id,project_id,revision,name,display_name,product_role,state,created_by,revoked_by,revoked_at,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,'',NULL,$9,$9) RETURNING `+serviceAccountColumns, account.ID, account.OrganizationID, project, account.Name, account.DisplayName, account.ProductRole, account.State, account.CreatedBy, now))
		if err != nil {
			return mapDBError(err)
		}
		out = v
		if err := s.appendAuditTx(ctx, tx, actor, "service_account.created", "serviceAccount", out.ID, out.Revision, "", map[string]any{"organizationId": out.OrganizationID, "projectId": out.ProjectID, "productRole": out.ProductRole}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "serviceAccount", out.ID, "service_account.created", out)
	})
	return out, err
}
func (s *PostgresStore) GetServiceAccount(ctx context.Context, id string) (controlplane.ServiceAccount, error) {
	v, err := scanServiceAccount(s.db.QueryRowContext(ctx, `SELECT `+serviceAccountColumns+` FROM service_accounts WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}
func (s *PostgresStore) ListServiceAccounts(ctx context.Context, organizationID string) ([]controlplane.ServiceAccount, error) {
	q := `SELECT ` + serviceAccountColumns + ` FROM service_accounts`
	args := []any{}
	if strings.TrimSpace(organizationID) != "" {
		q += ` WHERE organization_id=$1`
		args = append(args, strings.TrimSpace(organizationID))
	}
	q += ` ORDER BY organization_id,name,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.ServiceAccount{}
	for rows.Next() {
		v, e := scanServiceAccount(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) RevokeServiceAccount(ctx context.Context, id string, expected int64, actor string) (controlplane.ServiceAccount, error) {
	var out controlplane.ServiceAccount
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, err := scanServiceAccount(tx.QueryRowContext(ctx, `SELECT `+serviceAccountColumns+` FROM service_accounts WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if err != nil {
			return mapDBError(err)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		if cur.State == controlplane.ServiceAccountRevoked {
			out = cur
			return nil
		}
		now := utcNow(s.now)
		out, err = scanServiceAccount(tx.QueryRowContext(ctx, `UPDATE service_accounts SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE id=$1 RETURNING `+serviceAccountColumns, cur.ID, strings.TrimSpace(actor), now))
		if err != nil {
			return mapDBError(err)
		}
		if _, err = tx.ExecContext(ctx, `UPDATE api_tokens SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE service_account_id=$1 AND state='ACTIVE'`, cur.ID, strings.TrimSpace(actor), now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, actor, "service_account.revoked", "serviceAccount", out.ID, out.Revision, "", map[string]any{"organizationId": out.OrganizationID, "projectId": out.ProjectID}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "serviceAccount", out.ID, "service_account.revoked", out)
	})
	return out, err
}

func (s *PostgresStore) CreateAPIToken(ctx context.Context, token controlplane.APIToken, actor string) (controlplane.APIToken, error) {
	var out controlplane.APIToken
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		account, err := scanServiceAccount(tx.QueryRowContext(ctx, `SELECT `+serviceAccountColumns+` FROM service_accounts WHERE id=$1 FOR SHARE`, strings.TrimSpace(token.ServiceAccountID)))
		if err != nil {
			return mapDBError(err)
		}
		if account.State != controlplane.ServiceAccountActive {
			return fmt.Errorf("%w: service account is revoked", controlplane.ErrValidation)
		}
		now := utcNow(s.now)
		if token.ExpiresAt.IsZero() || !token.ExpiresAt.After(now) || token.ExpiresAt.After(now.Add(366*24*time.Hour)) {
			return fmt.Errorf("%w: token expiry must be in the future and within 366 days", controlplane.ErrValidation)
		}
		permissions, err := normalizeServiceTokenPermissions(account.ProductRole, token.Permissions)
		if err != nil {
			return err
		}
		if strings.TrimSpace(token.TokenDigest) == "" || strings.TrimSpace(token.TokenPrefix) == "" {
			return fmt.Errorf("%w: token digest and prefix are required", controlplane.ErrValidation)
		}
		token.IdempotencyKey = strings.TrimSpace(token.IdempotencyKey)
		if token.IdempotencyKey == "" || len(token.IdempotencyKey) > 200 {
			return fmt.Errorf("%w: idempotency key is required and must be at most 200 characters", controlplane.ErrValidation)
		}
		rawPerm, _ := json.Marshal(permissions)
		token.ID = strings.TrimSpace(token.ID)
		if token.ID == "" {
			token.ID = s.id("tok")
		}
		var project any = nil
		if account.ProjectID != "" {
			project = account.ProjectID
		}
		out, err = scanAPIToken(tx.QueryRowContext(ctx, `INSERT INTO api_tokens(id,service_account_id,organization_id,project_id,revision,token_prefix,token_digest,idempotency_key,permissions,state,expires_at,created_by,rotated_from_id,revoked_by,revoked_at,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8::jsonb,'ACTIVE',$9,$10,NULL,'',NULL,$11,$11) RETURNING `+apiTokenColumns, token.ID, account.ID, account.OrganizationID, project, token.TokenPrefix, token.TokenDigest, token.IdempotencyKey, rawPerm, token.ExpiresAt, strings.TrimSpace(actor), now))
		if err != nil {
			return mapDBError(err)
		}
		redacted := out
		redacted.TokenDigest = ""
		if err = s.appendAuditTx(ctx, tx, actor, "api_token.issued", "apiToken", out.ID, out.Revision, "", map[string]any{"serviceAccountId": account.ID, "organizationId": account.OrganizationID, "projectId": account.ProjectID, "expiresAt": out.ExpiresAt, "permissions": permissions}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "apiToken", out.ID, "api_token.issued", redacted)
	})
	return out, err
}
func (s *PostgresStore) GetAPIToken(ctx context.Context, id string) (controlplane.APIToken, error) {
	v, err := scanAPIToken(s.db.QueryRowContext(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}
func (s *PostgresStore) GetAPITokenByIdempotencyKey(ctx context.Context, serviceAccountID, key string) (controlplane.APIToken, error) {
	v, err := scanAPIToken(s.db.QueryRowContext(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens WHERE service_account_id=$1 AND idempotency_key=$2`, strings.TrimSpace(serviceAccountID), strings.TrimSpace(key)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListAPITokens(ctx context.Context, serviceAccountID string) ([]controlplane.APIToken, error) {
	q := `SELECT ` + apiTokenColumns + ` FROM api_tokens`
	args := []any{}
	if strings.TrimSpace(serviceAccountID) != "" {
		q += ` WHERE service_account_id=$1`
		args = append(args, strings.TrimSpace(serviceAccountID))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.APIToken{}
	for rows.Next() {
		v, e := scanAPIToken(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) RevokeAPIToken(ctx context.Context, id string, expected int64, actor string) (controlplane.APIToken, error) {
	var out controlplane.APIToken
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, err := scanAPIToken(tx.QueryRowContext(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if err != nil {
			return mapDBError(err)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		if cur.State == controlplane.APITokenRevoked {
			out = cur
			return nil
		}
		now := utcNow(s.now)
		out, err = scanAPIToken(tx.QueryRowContext(ctx, `UPDATE api_tokens SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE id=$1 RETURNING `+apiTokenColumns, cur.ID, strings.TrimSpace(actor), now))
		if err != nil {
			return mapDBError(err)
		}
		redacted := out
		redacted.TokenDigest = ""
		if err = s.appendAuditTx(ctx, tx, actor, "api_token.revoked", "apiToken", out.ID, out.Revision, "", map[string]any{"serviceAccountId": out.ServiceAccountID}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "apiToken", out.ID, "api_token.revoked", redacted)
	})
	return out, err
}
func (s *PostgresStore) RotateAPIToken(ctx context.Context, oldID string, expected int64, replacement controlplane.APIToken, actor string) (controlplane.APIToken, controlplane.APIToken, error) {
	var oldOut, newOut controlplane.APIToken
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		old, err := scanAPIToken(tx.QueryRowContext(ctx, `SELECT `+apiTokenColumns+` FROM api_tokens WHERE id=$1 FOR UPDATE`, strings.TrimSpace(oldID)))
		if err != nil {
			return mapDBError(err)
		}
		if old.Revision != expected {
			return controlplane.ErrConflict
		}
		if old.State != controlplane.APITokenActive {
			return fmt.Errorf("%w: only active token can be rotated", controlplane.ErrValidation)
		}
		account, err := scanServiceAccount(tx.QueryRowContext(ctx, `SELECT `+serviceAccountColumns+` FROM service_accounts WHERE id=$1 FOR SHARE`, old.ServiceAccountID))
		if err != nil {
			return mapDBError(err)
		}
		if account.State != controlplane.ServiceAccountActive {
			return fmt.Errorf("%w: service account is not active", controlplane.ErrValidation)
		}
		now := utcNow(s.now)
		if replacement.ExpiresAt.IsZero() {
			replacement.ExpiresAt = old.ExpiresAt
		}
		if !replacement.ExpiresAt.After(now) || replacement.ExpiresAt.After(now.Add(366*24*time.Hour)) {
			return fmt.Errorf("%w: replacement expiry must be in the future and within 366 days", controlplane.ErrValidation)
		}
		permissions := replacement.Permissions
		if len(permissions) == 0 {
			permissions = old.Permissions
		}
		permissions, err = normalizeServiceTokenPermissions(account.ProductRole, permissions)
		if err != nil {
			return err
		}
		if strings.TrimSpace(replacement.TokenDigest) == "" || strings.TrimSpace(replacement.TokenPrefix) == "" {
			return fmt.Errorf("%w: replacement token digest and prefix are required", controlplane.ErrValidation)
		}
		replacement.IdempotencyKey = strings.TrimSpace(replacement.IdempotencyKey)
		if replacement.IdempotencyKey == "" || len(replacement.IdempotencyKey) > 200 {
			return fmt.Errorf("%w: idempotency key is required and must be at most 200 characters", controlplane.ErrValidation)
		}
		var duplicateID string
		err = tx.QueryRowContext(ctx, `SELECT id FROM api_tokens WHERE service_account_id=$1 AND idempotency_key=$2`, account.ID, replacement.IdempotencyKey).Scan(&duplicateID)
		if err == nil {
			return controlplane.ErrConflict
		}
		if err != sql.ErrNoRows {
			return err
		}
		oldOut, err = scanAPIToken(tx.QueryRowContext(ctx, `UPDATE api_tokens SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE id=$1 RETURNING `+apiTokenColumns, old.ID, strings.TrimSpace(actor), now))
		if err != nil {
			return mapDBError(err)
		}
		replacement.ID = strings.TrimSpace(replacement.ID)
		if replacement.ID == "" {
			replacement.ID = s.id("tok")
		}
		rawPerm, _ := json.Marshal(permissions)
		var project any = nil
		if account.ProjectID != "" {
			project = account.ProjectID
		}
		newOut, err = scanAPIToken(tx.QueryRowContext(ctx, `INSERT INTO api_tokens(id,service_account_id,organization_id,project_id,revision,token_prefix,token_digest,idempotency_key,permissions,state,expires_at,created_by,rotated_from_id,revoked_by,revoked_at,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8::jsonb,'ACTIVE',$9,$10,$11,'',NULL,$12,$12) RETURNING `+apiTokenColumns, replacement.ID, account.ID, account.OrganizationID, project, replacement.TokenPrefix, replacement.TokenDigest, replacement.IdempotencyKey, rawPerm, replacement.ExpiresAt, strings.TrimSpace(actor), old.ID, now))
		if err != nil {
			return mapDBError(err)
		}
		redacted := newOut
		redacted.TokenDigest = ""
		if err = s.appendAuditTx(ctx, tx, actor, "api_token.rotated", "apiToken", newOut.ID, newOut.Revision, "", map[string]any{"serviceAccountId": account.ID, "rotatedFromId": old.ID, "expiresAt": newOut.ExpiresAt}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "apiToken", newOut.ID, "api_token.rotated", redacted)
	})
	return oldOut, newOut, err
}

var _ = errors.Is
var _ = time.Second
