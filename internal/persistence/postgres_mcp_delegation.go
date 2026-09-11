package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const mcpClientColumns = `id,revision,client_id,display_name,provider,redirect_uris,state,created_by,revoked_by,revoked_at,created_at,updated_at`
const mcpGrantColumns = `id,revision,issuer,subject,client_id,COALESCE(organization_id,''),COALESCE(project_id,''),access_profile,consent_digest,expires_at,state,created_by,revoked_by,revoked_at,created_at,updated_at`

func scanMCPClient(row interface{ Scan(...any) error }) (controlplane.MCPTrustedClient, error) {
	var v controlplane.MCPTrustedClient
	var redirect []byte
	err := row.Scan(&v.ID, &v.Revision, &v.ClientID, &v.DisplayName, &v.Provider, &redirect, &v.State, &v.CreatedBy, &v.RevokedBy, &v.RevokedAt, &v.CreatedAt, &v.UpdatedAt)
	if err == nil {
		err = decodeJSONColumn(redirect, &v.RedirectURIs, "mcp_trusted_clients.redirect_uris")
	}
	return v, err
}
func scanMCPGrant(row interface{ Scan(...any) error }) (controlplane.MCPDelegationGrant, error) {
	var v controlplane.MCPDelegationGrant
	err := row.Scan(&v.ID, &v.Revision, &v.Issuer, &v.Subject, &v.ClientID, &v.OrganizationID, &v.ProjectID, &v.AccessProfile, &v.ConsentDigest, &v.ExpiresAt, &v.State, &v.CreatedBy, &v.RevokedBy, &v.RevokedAt, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func (s *PostgresStore) CreateMCPTrustedClient(ctx context.Context, v controlplane.MCPTrustedClient, actor string) (controlplane.MCPTrustedClient, error) {
	clientID := strings.TrimSpace(v.ClientID)
	display := strings.TrimSpace(v.DisplayName)
	provider := strings.ToLower(strings.TrimSpace(v.Provider))
	if clientID == "" || display == "" {
		return v, fmt.Errorf("%w: clientId and displayName are required", controlplane.ErrValidation)
	}
	switch provider {
	case "chatgpt", "claude", "gemini", "grok", "other":
	default:
		return v, fmt.Errorf("%w: unsupported MCP client provider", controlplane.ErrValidation)
	}
	uris := []string{}
	seen := map[string]bool{}
	for _, u := range v.RedirectURIs {
		u = strings.TrimSpace(u)
		if u != "" && !seen[u] {
			seen[u] = true
			uris = append(uris, u)
		}
	}
	raw, _ := json.Marshal(uris)
	now := utcNow(s.now)
	v.ID = s.id("mcpcli")
	out, err := scanMCPClient(s.db.QueryRowContext(ctx, `INSERT INTO mcp_trusted_clients(id,revision,client_id,display_name,provider,redirect_uris,state,created_by,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5::jsonb,'ACTIVE',$6,$7,$7) RETURNING `+mcpClientColumns, v.ID, clientID, display, provider, raw, strings.TrimSpace(actor), now))
	return out, mapDBError(err)
}
func (s *PostgresStore) ListMCPTrustedClients(ctx context.Context) ([]controlplane.MCPTrustedClient, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+mcpClientColumns+` FROM mcp_trusted_clients ORDER BY display_name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.MCPTrustedClient{}
	for rows.Next() {
		v, e := scanMCPClient(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) GetMCPTrustedClientByClientID(ctx context.Context, clientID string) (controlplane.MCPTrustedClient, error) {
	v, err := scanMCPClient(s.db.QueryRowContext(ctx, `SELECT `+mcpClientColumns+` FROM mcp_trusted_clients WHERE client_id=$1`, strings.TrimSpace(clientID)))
	return v, mapDBError(err)
}
func (s *PostgresStore) RevokeMCPTrustedClient(ctx context.Context, id string, expected int64, actor string) (controlplane.MCPTrustedClient, error) {
	var out controlplane.MCPTrustedClient
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, e := scanMCPClient(tx.QueryRowContext(ctx, `SELECT `+mcpClientColumns+` FROM mcp_trusted_clients WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		if cur.State == controlplane.MCPTrustedClientRevoked {
			out = cur
			return nil
		}
		now := utcNow(s.now)
		out, e = scanMCPClient(tx.QueryRowContext(ctx, `UPDATE mcp_trusted_clients SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE id=$1 RETURNING `+mcpClientColumns, cur.ID, strings.TrimSpace(actor), now))
		if e != nil {
			return mapDBError(e)
		}
		if _, e = tx.ExecContext(ctx, `UPDATE mcp_delegation_grants SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE client_id=$1 AND state='ACTIVE'`, cur.ClientID, strings.TrimSpace(actor), now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "mcp_trusted_client.revoked", "mcpTrustedClient", out.ID, out.Revision, "", map[string]any{"clientId": out.ClientID}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "mcpTrustedClient", out.ID, "mcp_trusted_client.revoked", out)
	})
	return out, err
}

func (s *PostgresStore) CreateMCPDelegationGrant(ctx context.Context, v controlplane.MCPDelegationGrant, actor string) (controlplane.MCPDelegationGrant, error) {
	issuer := strings.TrimRight(strings.TrimSpace(v.Issuer), "/")
	sub := strings.TrimSpace(v.Subject)
	client := strings.TrimSpace(v.ClientID)
	org := strings.TrimSpace(v.OrganizationID)
	prj := strings.TrimSpace(v.ProjectID)
	digest := strings.TrimSpace(v.ConsentDigest)
	now := utcNow(s.now)
	if issuer == "" || sub == "" || client == "" || digest == "" {
		return v, fmt.Errorf("%w: issuer, subject, clientId and consentDigest are required", controlplane.ErrValidation)
	}
	switch v.AccessProfile {
	case controlplane.MCPDelegationView, controlplane.MCPDelegationOperate, controlplane.MCPDelegationAdministration:
	default:
		return v, fmt.Errorf("%w: unsupported MCP access profile", controlplane.ErrValidation)
	}
	if prj != "" && org == "" {
		return v, fmt.Errorf("%w: project grant requires organization", controlplane.ErrValidation)
	}
	if v.ExpiresAt.IsZero() || !v.ExpiresAt.After(now) || v.ExpiresAt.After(now.Add(30*24*time.Hour)) {
		return v, fmt.Errorf("%w: grant expiry must be within 30 days", controlplane.ErrValidation)
	}
	var out controlplane.MCPDelegationGrant
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		c, e := scanMCPClient(tx.QueryRowContext(ctx, `SELECT `+mcpClientColumns+` FROM mcp_trusted_clients WHERE client_id=$1 FOR SHARE`, client))
		if e != nil {
			return mapDBError(e)
		}
		if c.State != controlplane.MCPTrustedClientActive {
			return fmt.Errorf("%w: MCP client is revoked", controlplane.ErrValidation)
		}
		if org != "" {
			var found string
			if e = tx.QueryRowContext(ctx, `SELECT id FROM organizations WHERE id=$1`, org).Scan(&found); e != nil {
				return mapDBError(e)
			}
		}
		if prj != "" {
			var po string
			if e = tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1`, prj).Scan(&po); e != nil {
				return mapDBError(e)
			}
			if po != org {
				return fmt.Errorf("%w: project outside organization", controlplane.ErrValidation)
			}
		}
		var dup string
		e = tx.QueryRowContext(ctx, `SELECT id FROM mcp_delegation_grants WHERE issuer=$1 AND subject=$2 AND client_id=$3 AND COALESCE(organization_id,'')=$4 AND COALESCE(project_id,'')=$5 AND state='ACTIVE' AND expires_at>$6 LIMIT 1`, issuer, sub, client, org, prj, now).Scan(&dup)
		if e == nil {
			return controlplane.ErrConflict
		}
		if e != sql.ErrNoRows {
			return e
		}
		v.ID = s.id("mcpgr")
		var orgArg any = nil
		if org != "" {
			orgArg = org
		}
		var prjArg any = nil
		if prj != "" {
			prjArg = prj
		}
		out, e = scanMCPGrant(tx.QueryRowContext(ctx, `INSERT INTO mcp_delegation_grants(id,revision,issuer,subject,client_id,organization_id,project_id,access_profile,consent_digest,expires_at,state,created_by,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,'ACTIVE',$10,$11,$11) RETURNING `+mcpGrantColumns, v.ID, issuer, sub, client, orgArg, prjArg, v.AccessProfile, digest, v.ExpiresAt, strings.TrimSpace(actor), now))
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "mcp_delegation_grant.created", "mcpDelegationGrant", out.ID, out.Revision, "", map[string]any{"clientId": out.ClientID, "subject": out.Subject, "organizationId": out.OrganizationID, "projectId": out.ProjectID, "accessProfile": out.AccessProfile, "expiresAt": out.ExpiresAt}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "mcpDelegationGrant", out.ID, "mcp_delegation_grant.created", out)
	})
	return out, err
}
func (s *PostgresStore) ListMCPDelegationGrants(ctx context.Context, subject string) ([]controlplane.MCPDelegationGrant, error) {
	q := `SELECT ` + mcpGrantColumns + ` FROM mcp_delegation_grants`
	args := []any{}
	if strings.TrimSpace(subject) != "" {
		q += ` WHERE subject=$1`
		args = append(args, strings.TrimSpace(subject))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.MCPDelegationGrant{}
	for rows.Next() {
		v, e := scanMCPGrant(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) GetActiveMCPDelegationGrant(ctx context.Context, issuer, subject, clientID string, now time.Time) (controlplane.MCPDelegationGrant, error) {
	v, err := scanMCPGrant(s.db.QueryRowContext(ctx, `SELECT `+mcpGrantColumns+` FROM mcp_delegation_grants WHERE issuer=$1 AND subject=$2 AND client_id=$3 AND state='ACTIVE' AND expires_at>$4 ORDER BY created_at DESC LIMIT 1`, strings.TrimRight(strings.TrimSpace(issuer), "/"), strings.TrimSpace(subject), strings.TrimSpace(clientID), now))
	return v, mapDBError(err)
}
func (s *PostgresStore) RevokeMCPDelegationGrant(ctx context.Context, id string, expected int64, actor string) (controlplane.MCPDelegationGrant, error) {
	var out controlplane.MCPDelegationGrant
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, e := scanMCPGrant(tx.QueryRowContext(ctx, `SELECT `+mcpGrantColumns+` FROM mcp_delegation_grants WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		if cur.State == controlplane.MCPDelegationGrantRevoked {
			out = cur
			return nil
		}
		now := utcNow(s.now)
		out, e = scanMCPGrant(tx.QueryRowContext(ctx, `UPDATE mcp_delegation_grants SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE id=$1 RETURNING `+mcpGrantColumns, cur.ID, strings.TrimSpace(actor), now))
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "mcp_delegation_grant.revoked", "mcpDelegationGrant", out.ID, out.Revision, "", map[string]any{"clientId": out.ClientID, "subject": out.Subject}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "mcpDelegationGrant", out.ID, "mcp_delegation_grant.revoked", out)
	})
	return out, err
}
