package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const MCPHumanDelegationAuthority = "MCP_HUMAN_DELEGATION_AUTHORITY_V1"

type MCPTrustedClientState string

const (
	MCPTrustedClientActive  MCPTrustedClientState = "ACTIVE"
	MCPTrustedClientRevoked MCPTrustedClientState = "REVOKED"
)

type MCPTrustedClient struct {
	ResourceMeta
	ClientID     string                `json:"clientId"`
	DisplayName  string                `json:"displayName"`
	Provider     string                `json:"provider"`
	RedirectURIs []string              `json:"redirectUris,omitempty"`
	State        MCPTrustedClientState `json:"state"`
	CreatedBy    string                `json:"createdBy"`
	RevokedBy    string                `json:"revokedBy,omitempty"`
	RevokedAt    *time.Time            `json:"revokedAt,omitempty"`
}

type MCPDelegationAccessProfile string

const (
	MCPDelegationView           MCPDelegationAccessProfile = "VIEW"
	MCPDelegationOperate        MCPDelegationAccessProfile = "OPERATE"
	MCPDelegationAdministration MCPDelegationAccessProfile = "ADMINISTRATION"
)

type MCPDelegationGrantState string

const (
	MCPDelegationGrantActive  MCPDelegationGrantState = "ACTIVE"
	MCPDelegationGrantRevoked MCPDelegationGrantState = "REVOKED"
)

type MCPDelegationGrant struct {
	ResourceMeta
	Issuer         string                     `json:"issuer"`
	Subject        string                     `json:"subject"`
	ClientID       string                     `json:"clientId"`
	OrganizationID string                     `json:"organizationId,omitempty"`
	ProjectID      string                     `json:"projectId,omitempty"`
	AccessProfile  MCPDelegationAccessProfile `json:"accessProfile"`
	ConsentDigest  string                     `json:"consentDigest"`
	ExpiresAt      time.Time                  `json:"expiresAt"`
	State          MCPDelegationGrantState    `json:"state"`
	CreatedBy      string                     `json:"createdBy"`
	RevokedBy      string                     `json:"revokedBy,omitempty"`
	RevokedAt      *time.Time                 `json:"revokedAt,omitempty"`
}

func normalizeMCPClient(v MCPTrustedClient) (MCPTrustedClient, error) {
	v.ClientID = strings.TrimSpace(v.ClientID)
	v.DisplayName = strings.TrimSpace(v.DisplayName)
	v.Provider = strings.ToLower(strings.TrimSpace(v.Provider))
	if v.ClientID == "" || v.DisplayName == "" {
		return MCPTrustedClient{}, fmt.Errorf("%w: clientId and displayName are required", ErrValidation)
	}
	switch v.Provider {
	case "chatgpt", "claude", "gemini", "grok", "other":
	default:
		return MCPTrustedClient{}, fmt.Errorf("%w: unsupported MCP client provider", ErrValidation)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, u := range v.RedirectURIs {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	sort.Strings(out)
	v.RedirectURIs = out
	return v, nil
}

func normalizeMCPGrant(v MCPDelegationGrant, now time.Time) (MCPDelegationGrant, error) {
	v.Issuer = strings.TrimRight(strings.TrimSpace(v.Issuer), "/")
	v.Subject = strings.TrimSpace(v.Subject)
	v.ClientID = strings.TrimSpace(v.ClientID)
	v.OrganizationID = strings.TrimSpace(v.OrganizationID)
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ConsentDigest = strings.TrimSpace(v.ConsentDigest)
	if v.Issuer == "" || v.Subject == "" || v.ClientID == "" || v.ConsentDigest == "" {
		return MCPDelegationGrant{}, fmt.Errorf("%w: issuer, subject, clientId and consentDigest are required", ErrValidation)
	}
	switch v.AccessProfile {
	case MCPDelegationView, MCPDelegationOperate, MCPDelegationAdministration:
	default:
		return MCPDelegationGrant{}, fmt.Errorf("%w: unsupported MCP access profile", ErrValidation)
	}
	if v.ProjectID != "" && v.OrganizationID == "" {
		return MCPDelegationGrant{}, fmt.Errorf("%w: project grant requires organization", ErrValidation)
	}
	if v.ExpiresAt.IsZero() || !v.ExpiresAt.After(now) || v.ExpiresAt.After(now.Add(30*24*time.Hour)) {
		return MCPDelegationGrant{}, fmt.Errorf("%w: grant expiry must be in the future and within 30 days", ErrValidation)
	}
	return v, nil
}

func (s *MemoryStore) CreateMCPTrustedClient(_ context.Context, v MCPTrustedClient, actor string) (MCPTrustedClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	v, err = normalizeMCPClient(v)
	if err != nil {
		return MCPTrustedClient{}, err
	}
	for _, cur := range s.mcpTrustedClients {
		if cur.ClientID == v.ClientID && cur.State == MCPTrustedClientActive {
			return MCPTrustedClient{}, ErrConflict
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("mcpcli"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = MCPTrustedClientActive
	v.CreatedBy = strings.TrimSpace(actor)
	s.mcpTrustedClients[v.ID] = v
	s.appendAuditLocked(actor, "mcp_trusted_client.created", "mcpTrustedClient", v.ID, v.Revision, map[string]any{"clientId": v.ClientID, "provider": v.Provider})
	s.appendOutboxLocked("mcpTrustedClient", v.ID, "mcp_trusted_client.created", v)
	return v, nil
}
func (s *MemoryStore) ListMCPTrustedClients(_ context.Context) ([]MCPTrustedClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]MCPTrustedClient, 0, len(s.mcpTrustedClients))
	for _, v := range s.mcpTrustedClients {
		v.RedirectURIs = append([]string(nil), v.RedirectURIs...)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DisplayName < out[j].DisplayName })
	return out, nil
}
func (s *MemoryStore) GetMCPTrustedClientByClientID(_ context.Context, clientID string) (MCPTrustedClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clientID = strings.TrimSpace(clientID)
	for _, v := range s.mcpTrustedClients {
		if v.ClientID == clientID {
			v.RedirectURIs = append([]string(nil), v.RedirectURIs...)
			return v, nil
		}
	}
	return MCPTrustedClient{}, ErrNotFound
}
func (s *MemoryStore) RevokeMCPTrustedClient(_ context.Context, id string, expected int64, actor string) (MCPTrustedClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.mcpTrustedClients[strings.TrimSpace(id)]
	if !ok {
		return MCPTrustedClient{}, ErrNotFound
	}
	if v.Revision != expected {
		return MCPTrustedClient{}, ErrConflict
	}
	if v.State == MCPTrustedClientRevoked {
		return v, nil
	}
	now := nowUTC(s.now)
	v.Revision++
	v.UpdatedAt = now
	v.State = MCPTrustedClientRevoked
	v.RevokedBy = strings.TrimSpace(actor)
	v.RevokedAt = &now
	s.mcpTrustedClients[v.ID] = v
	for gid, g := range s.mcpDelegationGrants {
		if g.ClientID == v.ClientID && g.State == MCPDelegationGrantActive {
			g.Revision++
			g.UpdatedAt = now
			g.State = MCPDelegationGrantRevoked
			g.RevokedBy = strings.TrimSpace(actor)
			g.RevokedAt = &now
			s.mcpDelegationGrants[gid] = g
		}
	}
	s.appendAuditLocked(actor, "mcp_trusted_client.revoked", "mcpTrustedClient", v.ID, v.Revision, map[string]any{"clientId": v.ClientID})
	s.appendOutboxLocked("mcpTrustedClient", v.ID, "mcp_trusted_client.revoked", v)
	return v, nil
}

func (s *MemoryStore) CreateMCPDelegationGrant(_ context.Context, v MCPDelegationGrant, actor string) (MCPDelegationGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowUTC(s.now)
	var err error
	v, err = normalizeMCPGrant(v, now)
	if err != nil {
		return MCPDelegationGrant{}, err
	}
	trusted := false
	for _, c := range s.mcpTrustedClients {
		if c.ClientID == v.ClientID && c.State == MCPTrustedClientActive {
			trusted = true
			break
		}
	}
	if !trusted {
		return MCPDelegationGrant{}, fmt.Errorf("%w: MCP client is not trusted", ErrValidation)
	}
	if v.OrganizationID != "" {
		org, ok := s.organizations[v.OrganizationID]
		if !ok || org.ID == "" {
			return MCPDelegationGrant{}, ErrNotFound
		}
		if v.ProjectID != "" {
			p, ok := s.projects[v.ProjectID]
			if !ok {
				return MCPDelegationGrant{}, ErrNotFound
			}
			if p.OrganizationID != v.OrganizationID {
				return MCPDelegationGrant{}, fmt.Errorf("%w: project is outside organization", ErrValidation)
			}
		}
	}
	for _, g := range s.mcpDelegationGrants {
		if g.Subject == v.Subject && g.ClientID == v.ClientID && g.OrganizationID == v.OrganizationID && g.ProjectID == v.ProjectID && g.State == MCPDelegationGrantActive && g.ExpiresAt.After(now) {
			return MCPDelegationGrant{}, ErrConflict
		}
	}
	v.ResourceMeta = ResourceMeta{ID: s.id("mcpgr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = MCPDelegationGrantActive
	v.CreatedBy = strings.TrimSpace(actor)
	s.mcpDelegationGrants[v.ID] = v
	s.appendAuditLocked(actor, "mcp_delegation_grant.created", "mcpDelegationGrant", v.ID, v.Revision, map[string]any{"clientId": v.ClientID, "subject": v.Subject, "organizationId": v.OrganizationID, "projectId": v.ProjectID, "accessProfile": v.AccessProfile, "expiresAt": v.ExpiresAt})
	s.appendOutboxLocked("mcpDelegationGrant", v.ID, "mcp_delegation_grant.created", v)
	return v, nil
}
func (s *MemoryStore) ListMCPDelegationGrants(_ context.Context, subject string) ([]MCPDelegationGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	subject = strings.TrimSpace(subject)
	out := []MCPDelegationGrant{}
	for _, v := range s.mcpDelegationGrants {
		if subject == "" || v.Subject == subject {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *MemoryStore) GetActiveMCPDelegationGrant(_ context.Context, issuer, subject, clientID string, now time.Time) (MCPDelegationGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	subject = strings.TrimSpace(subject)
	clientID = strings.TrimSpace(clientID)
	for _, v := range s.mcpDelegationGrants {
		if v.Issuer == issuer && v.Subject == subject && v.ClientID == clientID && v.State == MCPDelegationGrantActive && v.ExpiresAt.After(now) {
			return v, nil
		}
	}
	return MCPDelegationGrant{}, ErrNotFound
}
func (s *MemoryStore) RevokeMCPDelegationGrant(_ context.Context, id string, expected int64, actor string) (MCPDelegationGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.mcpDelegationGrants[strings.TrimSpace(id)]
	if !ok {
		return MCPDelegationGrant{}, ErrNotFound
	}
	if v.Revision != expected {
		return MCPDelegationGrant{}, ErrConflict
	}
	if v.State == MCPDelegationGrantRevoked {
		return v, nil
	}
	now := nowUTC(s.now)
	v.Revision++
	v.UpdatedAt = now
	v.State = MCPDelegationGrantRevoked
	v.RevokedBy = strings.TrimSpace(actor)
	v.RevokedAt = &now
	s.mcpDelegationGrants[v.ID] = v
	s.appendAuditLocked(actor, "mcp_delegation_grant.revoked", "mcpDelegationGrant", v.ID, v.Revision, map[string]any{"clientId": v.ClientID, "subject": v.Subject})
	s.appendOutboxLocked("mcpDelegationGrant", v.ID, "mcp_delegation_grant.revoked", v)
	return v, nil
}
