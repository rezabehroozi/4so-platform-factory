package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

type mcpDelegationStore interface {
	CreateMCPTrustedClient(context.Context, controlplane.MCPTrustedClient, string) (controlplane.MCPTrustedClient, error)
	ListMCPTrustedClients(context.Context) ([]controlplane.MCPTrustedClient, error)
	GetMCPTrustedClientByClientID(context.Context, string) (controlplane.MCPTrustedClient, error)
	RevokeMCPTrustedClient(context.Context, string, int64, string) (controlplane.MCPTrustedClient, error)
	CreateMCPDelegationGrant(context.Context, controlplane.MCPDelegationGrant, string) (controlplane.MCPDelegationGrant, error)
	ListMCPDelegationGrants(context.Context, string) ([]controlplane.MCPDelegationGrant, error)
	GetActiveMCPDelegationGrant(context.Context, string, string, string, time.Time) (controlplane.MCPDelegationGrant, error)
	RevokeMCPDelegationGrant(context.Context, string, int64, string) (controlplane.MCPDelegationGrant, error)
}

type mcpConsentInput struct {
	ClientID       string                                  `json:"clientId"`
	OrganizationID string                                  `json:"organizationId,omitempty"`
	ProjectID      string                                  `json:"projectId,omitempty"`
	AccessProfile  controlplane.MCPDelegationAccessProfile `json:"accessProfile"`
	ExpiresInHours int                                     `json:"expiresInHours,omitempty"`
	ExpiresAt      *time.Time                              `json:"expiresAt,omitempty"`
	ConsentDigest  string                                  `json:"consentDigest,omitempty"`
}

type mcpConsentPreview struct {
	Authority      string                                  `json:"authority"`
	Subject        string                                  `json:"subject"`
	ClientID       string                                  `json:"clientId"`
	ClientName     string                                  `json:"clientName"`
	OrganizationID string                                  `json:"organizationId,omitempty"`
	ProjectID      string                                  `json:"projectId,omitempty"`
	AccessProfile  controlplane.MCPDelegationAccessProfile `json:"accessProfile"`
	ExpiresAt      time.Time                               `json:"expiresAt"`
	ConsentDigest  string                                  `json:"consentDigest"`
	Summary        string                                  `json:"summary"`
}

func (s *Server) mcpStore() (mcpDelegationStore, error) {
	st, ok := s.store.(mcpDelegationStore)
	if !ok {
		return nil, errors.New("MCP delegation authority is unavailable on this store")
	}
	return st, nil
}
func mcpProfileRequiredLevel(p controlplane.MCPDelegationAccessProfile) organizationAccessLevel {
	switch p {
	case controlplane.MCPDelegationView:
		return organizationRead
	case controlplane.MCPDelegationOperate:
		return organizationWrite
	case controlplane.MCPDelegationAdministration:
		return organizationAdminAccess
	default:
		return 0
	}
}
func canonicalConsentDigest(subject string, in mcpConsentInput, expires time.Time) string {
	payload := struct {
		Subject, ClientID, OrganizationID, ProjectID string
		AccessProfile                                controlplane.MCPDelegationAccessProfile
		ExpiresAt                                    string
	}{strings.TrimSpace(subject), strings.TrimSpace(in.ClientID), strings.TrimSpace(in.OrganizationID), strings.TrimSpace(in.ProjectID), in.AccessProfile, expires.UTC().Format(time.RFC3339)}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (s *Server) buildMCPConsentPreview(r *http.Request, in mcpConsentInput) (mcpConsentPreview, error) {
	principal, ok := requestPrincipal(r)
	if !ok || principal.Subject == "" {
		return mcpConsentPreview{}, errors.New("authenticated human principal is required")
	}
	if principal.Authentication == "api-token" {
		return mcpConsentPreview{}, errors.New("human OIDC session is required")
	}
	st, err := s.mcpStore()
	if err != nil {
		return mcpConsentPreview{}, err
	}
	client, err := st.GetMCPTrustedClientByClientID(r.Context(), strings.TrimSpace(in.ClientID))
	if err != nil || client.State != controlplane.MCPTrustedClientActive {
		return mcpConsentPreview{}, fmt.Errorf("trusted MCP client is required")
	}
	required := mcpProfileRequiredLevel(in.AccessProfile)
	if required == 0 {
		return mcpConsentPreview{}, fmt.Errorf("unsupported access profile")
	}
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	if in.ProjectID != "" {
		project, err := s.requireProjectAccess(r, in.ProjectID, required)
		if err != nil {
			return mcpConsentPreview{}, err
		}
		if in.OrganizationID == "" {
			in.OrganizationID = project.OrganizationID
		}
		if project.OrganizationID != in.OrganizationID {
			return mcpConsentPreview{}, errOrganizationAccessDenied
		}
	} else if in.OrganizationID != "" {
		if err := s.requireOrganizationAccess(r, in.OrganizationID, required); err != nil {
			return mcpConsentPreview{}, err
		}
	} else {
		if in.AccessProfile != controlplane.MCPDelegationAdministration || !auth.HasAnyRole(principal, "platform-admin") {
			return mcpConsentPreview{}, errPlatformAdminRequired
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	var expires time.Time
	if in.ExpiresAt != nil {
		expires = in.ExpiresAt.UTC().Truncate(time.Second)
		if !expires.After(now) || expires.After(now.Add(30*24*time.Hour)) {
			return mcpConsentPreview{}, fmt.Errorf("connection expiry must be in the future and within 30 days")
		}
	} else {
		hours := in.ExpiresInHours
		if hours <= 0 {
			hours = 24
		}
		if hours > 30*24 {
			return mcpConsentPreview{}, fmt.Errorf("connection lifetime must not exceed 30 days")
		}
		expires = now.Add(time.Duration(hours) * time.Hour)
	}
	digest := canonicalConsentDigest(principal.Subject, in, expires)
	scope := "کل پلتفرم"
	if in.ProjectID != "" {
		scope = "پروژه انتخاب‌شده"
	} else if in.OrganizationID != "" {
		scope = "سازمان انتخاب‌شده"
	}
	return mcpConsentPreview{Authority: controlplane.MCPHumanDelegationAuthority, Subject: principal.Subject, ClientID: client.ClientID, ClientName: client.DisplayName, OrganizationID: in.OrganizationID, ProjectID: in.ProjectID, AccessProfile: in.AccessProfile, ExpiresAt: expires, ConsentDigest: digest, Summary: fmt.Sprintf("اتصال %s به %s با دسترسی %s تا %s", client.DisplayName, scope, in.AccessProfile, expires.Format("2006-01-02 15:04 UTC"))}, nil
}

func (s *Server) createMCPTrustedClient(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "platform-admin is required")
		return
	}
	var in controlplane.MCPTrustedClient
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	st, e := s.mcpStore()
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP_DELEGATION_STORE_UNAVAILABLE", e.Error())
		return
	}
	out, e := st.CreateMCPTrustedClient(r.Context(), in, actor)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}
func (s *Server) listMCPTrustedClients(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "platform-admin is required")
		return
	}
	st, e := s.mcpStore()
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP_DELEGATION_STORE_UNAVAILABLE", e.Error())
		return
	}
	out, e := st.ListMCPTrustedClients(r.Context())
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) revokeMCPTrustedClient(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "platform-admin is required")
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	st, e := s.mcpStore()
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP_DELEGATION_STORE_UNAVAILABLE", e.Error())
		return
	}
	out, e := st.RevokeMCPTrustedClient(r.Context(), r.PathValue("id"), expected, actor)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) previewMCPDelegation(w http.ResponseWriter, r *http.Request) {
	var in mcpConsentInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	out, err := s.buildMCPConsentPreview(r, in)
	if err != nil {
		writeError(w, http.StatusForbidden, "MCP_CONSENT_NOT_ALLOWED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) createMCPDelegationGrant(w http.ResponseWriter, r *http.Request) {
	var in mcpConsentInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	if strings.TrimSpace(in.ConsentDigest) != "" && in.ExpiresAt == nil {
		writeError(w, http.StatusBadRequest, "CONSENT_EXPIRY_REQUIRED", "confirmed consent must include the exact preview expiresAt value")
		return
	}
	preview, err := s.buildMCPConsentPreview(r, in)
	if err != nil {
		writeError(w, http.StatusForbidden, "MCP_CONSENT_NOT_ALLOWED", err.Error())
		return
	}
	if strings.TrimSpace(in.ConsentDigest) == "" || in.ConsentDigest != preview.ConsentDigest {
		writeError(w, http.StatusConflict, "CONSENT_DIGEST_MISMATCH", "connection preview changed; review and confirm again")
		return
	}
	principal, _ := requestPrincipal(r)
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	st, e := s.mcpStore()
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP_DELEGATION_STORE_UNAVAILABLE", e.Error())
		return
	}
	grant := controlplane.MCPDelegationGrant{Issuer: principal.Issuer, Subject: principal.Subject, ClientID: preview.ClientID, OrganizationID: preview.OrganizationID, ProjectID: preview.ProjectID, AccessProfile: preview.AccessProfile, ConsentDigest: preview.ConsentDigest, ExpiresAt: preview.ExpiresAt}
	if grant.Issuer == "" {
		grant.Issuer = "local-development"
	}
	out, e := st.CreateMCPDelegationGrant(r.Context(), grant, actor)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}
func (s *Server) listMCPDelegationGrants(w http.ResponseWriter, r *http.Request) {
	principal, ok := requestPrincipal(r)
	subject := ""
	if ok {
		subject = principal.Subject
	}
	if r.URL.Query().Get("all") == "true" {
		if !requestHasRole(r, "platform-admin") {
			writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "platform-admin is required")
			return
		}
		subject = ""
	}
	st, e := s.mcpStore()
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP_DELEGATION_STORE_UNAVAILABLE", e.Error())
		return
	}
	out, e := st.ListMCPDelegationGrants(r.Context(), subject)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) revokeMCPDelegationGrant(w http.ResponseWriter, r *http.Request) {
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	st, e := s.mcpStore()
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "MCP_DELEGATION_STORE_UNAVAILABLE", e.Error())
		return
	}
	grants, e := st.ListMCPDelegationGrants(r.Context(), "")
	if e != nil {
		writeStoreError(w, e)
		return
	}
	principal, ok := requestPrincipal(r)
	allowed := !ok || requestHasRole(r, "platform-admin")
	for _, g := range grants {
		if g.ID == r.PathValue("id") && ok && g.Subject == principal.Subject {
			allowed = true
		}
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "MCP_GRANT_ACCESS_DENIED", "only the grant owner or platform-admin may revoke this connection")
		return
	}
	out, e := st.RevokeMCPDelegationGrant(r.Context(), r.PathValue("id"), expected, actor)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) applyMCPHumanDelegation(r *http.Request) (*http.Request, error) {
	p, ok := requestPrincipal(r)
	if !ok || p.Authentication != "oidc" {
		return r, nil
	}
	if strings.TrimSpace(p.AuthorizedClientID) == "" {
		return r, fmt.Errorf("MCP OAuth token is missing authorized client identity")
	}
	st, err := s.mcpStore()
	if err != nil {
		return r, err
	}
	client, err := st.GetMCPTrustedClientByClientID(r.Context(), p.AuthorizedClientID)
	if err != nil || client.State != controlplane.MCPTrustedClientActive {
		return r, fmt.Errorf("MCP client is not trusted or was revoked")
	}
	grant, err := st.GetActiveMCPDelegationGrant(r.Context(), p.Issuer, p.Subject, p.AuthorizedClientID, time.Now().UTC())
	if err != nil {
		return r, fmt.Errorf("active MCP delegation grant is required")
	}
	required := mcpProfileRequiredLevel(grant.AccessProfile)
	if grant.ProjectID != "" {
		if _, err = s.requireProjectAccess(r, grant.ProjectID, required); err != nil {
			return r, fmt.Errorf("current project RBAC no longer permits this grant")
		}
	} else if grant.OrganizationID != "" {
		if err = s.requireOrganizationAccess(r, grant.OrganizationID, required); err != nil {
			return r, fmt.Errorf("current organization RBAC no longer permits this grant")
		}
	} else if grant.AccessProfile != controlplane.MCPDelegationAdministration || !auth.HasAnyRole(p, "platform-admin") {
		return r, fmt.Errorf("current platform RBAC no longer permits this grant")
	}
	p.Authentication = "mcp-human"
	p.OrganizationID = grant.OrganizationID
	p.ProjectID = grant.ProjectID
	p.DelegationAccessProfile = string(grant.AccessProfile)
	return r.WithContext(auth.WithPrincipal(r.Context(), p)), nil
}
