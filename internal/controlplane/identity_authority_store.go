package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func (s *MemoryStore) CreateOIDCGroupMapping(_ context.Context, v OIDCGroupMapping, actor string) (OIDCGroupMapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Group = strings.TrimSpace(v.Group)
	v.ProductRole = strings.TrimSpace(v.ProductRole)
	v.OrganizationID = strings.TrimSpace(v.OrganizationID)
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ProjectRole = strings.TrimSpace(v.ProjectRole)
	if err := ValidateOIDCGroupMapping(v); err != nil {
		return OIDCGroupMapping{}, err
	}
	for _, cur := range s.oidcGroupMappings {
		if cur.State == OIDCGroupMappingActive && cur.Group == v.Group && cur.ProductRole == v.ProductRole && cur.OrganizationID == v.OrganizationID && cur.OrganizationRole == v.OrganizationRole && cur.ProjectID == v.ProjectID && cur.ProjectRole == v.ProjectRole {
			return OIDCGroupMapping{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("ogm"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = OIDCGroupMappingActive
	v.CreatedBy = strings.TrimSpace(actor)
	s.oidcGroupMappings[v.ID] = v
	s.appendAuditLocked(actor, "oidc_group_mapping.created", "oidcGroupMapping", v.ID, v.Revision, map[string]any{"group": v.Group, "productRole": v.ProductRole, "organizationId": v.OrganizationID, "projectId": v.ProjectID})
	s.appendOutboxLocked("oidcGroupMapping", v.ID, "oidc_group_mapping.created", v)
	return v, nil
}
func (s *MemoryStore) ListOIDCGroupMappings(_ context.Context, state OIDCGroupMappingState) ([]OIDCGroupMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []OIDCGroupMapping{}
	for _, v := range s.oidcGroupMappings {
		if state == "" || v.State == state {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group == out[j].Group {
			return out[i].ID < out[j].ID
		}
		return out[i].Group < out[j].Group
	})
	return out, nil
}
func (s *MemoryStore) RevokeOIDCGroupMapping(_ context.Context, id string, expected int64, actor string) (OIDCGroupMapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.oidcGroupMappings[strings.TrimSpace(id)]
	if !ok {
		return OIDCGroupMapping{}, ErrNotFound
	}
	if v.Revision != expected {
		return OIDCGroupMapping{}, ErrConflict
	}
	if v.State == OIDCGroupMappingRevoked {
		return v, nil
	}
	now := nowUTC(s.now)
	v.Revision++
	v.State = OIDCGroupMappingRevoked
	v.RevokedBy = strings.TrimSpace(actor)
	v.RevokedAt = &now
	v.UpdatedAt = now
	s.oidcGroupMappings[v.ID] = v
	s.appendAuditLocked(actor, "oidc_group_mapping.revoked", "oidcGroupMapping", v.ID, v.Revision, map[string]any{"group": v.Group})
	s.appendOutboxLocked("oidcGroupMapping", v.ID, "oidc_group_mapping.revoked", v)
	return v, nil
}
func (s *MemoryStore) ResolveOIDCGroups(_ context.Context, groups []string) (OIDCGroupResolution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := make([]OIDCGroupMapping, 0, len(s.oidcGroupMappings))
	for _, v := range s.oidcGroupMappings {
		all = append(all, v)
	}
	return ResolveOIDCGroupMappings(all, groups), nil
}
func (s *MemoryStore) AppendSecurityAudit(_ context.Context, in SecurityAuditInput) (SecurityAuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(in.Category) == "" || strings.TrimSpace(in.Decision) == "" {
		return SecurityAuditEvent{}, fmt.Errorf("%w: security audit category and decision are required", ErrValidation)
	}
	seq := int64(len(s.securityAudit) + 1)
	prev := ""
	if len(s.securityAudit) > 0 {
		prev = s.securityAudit[len(s.securityAudit)-1].Digest
	}
	v := SecurityAuditEvent{ID: s.id("sau"), Sequence: seq, OccurredAt: nowUTC(s.now), MethodVersion: SecurityAuditMethod, SecurityAuditInput: in, PreviousDigest: prev}
	if strings.TrimSpace(v.ActorID) == "" {
		v.ActorID = "anonymous"
	}
	v.Digest = SecurityAuditEventDigest(v)
	s.securityAudit = append(s.securityAudit, v)
	return v, nil
}
func (s *MemoryStore) ListSecurityAudit(_ context.Context, limit int) ([]SecurityAuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	start := len(s.securityAudit) - limit
	if start < 0 {
		start = 0
	}
	out := append([]SecurityAuditEvent(nil), s.securityAudit[start:]...)
	return out, nil
}
