package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func validateAgentCertificate(v AgentCertificate) error {
	if strings.TrimSpace(v.ClusterID) == "" || strings.TrimSpace(v.SerialNumber) == "" || !strings.HasPrefix(v.Fingerprint, "sha256:") || strings.TrimSpace(v.Subject) == "" || v.NotBefore.IsZero() || v.NotAfter.IsZero() || !v.NotAfter.After(v.NotBefore) {
		return fmt.Errorf("%w: invalid agent certificate metadata", ErrValidation)
	}
	return nil
}

func (s *MemoryStore) CreateAgentCertificate(_ context.Context, v AgentCertificate, actor string) (AgentCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateAgentCertificate(v); err != nil {
		return AgentCertificate{}, err
	}
	if _, ok := s.managedClusters[v.ClusterID]; !ok {
		return AgentCertificate{}, ErrNotFound
	}
	for _, x := range s.agentCertificates {
		if x.SerialNumber == v.SerialNumber {
			return AgentCertificate{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("acert"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = AgentCertificateActive
	v.IssuedBy = strings.TrimSpace(actor)
	s.agentCertificates[v.ID] = v
	s.appendAuditLocked(actor, "agent_certificate.issued", "agentCertificate", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "serialNumber": v.SerialNumber, "fingerprint": v.Fingerprint, "notAfter": v.NotAfter})
	s.appendOutboxLocked("agentCertificate", v.ID, "agent_certificate.issued", v)
	return v, nil
}
func (s *MemoryStore) GetAgentCertificate(_ context.Context, id string) (AgentCertificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.agentCertificates[id]
	if !ok {
		return AgentCertificate{}, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) GetAgentCertificateBySerial(_ context.Context, serial string) (AgentCertificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.agentCertificates {
		if v.SerialNumber == strings.ToLower(strings.TrimSpace(serial)) {
			return v, nil
		}
	}
	return AgentCertificate{}, ErrNotFound
}
func (s *MemoryStore) ListAgentCertificates(_ context.Context, clusterID string) ([]AgentCertificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []AgentCertificate{}
	for _, v := range s.agentCertificates {
		if clusterID == "" || v.ClusterID == clusterID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (s *MemoryStore) RotateAgentCertificate(_ context.Context, oldID string, next AgentCertificate, actor string) (AgentCertificate, AgentCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.agentCertificates[oldID]
	if !ok {
		return AgentCertificate{}, AgentCertificate{}, ErrNotFound
	}
	if old.State != AgentCertificateActive {
		return AgentCertificate{}, AgentCertificate{}, ErrInvalidTransition
	}
	if err := validateAgentCertificate(next); err != nil {
		return AgentCertificate{}, AgentCertificate{}, err
	}
	if next.ClusterID != old.ClusterID {
		return AgentCertificate{}, AgentCertificate{}, ErrValidation
	}
	for _, x := range s.agentCertificates {
		if x.SerialNumber == next.SerialNumber {
			return AgentCertificate{}, AgentCertificate{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	next.ResourceMeta = ResourceMeta{ID: s.id("acert"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	next.State = AgentCertificateActive
	next.IssuedBy = strings.TrimSpace(actor)
	s.agentCertificates[next.ID] = next
	old.State = AgentCertificateRevoked
	old.RevokedBy = strings.TrimSpace(actor)
	old.RevokedAt = &now
	old.ReplacedByID = next.ID
	old.Revision++
	old.UpdatedAt = now
	s.agentCertificates[old.ID] = old
	s.appendAuditLocked(actor, "agent_certificate.rotated", "agentCertificate", old.ID, old.Revision, map[string]any{"clusterId": old.ClusterID, "replacementId": next.ID, "replacementFingerprint": next.Fingerprint})
	s.appendOutboxLocked("agentCertificate", next.ID, "agent_certificate.rotated", map[string]any{"previous": old, "replacement": next})
	return old, next, nil
}
func (s *MemoryStore) RevokeAgentCertificate(_ context.Context, id string, rev int64, actor string) (AgentCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.agentCertificates[id]
	if !ok {
		return AgentCertificate{}, ErrNotFound
	}
	if v.Revision != rev {
		return AgentCertificate{}, ErrConflict
	}
	if v.State == AgentCertificateRevoked {
		return v, nil
	}
	now := nowUTC(s.now)
	v.State = AgentCertificateRevoked
	v.RevokedBy = strings.TrimSpace(actor)
	v.RevokedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.agentCertificates[id] = v
	s.appendAuditLocked(actor, "agent_certificate.revoked", "agentCertificate", id, v.Revision, map[string]any{"clusterId": v.ClusterID, "serialNumber": v.SerialNumber})
	s.appendOutboxLocked("agentCertificate", id, "agent_certificate.revoked", v)
	return v, nil
}
func (s *MemoryStore) revokeAgentCertificatesLocked(clusterID, actor string) {
	now := nowUTC(s.now)
	for id, v := range s.agentCertificates {
		if v.ClusterID == clusterID && v.State == AgentCertificateActive {
			v.State = AgentCertificateRevoked
			v.RevokedBy = actor
			v.RevokedAt = &now
			v.Revision++
			v.UpdatedAt = now
			s.agentCertificates[id] = v
			s.appendAuditLocked(actor, "agent_certificate.revoked", "agentCertificate", id, v.Revision, map[string]any{"clusterId": clusterID, "reason": "managed-cluster-revoked"})
		}
	}
}
