package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

func ValidateRecoveryCheckpointCreate(v *RecoveryCheckpoint, cluster ManagedCluster, now time.Time) error {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	v.Provider = strings.TrimSpace(v.Provider)
	v.Reference = strings.TrimSpace(v.Reference)
	v.EvidenceDigest = strings.TrimSpace(v.EvidenceDigest)
	if v.ProjectID == "" || v.ClusterID == "" || v.Provider == "" || v.Reference == "" || !strings.HasPrefix(v.EvidenceDigest, "sha256:") {
		return fmt.Errorf("%w: project, cluster, provider, reference and evidence digest are required", ErrValidation)
	}
	if cluster.ProjectID != v.ProjectID || cluster.ID != v.ClusterID {
		return ErrNotFound
	}
	if strings.TrimSpace(cluster.InventoryDigest) == "" || !strings.HasPrefix(cluster.InventoryDigest, "sha256:") {
		return fmt.Errorf("%w: cluster must have fresh inventory before recovery evidence can be registered", ErrPrerequisite)
	}
	if v.CompletedAt.IsZero() || v.CompletedAt.After(now.Add(time.Minute)) {
		return fmt.Errorf("%w: completedAt must describe a completed backup", ErrValidation)
	}
	if v.ExpiresAt.IsZero() || !v.ExpiresAt.After(now) || !v.ExpiresAt.After(v.CompletedAt) {
		return fmt.Errorf("%w: expiresAt must be after completedAt and in the future", ErrValidation)
	}
	return nil
}

func (s *MemoryStore) CreateRecoveryCheckpoint(_ context.Context, v RecoveryCheckpoint, actor string) (RecoveryCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok {
		return RecoveryCheckpoint{}, ErrNotFound
	}
	now := nowUTC(s.now)
	if err := ValidateRecoveryCheckpointCreate(&v, cluster, now); err != nil {
		return RecoveryCheckpoint{}, err
	}
	for _, existing := range s.recoveryCheckpoints {
		if existing.ProjectID == v.ProjectID && existing.ClusterID == v.ClusterID && existing.EvidenceDigest == v.EvidenceDigest && existing.State != RecoveryCheckpointRevoked {
			return RecoveryCheckpoint{}, ErrDuplicateName
		}
	}
	v.ResourceMeta = ResourceMeta{ID: s.id("rcp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.InventoryDigest = cluster.InventoryDigest
	v.State = RecoveryCheckpointVerified
	v.RequestedBy = actor
	s.recoveryCheckpoints[v.ID] = v
	s.appendAuditLocked(actor, "recovery_checkpoint.registered", "recoveryCheckpoint", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "provider": v.Provider, "evidenceDigest": v.EvidenceDigest})
	s.appendOutboxLocked("recoveryCheckpoint", v.ID, "recovery_checkpoint.verified", v)
	return v, nil
}

func (s *MemoryStore) GetRecoveryCheckpoint(_ context.Context, id string) (RecoveryCheckpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.recoveryCheckpoints[id]
	if !ok {
		return RecoveryCheckpoint{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListRecoveryCheckpoints(_ context.Context, projectID, clusterID string) ([]RecoveryCheckpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []RecoveryCheckpoint{}
	for _, v := range s.recoveryCheckpoints {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) RevokeRecoveryCheckpoint(_ context.Context, id string, expected int64, actor string) (RecoveryCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.recoveryCheckpoints[id]
	if !ok {
		return RecoveryCheckpoint{}, ErrNotFound
	}
	if v.Revision != expected {
		return RecoveryCheckpoint{}, ErrConflict
	}
	if v.State != RecoveryCheckpointVerified {
		return RecoveryCheckpoint{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	v.State = RecoveryCheckpointRevoked
	v.RevokedBy = actor
	v.RevokedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.recoveryCheckpoints[id] = v
	s.appendAuditLocked(actor, "recovery_checkpoint.revoked", "recoveryCheckpoint", id, v.Revision, nil)
	s.appendOutboxLocked("recoveryCheckpoint", id, "recovery_checkpoint.revoked", v)
	return v, nil
}
