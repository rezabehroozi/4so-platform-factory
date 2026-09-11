package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func ValidateRuntimeClosureCampaign(v *RuntimeClosureCampaign) error {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	v.BaselineDeploymentID = strings.TrimSpace(v.BaselineDeploymentID)
	v.RuntimeVerificationID = strings.TrimSpace(v.RuntimeVerificationID)
	v.DesiredDigest = strings.TrimSpace(v.DesiredDigest)
	v.ObservedDigest = strings.TrimSpace(v.ObservedDigest)
	v.EvidenceDigest = strings.TrimSpace(v.EvidenceDigest)
	v.ReleaseArtifactDigest = strings.TrimSpace(v.ReleaseArtifactDigest)
	v.ProducerBinaryDigest = strings.TrimSpace(v.ProducerBinaryDigest)
	v.NextAction = strings.TrimSpace(v.NextAction)
	v.Summary = strings.TrimSpace(v.Summary)
	v.LastError = strings.TrimSpace(v.LastError)
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	v.RequestDigest = strings.TrimSpace(v.RequestDigest)
	if v.ProjectID == "" || v.ClusterID == "" || v.BaselineDeploymentID == "" {
		return fmt.Errorf("%w: projectId, clusterId and baselineDeploymentId are required", ErrValidation)
	}
	if !strings.HasPrefix(v.DesiredDigest, "sha256:") || !strings.HasPrefix(v.RequestDigest, "sha256:") || v.IdempotencyKey == "" {
		return fmt.Errorf("%w: desired digest, request digest and idempotency key are required", ErrValidation)
	}
	if v.NextAction == "" {
		return fmt.Errorf("%w: nextAction is required", ErrValidation)
	}
	if v.EvidenceSchemaVersion == 0 {
		if v.ReleaseArtifactDigest != "" || v.ProducerBinaryDigest != "" {
			return fmt.Errorf("%w: legacy runtime closure campaign must not contain exact-release identity", ErrValidation)
		}
	} else if v.EvidenceSchemaVersion == 2 {
		for name, value := range map[string]string{"releaseArtifactDigest": v.ReleaseArtifactDigest, "producerBinaryDigest": v.ProducerBinaryDigest} {
			if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
				return fmt.Errorf("%w: %s must be a lowercase sha256 digest", ErrValidation, name)
			}
			for _, ch := range value[len("sha256:"):] {
				if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
					return fmt.Errorf("%w: %s must be a lowercase sha256 digest", ErrValidation, name)
				}
			}
		}
	} else {
		return fmt.Errorf("%w: unsupported runtime closure evidence schema version", ErrValidation)
	}
	switch v.State {
	case RuntimeClosureWaitingBaseline, RuntimeClosureWaitingApproval, RuntimeClosureWaitingVerification, RuntimeClosureFailed:
		return nil
	default:
		return fmt.Errorf("%w: invalid initial runtime closure state", ErrValidation)
	}
}

func runtimeClosureTransitionAllowed(from, to RuntimeClosureCampaignState) bool {
	if from == to {
		return true
	}
	switch from {
	case RuntimeClosureWaitingBaseline:
		return to == RuntimeClosureWaitingApproval || to == RuntimeClosureWaitingVerification || to == RuntimeClosureFailed
	case RuntimeClosureWaitingApproval:
		return to == RuntimeClosureWaitingBaseline || to == RuntimeClosureWaitingVerification || to == RuntimeClosureFailed
	case RuntimeClosureWaitingVerification:
		return to == RuntimeClosureSucceeded || to == RuntimeClosureFailed
	case RuntimeClosureFailed:
		return to == RuntimeClosureWaitingBaseline || to == RuntimeClosureWaitingApproval || to == RuntimeClosureWaitingVerification
	default:
		return false
	}
}

func (s *MemoryStore) CreateRuntimeClosureCampaign(_ context.Context, v RuntimeClosureCampaign, actor string) (RuntimeClosureCampaign, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ValidateRuntimeClosureCampaign(&v); err != nil {
		return RuntimeClosureCampaign{}, false, err
	}
	if _, ok := s.projects[v.ProjectID]; !ok {
		return RuntimeClosureCampaign{}, false, ErrNotFound
	}
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || cluster.ProjectID != v.ProjectID {
		return RuntimeClosureCampaign{}, false, ErrNotFound
	}
	baseline, ok := s.baselineDeployments[v.BaselineDeploymentID]
	if !ok || baseline.ProjectID != v.ProjectID || baseline.ClusterID != v.ClusterID || baseline.DesiredDigest != v.DesiredDigest {
		return RuntimeClosureCampaign{}, false, ErrNotFound
	}
	for _, existing := range s.runtimeClosureCampaigns {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return RuntimeClosureCampaign{}, false, ErrIdempotencyConflict
			}
			return existing, true, nil
		}
		if existing.BaselineDeploymentID == v.BaselineDeploymentID {
			return RuntimeClosureCampaign{}, false, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("rcc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.RequestedBy = actor
	v.StartedAt = &now
	if v.State == RuntimeClosureFailed {
		v.FinishedAt = &now
	}
	s.runtimeClosureCampaigns[v.ID] = v
	s.appendAuditLocked(actor, "runtime_closure.created", "runtimeClosureCampaign", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "baselineDeploymentId": v.BaselineDeploymentID, "state": v.State})
	s.appendOutboxLocked("runtimeClosureCampaign", v.ID, "runtime_closure.created", v)
	return v, false, nil
}

func (s *MemoryStore) GetRuntimeClosureCampaign(_ context.Context, id string) (RuntimeClosureCampaign, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.runtimeClosureCampaigns[id]
	if !ok {
		return RuntimeClosureCampaign{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListRuntimeClosureCampaigns(_ context.Context, projectID, clusterID string) ([]RuntimeClosureCampaign, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []RuntimeClosureCampaign{}
	for _, v := range s.runtimeClosureCampaigns {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) UpdateRuntimeClosureCampaign(_ context.Context, id string, expected int64, update RuntimeClosureCampaignUpdate, actor string) (RuntimeClosureCampaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.runtimeClosureCampaigns[id]
	if !ok {
		return RuntimeClosureCampaign{}, ErrNotFound
	}
	if v.Revision != expected {
		return RuntimeClosureCampaign{}, ErrConflict
	}
	if !runtimeClosureTransitionAllowed(v.State, update.State) {
		return RuntimeClosureCampaign{}, ErrInvalidTransition
	}
	update.RuntimeVerificationID = strings.TrimSpace(update.RuntimeVerificationID)
	if v.RuntimeVerificationID != "" && update.RuntimeVerificationID != "" && v.RuntimeVerificationID != update.RuntimeVerificationID {
		return RuntimeClosureCampaign{}, fmt.Errorf("%w: runtime verification binding is immutable", ErrValidation)
	}
	if update.RuntimeVerificationID != "" {
		verification, exists := s.runtimeVerifications[update.RuntimeVerificationID]
		if !exists || verification.ProjectID != v.ProjectID || verification.ClusterID != v.ClusterID || verification.BaselineDeploymentID != v.BaselineDeploymentID {
			return RuntimeClosureCampaign{}, ErrNotFound
		}
		v.RuntimeVerificationID = update.RuntimeVerificationID
	}
	if update.State == RuntimeClosureSucceeded {
		verification, exists := s.runtimeVerifications[v.RuntimeVerificationID]
		if !exists || verification.State != RuntimeVerificationSucceeded || verification.DesiredDigest != verification.ObservedDigest || verification.DesiredDigest != v.DesiredDigest || !strings.HasPrefix(update.EvidenceDigest, "sha256:") {
			return RuntimeClosureCampaign{}, ErrInvalidTransition
		}
	}
	if update.State == RuntimeClosureFailed && strings.TrimSpace(update.LastError) == "" {
		return RuntimeClosureCampaign{}, fmt.Errorf("%w: failed campaign requires lastError", ErrValidation)
	}
	if strings.TrimSpace(update.NextAction) == "" {
		return RuntimeClosureCampaign{}, fmt.Errorf("%w: nextAction is required", ErrValidation)
	}
	now := nowUTC(s.now)
	v.State = update.State
	v.ObservedDigest = strings.TrimSpace(update.ObservedDigest)
	v.EvidenceDigest = strings.TrimSpace(update.EvidenceDigest)
	v.NextAction = strings.TrimSpace(update.NextAction)
	v.Summary = strings.TrimSpace(update.Summary)
	v.LastError = strings.TrimSpace(update.LastError)
	if v.State == RuntimeClosureSucceeded || v.State == RuntimeClosureFailed {
		v.FinishedAt = &now
	} else {
		v.FinishedAt = nil
	}
	v.Revision++
	v.UpdatedAt = now
	s.runtimeClosureCampaigns[v.ID] = v
	action := "runtime_closure." + strings.ToLower(string(v.State))
	s.appendAuditLocked(actor, action, "runtimeClosureCampaign", v.ID, v.Revision, map[string]any{"nextAction": v.NextAction, "runtimeVerificationId": v.RuntimeVerificationID})
	s.appendOutboxLocked("runtimeClosureCampaign", v.ID, action, v)
	return v, nil
}
