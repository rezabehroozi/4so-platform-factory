package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func cloneFinOpsBudgetPolicy(v FinOpsBudgetPolicy) FinOpsBudgetPolicy {
	if v.EffectiveUntil != nil {
		t := *v.EffectiveUntil
		v.EffectiveUntil = &t
	}
	return v
}

func (s *MemoryStore) CreateFinOpsBudgetPolicy(_ context.Context, in FinOpsBudgetPolicy, actor string) (FinOpsBudgetPolicy, error) {
	normalized, err := NormalizeFinOpsBudgetPolicy(in)
	if err != nil {
		return FinOpsBudgetPolicy{}, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return FinOpsBudgetPolicy{}, fmt.Errorf("%w: actor is required", ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.organizations[normalized.OrganizationID]; !ok {
		return FinOpsBudgetPolicy{}, ErrNotFound
	}
	if normalized.ProjectID != "" {
		project, ok := s.projects[normalized.ProjectID]
		if !ok {
			return FinOpsBudgetPolicy{}, ErrNotFound
		}
		if project.OrganizationID != normalized.OrganizationID {
			return FinOpsBudgetPolicy{}, fmt.Errorf("%w: FinOps budget project is outside organization authority", ErrValidation)
		}
	}
	for _, existing := range s.finOpsBudgetPolicies {
		if existing.OrganizationID != normalized.OrganizationID || existing.ProjectID != normalized.ProjectID {
			continue
		}
		if normalizeName(existing.Name) == normalizeName(normalized.Name) && existing.Version == normalized.Version {
			return FinOpsBudgetPolicy{}, ErrDuplicateName
		}
		if existing.Currency == normalized.Currency && finOpsIntervalsOverlap(existing.EffectiveFrom, existing.EffectiveUntil, normalized.EffectiveFrom, normalized.EffectiveUntil) {
			return FinOpsBudgetPolicy{}, ErrConflict
		}
	}
	now := nowUTC(s.now)
	normalized.ResourceMeta = ResourceMeta{ID: s.id("fbp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	normalized = cloneFinOpsBudgetPolicy(normalized)
	s.finOpsBudgetPolicies[normalized.ID] = normalized
	s.appendAuditLocked(actor, "finops.budget_policy.created", "finOpsBudgetPolicy", normalized.ID, normalized.Revision, map[string]any{"organizationId": normalized.OrganizationID, "projectId": normalized.ProjectID, "currency": normalized.Currency, "digest": normalized.Digest})
	s.appendOutboxLocked("finOpsBudgetPolicy", normalized.ID, "finops.budget_policy.created", normalized)
	return cloneFinOpsBudgetPolicy(normalized), nil
}

func (s *MemoryStore) GetFinOpsBudgetPolicy(_ context.Context, id string) (FinOpsBudgetPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.finOpsBudgetPolicies[id]
	if !ok {
		return FinOpsBudgetPolicy{}, ErrNotFound
	}
	return cloneFinOpsBudgetPolicy(v), nil
}

func (s *MemoryStore) ListFinOpsBudgetPolicies(_ context.Context, orgID, projectID string) ([]FinOpsBudgetPolicy, error) {
	orgID = strings.TrimSpace(orgID)
	projectID = strings.TrimSpace(projectID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []FinOpsBudgetPolicy{}
	for _, v := range s.finOpsBudgetPolicies {
		if orgID != "" && v.OrganizationID != orgID {
			continue
		}
		if projectID != "" && v.ProjectID != projectID {
			continue
		}
		out = append(out, cloneFinOpsBudgetPolicy(v))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EffectiveFrom.Equal(out[j].EffectiveFrom) {
			return out[i].ID < out[j].ID
		}
		return out[i].EffectiveFrom.Before(out[j].EffectiveFrom)
	})
	return out, nil
}
