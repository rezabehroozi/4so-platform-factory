package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

func cloneFinOpsRateCard(v FinOpsRateCard) FinOpsRateCard {
	rates := v.Rates
	v.Rates = make(map[FinOpsUsageMetric]int64, len(rates))
	for k, value := range rates {
		v.Rates[k] = value
	}
	if v.EffectiveUntil != nil {
		t := *v.EffectiveUntil
		v.EffectiveUntil = &t
	}
	return v
}

func cloneFinOpsUsageMeasurement(v FinOpsUsageMeasurement) FinOpsUsageMeasurement {
	metrics := v.Metrics
	v.Metrics = make(map[FinOpsUsageMetric]FinOpsMetricSample, len(metrics))
	for k, value := range metrics {
		v.Metrics[k] = value
	}
	return v
}

func cloneFinOpsCapacityObservation(v FinOpsCapacityObservation) FinOpsCapacityObservation {
	metrics := v.Metrics
	v.Metrics = make(map[FinOpsCapacityMetric]FinOpsMetricSample, len(metrics))
	for k, value := range metrics {
		v.Metrics[k] = value
	}
	return v
}

func finOpsUsageIdempotencyKey(v FinOpsUsageMeasurement) string {
	return v.ProjectID + "\x00" + v.Source + "\x00" + v.SourceEventID
}
func finOpsCapacityIdempotencyKey(v FinOpsCapacityObservation) string {
	return v.ProjectID + "\x00" + v.Source + "\x00" + v.SourceEventID
}

func (s *MemoryStore) validateFinOpsProjectScopeLocked(orgID, projectID, clusterID, workspaceID, virtualClusterID, namespace string) error {
	project, ok := s.projects[projectID]
	if !ok || project.OrganizationID != orgID {
		return fmt.Errorf("%w: FinOps project is outside organization authority", ErrValidation)
	}
	if clusterID != "" {
		cluster, ok := s.managedClusters[clusterID]
		if !ok || cluster.ProjectID != projectID {
			return fmt.Errorf("%w: FinOps cluster is outside project authority", ErrValidation)
		}
	}
	if workspaceID != "" {
		workspace, ok := s.workspaces[workspaceID]
		if !ok || workspace.ProjectID != projectID {
			return fmt.Errorf("%w: FinOps workspace is outside project authority", ErrValidation)
		}
	}
	if virtualClusterID != "" {
		v, ok := s.virtualClusters[virtualClusterID]
		if !ok {
			return fmt.Errorf("%w: FinOps virtual cluster does not exist", ErrValidation)
		}
		if v.ProjectID != projectID || v.WorkspaceID != workspaceID || v.HostClusterID != clusterID || v.HostNamespace != namespace {
			return fmt.Errorf("%w: FinOps virtual-cluster attribution does not match project/workspace/cluster/namespace authority", ErrValidation)
		}
	}
	return nil
}

func (s *MemoryStore) CreateFinOpsRateCard(_ context.Context, in FinOpsRateCard, actor string) (FinOpsRateCard, error) {
	normalized, err := NormalizeFinOpsRateCard(in)
	if err != nil {
		return FinOpsRateCard{}, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return FinOpsRateCard{}, fmt.Errorf("%w: actor is required", ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.organizations[normalized.OrganizationID]; !ok {
		return FinOpsRateCard{}, ErrNotFound
	}
	for _, existing := range s.finOpsRateCards {
		if existing.OrganizationID != normalized.OrganizationID {
			continue
		}
		if normalizeName(existing.Name) == normalizeName(normalized.Name) && existing.Version == normalized.Version {
			return FinOpsRateCard{}, ErrDuplicateName
		}
		if existing.Currency == normalized.Currency && finOpsIntervalsOverlap(existing.EffectiveFrom, existing.EffectiveUntil, normalized.EffectiveFrom, normalized.EffectiveUntil) {
			return FinOpsRateCard{}, ErrConflict
		}
	}
	now := nowUTC(s.now)
	normalized.ResourceMeta = ResourceMeta{ID: s.id("frc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	normalized = cloneFinOpsRateCard(normalized)
	s.finOpsRateCards[normalized.ID] = normalized
	s.appendAuditLocked(actor, "finops.rate_card.created", "finOpsRateCard", normalized.ID, normalized.Revision, map[string]any{"organizationId": normalized.OrganizationID, "currency": normalized.Currency, "digest": normalized.Digest})
	s.appendOutboxLocked("finOpsRateCard", normalized.ID, "finops.rate_card.created", normalized)
	return cloneFinOpsRateCard(normalized), nil
}

func (s *MemoryStore) GetFinOpsRateCard(_ context.Context, id string) (FinOpsRateCard, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.finOpsRateCards[id]
	if !ok {
		return FinOpsRateCard{}, ErrNotFound
	}
	return cloneFinOpsRateCard(v), nil
}
func (s *MemoryStore) ListFinOpsRateCards(_ context.Context, orgID string) ([]FinOpsRateCard, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []FinOpsRateCard{}
	for _, v := range s.finOpsRateCards {
		if orgID == "" || v.OrganizationID == orgID {
			out = append(out, cloneFinOpsRateCard(v))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EffectiveFrom.Equal(out[j].EffectiveFrom) {
			return out[i].ID < out[j].ID
		}
		return out[i].EffectiveFrom.Before(out[j].EffectiveFrom)
	})
	return out, nil
}

func (s *MemoryStore) CreateFinOpsUsageMeasurement(_ context.Context, in FinOpsUsageMeasurement, actor string) (FinOpsUsageMeasurement, bool, error) {
	normalized, err := NormalizeFinOpsUsageMeasurement(in)
	if err != nil {
		return FinOpsUsageMeasurement{}, false, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return FinOpsUsageMeasurement{}, false, fmt.Errorf("%w: actor is required", ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateFinOpsProjectScopeLocked(normalized.OrganizationID, normalized.ProjectID, normalized.ClusterID, normalized.WorkspaceID, normalized.VirtualClusterID, normalized.Namespace); err != nil {
		return FinOpsUsageMeasurement{}, false, err
	}
	key := finOpsUsageIdempotencyKey(normalized)
	for _, existing := range s.finOpsUsageMeasurements {
		if finOpsUsageIdempotencyKey(existing) != key {
			continue
		}
		if existing.Digest != normalized.Digest {
			return FinOpsUsageMeasurement{}, false, ErrIdempotencyConflict
		}
		return cloneFinOpsUsageMeasurement(existing), true, nil
	}
	now := nowUTC(s.now)
	normalized.ResourceMeta = ResourceMeta{ID: s.id("fus"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	normalized = cloneFinOpsUsageMeasurement(normalized)
	s.finOpsUsageMeasurements[normalized.ID] = normalized
	s.appendAuditLocked(actor, "finops.usage_measurement.created", "finOpsUsageMeasurement", normalized.ID, normalized.Revision, map[string]any{"organizationId": normalized.OrganizationID, "projectId": normalized.ProjectID, "virtualClusterId": normalized.VirtualClusterID, "source": normalized.Source, "digest": normalized.Digest})
	return cloneFinOpsUsageMeasurement(normalized), false, nil
}
func (s *MemoryStore) GetFinOpsUsageMeasurement(_ context.Context, id string) (FinOpsUsageMeasurement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.finOpsUsageMeasurements[id]
	if !ok {
		return FinOpsUsageMeasurement{}, ErrNotFound
	}
	return cloneFinOpsUsageMeasurement(v), nil
}
func (s *MemoryStore) ListFinOpsUsageMeasurements(_ context.Context, orgID, projectID string, from, until time.Time, limit int) ([]FinOpsUsageMeasurement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	out := []FinOpsUsageMeasurement{}
	for _, v := range s.finOpsUsageMeasurements {
		if orgID != "" && v.OrganizationID != orgID || projectID != "" && v.ProjectID != projectID {
			continue
		}
		if !from.IsZero() && v.WindowEnd.Before(from) {
			continue
		}
		if !until.IsZero() && v.WindowStart.After(until) {
			continue
		}
		out = append(out, cloneFinOpsUsageMeasurement(v))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].WindowStart.Equal(out[j].WindowStart) {
			return out[i].ID > out[j].ID
		}
		return out[i].WindowStart.After(out[j].WindowStart)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) CreateFinOpsCapacityObservation(_ context.Context, in FinOpsCapacityObservation, actor string) (FinOpsCapacityObservation, bool, error) {
	normalized, err := NormalizeFinOpsCapacityObservation(in)
	if err != nil {
		return FinOpsCapacityObservation{}, false, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return FinOpsCapacityObservation{}, false, fmt.Errorf("%w: actor is required", ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateFinOpsProjectScopeLocked(normalized.OrganizationID, normalized.ProjectID, normalized.ClusterID, "", "", ""); err != nil {
		return FinOpsCapacityObservation{}, false, err
	}
	key := finOpsCapacityIdempotencyKey(normalized)
	for _, existing := range s.finOpsCapacityObservations {
		if finOpsCapacityIdempotencyKey(existing) != key {
			continue
		}
		if existing.Digest != normalized.Digest {
			return FinOpsCapacityObservation{}, false, ErrIdempotencyConflict
		}
		return cloneFinOpsCapacityObservation(existing), true, nil
	}
	now := nowUTC(s.now)
	normalized.ResourceMeta = ResourceMeta{ID: s.id("fco"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	normalized = cloneFinOpsCapacityObservation(normalized)
	s.finOpsCapacityObservations[normalized.ID] = normalized
	s.appendAuditLocked(actor, "finops.capacity_observation.created", "finOpsCapacityObservation", normalized.ID, normalized.Revision, map[string]any{"organizationId": normalized.OrganizationID, "projectId": normalized.ProjectID, "source": normalized.Source, "digest": normalized.Digest})
	return cloneFinOpsCapacityObservation(normalized), false, nil
}
func (s *MemoryStore) GetFinOpsCapacityObservation(_ context.Context, id string) (FinOpsCapacityObservation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.finOpsCapacityObservations[id]
	if !ok {
		return FinOpsCapacityObservation{}, ErrNotFound
	}
	return cloneFinOpsCapacityObservation(v), nil
}
func (s *MemoryStore) ListFinOpsCapacityObservations(_ context.Context, orgID, projectID string, from, until time.Time, limit int) ([]FinOpsCapacityObservation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	out := []FinOpsCapacityObservation{}
	for _, v := range s.finOpsCapacityObservations {
		if orgID != "" && v.OrganizationID != orgID || projectID != "" && v.ProjectID != projectID {
			continue
		}
		if !from.IsZero() && v.ObservedAt.Before(from) {
			continue
		}
		if !until.IsZero() && v.ObservedAt.After(until) {
			continue
		}
		out = append(out, cloneFinOpsCapacityObservation(v))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].ObservedAt.After(out[j].ObservedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
