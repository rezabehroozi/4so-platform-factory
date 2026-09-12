package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/reliability"
)

func (s *MemoryStore) CreateHealthObservation(_ context.Context, v reliability.HealthObservation) (reliability.HealthObservation, bool, error) {
	id, err := reliability.ObservationIdentity(v)
	if err != nil {
		return reliability.HealthObservation{}, false, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.healthObservations[id]; ok {
		return existing, false, nil
	}
	v.ID = id
	v.ObservedAt = v.ObservedAt.UTC()
	s.healthObservations[id] = v
	return v, true, nil
}

func (s *MemoryStore) ListHealthObservations(_ context.Context, projectID, clusterID string, from, until time.Time, limit int) ([]reliability.HealthObservation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows := make([]reliability.HealthObservation, 0)
	for _, v := range s.healthObservations {
		if v.ProjectID != projectID || (clusterID != "" && v.ClusterID != clusterID) {
			continue
		}
		at := v.ObservedAt.UTC()
		if !from.IsZero() && at.Before(from.UTC()) {
			continue
		}
		if !until.IsZero() && !at.Before(until.UTC()) {
			continue
		}
		rows = append(rows, v)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ObservedAt.Equal(rows[j].ObservedAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].ObservedAt.Before(rows[j].ObservedAt)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func (s *MemoryStore) CreateIncident(_ context.Context, v reliability.Incident, actor string) (reliability.Incident, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(v.OrganizationID) == "" || strings.TrimSpace(v.ProjectID) == "" || strings.TrimSpace(v.Severity) == "" {
		return reliability.Incident{}, fmt.Errorf("%w: incident scope, severity and actor are required", ErrValidation)
	}
	if v.State == "" {
		v.State = reliability.IncidentOpen
	}
	if v.State != reliability.IncidentOpen {
		return reliability.Incident{}, fmt.Errorf("%w: new incident must start OPEN", ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v.ID = s.id("inc")
	v.Revision = 1
	s.incidents[v.ID] = v
	return v, nil
}

func (s *MemoryStore) GetIncident(_ context.Context, id string) (reliability.Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.incidents[id]
	if !ok {
		return reliability.Incident{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListIncidents(_ context.Context, projectID, state string, limit int) ([]reliability.Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows := make([]reliability.Incident, 0)
	for _, v := range s.incidents {
		if v.ProjectID == projectID && (state == "" || v.State == state) {
			rows = append(rows, v)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func (s *MemoryStore) TransitionIncident(_ context.Context, id string, expected int64, action, actor, summary string) (reliability.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.incidents[id]
	if !ok {
		return reliability.Incident{}, ErrNotFound
	}
	if current.Revision != expected {
		return reliability.Incident{}, ErrConflict
	}
	next, err := reliability.TransitionIncident(current, action, actor, summary)
	if err != nil {
		return reliability.Incident{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	s.incidents[id] = next
	return next, nil
}

func (s *MemoryStore) CreateSLOPolicy(_ context.Context, v reliability.SLOPolicy, actor string) (reliability.SLOPolicy, error) {
	if strings.TrimSpace(actor) == "" {
		return reliability.SLOPolicy{}, fmt.Errorf("%w: actor is required", ErrValidation)
	}
	if err := reliability.ValidateSLOPolicy(v); err != nil {
		return reliability.SLOPolicy{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v.ID = s.id("slo")
	v.Revision = 1
	s.sloPolicies[v.ID] = v
	return v, nil
}

func (s *MemoryStore) CreateSLOPolicyRevision(_ context.Context, predecessor string, expected int64, next reliability.SLOPolicy, actor string) (reliability.SLOPolicy, error) {
	if strings.TrimSpace(actor) == "" {
		return reliability.SLOPolicy{}, fmt.Errorf("%w: actor is required", ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sloPolicies[predecessor]
	if !ok {
		return reliability.SLOPolicy{}, ErrNotFound
	}
	if current.Revision != expected {
		return reliability.SLOPolicy{}, ErrConflict
	}
	next.OrganizationID, next.ProjectID, next.Name = current.OrganizationID, current.ProjectID, current.Name
	next.Revision = current.Revision + 1
	if err := reliability.ValidateSLOPolicy(next); err != nil {
		return reliability.SLOPolicy{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	next.ID = s.id("slo")
	s.sloPolicies[next.ID] = next
	return next, nil
}

func (s *MemoryStore) GetSLOPolicy(_ context.Context, id string) (reliability.SLOPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.sloPolicies[id]
	if !ok {
		return reliability.SLOPolicy{}, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) ListSLOPolicies(_ context.Context, projectID, name string, limit int) ([]reliability.SLOPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows := make([]reliability.SLOPolicy, 0)
	for _, v := range s.sloPolicies {
		if v.ProjectID == projectID && (name == "" || v.Name == name) {
			rows = append(rows, v)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		if rows[i].Revision != rows[j].Revision {
			return rows[i].Revision < rows[j].Revision
		}
		return rows[i].ID < rows[j].ID
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

var _ ReliabilityStore = (*MemoryStore)(nil)
