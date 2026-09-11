package controlplane

import (
	"context"
	"sort"
	"strings"
	"time"
)

// ScopedOperationTrace is an operator-facing execution log record whose project
// ownership has already been resolved before pagination. It lets the API merge
// execution traces with audit and notification history without N+1 operation
// lookups or post-LIMIT authorization filtering.
type ScopedOperationTrace struct {
	OperationStepTrace
	ProjectID     string `json:"projectId"`
	OperationKind string `json:"operationKind"`
	TargetRef     string `json:"targetRef"`
}

// OperationsQueueItem is a read-only projection for the operator Queue Center.
// It never carries claim/transition controls; mutation authority remains with
// authenticated operation executors and notification workers.
type OperationsQueueItem struct {
	Lane           string     `json:"lane"`
	ID             string     `json:"id"`
	ProjectID      string     `json:"projectId,omitempty"`
	Kind           string     `json:"kind"`
	State          string     `json:"state"`
	Attempt        int        `json:"attempt,omitempty"`
	MaxAttempts    int        `json:"maxAttempts,omitempty"`
	LeaseOwner     string     `json:"leaseOwner,omitempty"`
	LeaseExpiresAt *time.Time `json:"leaseExpiresAt,omitempty"`
	NextAttemptAt  *time.Time `json:"nextAttemptAt,omitempty"`
	LastError      string     `json:"lastError,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

// ListOperationTracesPage returns the bounded global/development trace window.
// Global access is decided by the API; this method performs no authorization.
func (s *MemoryStore) ListOperationTracesPage(_ context.Context, operationID string, limit int) ([]ScopedOperationTrace, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	operationID = strings.TrimSpace(operationID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScopedOperationTrace, 0, min(limit, len(s.stepTraces)))
	for _, trace := range s.stepTraces {
		op, ok := s.operations[trace.OperationID]
		if !ok || (operationID != "" && op.ID != operationID) {
			continue
		}
		out = append(out, ScopedOperationTrace{OperationStepTrace: trace, ProjectID: op.ProjectID, OperationKind: op.Kind, TargetRef: op.TargetRef})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListOperationTracesPageByProjects scopes operation ownership before LIMIT.
// This is the in-memory/development equivalent of the PostgreSQL join-based
// pager and deliberately matches its newest-first ordering.
func (s *MemoryStore) ListOperationTracesPageByProjects(_ context.Context, projectIDs []string, operationID string, limit int) ([]ScopedOperationTrace, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	operationID = strings.TrimSpace(operationID)
	allowed := make(map[string]bool, len(projectIDs))
	for _, projectID := range projectIDs {
		projectID = strings.TrimSpace(projectID)
		if projectID != "" {
			allowed[projectID] = true
		}
	}
	if len(allowed) == 0 {
		return []ScopedOperationTrace{}, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScopedOperationTrace, 0, min(limit, len(s.stepTraces)))
	for _, trace := range s.stepTraces {
		op, ok := s.operations[trace.OperationID]
		if !ok || !allowed[op.ProjectID] || (operationID != "" && op.ID != operationID) {
			continue
		}
		out = append(out, ScopedOperationTrace{OperationStepTrace: trace, ProjectID: op.ProjectID, OperationKind: op.Kind, TargetRef: op.TargetRef})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
