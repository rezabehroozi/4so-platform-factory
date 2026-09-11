package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ListOperationsPage is the bounded operator-facing collection path for the
// in-memory/development authority. Its ordering intentionally matches the
// PostgreSQL production pager: most recently updated first, then newest
// creation time, then descending ID as a stable tie-breaker.
func (s *MemoryStore) ListOperationsPage(_ context.Context, projectID string, limit int) ([]Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listOperationsPageLocked(projectID, nil, limit), nil
}

// ListOperationsPageByProjects applies project authorization before LIMIT so
// unrelated tenant activity cannot evict an older authorized operation from a
// scoped page. The returned chronology matches PostgreSQL exactly.
func (s *MemoryStore) ListOperationsPageByProjects(_ context.Context, projectIDs []string, limit int) ([]Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	allowed := make(map[string]bool, len(projectIDs))
	for _, projectID := range projectIDs {
		projectID = strings.TrimSpace(projectID)
		if projectID != "" {
			allowed[projectID] = true
		}
	}
	if len(allowed) == 0 {
		return []Operation{}, nil
	}
	return s.listOperationsPageLocked("", allowed, limit), nil
}

func (s *MemoryStore) listOperationsPageLocked(projectID string, allowedProjects map[string]bool, limit int) []Operation {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	out := make([]Operation, 0, min(limit, len(s.operations)))
	for _, operation := range s.operations {
		if projectID != "" && operation.ProjectID != projectID {
			continue
		}
		if allowedProjects != nil && !allowedProjects[operation.ProjectID] {
			continue
		}
		out = append(out, operation)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].UpdatedAt.After(out[j].UpdatedAt)
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ListClaimableOperationsByKind is the bounded internal worker queue for
// operation kinds implemented by control-plane workers (for example durable
// support-bundle generation). It never claims work itself; ClaimOperation is
// still the sole lease/fence authority and closes races between replicas.
func (s *MemoryStore) ListClaimableOperationsByKind(_ context.Context, kind string, at time.Time, limit int) ([]Operation, error) {
	kind = strings.TrimSpace(kind)
	if kind == "" || limit <= 0 || limit > 200 {
		return nil, fmt.Errorf("%w: operation kind and limit 1..200 are required", ErrValidation)
	}
	at = at.UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Operation, 0, min(limit, len(s.operations)))
	for _, op := range s.operations {
		if op.Kind != kind {
			continue
		}
		eligible := op.State == OperationQueued ||
			(op.State == OperationRetryWait && op.NextAttemptAt != nil && !op.NextAttemptAt.After(at)) ||
			(op.State == OperationRunning && (op.LeaseExpiresAt == nil || !op.LeaseExpiresAt.After(at)))
		if !eligible {
			continue
		}
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool {
		// Retry due time is the effective eligibility boundary; queued work uses
		// creation time. Stable ID tie-break prevents map iteration drift.
		ai, aj := out[i].CreatedAt, out[j].CreatedAt
		if out[i].State == OperationRetryWait && out[i].NextAttemptAt != nil {
			ai = *out[i].NextAttemptAt
		}
		if out[j].State == OperationRetryWait && out[j].NextAttemptAt != nil {
			aj = *out[j].NextAttemptAt
		}
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListClaimableOperationsByKindTargetPrefix is the bounded target-worker queue.
// Filtering the target prefix before LIMIT prevents unrelated clusters from
// starving a connected Agent's read-only operation lane.
func (s *MemoryStore) ListClaimableOperationsByKindTargetPrefix(_ context.Context, kind, targetPrefix string, at time.Time, limit int) ([]Operation, error) {
	kind, targetPrefix = strings.TrimSpace(kind), strings.TrimSpace(targetPrefix)
	if kind == "" || targetPrefix == "" || limit <= 0 || limit > 200 {
		return nil, fmt.Errorf("%w: operation kind, target prefix and limit 1..200 are required", ErrValidation)
	}
	at = at.UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Operation, 0, min(limit, len(s.operations)))
	for _, op := range s.operations {
		if op.Kind != kind || !strings.HasPrefix(op.TargetRef, targetPrefix) {
			continue
		}
		eligible := op.State == OperationQueued ||
			(op.State == OperationRetryWait && op.NextAttemptAt != nil && !op.NextAttemptAt.After(at)) ||
			(op.State == OperationRunning && (op.LeaseExpiresAt == nil || !op.LeaseExpiresAt.After(at)))
		if !eligible {
			continue
		}
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].CreatedAt, out[j].CreatedAt
		if out[i].State == OperationRetryWait && out[i].NextAttemptAt != nil {
			ai = *out[i].NextAttemptAt
		}
		if out[j].State == OperationRetryWait && out[j].NextAttemptAt != nil {
			aj = *out[j].NextAttemptAt
		}
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
