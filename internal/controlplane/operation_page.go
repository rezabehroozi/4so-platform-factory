package controlplane

import (
	"context"
	"sort"
	"strings"
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
