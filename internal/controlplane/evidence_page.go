package controlplane

import (
	"context"
	"sort"
	"strings"
)

// ListEvidencePageByProject applies project ownership before LIMIT. Search and
// operator projections must never scan global evidence and filter it in
// process, because unrelated tenants could evict authorized rows and make the
// projection both expensive and incomplete.
func (s *MemoryStore) ListEvidencePageByProject(_ context.Context, projectID string, limit int) ([]EvidenceMetadata, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return []EvidenceMetadata{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	operationIDs := make(map[string]bool)
	for _, operation := range s.operations {
		if operation.ProjectID == projectID {
			operationIDs[operation.ID] = true
		}
	}
	out := make([]EvidenceMetadata, 0, min(limit, len(s.evidence)))
	for _, evidence := range s.evidence {
		if operationIDs[evidence.OperationID] {
			out = append(out, evidence)
		}
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
	return out, nil
}

func (s *MemoryStore) ListEvidencePageByOperation(_ context.Context, operationID string, limit int) ([]EvidenceMetadata, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return []EvidenceMetadata{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.operations[operationID]; !ok {
		return nil, ErrNotFound
	}
	out := make([]EvidenceMetadata, 0, min(limit, len(s.evidence)))
	for _, evidence := range s.evidence {
		if evidence.OperationID == operationID {
			out = append(out, evidence)
		}
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
	return out, nil
}
