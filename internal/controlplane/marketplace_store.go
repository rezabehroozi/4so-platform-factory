package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func cloneMarketplaceRecommendation(v MarketplaceRecommendation) MarketplaceRecommendation {
	v.Items = append([]MarketplaceRecommendationItem(nil), v.Items...)
	return v
}

func ValidateMarketplaceRecommendation(v *MarketplaceRecommendation) error {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	v.Objective = strings.TrimSpace(v.Objective)
	v.Engine = strings.ToLower(strings.TrimSpace(v.Engine))
	v.Model = strings.TrimSpace(v.Model)
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	if v.ProjectID == "" || v.ClusterID == "" || v.Objective == "" || len(v.Objective) > 1000 {
		return fmt.Errorf("%w: projectId, clusterId and an objective up to 1000 characters are required", ErrValidation)
	}
	if v.Engine != "policy" && v.Engine != "model" {
		return fmt.Errorf("%w: recommendation engine must be policy or model", ErrValidation)
	}
	if v.Engine == "model" && v.Model == "" {
		return fmt.Errorf("%w: model name is required for model recommendations", ErrValidation)
	}
	if !strings.HasPrefix(v.ContextDigest, "sha256:") || !strings.HasPrefix(v.ResponseDigest, "sha256:") || !strings.HasPrefix(v.RequestDigest, "sha256:") || v.IdempotencyKey == "" {
		return fmt.Errorf("%w: recommendation digests and idempotency key are required", ErrValidation)
	}
	if len(v.Items) > 3 {
		return fmt.Errorf("%w: at most three recommendations are allowed", ErrValidation)
	}
	seen := map[string]bool{}
	for i := range v.Items {
		item := &v.Items[i]
		item.OfferID = strings.TrimSpace(item.OfferID)
		item.OfferVersion = strings.TrimSpace(item.OfferVersion)
		item.Reason = strings.TrimSpace(item.Reason)
		item.Risk = strings.ToLower(strings.TrimSpace(item.Risk))
		key := item.OfferID + "@" + item.OfferVersion
		if item.OfferID == "" || item.OfferVersion == "" || item.Score < 0 || item.Score > 100 || item.Reason == "" || len(item.Reason) > 500 || seen[key] {
			return fmt.Errorf("%w: recommendation items must be unique, scored 0-100 and include a concise reason", ErrValidation)
		}
		seen[key] = true
	}
	return nil
}

func (s *MemoryStore) CreateMarketplaceRecommendation(_ context.Context, v MarketplaceRecommendation, actor string) (MarketplaceRecommendation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ValidateMarketplaceRecommendation(&v); err != nil {
		return MarketplaceRecommendation{}, false, err
	}
	if _, ok := s.projects[v.ProjectID]; !ok {
		return MarketplaceRecommendation{}, false, ErrNotFound
	}
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || cluster.ProjectID != v.ProjectID {
		return MarketplaceRecommendation{}, false, ErrNotFound
	}
	for _, existing := range s.marketplaceRecommendations {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return MarketplaceRecommendation{}, false, ErrIdempotencyConflict
			}
			return cloneMarketplaceRecommendation(existing), true, nil
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("mrc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.RequestedBy = actor
	s.marketplaceRecommendations[v.ID] = cloneMarketplaceRecommendation(v)
	s.appendAuditLocked(actor, "marketplace_recommendation.created", "marketplaceRecommendation", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "engine": v.Engine, "itemCount": len(v.Items)})
	s.appendOutboxLocked("marketplaceRecommendation", v.ID, "marketplace_recommendation.created", v)
	return cloneMarketplaceRecommendation(v), false, nil
}

func (s *MemoryStore) GetMarketplaceRecommendation(_ context.Context, id string) (MarketplaceRecommendation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.marketplaceRecommendations[id]
	if !ok {
		return MarketplaceRecommendation{}, ErrNotFound
	}
	return cloneMarketplaceRecommendation(v), nil
}

func (s *MemoryStore) GetMarketplaceRecommendationByIdempotencyKey(_ context.Context, projectID, key string) (MarketplaceRecommendation, error) {
	projectID, key = strings.TrimSpace(projectID), strings.TrimSpace(key)
	if projectID == "" || key == "" {
		return MarketplaceRecommendation{}, ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.marketplaceRecommendations {
		if v.ProjectID == projectID && v.IdempotencyKey == key {
			return cloneMarketplaceRecommendation(v), nil
		}
	}
	return MarketplaceRecommendation{}, ErrNotFound
}

func (s *MemoryStore) ListMarketplaceRecommendations(_ context.Context, projectID, clusterID string) ([]MarketplaceRecommendation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []MarketplaceRecommendation{}
	for _, v := range s.marketplaceRecommendations {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) {
			out = append(out, cloneMarketplaceRecommendation(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
