package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

const (
	serviceHealthResultLimit      = 200
	serviceHealthObservationLimit = 500
	serviceHealthStaleAfter       = 5 * time.Minute
)

type operatorServiceHealth struct {
	Service        string     `json:"service"`
	ClusterID      string     `json:"clusterId"`
	Health         string     `json:"health"`
	CoverageStatus string     `json:"coverageStatus"`
	Reason         string     `json:"reason,omitempty"`
	ObservedAt     *time.Time `json:"observedAt,omitempty"`
}

func (s *Server) serviceHealth(w http.ResponseWriter, r *http.Request) {
	s.serviceHealthAt(w, r, time.Now().UTC())
}
func (s *Server) serviceHealthAt(w http.ResponseWriter, r *http.Request, now time.Time) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_REQUIRED", "projectId is required for service health")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	pager, ok := s.store.(managedClusterPageStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "BOUNDED_SERVICE_HEALTH_UNAVAILABLE", "service health requires bounded cluster paging")
		return
	}
	reliabilityStore, ok := s.store.(controlplane.ReliabilityStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "RELIABILITY_STORE_UNAVAILABLE", "reliability authority is unavailable")
		return
	}
	clusters, err := pager.ListManagedClustersPage(r.Context(), []string{projectID}, false, nil, serviceHealthResultLimit+1)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	truncated := len(clusters) > serviceHealthResultLimit
	if truncated {
		clusters = clusters[:serviceHealthResultLimit]
	}
	w.Header().Set("X-4SO-Result-Limit", fmt.Sprint(serviceHealthResultLimit))
	now = now.UTC()
	from := now.Add(-serviceHealthStaleAfter)
	until := now.Add(time.Nanosecond)
	rows := make([]operatorServiceHealth, 0, len(clusters))
	summary := map[string]int{"total": len(clusters), "healthy": 0, "warning": 0, "degraded": 0, "stale": 0, "critical": 0, "unknown": 0}
	coverage := reliability.CoverageComplete
	if len(clusters) == 0 || truncated {
		coverage = reliability.CoverageUnknown
	}
	for _, cluster := range clusters {
		observations, err := reliabilityStore.ListHealthObservations(r.Context(), projectID, cluster.ID, from, until, serviceHealthObservationLimit)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		row := operatorServiceHealth{Service: "cluster-runtime", ClusterID: cluster.ID, Health: reliability.CoverageUnknown, CoverageStatus: reliability.CoverageUnknown}
		if len(observations) == 0 {
			row.Reason = "MISSING_OR_STALE"
			coverage = reliability.CoverageUnknown
			summary["unknown"]++
			rows = append(rows, row)
			continue
		}
		if len(observations) >= serviceHealthObservationLimit {
			row.Reason = "INCOMPLETE"
			coverage = reliability.CoverageUnknown
			summary["unknown"]++
			rows = append(rows, row)
			continue
		}
		latest := observations[len(observations)-1]
		observedAt := latest.ObservedAt.UTC()
		row.ObservedAt = &observedAt
		row.CoverageStatus = reliability.CoverageComplete
		switch latest.Health {
		case "HEALTHY", "WARNING", "DEGRADED", "STALE", "CRITICAL":
			row.Health = latest.Health
			summary[strings.ToLower(latest.Health)]++
		default:
			row.Health = reliability.CoverageUnknown
			row.CoverageStatus = reliability.CoverageUnknown
			row.Reason = "UNRECOGNIZED_HEALTH"
			coverage = reliability.CoverageUnknown
			summary["unknown"]++
		}
		rows = append(rows, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":      reliability.ServiceHealthAuthority,
		"projectId":      projectID,
		"generatedAt":    now,
		"coverageStatus": coverage,
		"bounded":        true,
		"resultLimit":    serviceHealthResultLimit,
		"truncated":      truncated,
		"summary":        summary,
		"services":       rows,
	})
}
