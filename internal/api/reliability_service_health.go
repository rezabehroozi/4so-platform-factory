package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

const (
	serviceHealthObservationCap  = 500
	serviceHealthStaleAfter       = 5 * time.Minute
	serviceHealthCoverageComplete = "COMPLETE"
	serviceHealthCoverageUnknown  = "UNKNOWN"
)

type serviceHealthClusterProjection struct {
	ClusterID      string     `json:"clusterId"`
	Health         string     `json:"health"`
	CoverageStatus string     `json:"coverageStatus"`
	ObservedAt     *time.Time `json:"observedAt,omitempty"`
	Reason         string     `json:"reason,omitempty"`
}

type serviceHealthProjection struct {
	Authority        string                           `json:"authority"`
	ProjectID        string                           `json:"projectId"`
	CoverageStatus   string                           `json:"coverageStatus"`
	Truncated        bool                             `json:"truncated"`
	ClusterCount     int                              `json:"clusterCount"`
	ReturnedClusters int                              `json:"returnedClusters"`
	Summary          map[string]int                   `json:"summary"`
	Clusters         []serviceHealthClusterProjection `json:"clusters"`
}

func knownReliabilityHealth(value string) bool {
	switch value {
	case "HEALTHY", "WARNING", "DEGRADED", "STALE", "CRITICAL":
		return true
	default:
		return false
	}
}

func markServiceHealthPageIncomplete(projection serviceHealthProjection, incomplete bool) serviceHealthProjection {
	if incomplete {
		projection.Truncated = true
		projection.CoverageStatus = serviceHealthCoverageUnknown
	}
	return projection
}

func projectServiceHealth(projectID string, now time.Time, clusters []controlplane.ManagedCluster, observations []reliability.HealthObservation, observationTruncated bool) serviceHealthProjection {
	now = now.UTC()
	rows := append([]controlplane.ManagedCluster(nil), clusters...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	latest := make(map[string]reliability.HealthObservation, len(rows))
	for _, observation := range observations {
		if observation.ProjectID != projectID || strings.TrimSpace(observation.ClusterID) == "" {
			continue
		}
		current, ok := latest[observation.ClusterID]
		if !ok || observation.ObservedAt.After(current.ObservedAt) {
			latest[observation.ClusterID] = observation
		}
	}
	projection := serviceHealthProjection{
		Authority:        reliability.ServiceHealthAuthority,
		ProjectID:        projectID,
		CoverageStatus:   serviceHealthCoverageComplete,
		Truncated:        observationTruncated,
		ClusterCount:     len(rows),
		ReturnedClusters: len(rows),
		Summary:          map[string]int{},
		Clusters:         make([]serviceHealthClusterProjection, 0, len(rows)),
	}
	if observationTruncated || len(rows) == 0 {
		projection.CoverageStatus = serviceHealthCoverageUnknown
	}
	for _, cluster := range rows {
		item := serviceHealthClusterProjection{ClusterID: cluster.ID, Health: serviceHealthCoverageUnknown, CoverageStatus: serviceHealthCoverageUnknown}
		observation, ok := latest[cluster.ID]
		switch {
		case observationTruncated:
			item.Reason = "bounded reliability observation coverage is incomplete"
		case !ok:
			item.Reason = "no fresh health observation"
		case observation.ObservedAt.IsZero() || observation.ObservedAt.After(now.Add(time.Second)) || now.Sub(observation.ObservedAt.UTC()) > serviceHealthStaleAfter:
			item.Reason = "latest health observation is stale or temporally invalid"
		case !knownReliabilityHealth(observation.Health):
			item.Reason = "latest health observation has an unrecognized state"
		default:
			at := observation.ObservedAt.UTC()
			item.Health = observation.Health
			item.CoverageStatus = serviceHealthCoverageComplete
			item.ObservedAt = &at
		}
		if item.CoverageStatus != serviceHealthCoverageComplete {
			projection.CoverageStatus = serviceHealthCoverageUnknown
		}
		projection.Summary[item.Health]++
		projection.Clusters = append(projection.Clusters, item)
	}
	return projection
}

func (s *Server) reliabilityServiceHealth(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	pager, ok := s.store.(managedClusterPageStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "BOUNDED_CLUSTER_PAGER_REQUIRED", "service health requires the bounded managed-cluster paging authority")
		return
	}
	page := func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ManagedCluster, error) {
		return pager.ListManagedClustersPage(r.Context(), ids, all, cursor, limit)
	}
	clusters, err := boundedProjectCollection[controlplane.ManagedCluster](s, w, r, projectID, nil, page, func(cluster controlplane.ManagedCluster) string { return cluster.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	reliabilityStore, ok := s.store.(controlplane.ReliabilityStore)
	if !ok {
		writeReliabilityStoreUnavailable(w)
		return
	}
	now := time.Now().UTC()
	observations, err := reliabilityStore.ListHealthObservations(r.Context(), projectID, "", now.Add(-serviceHealthStaleAfter), now.Add(time.Second), serviceHealthObservationCap)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	observationTruncated := len(observations) >= serviceHealthObservationCap
	projection := projectServiceHealth(projectID, now, clusters, observations, observationTruncated)
	projection = markServiceHealthPageIncomplete(projection, strings.TrimSpace(w.Header().Get("X-4SO-Next-Cursor")) != "")
	writeJSON(w, http.StatusOK, projection)
}
