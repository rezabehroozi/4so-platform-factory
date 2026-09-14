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
	serviceHealthClusterCap      = 200
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
	Authority       string                           `json:"authority"`
	ProjectID       string                           `json:"projectId"`
	CoverageStatus  string                           `json:"coverageStatus"`
	Truncated       bool                             `json:"truncated"`
	ClusterCount    int                              `json:"clusterCount"`
	ReturnedClusters int                             `json:"returnedClusters"`
	Summary         map[string]int                   `json:"summary"`
	Clusters        []serviceHealthClusterProjection `json:"clusters"`
}

func knownReliabilityHealth(value string) bool {
	switch value {
	case "HEALTHY", "WARNING", "DEGRADED", "STALE", "CRITICAL":
		return true
	default:
		return false
	}
}

func projectServiceHealth(projectID string, now time.Time, clusters []controlplane.ManagedCluster, observations []reliability.HealthObservation, truncated bool) serviceHealthProjection {
	now = now.UTC()
	rows := append([]controlplane.ManagedCluster(nil), clusters...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	total := len(rows)
	if len(rows) > serviceHealthClusterCap {
		rows = rows[:serviceHealthClusterCap]
		truncated = true
	}

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
		Truncated:        truncated,
		ClusterCount:     total,
		ReturnedClusters: len(rows),
		Summary:          map[string]int{},
		Clusters:         make([]serviceHealthClusterProjection, 0, len(rows)),
	}
	if truncated || total == 0 {
		projection.CoverageStatus = serviceHealthCoverageUnknown
	}
	for _, cluster := range rows {
		item := serviceHealthClusterProjection{ClusterID: cluster.ID, Health: serviceHealthCoverageUnknown, CoverageStatus: serviceHealthCoverageUnknown}
		observation, ok := latest[cluster.ID]
		switch {
		case truncated:
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
	clusters, err := s.store.ListManagedClusters(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	reliabilityStore, ok := s.store.(controlplane.ReliabilityStore)
	if !ok {
		writeError(w, http.StatusInternalServerError, "RELIABILITY_STORE_UNAVAILABLE", "control-plane store does not expose reliability authority")
		return
	}
	now := time.Now().UTC()
	observations, err := reliabilityStore.ListHealthObservations(r.Context(), projectID, "", now.Add(-serviceHealthStaleAfter), now.Add(time.Second), serviceHealthObservationCap)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	truncated := len(observations) >= serviceHealthObservationCap
	writeJSON(w, http.StatusOK, projectServiceHealth(projectID, now, clusters, observations, truncated))
}
