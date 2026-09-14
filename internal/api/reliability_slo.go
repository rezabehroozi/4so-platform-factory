package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

const reliabilityErrorBudgetObservationCap = 500

type reliabilitySLOPolicyInput struct {
	PredecessorID              string `json:"predecessorId,omitempty"`
	ProjectID                  string `json:"projectId,omitempty"`
	ClusterID                  string `json:"clusterId,omitempty"`
	Name                       string `json:"name,omitempty"`
	ObjectiveBasisPoints       int    `json:"objectiveBasisPoints"`
	WindowSeconds              int64  `json:"windowSeconds"`
	ObservationIntervalSeconds int64  `json:"observationIntervalSeconds"`
}

type reliabilityErrorBudgetView struct {
	Policy     reliability.SLOPolicy              `json:"policy"`
	Projection reliability.ErrorBudgetProjection `json:"projection"`
	Reason     string                             `json:"reason,omitempty"`
}

func writeSLOStoreUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "RELIABILITY_STORE_UNAVAILABLE", "control-plane store does not expose reliability authority")
}

func expectedSLORevision(r *http.Request) (int64, error) {
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if raw == "" {
		return 0, controlplane.ErrValidation
	}
	raw = strings.TrimSpace(strings.Trim(raw, `"`))
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, controlplane.ErrValidation
	}
	return value, nil
}

func latestSLOPolicies(rows []reliability.SLOPolicy) []reliability.SLOPolicy {
	latest := map[string]reliability.SLOPolicy{}
	for _, row := range rows {
		key := row.ClusterID + "\x00" + row.Name
		current, ok := latest[key]
		if !ok || row.Revision > current.Revision || (row.Revision == current.Revision && row.ID > current.ID) {
			latest[key] = row
		}
	}
	out := make([]reliability.SLOPolicy, 0, len(latest))
	for _, row := range latest {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClusterID != out[j].ClusterID {
			return out[i].ClusterID < out[j].ClusterID
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Server) createReliabilitySLOPolicy(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input reliabilitySLOPolicyInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	store, ok := s.store.(controlplane.ReliabilityStore)
	if !ok {
		writeSLOStoreUnavailable(w)
		return
	}
	input.PredecessorID = strings.TrimSpace(input.PredecessorID)
	if input.PredecessorID != "" {
		current, getErr := store.GetSLOPolicy(r.Context(), input.PredecessorID)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
			writeScopeError(w, err)
			return
		}
		if strings.TrimSpace(input.ProjectID) != "" && strings.TrimSpace(input.ProjectID) != current.ProjectID {
			writeError(w, http.StatusUnprocessableEntity, "SLO_SCOPE_IMMUTABLE", "projectId cannot change across an SLO revision")
			return
		}
		if strings.TrimSpace(input.ClusterID) != "" && strings.TrimSpace(input.ClusterID) != current.ClusterID {
			writeError(w, http.StatusUnprocessableEntity, "SLO_SCOPE_IMMUTABLE", "clusterId cannot change across an SLO revision")
			return
		}
		if strings.TrimSpace(input.Name) != "" && strings.TrimSpace(input.Name) != current.Name {
			writeError(w, http.StatusUnprocessableEntity, "SLO_SCOPE_IMMUTABLE", "name cannot change across an SLO revision")
			return
		}
		expected, revErr := expectedSLORevision(r)
		if revErr != nil {
			writeError(w, http.StatusBadRequest, "EXPECTED_REVISION_REQUIRED", "a positive If-Match revision is required for SLO revision creation")
			return
		}
		created, createErr := store.CreateSLOPolicyRevision(r.Context(), current.ID, expected, reliability.SLOPolicy{
			ObjectiveBasisPoints:       input.ObjectiveBasisPoints,
			WindowSeconds:              input.WindowSeconds,
			ObservationIntervalSeconds: input.ObservationIntervalSeconds,
		}, actor)
		if createErr != nil {
			writeStoreError(w, createErr)
			return
		}
		writeJSON(w, http.StatusCreated, created)
		return
	}

	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.ClusterID = strings.TrimSpace(input.ClusterID)
	input.Name = strings.TrimSpace(input.Name)
	if input.ProjectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	project, err := s.requireProjectAccess(r, input.ProjectID, organizationWrite)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	if input.ClusterID == "" {
		writeError(w, http.StatusUnprocessableEntity, "CLUSTER_REQUIRED", "clusterId is required for an SLO policy")
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), input.ClusterID)
	if err != nil || cluster.ProjectID != project.ID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	created, err := store.CreateSLOPolicy(r.Context(), reliability.SLOPolicy{
		OrganizationID:             project.OrganizationID,
		ProjectID:                  project.ID,
		ClusterID:                  cluster.ID,
		Name:                       input.Name,
		ObjectiveBasisPoints:       input.ObjectiveBasisPoints,
		WindowSeconds:              input.WindowSeconds,
		ObservationIntervalSeconds: input.ObservationIntervalSeconds,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) listReliabilitySLOPolicies(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	store, ok := s.store.(controlplane.ReliabilityStore)
	if !ok {
		writeSLOStoreUnavailable(w)
		return
	}
	rows, err := store.ListSLOPolicies(r.Context(), projectID, strings.TrimSpace(r.URL.Query().Get("name")), 200)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) reliabilityErrorBudgets(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	store, ok := s.store.(controlplane.ReliabilityStore)
	if !ok {
		writeSLOStoreUnavailable(w)
		return
	}
	policies, err := store.ListSLOPolicies(r.Context(), projectID, strings.TrimSpace(r.URL.Query().Get("name")), 200)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	views := make([]reliabilityErrorBudgetView, 0)
	for _, policy := range latestSLOPolicies(policies) {
		view := reliabilityErrorBudgetView{Policy: policy, Projection: reliability.ErrorBudgetProjection{CoverageStatus: reliability.CoverageUnknown}}
		if strings.TrimSpace(policy.ClusterID) == "" {
			view.Reason = "legacy SLO policy has no authoritative cluster target"
			views = append(views, view)
			continue
		}
		start := now.Add(-time.Duration(policy.WindowSeconds) * time.Second)
		observations, listErr := store.ListHealthObservations(r.Context(), projectID, policy.ClusterID, start, now, reliabilityErrorBudgetObservationCap)
		if listErr != nil {
			writeStoreError(w, listErr)
			return
		}
		if len(observations) >= reliabilityErrorBudgetObservationCap {
			view.Projection.ExpectedObservations = int(policy.WindowSeconds / policy.ObservationIntervalSeconds)
			view.Projection.ObservedObservations = len(observations)
			view.Reason = "bounded observation query may be truncated"
			views = append(views, view)
			continue
		}
		projection, projectErr := reliability.ProjectErrorBudget(policy, observations, start, now)
		if projectErr != nil {
			view.Reason = projectErr.Error()
			views = append(views, view)
			continue
		}
		view.Projection = projection
		if projection.CoverageStatus != reliability.CoverageComplete {
			view.Reason = "observation coverage is incomplete"
		}
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, views)
}
