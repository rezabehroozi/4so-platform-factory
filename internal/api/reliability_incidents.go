package api

import (
	"net/http"
	"strconv"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

type reliabilityIncidentCreateInput struct {
	ProjectID   string `json:"projectId"`
	OperationID string `json:"operationId,omitempty"`
	ClusterID   string `json:"clusterId,omitempty"`
	Service     string `json:"service,omitempty"`
	Severity    string `json:"severity"`
}

type reliabilityIncidentResolveInput struct {
	ResolutionSummary string `json:"resolutionSummary"`
}

const reliabilityIncidentEvidenceLimit = 50

type reliabilityIncidentEvidenceView struct {
	ID          string `json:"id"`
	OperationID string `json:"operationId"`
	Phase       string `json:"phase,omitempty"`
	StepKey     string `json:"stepKey,omitempty"`
	Attempt     int    `json:"attempt,omitempty"`
	Kind        string `json:"kind"`
	Digest      string `json:"digest"`
	MediaType   string `json:"mediaType"`
	Size        int64  `json:"size"`
	HasPayload  bool   `json:"hasPayload"`
	Sealed      bool   `json:"sealed"`
}

type reliabilityIncidentDetail struct {
	reliability.Incident
	Evidence          []reliabilityIncidentEvidenceView `json:"evidence,omitempty"`
	EvidenceTruncated bool                              `json:"evidenceTruncated,omitempty"`
}

func projectReliabilityIncidentEvidence(in controlplane.EvidenceMetadata) reliabilityIncidentEvidenceView {
	return reliabilityIncidentEvidenceView{ID: in.ID, OperationID: in.OperationID, Phase: string(in.Phase), StepKey: in.StepKey, Attempt: in.Attempt, Kind: in.Kind, Digest: in.Digest, MediaType: in.MediaType, Size: in.Size, HasPayload: in.HasPayload, Sealed: in.Sealed}
}

func (s *Server) reliabilityStore() (controlplane.ReliabilityStore, bool) {
	store, ok := s.store.(controlplane.ReliabilityStore)
	return store, ok
}

func writeReliabilityStoreUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "RELIABILITY_STORE_UNAVAILABLE", "control-plane store does not expose reliability authority")
}

func rejectUnsupportedReliabilityCursor(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.URL.Query().Get("cursor")) == "" {
		return false
	}
	writeError(w, http.StatusUnprocessableEntity, "RELIABILITY_CURSOR_NOT_SUPPORTED", "cursor paging is not authoritative for this reliability collection yet")
	return true
}

func expectedReliabilityRevision(r *http.Request) (int64, error) {
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

func (s *Server) createReliabilityIncident(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input reliabilityIncidentCreateInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if input.ProjectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	project, err := s.requireProjectAccess(r, input.ProjectID, organizationWrite)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	input.ClusterID = strings.TrimSpace(input.ClusterID)
	if input.ClusterID != "" {
		cluster, lookupErr := s.store.GetManagedCluster(r.Context(), input.ClusterID)
		if lookupErr != nil || cluster.ProjectID != project.ID {
			writeStoreError(w, controlplane.ErrNotFound)
			return
		}
	}
	store, ok := s.reliabilityStore()
	if !ok {
		writeReliabilityStoreUnavailable(w)
		return
	}
	created, err := store.CreateIncident(r.Context(), reliability.Incident{
		OrganizationID: project.OrganizationID,
		ProjectID:      project.ID,
		OperationID:    strings.TrimSpace(input.OperationID),
		ClusterID:      input.ClusterID,
		Service:        strings.TrimSpace(input.Service),
		Severity:       strings.TrimSpace(input.Severity),
		State:          reliability.IncidentOpen,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) listReliabilityIncidents(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	if rejectUnsupportedReliabilityCursor(w, r) {
		return
	}
	store, ok := s.reliabilityStore()
	if !ok {
		writeReliabilityStoreUnavailable(w)
		return
	}
	limit, err := operatorCollectionLimit(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	rows, err := store.ListIncidents(r.Context(), projectID, strings.TrimSpace(r.URL.Query().Get("state")), limit+1)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if len(rows) > limit {
		rows = rows[:limit]
		w.Header().Set("X-4SO-Result-Truncated", "true")
	}
	w.Header().Set("X-4SO-Result-Limit", strconv.Itoa(limit))
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) getReliabilityIncident(w http.ResponseWriter, r *http.Request) {
	store, ok := s.reliabilityStore()
	if !ok {
		writeReliabilityStoreUnavailable(w)
		return
	}
	incident, err := store.GetIncident(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, incident.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	if strings.TrimSpace(incident.OperationID) == "" {
		writeJSON(w, http.StatusOK, incident)
		return
	}
	evidenceStore, ok := s.store.(controlplane.OperationEvidencePageStore)
	if !ok {
		writeError(w, http.StatusInternalServerError, "EVIDENCE_STORE_UNAVAILABLE", "control-plane store does not expose bounded operation evidence metadata")
		return
	}
	rows, err := evidenceStore.ListEvidencePageByOperation(r.Context(), incident.OperationID, reliabilityIncidentEvidenceLimit+1)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	truncated := len(rows) > reliabilityIncidentEvidenceLimit
	if truncated {
		rows = rows[:reliabilityIncidentEvidenceLimit]
	}
	views := make([]reliabilityIncidentEvidenceView, 0, len(rows))
	for _, row := range rows {
		views = append(views, projectReliabilityIncidentEvidence(row))
	}
	writeJSON(w, http.StatusOK, reliabilityIncidentDetail{Incident: incident, Evidence: views, EvidenceTruncated: truncated})
}

func (s *Server) acknowledgeReliabilityIncident(w http.ResponseWriter, r *http.Request) {
	s.transitionReliabilityIncident(w, r, reliability.IncidentActionAcknowledge, "")
}

func (s *Server) resolveReliabilityIncident(w http.ResponseWriter, r *http.Request) {
	var input reliabilityIncidentResolveInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	s.transitionReliabilityIncident(w, r, reliability.IncidentActionResolve, strings.TrimSpace(input.ResolutionSummary))
}

func (s *Server) transitionReliabilityIncident(w http.ResponseWriter, r *http.Request, action, summary string) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	store, ok := s.reliabilityStore()
	if !ok {
		writeReliabilityStoreUnavailable(w)
		return
	}
	incident, err := store.GetIncident(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, incident.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	expected, err := expectedReliabilityRevision(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "EXPECTED_REVISION_REQUIRED", "a positive If-Match revision is required")
		return
	}
	updated, err := store.TransitionIncident(r.Context(), incident.ID, expected, action, actor, summary)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
