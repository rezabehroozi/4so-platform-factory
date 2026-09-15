package api

import (
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

const reliabilityCollectionLimit = 200

type createReliabilityIncidentInput struct {
	ProjectID string `json:"projectId"`
	ClusterID string `json:"clusterId,omitempty"`
	Service   string `json:"service,omitempty"`
	Severity  string `json:"severity"`
}

func (s *Server) listReliabilityIncidents(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	state := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("state")))
	if state != "" && state != reliability.IncidentOpen && state != reliability.IncidentAcknowledged && state != reliability.IncidentResolved {
		writeError(w, http.StatusUnprocessableEntity, "INCIDENT_STATE_INVALID", "state must be OPEN, ACKNOWLEDGED or RESOLVED")
		return
	}
	items, err := s.store.(controlplane.ReliabilityStore).ListIncidents(r.Context(), projectID, state, reliabilityCollectionLimit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("X-4SO-Result-Limit", "200")
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": reliability.IncidentAuthority,
		"projectId": projectID,
		"bounded": true,
		"resultLimit": reliabilityCollectionLimit,
		"incidents": items,
	})
}

func (s *Server) getReliabilityIncident(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.(controlplane.ReliabilityStore).GetIncident(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createReliabilityIncident(w http.ResponseWriter, r *http.Request) {
	var in createReliabilityIncidentInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.ProjectID, in.ClusterID = strings.TrimSpace(in.ProjectID), strings.TrimSpace(in.ClusterID)
	project, err := s.requireProjectAccess(r, in.ProjectID, organizationWrite)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	if in.ClusterID != "" {
		cluster, getErr := s.store.GetManagedCluster(r.Context(), in.ClusterID)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		if cluster.ProjectID != project.ID {
			writeError(w, http.StatusUnprocessableEntity, "INCIDENT_SCOPE_MISMATCH", "cluster is outside the requested project")
			return
		}
	}
	v, err := s.store.(controlplane.ReliabilityStore).CreateIncident(r.Context(), reliability.Incident{
		OrganizationID: project.OrganizationID,
		ProjectID:      project.ID,
		ClusterID:      in.ClusterID,
		Service:        strings.TrimSpace(in.Service),
		Severity:       strings.ToUpper(strings.TrimSpace(in.Severity)),
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) acknowledgeReliabilityIncident(w http.ResponseWriter, r *http.Request) {
	s.transitionReliabilityIncident(w, r, reliability.IncidentActionAcknowledge)
}

func (s *Server) resolveReliabilityIncident(w http.ResponseWriter, r *http.Request) {
	s.transitionReliabilityIncident(w, r, reliability.IncidentActionResolve)
}

func (s *Server) transitionReliabilityIncident(w http.ResponseWriter, r *http.Request, action string) {
	store := s.store.(controlplane.ReliabilityStore)
	current, err := store.GetIncident(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "REVISION_REQUIRED", err.Error())
		return
	}
	summary := ""
	if action == reliability.IncidentActionResolve {
		var in struct { Summary string `json:"summary"` }
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		summary = strings.TrimSpace(in.Summary)
	} else if r.Body != nil {
		var in struct{}
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
	}
	next, err := store.TransitionIncident(r.Context(), current.ID, expected, action, actor, summary)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, next.Revision)
	writeJSON(w, http.StatusOK, next)
}
