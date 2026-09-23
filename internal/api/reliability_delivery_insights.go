package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/reliability"
)

func parseDeliveryInsightsWindow(r *http.Request) (time.Time, time.Time, error) {
	from, err := time.Parse(time.RFC3339, strings.TrimSpace(r.URL.Query().Get("from")))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	to, err := time.Parse(time.RFC3339, strings.TrimSpace(r.URL.Query().Get("to")))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid delivery insight window")
	}
	return from.UTC(), to.UTC(), nil
}

func (s *Server) reliabilityDeliveryInsights(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_REQUIRED", "projectId is required")
		return
	}
	if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	from, to, err := parseDeliveryInsightsWindow(r)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "DELIVERY_WINDOW_INVALID", "from/to must be RFC3339 and to must be after from")
		return
	}
	reliabilityStore, ok := s.reliabilityStore()
	if !ok {
		writeReliabilityStoreUnavailable(w)
		return
	}
	applicationStore, ok := s.store.(applicationPlatformStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "APPLICATION_PLATFORM_AUTHORITY_UNAVAILABLE", "application platform persistence authority is unavailable")
		return
	}
	releases, err := applicationStore.ListApplicationReleases(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	bindings, err := applicationStore.ListEnvironmentBindings(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	operations, err := s.store.ListOperations(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	evidence, err := projectApplicationDeliveryEvidence(projectID, releases, bindings, operations)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "DELIVERY_DEPLOYMENT_EVIDENCE_INVALID", err.Error())
		return
	}

	incidents, err := reliabilityStore.ListIncidents(r.Context(), projectID, "", 1000)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, incident := range incidents {
		evidence = append(evidence, reliability.DeliveryEvidence{
			EvidenceID: "incident-opened:" + incident.ID,
			ProjectID:  projectID,
			EventType:  reliability.DeliveryEventIncidentOpened,
			OccurredAt: incident.CreatedAt,
			IncidentID: incident.ID,
		})
		if incident.State == reliability.IncidentResolved {
			evidence = append(evidence, reliability.DeliveryEvidence{
				EvidenceID: "incident-resolved:" + incident.ID,
				ProjectID:  projectID,
				EventType:  reliability.DeliveryEventIncidentResolved,
				OccurredAt: incident.UpdatedAt,
				IncidentID: incident.ID,
			})
		}
	}
	insights, err := reliability.BuildDeliveryInsights(projectID, from, to, evidence)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "DELIVERY_INSIGHTS_INVALID", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, insights)
}
