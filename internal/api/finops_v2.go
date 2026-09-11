package api

import (
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) createFinOpsBudgetPolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireFinancialAdmin(w, r)
	if !ok {
		return
	}
	var in controlplane.FinOpsBudgetPolicy
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.ProjectID = strings.TrimSpace(in.ProjectID)
	if in.OrganizationID == "" {
		writeError(w, http.StatusUnprocessableEntity, "ORGANIZATION_REQUIRED", "organizationId is required")
		return
	}
	if in.ProjectID != "" {
		project, err := s.requireProjectAccess(r, in.ProjectID, organizationAdminAccess)
		if err != nil {
			writeScopeError(w, err)
			return
		}
		if project.OrganizationID != in.OrganizationID {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to selected organization")
			return
		}
	} else if err := s.requireOrganizationAccess(r, in.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.CreateFinOpsBudgetPolicy(r.Context(), in, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) listFinOpsBudgetPolicies(w http.ResponseWriter, r *http.Request) {
	org, project, err := s.authorizeFinOpsRead(r, r.URL.Query().Get("organizationId"), r.URL.Query().Get("projectId"))
	if err != nil {
		if err == errOrganizationAccessDenied {
			writeScopeError(w, err)
		} else {
			writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_SCOPE", err.Error())
		}
		return
	}
	v, err := s.store.ListFinOpsBudgetPolicies(r.Context(), org, project)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) getFinOpsBudgetPolicy(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetFinOpsBudgetPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if v.ProjectID != "" {
		project, err := s.requireProjectAccess(r, v.ProjectID, organizationRead)
		if err != nil {
			writeScopeError(w, err)
			return
		}
		if project.OrganizationID != v.OrganizationID {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "budget project organization mismatch")
			return
		}
	} else if err := s.requireOrganizationAccess(r, v.OrganizationID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) getFinOpsInsights(w http.ResponseWriter, r *http.Request) {
	org, project, err := s.authorizeFinOpsRead(r, r.URL.Query().Get("organizationId"), r.URL.Query().Get("projectId"))
	if err != nil {
		if err == errOrganizationAccessDenied {
			writeScopeError(w, err)
		} else {
			writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_SCOPE", err.Error())
		}
		return
	}
	start, err := parseFinOpsTime(r.URL.Query().Get("windowStart"), "windowStart", true)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_WINDOW", err.Error())
		return
	}
	observed, err := parseFinOpsTime(r.URL.Query().Get("observedThrough"), "observedThrough", true)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_WINDOW", err.Error())
		return
	}
	forecastEnd, err := parseFinOpsTime(r.URL.Query().Get("forecastEnd"), "forecastEnd", true)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_WINDOW", err.Error())
		return
	}
	usage, err := s.store.ListFinOpsUsageMeasurements(r.Context(), org, project, start, observed, finOpsShowbackMeasurementCap)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if len(usage) >= finOpsShowbackMeasurementCap {
		writeError(w, http.StatusUnprocessableEntity, "FINOPS_INSIGHT_WINDOW_TOO_LARGE", "insight window reaches the measurement safety cap; narrow the window")
		return
	}
	cards, err := s.store.ListFinOpsRateCards(r.Context(), org)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	policies, err := s.store.ListFinOpsBudgetPolicies(r.Context(), org, project)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	capacityFrom := observed.Add(-24 * time.Hour)
	capacity, err := s.store.ListFinOpsCapacityObservations(r.Context(), org, project, capacityFrom, observed, 5000)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	v, err := controlplane.BuildFinOpsInsights(controlplane.FinOpsInsightQuery{OrganizationID: org, ProjectID: project, Currency: r.URL.Query().Get("currency"), WindowStart: start, ObservedThrough: observed, ForecastEnd: forecastEnd}, usage, cards, capacity, policies)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "FINOPS_INSIGHTS_UNAVAILABLE", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}
