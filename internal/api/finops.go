package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const finOpsShowbackMeasurementCap = 5000

func requireFinancialAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "FinOps financial evidence writes require platform-admin")
		return "", false
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return "", false
	}
	return actor, true
}

func (s *Server) createFinOpsRateCard(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireFinancialAdmin(w, r)
	if !ok {
		return
	}
	var in controlplane.FinOpsRateCard
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if strings.TrimSpace(in.OrganizationID) == "" {
		writeError(w, http.StatusUnprocessableEntity, "ORGANIZATION_REQUIRED", "organizationId is required")
		return
	}
	if err := s.requireOrganizationAccess(r, in.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.CreateFinOpsRateCard(r.Context(), in, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) listFinOpsRateCards(w http.ResponseWriter, r *http.Request) {
	org := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	if org == "" {
		writeError(w, http.StatusUnprocessableEntity, "ORGANIZATION_REQUIRED", "organizationId is required")
		return
	}
	if err := s.requireOrganizationAccess(r, org, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.ListFinOpsRateCards(r.Context(), org)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) getFinOpsRateCard(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetFinOpsRateCard(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, v.OrganizationID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createFinOpsUsageMeasurement(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireFinancialAdmin(w, r)
	if !ok {
		return
	}
	var in controlplane.FinOpsUsageMeasurement
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	project, err := s.store.GetProject(r.Context(), strings.TrimSpace(in.ProjectID))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if project.OrganizationID != strings.TrimSpace(in.OrganizationID) {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to selected organization")
		return
	}
	v, replay, err := s.store.CreateFinOpsUsageMeasurement(r.Context(), in, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"measurement": v, "replay": replay})
}
func (s *Server) createFinOpsCapacityObservation(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireFinancialAdmin(w, r)
	if !ok {
		return
	}
	var in controlplane.FinOpsCapacityObservation
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	project, err := s.store.GetProject(r.Context(), strings.TrimSpace(in.ProjectID))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if project.OrganizationID != strings.TrimSpace(in.OrganizationID) {
		writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to selected organization")
		return
	}
	v, replay, err := s.store.CreateFinOpsCapacityObservation(r.Context(), in, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"observation": v, "replay": replay})
}

func parseFinOpsTime(raw, name string, required bool) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if required {
			return time.Time{}, fmt.Errorf("%s is required", name)
		}
		return time.Time{}, nil
	}
	v, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", name)
	}
	return v.UTC(), nil
}
func parseFinOpsLimit(raw string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(raw))
	if n <= 0 {
		n = 500
	}
	if n > 5000 {
		n = 5000
	}
	return n
}
func (s *Server) authorizeFinOpsRead(r *http.Request, orgID, projectID string) (string, string, error) {
	orgID = strings.TrimSpace(orgID)
	projectID = strings.TrimSpace(projectID)
	if projectID != "" {
		project, err := s.requireProjectAccess(r, projectID, organizationRead)
		if err != nil {
			return "", "", err
		}
		if orgID != "" && orgID != project.OrganizationID {
			return "", "", fmt.Errorf("%w: project organization mismatch", controlplane.ErrValidation)
		}
		return project.OrganizationID, projectID, nil
	}
	if orgID == "" {
		return "", "", fmt.Errorf("%w: organizationId or projectId is required", controlplane.ErrValidation)
	}
	if err := s.requireOrganizationAccess(r, orgID, organizationRead); err != nil {
		return "", "", err
	}
	return orgID, "", nil
}

func (s *Server) listFinOpsUsageMeasurements(w http.ResponseWriter, r *http.Request) {
	org, project, err := s.authorizeFinOpsRead(r, r.URL.Query().Get("organizationId"), r.URL.Query().Get("projectId"))
	if err != nil {
		if err == errOrganizationAccessDenied {
			writeScopeError(w, err)
		} else {
			writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_SCOPE", err.Error())
		}
		return
	}
	from, err := parseFinOpsTime(r.URL.Query().Get("from"), "from", false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_WINDOW", err.Error())
		return
	}
	to, err := parseFinOpsTime(r.URL.Query().Get("to"), "to", false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_WINDOW", err.Error())
		return
	}
	v, err := s.store.ListFinOpsUsageMeasurements(r.Context(), org, project, from, to, parseFinOpsLimit(r.URL.Query().Get("limit")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) listFinOpsCapacityObservations(w http.ResponseWriter, r *http.Request) {
	org, project, err := s.authorizeFinOpsRead(r, r.URL.Query().Get("organizationId"), r.URL.Query().Get("projectId"))
	if err != nil {
		if err == errOrganizationAccessDenied {
			writeScopeError(w, err)
		} else {
			writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_SCOPE", err.Error())
		}
		return
	}
	from, err := parseFinOpsTime(r.URL.Query().Get("from"), "from", false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_WINDOW", err.Error())
		return
	}
	to, err := parseFinOpsTime(r.URL.Query().Get("to"), "to", false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_FINOPS_WINDOW", err.Error())
		return
	}
	v, err := s.store.ListFinOpsCapacityObservations(r.Context(), org, project, from, to, parseFinOpsLimit(r.URL.Query().Get("limit")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) finOpsShowbackValue(r *http.Request) (controlplane.FinOpsShowback, error) {
	org, project, err := s.authorizeFinOpsRead(r, r.URL.Query().Get("organizationId"), r.URL.Query().Get("projectId"))
	if err != nil {
		return controlplane.FinOpsShowback{}, err
	}
	from, err := parseFinOpsTime(r.URL.Query().Get("from"), "from", true)
	if err != nil {
		return controlplane.FinOpsShowback{}, err
	}
	to, err := parseFinOpsTime(r.URL.Query().Get("to"), "to", true)
	if err != nil {
		return controlplane.FinOpsShowback{}, err
	}
	usage, err := s.store.ListFinOpsUsageMeasurements(r.Context(), org, project, from, to, finOpsShowbackMeasurementCap)
	if err != nil {
		return controlplane.FinOpsShowback{}, err
	}
	if len(usage) >= finOpsShowbackMeasurementCap {
		return controlplane.FinOpsShowback{}, fmt.Errorf("%w: showback window reaches the %d-measurement safety cap; narrow the window", controlplane.ErrValidation, finOpsShowbackMeasurementCap)
	}
	cards, err := s.store.ListFinOpsRateCards(r.Context(), org)
	if err != nil {
		return controlplane.FinOpsShowback{}, err
	}
	return controlplane.BuildFinOpsShowback(controlplane.FinOpsShowbackQuery{OrganizationID: org, ProjectID: project, Currency: r.URL.Query().Get("currency"), GroupBy: controlplane.FinOpsGroupBy(strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("groupBy")))), WindowStart: from, WindowEnd: to}, usage, cards)
}
func (s *Server) getFinOpsShowback(w http.ResponseWriter, r *http.Request) {
	v, err := s.finOpsShowbackValue(r)
	if err != nil {
		if err == errOrganizationAccessDenied {
			writeScopeError(w, err)
		} else {
			writeError(w, http.StatusUnprocessableEntity, "FINOPS_SHOWBACK_UNAVAILABLE", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) exportFinOpsChargeback(w http.ResponseWriter, r *http.Request) {
	v, err := s.finOpsShowbackValue(r)
	if err != nil {
		if err == errOrganizationAccessDenied {
			writeScopeError(w, err)
		} else {
			writeError(w, http.StatusUnprocessableEntity, "FINOPS_EXPORT_UNAVAILABLE", err.Error())
		}
		return
	}
	raw, digest, err := controlplane.FinOpsChargebackCSV(v)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="4so-finops-chargeback.csv"`)
	w.Header().Set("X-FinOps-Export-Digest", digest)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
