package api

import (
	"net/http"
	"strconv"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

type notificationDestinationInput struct {
	OrganizationID   string                                   `json:"organizationId"`
	Name             string                                   `json:"name"`
	Kind             controlplane.NotificationDestinationKind `json:"kind"`
	Endpoint         string                                   `json:"endpoint,omitempty"`
	AuthorizationEnv string                                   `json:"authorizationEnv,omitempty"`
	HMACSecretEnv    string                                   `json:"hmacSecretEnv,omitempty"`
	AllowHTTP        bool                                     `json:"allowHttp"`
	TimeoutSeconds   int                                      `json:"timeoutSeconds"`
}

type notificationRouteInput struct {
	OrganizationID  string                            `json:"organizationId"`
	ProjectID       string                            `json:"projectId,omitempty"`
	Name            string                            `json:"name"`
	Enabled         bool                              `json:"enabled"`
	EventPatterns   []string                          `json:"eventPatterns"`
	MinimumSeverity controlplane.NotificationSeverity `json:"minimumSeverity"`
	DestinationIDs  []string                          `json:"destinationIds"`
}

func destinationFromInput(in notificationDestinationInput) controlplane.NotificationDestination {
	return controlplane.NotificationDestination{OrganizationID: in.OrganizationID, Name: in.Name, Kind: in.Kind, Endpoint: in.Endpoint, AuthorizationEnv: in.AuthorizationEnv, HMACSecretEnv: in.HMACSecretEnv, AllowHTTP: in.AllowHTTP, TimeoutSeconds: in.TimeoutSeconds}
}

func requireNotificationCredentialAuthority(w http.ResponseWriter, r *http.Request, in notificationDestinationInput) bool {
	if strings.TrimSpace(in.AuthorizationEnv) == "" && strings.TrimSpace(in.HMACSecretEnv) == "" {
		return true
	}
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "notification process credential references require platform-admin")
		return false
	}
	return true
}
func routeFromInput(in notificationRouteInput) controlplane.NotificationRoute {
	return controlplane.NotificationRoute{OrganizationID: in.OrganizationID, ProjectID: in.ProjectID, Name: in.Name, Enabled: in.Enabled, EventPatterns: in.EventPatterns, MinimumSeverity: in.MinimumSeverity, DestinationIDs: in.DestinationIDs}
}

func projectScopedTokenProjectID(r *http.Request) string {
	principal, ok := requestPrincipal(r)
	if !ok || principal.Authentication != "api-token" {
		return ""
	}
	return strings.TrimSpace(principal.ProjectID)
}

func (s *Server) requireNotificationResourceAccess(r *http.Request, organizationID, projectID string, required organizationAccessLevel) error {
	projectID = strings.TrimSpace(projectID)
	if projectID != "" {
		_, err := s.requireProjectAccess(r, projectID, required)
		return err
	}
	return s.requireOrganizationAccess(r, strings.TrimSpace(organizationID), required)
}

func (s *Server) notificationEventVisible(r *http.Request, event controlplane.NotificationEvent, allowedProjects map[string]bool, allProjects bool) bool {
	if strings.TrimSpace(event.ProjectID) != "" {
		return allProjects || allowedProjects[event.ProjectID]
	}
	level, err := s.organizationAccess(r, event.OrganizationID)
	return err == nil && level >= organizationRead
}

func notificationEventVisibleInScope(event controlplane.NotificationEvent, allowedOrganizations map[string]bool, allOrganizations bool, allowedProjects map[string]bool, allProjects bool) bool {
	if strings.TrimSpace(event.ProjectID) != "" {
		return allProjects || allowedProjects[event.ProjectID]
	}
	return allOrganizations || allowedOrganizations[event.OrganizationID]
}

func limitNotificationEvents(values []controlplane.NotificationEvent, limit int) []controlplane.NotificationEvent {
	if limit > 0 && len(values) > limit {
		return values[:limit]
	}
	return values
}

func limitNotificationDeliveries(values []controlplane.NotificationDelivery, limit int) []controlplane.NotificationDelivery {
	if limit > 0 && len(values) > limit {
		return values[:limit]
	}
	return values
}

func (s *Server) notificationEventTypes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, []map[string]string{
		{"eventType": "operation.failed", "severity": "CRITICAL", "description": "durable operation entered FAILED"},
		{"eventType": "plan.stale", "severity": "WARNING", "description": "approved baseline plan became stale"},
		{"eventType": "fleet.health.degraded", "severity": "WARNING/CRITICAL", "description": "cluster heartbeat, inventory or Ready health degraded"},
		{"eventType": "certificate.expiring", "severity": "WARNING", "description": "observed cluster or agent certificate is within expiry threshold"},
		{"eventType": "certificate.expired", "severity": "CRITICAL", "description": "observed cluster or agent certificate expired"},
		{"eventType": "kubernetes.eol_soon", "severity": "WARNING", "description": "Kubernetes minor release approaches bundled-policy EOL"},
		{"eventType": "kubernetes.eol", "severity": "CRITICAL", "description": "Kubernetes minor release is EOL in bundled policy"},
		{"eventType": "upgrade.blocked", "severity": "CRITICAL", "description": "upgrade campaign halted or failed"},
		{"eventType": "certification.blocked", "severity": "WARNING", "description": "runtime certification lacks a required capability"},
		{"eventType": "certification.failed", "severity": "CRITICAL", "description": "runtime certification failed"},
		{"eventType": "certification.succeeded", "severity": "INFO", "description": "runtime certification succeeded"},
	})
}

func (s *Server) createNotificationDestination(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in notificationDestinationInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err = s.requireOrganizationAccess(r, strings.TrimSpace(in.OrganizationID), organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	if !requireNotificationCredentialAuthority(w, r, in) {
		return
	}
	v, err := s.store.CreateNotificationDestination(r.Context(), destinationFromInput(in), actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}
func (s *Server) updateNotificationDestination(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetNotificationDestination(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, current.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in notificationDestinationInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if !requireNotificationCredentialAuthority(w, r, in) {
		return
	}
	v, err := s.store.UpdateNotificationDestination(r.Context(), current.ID, rev, destinationFromInput(in), actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) disableNotificationDestination(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("X-Confirm-Disable")) != "disable-notification-destination" {
		writeError(w, http.StatusBadRequest, "DISABLE_CONFIRMATION_REQUIRED", "X-Confirm-Disable must be disable-notification-destination")
		return
	}
	current, err := s.store.GetNotificationDestination(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, current.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	v, err := s.store.DisableNotificationDestination(r.Context(), current.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) listNotificationDestinations(w http.ResponseWriter, r *http.Request) {
	org := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	if org != "" {
		if err := s.requireOrganizationAccess(r, org, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	values, err := s.store.ListNotificationDestinations(r.Context(), org)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.resourceOrganizationSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !all {
		filtered := values[:0]
		for _, v := range values {
			if allowed[v.OrganizationID] {
				filtered = append(filtered, v)
			}
		}
		values = filtered
	}
	writeJSON(w, http.StatusOK, values)
}
func (s *Server) getNotificationDestination(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetNotificationDestination(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireOrganizationAccess(r, v.OrganizationID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createNotificationRoute(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in notificationRouteInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if strings.TrimSpace(in.ProjectID) != "" {
		project, e := s.requireProjectAccess(r, in.ProjectID, organizationWrite)
		if e != nil {
			writeScopeError(w, e)
			return
		}
		if project.OrganizationID != strings.TrimSpace(in.OrganizationID) {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to route organization")
			return
		}
	} else if err = s.requireOrganizationAccess(r, strings.TrimSpace(in.OrganizationID), organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.CreateNotificationRoute(r.Context(), routeFromInput(in), actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusCreated, v)
}
func (s *Server) updateNotificationRoute(w http.ResponseWriter, r *http.Request) {
	cur, err := s.store.GetNotificationRoute(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireNotificationResourceAccess(r, cur.OrganizationID, cur.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var in notificationRouteInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.OrganizationID = cur.OrganizationID
	if strings.TrimSpace(in.ProjectID) != "" {
		project, accessErr := s.requireProjectAccess(r, in.ProjectID, organizationWrite)
		if accessErr != nil {
			writeScopeError(w, accessErr)
			return
		}
		if project.OrganizationID != cur.OrganizationID {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to route organization")
			return
		}
	} else if strings.TrimSpace(cur.ProjectID) != "" {
		// Moving a project-scoped route to organization-wide scope expands its
		// audience and therefore requires organization-level write authority.
		if accessErr := s.requireOrganizationAccess(r, cur.OrganizationID, organizationWrite); accessErr != nil {
			writeScopeError(w, accessErr)
			return
		}
	}
	v, err := s.store.UpdateNotificationRoute(r.Context(), cur.ID, rev, routeFromInput(in), actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) listNotificationRoutes(w http.ResponseWriter, r *http.Request) {
	org := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	project := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if tokenProject := projectScopedTokenProjectID(r); tokenProject != "" {
		if project != "" && project != tokenProject {
			writeScopeError(w, errOrganizationAccessDenied)
			return
		}
		project = tokenProject
	}
	if project != "" {
		p, err := s.requireProjectAccess(r, project, organizationRead)
		if err != nil {
			writeScopeError(w, err)
			return
		}
		if org != "" && p.OrganizationID != org {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to selected organization")
			return
		}
		org = p.OrganizationID
	} else if org != "" {
		if err := s.requireOrganizationAccess(r, org, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	values, err := s.store.ListNotificationRoutes(r.Context(), org, project)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if org == "" && project == "" {
		allowedProjects, allProjects, err := s.accessibleProjectSet(r)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		filtered := make([]controlplane.NotificationRoute, 0, len(values))
		for _, v := range values {
			if v.ProjectID != "" {
				if allProjects || allowedProjects[v.ProjectID] {
					filtered = append(filtered, v)
				}
				continue
			}
			if level, accessErr := s.organizationAccess(r, v.OrganizationID); accessErr == nil && level >= organizationRead {
				filtered = append(filtered, v)
			}
		}
		values = filtered
	}
	writeJSON(w, http.StatusOK, values)
}

func (s *Server) getNotificationRoute(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetNotificationRoute(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireNotificationResourceAccess(r, v.OrganizationID, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func notificationLimit(r *http.Request) int {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return 100
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return 100
	}
	if v > 500 {
		return 500
	}
	return v
}
func (s *Server) listNotificationEvents(w http.ResponseWriter, r *http.Request) {
	org := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	project := strings.TrimSpace(r.URL.Query().Get("projectId"))
	limit := notificationLimit(r)
	if tokenProject := projectScopedTokenProjectID(r); tokenProject != "" {
		if project != "" && project != tokenProject {
			writeScopeError(w, errOrganizationAccessDenied)
			return
		}
		project = tokenProject
	}
	if project != "" {
		p, err := s.requireProjectAccess(r, project, organizationRead)
		if err != nil {
			writeScopeError(w, err)
			return
		}
		if org != "" && p.OrganizationID != org {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to selected organization")
			return
		}
		org = p.OrganizationID
	} else if org != "" {
		if err := s.requireOrganizationAccess(r, org, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	var (
		values []controlplane.NotificationEvent
		err    error
	)
	if org == "" && project == "" {
		allowedProjects, allProjects, accessErr := s.accessibleProjectSet(r)
		if accessErr != nil {
			writeStoreError(w, accessErr)
			return
		}
		if allProjects {
			values, err = s.store.ListNotificationEvents(r.Context(), "", "", limit)
		} else {
			allowedOrganizations, allOrganizations, scopeErr := s.resourceOrganizationSet(r)
			if scopeErr != nil {
				writeStoreError(w, scopeErr)
				return
			}
			if pager, ok := s.store.(notificationScopedEventPageStore); ok {
				values, err = pager.ListNotificationEventsPageByScopes(r.Context(), boolSetIDs(allowedOrganizations), boolSetIDs(allowedProjects), limit)
			} else {
				// Compatibility fallback for external Store implementations. Product
				// stores implement the scoped pager so production requests never scan
				// global notification history merely to return one tenant page.
				values, err = s.store.ListNotificationEvents(r.Context(), "", "", 0)
				if err == nil {
					filtered := make([]controlplane.NotificationEvent, 0, len(values))
					for _, v := range values {
						if notificationEventVisibleInScope(v, allowedOrganizations, allOrganizations, allowedProjects, false) {
							filtered = append(filtered, v)
						}
					}
					values = limitNotificationEvents(filtered, limit)
				}
			}
		}
	} else {
		values, err = s.store.ListNotificationEvents(r.Context(), org, project, limit)
		if err != nil {
			writeStoreError(w, err)
			return
		}
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, values)
}

func (s *Server) getNotificationEvent(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetNotificationEvent(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireNotificationResourceAccess(r, v.OrganizationID, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	org := strings.TrimSpace(r.URL.Query().Get("organizationId"))
	project := strings.TrimSpace(r.URL.Query().Get("projectId"))
	state := controlplane.NotificationDeliveryState(strings.TrimSpace(r.URL.Query().Get("state")))
	limit := notificationLimit(r)
	if tokenProject := projectScopedTokenProjectID(r); tokenProject != "" {
		if project != "" && project != tokenProject {
			writeScopeError(w, errOrganizationAccessDenied)
			return
		}
		project = tokenProject
	}
	if project != "" {
		p, err := s.requireProjectAccess(r, project, organizationRead)
		if err != nil {
			writeScopeError(w, err)
			return
		}
		if org != "" && p.OrganizationID != org {
			writeError(w, http.StatusUnprocessableEntity, "PROJECT_SCOPE_MISMATCH", "project must belong to selected organization")
			return
		}
		org = p.OrganizationID
	} else if org != "" {
		if err := s.requireOrganizationAccess(r, org, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	var (
		values []controlplane.NotificationDelivery
		err    error
	)
	if org == "" && project == "" {
		allowedProjects, allProjects, accessErr := s.accessibleProjectSet(r)
		if accessErr != nil {
			writeStoreError(w, accessErr)
			return
		}
		if allProjects {
			values, err = s.store.ListNotificationDeliveries(r.Context(), "", "", state, limit)
		} else {
			allowedOrganizations, _, scopeErr := s.resourceOrganizationSet(r)
			if scopeErr != nil {
				writeStoreError(w, scopeErr)
				return
			}
			if pager, ok := s.store.(notificationScopedDeliveryPageStore); ok {
				values, err = pager.ListNotificationDeliveriesPageByScopes(r.Context(), boolSetIDs(allowedOrganizations), boolSetIDs(allowedProjects), state, limit)
			} else {
				values, err = s.store.ListNotificationDeliveries(r.Context(), "", "", state, 0)
				if err == nil {
					filtered := make([]controlplane.NotificationDelivery, 0, len(values))
					for _, d := range values {
						ev, eventErr := s.store.GetNotificationEvent(r.Context(), d.EventID)
						if eventErr == nil && notificationEventVisibleInScope(ev, allowedOrganizations, false, allowedProjects, false) {
							filtered = append(filtered, d)
						}
					}
					values = limitNotificationDeliveries(filtered, limit)
				}
			}
		}
	} else {
		values, err = s.store.ListNotificationDeliveries(r.Context(), org, project, state, limit)
		if err != nil {
			writeStoreError(w, err)
			return
		}
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, values)
}

func (s *Server) getNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetNotificationDelivery(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ev, err := s.store.GetNotificationEvent(r.Context(), d.EventID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireNotificationResourceAccess(r, ev.OrganizationID, ev.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	attempts, err := s.store.ListNotificationDeliveryAttempts(r.Context(), d.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, d.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"delivery": d, "attempts": attempts})
}
func (s *Server) retryNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetNotificationDelivery(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ev, err := s.store.GetNotificationEvent(r.Context(), d.EventID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireNotificationResourceAccess(r, ev.OrganizationID, ev.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RetryNotificationDelivery(r.Context(), d.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
