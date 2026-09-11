package controlplane

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

func notificationScopeSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = true
		}
	}
	return out
}

var notificationEnvNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const notificationSecretEnvPrefix = "PLATFORM_FACTORY_NOTIFICATION_SECRET_"

// NotificationSecretEnvPrefixForOrganization binds process-level notification
// credentials to one immutable organization authority. Organization IDs are
// product-generated stable identifiers, so this prevents one organization from
// naming another organization's notification secret even inside the dedicated
// notification namespace.
func NotificationSecretEnvPrefixForOrganization(organizationID string) string {
	raw := strings.ToUpper(strings.TrimSpace(organizationID))
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return notificationSecretEnvPrefix
	}
	return notificationSecretEnvPrefix + b.String() + "_"
}

func NotificationSecretEnvAllowedForOrganization(organizationID, name string) bool {
	name = strings.TrimSpace(name)
	prefix := NotificationSecretEnvPrefixForOrganization(organizationID)
	return strings.TrimSpace(organizationID) != "" && name != "" && strings.HasPrefix(name, prefix) && notificationEnvNameRE.MatchString(name)
}

func validNotificationSeverity(v NotificationSeverity) bool {
	return v == NotificationInfo || v == NotificationWarning || v == NotificationCritical
}

func notificationSeverityRank(v NotificationSeverity) int {
	switch v {
	case NotificationCritical:
		return 3
	case NotificationWarning:
		return 2
	case NotificationInfo:
		return 1
	default:
		return 0
	}
}

func validateNotificationDestination(v NotificationDestination) error {
	if strings.TrimSpace(v.OrganizationID) == "" || normalizeName(v.Name) == "" {
		return fmt.Errorf("%w: organizationId and name are required", ErrValidation)
	}
	if v.TimeoutSeconds == 0 {
		v.TimeoutSeconds = 10
	}
	if v.TimeoutSeconds < 1 || v.TimeoutSeconds > 60 {
		return fmt.Errorf("%w: timeoutSeconds must be between 1 and 60", ErrValidation)
	}
	for _, envName := range []string{v.AuthorizationEnv, v.HMACSecretEnv} {
		if envName != "" && !NotificationSecretEnvAllowedForOrganization(v.OrganizationID, envName) {
			return fmt.Errorf("%w: notification secret references must use the %s* namespace", ErrValidation, NotificationSecretEnvPrefixForOrganization(v.OrganizationID))
		}
	}
	switch v.Kind {
	case NotificationDestinationConsole:
		if strings.TrimSpace(v.Endpoint) != "" || v.AuthorizationEnv != "" || v.HMACSecretEnv != "" {
			return fmt.Errorf("%w: console destination cannot define endpoint or credentials", ErrValidation)
		}
	case NotificationDestinationWebhook:
		parsed, err := url.Parse(strings.TrimSpace(v.Endpoint))
		if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return fmt.Errorf("%w: webhook endpoint must be an absolute http(s) URL", ErrValidation)
		}
		if parsed.Scheme == "http" && !v.AllowHTTP {
			return fmt.Errorf("%w: plain HTTP webhook requires allowHttp=true", ErrValidation)
		}
		if parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("%w: webhook endpoint cannot contain userinfo or fragment", ErrValidation)
		}
	default:
		return fmt.Errorf("%w: unsupported notification destination kind", ErrValidation)
	}
	return nil
}

func NormalizeNotificationDestinationInput(v NotificationDestination) NotificationDestination {
	return normalizeNotificationDestination(v)
}

func ValidateNotificationDestinationInput(v NotificationDestination) error {
	return validateNotificationDestination(normalizeNotificationDestination(v))
}

func normalizeNotificationDestination(v NotificationDestination) NotificationDestination {
	v.OrganizationID = strings.TrimSpace(v.OrganizationID)
	v.Name = normalizeName(v.Name)
	v.Endpoint = strings.TrimSpace(v.Endpoint)
	v.AuthorizationEnv = strings.TrimSpace(v.AuthorizationEnv)
	v.HMACSecretEnv = strings.TrimSpace(v.HMACSecretEnv)
	if v.TimeoutSeconds == 0 {
		v.TimeoutSeconds = 10
	}
	return v
}

func (s *MemoryStore) CreateNotificationDestination(_ context.Context, v NotificationDestination, actor string) (NotificationDestination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v = normalizeNotificationDestination(v)
	if err := validateNotificationDestination(v); err != nil {
		return NotificationDestination{}, err
	}
	if _, ok := s.organizations[v.OrganizationID]; !ok {
		return NotificationDestination{}, ErrNotFound
	}
	for _, existing := range s.notificationDestinations {
		if existing.OrganizationID == v.OrganizationID && existing.Name == v.Name {
			return NotificationDestination{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("ntd"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = NotificationDestinationActive
	v.CreatedBy = actor
	s.notificationDestinations[v.ID] = v
	s.appendAuditLocked(actor, "notification_destination.created", "notificationDestination", v.ID, v.Revision, map[string]any{"organizationId": v.OrganizationID, "kind": v.Kind})
	return v, nil
}

func (s *MemoryStore) UpdateNotificationDestination(_ context.Context, id string, expected int64, input NotificationDestination, actor string) (NotificationDestination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.notificationDestinations[id]
	if !ok {
		return NotificationDestination{}, ErrNotFound
	}
	if current.Revision != expected {
		return NotificationDestination{}, ErrConflict
	}
	if current.State != NotificationDestinationActive {
		return NotificationDestination{}, ErrInvalidTransition
	}
	input.OrganizationID = current.OrganizationID
	input.State = current.State
	input.CreatedBy = current.CreatedBy
	input.ResourceMeta = current.ResourceMeta
	input = normalizeNotificationDestination(input)
	if err := validateNotificationDestination(input); err != nil {
		return NotificationDestination{}, err
	}
	for otherID, existing := range s.notificationDestinations {
		if otherID != id && existing.OrganizationID == current.OrganizationID && existing.Name == input.Name {
			return NotificationDestination{}, ErrDuplicateName
		}
	}
	input.Revision++
	input.UpdatedAt = nowUTC(s.now)
	s.notificationDestinations[id] = input
	s.appendAuditLocked(actor, "notification_destination.updated", "notificationDestination", id, input.Revision, map[string]any{"kind": input.Kind})
	return input, nil
}

func (s *MemoryStore) DisableNotificationDestination(_ context.Context, id string, expected int64, actor string) (NotificationDestination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.notificationDestinations[id]
	if !ok {
		return NotificationDestination{}, ErrNotFound
	}
	if current.Revision != expected {
		return NotificationDestination{}, ErrConflict
	}
	if current.State != NotificationDestinationActive {
		return NotificationDestination{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	current.State = NotificationDestinationDisabled
	current.DisabledBy = actor
	current.DisabledAt = &now
	current.Revision++
	current.UpdatedAt = now
	s.notificationDestinations[id] = current
	s.appendAuditLocked(actor, "notification_destination.disabled", "notificationDestination", id, current.Revision, nil)
	return current, nil
}

func (s *MemoryStore) GetNotificationDestination(_ context.Context, id string) (NotificationDestination, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.notificationDestinations[id]
	if !ok {
		return NotificationDestination{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListNotificationDestinations(_ context.Context, organizationID string) ([]NotificationDestination, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []NotificationDestination{}
	for _, v := range s.notificationDestinations {
		if organizationID == "" || v.OrganizationID == organizationID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func NormalizeNotificationRouteInput(v NotificationRoute) NotificationRoute {
	return normalizeNotificationRoute(v)
}

func ValidateNotificationRouteSyntax(v NotificationRoute) error {
	v = normalizeNotificationRoute(v)
	if v.OrganizationID == "" || v.Name == "" || len(v.EventPatterns) == 0 || len(v.DestinationIDs) == 0 || !validNotificationSeverity(v.MinimumSeverity) {
		return fmt.Errorf("%w: organizationId, name, eventPatterns, minimumSeverity and destinationIds are required", ErrValidation)
	}
	for _, pattern := range v.EventPatterns {
		if strings.ContainsAny(pattern, " \t\r\n") || strings.Count(pattern, "*") > 1 || (strings.Contains(pattern, "*") && !strings.HasSuffix(pattern, "*")) {
			return fmt.Errorf("%w: event patterns must be exact values or prefix*", ErrValidation)
		}
	}
	return nil
}

func normalizeNotificationRoute(v NotificationRoute) NotificationRoute {
	v.OrganizationID = strings.TrimSpace(v.OrganizationID)
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.Name = normalizeName(v.Name)
	patterns := make([]string, 0, len(v.EventPatterns))
	seenPatterns := map[string]bool{}
	for _, raw := range v.EventPatterns {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		if pattern != "" && !seenPatterns[pattern] {
			seenPatterns[pattern] = true
			patterns = append(patterns, pattern)
		}
	}
	sort.Strings(patterns)
	v.EventPatterns = patterns
	ids := make([]string, 0, len(v.DestinationIDs))
	seenIDs := map[string]bool{}
	for _, raw := range v.DestinationIDs {
		id := strings.TrimSpace(raw)
		if id != "" && !seenIDs[id] {
			seenIDs[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	v.DestinationIDs = ids
	if v.MinimumSeverity == "" {
		v.MinimumSeverity = NotificationInfo
	}
	return v
}

func (s *MemoryStore) validateNotificationRouteLocked(v NotificationRoute) error {
	if v.OrganizationID == "" || v.Name == "" || len(v.EventPatterns) == 0 || len(v.DestinationIDs) == 0 || !validNotificationSeverity(v.MinimumSeverity) {
		return fmt.Errorf("%w: organizationId, name, eventPatterns, minimumSeverity and destinationIds are required", ErrValidation)
	}
	if _, ok := s.organizations[v.OrganizationID]; !ok {
		return ErrNotFound
	}
	if v.ProjectID != "" {
		project, ok := s.projects[v.ProjectID]
		if !ok || project.OrganizationID != v.OrganizationID {
			return ErrNotFound
		}
	}
	for _, pattern := range v.EventPatterns {
		if strings.ContainsAny(pattern, " \t\r\n") || strings.Count(pattern, "*") > 1 || (strings.Contains(pattern, "*") && !strings.HasSuffix(pattern, "*")) {
			return fmt.Errorf("%w: event patterns must be exact values or prefix*", ErrValidation)
		}
	}
	for _, id := range v.DestinationIDs {
		destination, ok := s.notificationDestinations[id]
		if !ok || destination.OrganizationID != v.OrganizationID || destination.State != NotificationDestinationActive {
			return fmt.Errorf("%w: destination %s is not active in this organization", ErrValidation, id)
		}
	}
	return nil
}

func (s *MemoryStore) CreateNotificationRoute(_ context.Context, v NotificationRoute, actor string) (NotificationRoute, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v = normalizeNotificationRoute(v)
	if err := s.validateNotificationRouteLocked(v); err != nil {
		return NotificationRoute{}, err
	}
	for _, existing := range s.notificationRoutes {
		if existing.OrganizationID == v.OrganizationID && existing.Name == v.Name {
			return NotificationRoute{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("ntr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.CreatedBy = actor
	s.notificationRoutes[v.ID] = v
	s.appendAuditLocked(actor, "notification_route.created", "notificationRoute", v.ID, v.Revision, map[string]any{"organizationId": v.OrganizationID, "projectId": v.ProjectID})
	return v, nil
}

func (s *MemoryStore) UpdateNotificationRoute(_ context.Context, id string, expected int64, input NotificationRoute, actor string) (NotificationRoute, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.notificationRoutes[id]
	if !ok {
		return NotificationRoute{}, ErrNotFound
	}
	if current.Revision != expected {
		return NotificationRoute{}, ErrConflict
	}
	input.OrganizationID = current.OrganizationID
	input.ResourceMeta = current.ResourceMeta
	input.CreatedBy = current.CreatedBy
	input = normalizeNotificationRoute(input)
	if err := s.validateNotificationRouteLocked(input); err != nil {
		return NotificationRoute{}, err
	}
	for otherID, existing := range s.notificationRoutes {
		if otherID != id && existing.OrganizationID == current.OrganizationID && existing.Name == input.Name {
			return NotificationRoute{}, ErrDuplicateName
		}
	}
	input.Revision++
	input.UpdatedAt = nowUTC(s.now)
	s.notificationRoutes[id] = input
	s.appendAuditLocked(actor, "notification_route.updated", "notificationRoute", id, input.Revision, map[string]any{"enabled": input.Enabled})
	return input, nil
}

func (s *MemoryStore) GetNotificationRoute(_ context.Context, id string) (NotificationRoute, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.notificationRoutes[id]
	if !ok {
		return NotificationRoute{}, ErrNotFound
	}
	v.EventPatterns = append([]string(nil), v.EventPatterns...)
	v.DestinationIDs = append([]string(nil), v.DestinationIDs...)
	return v, nil
}

func (s *MemoryStore) ListNotificationRoutes(_ context.Context, organizationID, projectID string) ([]NotificationRoute, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []NotificationRoute{}
	for _, v := range s.notificationRoutes {
		if organizationID != "" && v.OrganizationID != organizationID {
			continue
		}
		if projectID != "" && v.ProjectID != "" && v.ProjectID != projectID {
			continue
		}
		copy := v
		copy.EventPatterns = append([]string(nil), v.EventPatterns...)
		copy.DestinationIDs = append([]string(nil), v.DestinationIDs...)
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func notificationPatternMatches(pattern, eventType string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(eventType, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == eventType
}

func NotificationRouteMatches(v NotificationRoute, event NotificationEvent) bool {
	return notificationRouteMatches(v, event)
}

func notificationRouteMatches(v NotificationRoute, event NotificationEvent) bool {
	if !v.Enabled || v.OrganizationID != event.OrganizationID || (v.ProjectID != "" && v.ProjectID != event.ProjectID) || notificationSeverityRank(event.Severity) < notificationSeverityRank(v.MinimumSeverity) {
		return false
	}
	for _, pattern := range v.EventPatterns {
		if notificationPatternMatches(pattern, event.EventType) {
			return true
		}
	}
	return false
}

func (s *MemoryStore) RouteNotificationEvent(_ context.Context, event NotificationEvent, actor string) (NotificationEvent, []NotificationDelivery, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.OrganizationID = strings.TrimSpace(event.OrganizationID)
	event.ProjectID = strings.TrimSpace(event.ProjectID)
	event.SourceEventID = strings.TrimSpace(event.SourceEventID)
	event.EventType = strings.ToLower(strings.TrimSpace(event.EventType))
	event.Title = strings.TrimSpace(event.Title)
	event.Summary = strings.TrimSpace(event.Summary)
	if event.OrganizationID == "" || event.SourceEventID == "" || event.EventType == "" || !validNotificationSeverity(event.Severity) || event.Title == "" {
		return NotificationEvent{}, nil, false, fmt.Errorf("%w: notification event organizationId, sourceEventId, eventType, severity and title are required", ErrValidation)
	}
	if _, ok := s.organizations[event.OrganizationID]; !ok {
		return NotificationEvent{}, nil, false, ErrNotFound
	}
	if event.ProjectID != "" {
		project, ok := s.projects[event.ProjectID]
		if !ok || project.OrganizationID != event.OrganizationID {
			return NotificationEvent{}, nil, false, ErrNotFound
		}
	}
	for _, existing := range s.notificationEvents {
		if existing.SourceEventID == event.SourceEventID {
			deliveries := []NotificationDelivery{}
			for _, d := range s.notificationDeliveries {
				if d.EventID == existing.ID {
					deliveries = append(deliveries, d)
				}
			}
			sort.Slice(deliveries, func(i, j int) bool { return deliveries[i].ID < deliveries[j].ID })
			existing.Payload = append([]byte(nil), existing.Payload...)
			return existing, deliveries, true, nil
		}
	}
	now := nowUTC(s.now)
	if event.OccurredAt.IsZero() {
		event.OccurredAt = now
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	event.ResourceMeta = ResourceMeta{ID: s.id("nte"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	event.Payload = append([]byte(nil), event.Payload...)
	s.notificationEvents[event.ID] = event
	deliveries := []NotificationDelivery{}
	for _, route := range s.notificationRoutes {
		if !notificationRouteMatches(route, event) {
			continue
		}
		for _, destinationID := range route.DestinationIDs {
			destination, ok := s.notificationDestinations[destinationID]
			if !ok || destination.State != NotificationDestinationActive || destination.OrganizationID != event.OrganizationID {
				continue
			}
			d := NotificationDelivery{ResourceMeta: ResourceMeta{ID: s.id("ndl"), Revision: 1, CreatedAt: now, UpdatedAt: now}, EventID: event.ID, RouteID: route.ID, DestinationID: destinationID, State: NotificationDeliveryPending, MaxAttempts: 5, NextAttemptAt: now}
			s.notificationDeliveries[d.ID] = d
			deliveries = append(deliveries, d)
		}
	}
	s.appendAuditLocked(actor, "notification_event.routed", "notificationEvent", event.ID, event.Revision, map[string]any{"eventType": event.EventType, "deliveryCount": len(deliveries), "sourceEventId": event.SourceEventID})
	return event, deliveries, false, nil
}

func (s *MemoryStore) GetNotificationEvent(_ context.Context, id string) (NotificationEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.notificationEvents[id]
	if !ok {
		return NotificationEvent{}, ErrNotFound
	}
	v.Payload = append([]byte(nil), v.Payload...)
	return v, nil
}

func (s *MemoryStore) ListNotificationEvents(_ context.Context, organizationID, projectID string, limit int) ([]NotificationEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []NotificationEvent{}
	for _, v := range s.notificationEvents {
		if organizationID != "" && v.OrganizationID != organizationID {
			continue
		}
		if projectID != "" && v.ProjectID != projectID {
			continue
		}
		v.Payload = append([]byte(nil), v.Payload...)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].OccurredAt.After(out[j].OccurredAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListNotificationEventsPageByScopes applies notification authorization before
// pagination. Organization IDs cover organization-wide events (project_id is
// empty); project IDs cover project-scoped events. Keeping this query bounded is
// important for interactive principals whose visible history can be much older
// than unrelated tenant traffic.
func (s *MemoryStore) ListNotificationEventsPageByScopes(_ context.Context, organizationIDs, projectIDs []string, limit int) ([]NotificationEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organizations := notificationScopeSet(organizationIDs)
	projects := notificationScopeSet(projectIDs)
	out := []NotificationEvent{}
	for _, v := range s.notificationEvents {
		if v.ProjectID != "" {
			if !projects[v.ProjectID] {
				continue
			}
		} else if !organizations[v.OrganizationID] {
			continue
		}
		v.Payload = append([]byte(nil), v.Payload...)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].OccurredAt.After(out[j].OccurredAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) GetNotificationDelivery(_ context.Context, id string) (NotificationDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.notificationDeliveries[id]
	if !ok {
		return NotificationDelivery{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListNotificationDeliveries(_ context.Context, organizationID, projectID string, state NotificationDeliveryState, limit int) ([]NotificationDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []NotificationDelivery{}
	for _, delivery := range s.notificationDeliveries {
		event, ok := s.notificationEvents[delivery.EventID]
		if !ok || (organizationID != "" && event.OrganizationID != organizationID) || (projectID != "" && event.ProjectID != projectID) || (state != "" && delivery.State != state) {
			continue
		}
		out = append(out, delivery)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListNotificationDeliveriesPageByScopes performs the event-scope join while
// the MemoryStore lock is held, avoiding one GetNotificationEvent lookup per
// delivery and ensuring LIMIT is applied only after authorization.
func (s *MemoryStore) ListNotificationDeliveriesPageByScopes(_ context.Context, organizationIDs, projectIDs []string, state NotificationDeliveryState, limit int) ([]NotificationDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organizations := notificationScopeSet(organizationIDs)
	projects := notificationScopeSet(projectIDs)
	out := []NotificationDelivery{}
	for _, delivery := range s.notificationDeliveries {
		if state != "" && delivery.State != state {
			continue
		}
		event, ok := s.notificationEvents[delivery.EventID]
		if !ok {
			continue
		}
		if event.ProjectID != "" {
			if !projects[event.ProjectID] {
				continue
			}
		} else if !organizations[event.OrganizationID] {
			continue
		}
		out = append(out, delivery)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) ClaimNotificationDeliveries(_ context.Context, worker string, limit int, ttl time.Duration, at time.Time) ([]NotificationDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	worker = strings.TrimSpace(worker)
	if worker == "" || limit <= 0 || ttl <= 0 {
		return nil, fmt.Errorf("%w: worker, positive limit and ttl are required", ErrValidation)
	}
	at = at.UTC()
	ids := make([]string, 0, len(s.notificationDeliveries))
	for id := range s.notificationDeliveries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.notificationDeliveries[ids[i]], s.notificationDeliveries[ids[j]]
		if !a.NextAttemptAt.Equal(b.NextAttemptAt) {
			return a.NextAttemptAt.Before(b.NextAttemptAt)
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID < b.ID
	})
	out := []NotificationDelivery{}
	for _, id := range ids {
		if len(out) >= limit {
			break
		}
		d := s.notificationDeliveries[id]
		if d.State != NotificationDeliveryPending && d.State != NotificationDeliveryRetryWait && d.State != NotificationDeliveryDelivering {
			continue
		}
		if d.NextAttemptAt.After(at) {
			continue
		}
		if d.ClaimedUntil != nil && d.ClaimedUntil.After(at) {
			continue
		}
		until := at.Add(ttl)
		d.State = NotificationDeliveryDelivering
		d.ClaimedBy = worker
		d.ClaimedUntil = &until
		d.Attempt++
		d.Revision++
		d.UpdatedAt = nowUTC(s.now)
		s.notificationDeliveries[id] = d
		out = append(out, d)
	}
	return out, nil
}

// ClaimNotificationHealthScanLease elects one notification worker to perform
// the fleet-wide health scan for a bounded interval. The lease is ephemeral
// authority: losing the process or letting the deadline expire permits another
// replica to continue without requiring manual cleanup.
func (s *MemoryStore) ClaimNotificationHealthScanLease(_ context.Context, worker string, ttl time.Duration, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	worker = strings.TrimSpace(worker)
	if worker == "" || ttl <= 0 {
		return false, fmt.Errorf("%w: worker and positive ttl are required", ErrValidation)
	}
	at = at.UTC()
	if s.notificationHealthLeaseUntil != nil && s.notificationHealthLeaseUntil.After(at) && s.notificationHealthLeaseBy != worker {
		return false, nil
	}
	until := at.Add(ttl)
	s.notificationHealthLeaseBy = worker
	s.notificationHealthLeaseUntil = &until
	return true, nil
}

// ListNotificationHealthCandidates returns a deterministic page of clusters
// whose health inputs changed after the supplied cursor. Development stores
// compute the same authority in-memory; PostgreSQL performs it in bounded SQL.
func (s *MemoryStore) ListNotificationHealthCandidates(_ context.Context, after time.Time, afterID string, limit int) ([]NotificationHealthCandidate, bool, error) {
	if limit <= 0 || limit > 500 {
		return nil, false, fmt.Errorf("%w: health candidate limit must be between 1 and 500", ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	after = after.UTC()
	afterID = strings.TrimSpace(afterID)
	changed := make(map[string]time.Time, len(s.managedClusters))
	for id, cluster := range s.managedClusters {
		changed[id] = cluster.UpdatedAt.UTC()
	}
	for clusterID, inventory := range s.clusterInventories {
		if inventory.UpdatedAt.After(changed[clusterID]) {
			changed[clusterID] = inventory.UpdatedAt.UTC()
		}
	}
	for _, cert := range s.agentCertificates {
		if cert.UpdatedAt.After(changed[cert.ClusterID]) {
			changed[cert.ClusterID] = cert.UpdatedAt.UTC()
		}
	}
	out := make([]NotificationHealthCandidate, 0, len(changed))
	for clusterID, changedAt := range changed {
		if changedAt.Before(after) || (changedAt.Equal(after) && clusterID <= afterID) {
			continue
		}
		out = append(out, NotificationHealthCandidate{ClusterID: clusterID, ChangedAt: changedAt})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ChangedAt.Equal(out[j].ChangedAt) {
			return out[i].ClusterID < out[j].ClusterID
		}
		return out[i].ChangedAt.Before(out[j].ChangedAt)
	})
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func notificationRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := 15 * time.Second
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= 15*time.Minute {
			return 15 * time.Minute
		}
	}
	return delay
}

func (s *MemoryStore) ReportNotificationDelivery(_ context.Context, id, worker string, at time.Time, result NotificationDeliveryResult) (NotificationDelivery, NotificationDeliveryAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.notificationDeliveries[id]
	if !ok {
		return NotificationDelivery{}, NotificationDeliveryAttempt{}, ErrNotFound
	}
	at = at.UTC()
	if d.State != NotificationDeliveryDelivering || d.ClaimedBy != worker || d.ClaimedUntil == nil || !d.ClaimedUntil.After(at) {
		return NotificationDelivery{}, NotificationDeliveryAttempt{}, ErrStaleFence
	}
	now := nowUTC(s.now)
	started := d.UpdatedAt
	if started.After(now) {
		started = now
	}
	attempt := NotificationDeliveryAttempt{ResourceMeta: ResourceMeta{ID: s.id("nda"), Revision: 1, CreatedAt: now, UpdatedAt: now}, DeliveryID: d.ID, Attempt: d.Attempt, StartedAt: started, FinishedAt: now, Success: result.Success, Retryable: result.Retryable, StatusCode: result.StatusCode, Error: strings.TrimSpace(result.Error), ResponseDigest: strings.TrimSpace(result.ResponseDigest), DurationMillis: result.DurationMillis}
	s.notificationAttempts[attempt.ID] = attempt
	d.LastStatusCode = result.StatusCode
	d.LastError = strings.TrimSpace(result.Error)
	d.ClaimedBy = ""
	d.ClaimedUntil = nil
	if result.Success {
		d.State = NotificationDeliverySucceeded
		d.DeliveredAt = &now
		d.LastError = ""
	} else if result.Retryable && d.Attempt < d.MaxAttempts {
		d.State = NotificationDeliveryRetryWait
		d.NextAttemptAt = now.Add(notificationRetryDelay(d.Attempt))
	} else {
		d.State = NotificationDeliveryDeadLetter
	}
	d.Revision++
	d.UpdatedAt = now
	s.notificationDeliveries[id] = d
	action := "notification_delivery.failed"
	if d.State == NotificationDeliverySucceeded {
		action = "notification_delivery.succeeded"
	} else if d.State == NotificationDeliveryRetryWait {
		action = "notification_delivery.retry_scheduled"
	} else if d.State == NotificationDeliveryDeadLetter {
		action = "notification_delivery.dead_lettered"
	}
	s.appendAuditLocked("notification-worker", action, "notificationDelivery", d.ID, d.Revision, map[string]any{"attempt": d.Attempt, "statusCode": d.LastStatusCode, "retryable": result.Retryable})
	return d, attempt, nil
}

func (s *MemoryStore) ListNotificationDeliveryAttempts(_ context.Context, deliveryID string) ([]NotificationDeliveryAttempt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []NotificationDeliveryAttempt{}
	for _, v := range s.notificationAttempts {
		if v.DeliveryID == deliveryID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Attempt != out[j].Attempt {
			return out[i].Attempt < out[j].Attempt
		}
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.Before(out[j].StartedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *MemoryStore) RetryNotificationDelivery(_ context.Context, id string, expected int64, actor string) (NotificationDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.notificationDeliveries[id]
	if !ok {
		return NotificationDelivery{}, ErrNotFound
	}
	if d.Revision != expected {
		return NotificationDelivery{}, ErrConflict
	}
	if d.State != NotificationDeliveryDeadLetter {
		return NotificationDelivery{}, ErrInvalidTransition
	}
	destination, ok := s.notificationDestinations[d.DestinationID]
	if !ok || destination.State != NotificationDestinationActive {
		return NotificationDelivery{}, fmt.Errorf("%w: notification destination must be active before retry", ErrPrerequisite)
	}
	now := nowUTC(s.now)
	d.State = NotificationDeliveryPending
	d.Attempt = 0
	d.NextAttemptAt = now
	d.ClaimedBy = ""
	d.ClaimedUntil = nil
	d.LastError = ""
	d.LastStatusCode = 0
	d.DeliveredAt = nil
	d.Revision++
	d.UpdatedAt = now
	s.notificationDeliveries[id] = d
	s.appendAuditLocked(actor, "notification_delivery.requeued", "notificationDelivery", id, d.Revision, nil)
	return d, nil
}
