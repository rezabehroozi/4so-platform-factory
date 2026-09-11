package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const (
	operationsQueueCenterAuthority = "OPERATIONS_QUEUE_CENTER_V1"
	productLogCenterAuthority      = "PRODUCT_LOG_CENTER_V1"
	operationsCenterDefaultLimit   = 100
	operationsCenterMaxLimit       = 200
)

type operationTracePageStore interface {
	ListOperationTracesPage(context.Context, string, int) ([]controlplane.ScopedOperationTrace, error)
}

type operationTraceScopedPageStore interface {
	ListOperationTracesPageByProjects(context.Context, []string, string, int) ([]controlplane.ScopedOperationTrace, error)
}

type agentTaskQueueCounter interface {
	AgentTaskQueueCounts(context.Context, []string, bool) (controlplane.AgentTaskQueueCounts, error)
}

type queueLaneView struct {
	ID                string         `json:"id"`
	Label             string         `json:"label"`
	Pending           int            `json:"pending"`
	Executing         int            `json:"executing"`
	RetryWait         int            `json:"retryWait"`
	Attention         int            `json:"attention"`
	DeadLetter        int            `json:"deadLetter"`
	ExpiredClaims     int            `json:"expiredClaims"`
	Retried           int            `json:"retried"`
	MaxAttempt        int            `json:"maxAttempt"`
	OldestPendingAt   *time.Time     `json:"oldestPendingAt,omitempty"`
	OldestExecutingAt *time.Time     `json:"oldestExecutingAt,omitempty"`
	LoadedItems       int            `json:"loadedItems"`
	Truncated         bool           `json:"truncated"`
	OldestLoadedAt    *time.Time     `json:"oldestLoadedAt,omitempty"`
	States            map[string]int `json:"states,omitempty"`
}

type operationsQueueCenterView struct {
	Authority   string                             `json:"authority"`
	GeneratedAt time.Time                          `json:"generatedAt"`
	Backend     string                             `json:"backend"`
	Limit       int                                `json:"limit"`
	Lanes       []queueLaneView                    `json:"lanes"`
	Items       []controlplane.OperationsQueueItem `json:"items"`
	Safety      map[string]any                     `json:"safety"`
}

type productLogEntry struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Source         string    `json:"source"`
	Level          string    `json:"level"`
	ProjectID      string    `json:"projectId,omitempty"`
	OrganizationID string    `json:"organizationId,omitempty"`
	OperationID    string    `json:"operationId,omitempty"`
	ResourceType   string    `json:"resourceType,omitempty"`
	ResourceID     string    `json:"resourceId,omitempty"`
	EventType      string    `json:"eventType"`
	Message        string    `json:"message"`
	ActorID        string    `json:"actorId,omitempty"`
	RequestID      string    `json:"requestId,omitempty"`
	StepKey        string    `json:"stepKey,omitempty"`
	Phase          string    `json:"phase,omitempty"`
	Attempt        int       `json:"attempt,omitempty"`
	EvidenceID     string    `json:"evidenceId,omitempty"`
	EvidenceDigest string    `json:"evidenceDigest,omitempty"`
	TargetRef      string    `json:"targetRef,omitempty"`
}

func boundedOperationsCenterLimit(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return operationsCenterDefaultLimit, nil
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 || v > operationsCenterMaxLimit {
		return 0, fmt.Errorf("limit must be an integer between 1 and %d", operationsCenterMaxLimit)
	}
	return v, nil
}

func (s *Server) scopedSummaryCounts(ctx context.Context, scope requestedReadScope) (controlplane.ControlPlaneSummaryCounts, error) {
	if counter, ok := s.store.(controlPlaneSummaryCounter); ok {
		return counter.ControlPlaneSummaryCounts(ctx, boolSetIDs(scope.organizations), boolSetIDs(scope.projects), boolSetIDs(scope.resourceOrganizations), scope.allOrganizationsAndProjects, scope.allResourceOrganizations)
	}
	// Development-only fallback. Production PostgreSQL always uses aggregate SQL.
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		return controlplane.ControlPlaneSummaryCounts{}, err
	}
	projects := scope.projects
	resourceOrganizations := scope.resourceOrganizations
	if scope.allOrganizationsAndProjects {
		projects = map[string]bool{}
		for _, project := range snap.Projects {
			projects[project.ID] = true
		}
	}
	if scope.allResourceOrganizations {
		resourceOrganizations = map[string]bool{}
		for _, organization := range snap.Organizations {
			resourceOrganizations[organization.ID] = true
		}
	}
	out := controlplane.ControlPlaneSummaryCounts{OperationStates: map[controlplane.OperationState]int{}, NotificationDeliveryStates: map[controlplane.NotificationDeliveryState]int{}}
	visibleOperations := map[string]bool{}
	visibleNotificationEvents := map[string]bool{}
	for _, op := range snap.Operations {
		if projects[op.ProjectID] {
			out.Operations++
			out.OperationStates[op.State]++
			visibleOperations[op.ID] = true
		}
	}
	for _, event := range snap.NotificationEvents {
		if (event.ProjectID != "" && projects[event.ProjectID]) || (event.ProjectID == "" && resourceOrganizations[event.OrganizationID]) {
			visibleNotificationEvents[event.ID] = true
		}
	}
	for _, delivery := range snap.NotificationDeliveries {
		if visibleNotificationEvents[delivery.EventID] {
			out.NotificationDeliveryStates[delivery.State]++
		}
	}
	index := buildScopeIndex(snap, resourceOrganizations, projects)
	for _, event := range snap.Outbox {
		if event.PublishedAt == nil && index.resources[event.AggregateID] {
			out.UnpublishedOutbox++
		}
	}
	return out, nil
}

func (s *Server) scopedOperationsPage(ctx context.Context, scope requestedReadScope, limit int) ([]controlplane.Operation, error) {
	projectID := scope.explicitProjectID
	if projectID != "" {
		if pager, ok := s.store.(operationPageStore); ok {
			return pager.ListOperationsPage(ctx, projectID, limit)
		}
		values, err := s.store.ListOperations(ctx, projectID)
		if err == nil && len(values) > limit {
			values = values[len(values)-limit:]
		}
		return values, err
	}
	if scope.allOrganizationsAndProjects {
		if pager, ok := s.store.(operationPageStore); ok {
			return pager.ListOperationsPage(ctx, "", limit)
		}
		values, err := s.store.ListOperations(ctx, "")
		if err == nil && len(values) > limit {
			values = values[len(values)-limit:]
		}
		return values, err
	}
	if pager, ok := s.store.(operationScopedPageStore); ok {
		return pager.ListOperationsPageByProjects(ctx, boolSetIDs(scope.projects), limit)
	}
	values, err := s.store.ListOperations(ctx, "")
	if err != nil {
		return nil, err
	}
	values = filterProjectScoped(values, scope.projects, false, func(item controlplane.Operation) string { return item.ProjectID })
	if len(values) > limit {
		values = values[len(values)-limit:]
	}
	return values, nil
}

func operationIsAttention(state controlplane.OperationState) bool {
	switch state {
	case controlplane.OperationPlanFailed, controlplane.OperationFailed, controlplane.OperationRollbackFailed, controlplane.OperationNeedsOperator:
		return true
	default:
		return false
	}
}

func operationIsExecuting(state controlplane.OperationState) bool {
	switch state {
	case controlplane.OperationRunning, controlplane.OperationVerifying, controlplane.OperationRollingBack, controlplane.OperationCancelRequested:
		return true
	default:
		return false
	}
}

func operationIsPending(state controlplane.OperationState) bool {
	switch state {
	case controlplane.OperationDraft, controlplane.OperationPlanning, controlplane.OperationAwaitingApproval, controlplane.OperationApproved, controlplane.OperationQueued, controlplane.OperationRetryWait:
		return true
	default:
		return false
	}
}

func operationIsTerminal(state controlplane.OperationState) bool {
	switch state {
	case controlplane.OperationSucceeded, controlplane.OperationRolledBack, controlplane.OperationCancelled:
		return true
	default:
		return false
	}
}

func operationQueueItem(op controlplane.Operation) controlplane.OperationsQueueItem {
	return controlplane.OperationsQueueItem{Lane: "operations", ID: op.ID, ProjectID: op.ProjectID, Kind: op.Kind, State: string(op.State), Attempt: op.Attempt, MaxAttempts: op.RetryPolicy.MaxAttempts, LeaseOwner: op.LeaseOwner, LeaseExpiresAt: op.LeaseExpiresAt, NextAttemptAt: op.NextAttemptAt, LastError: op.LastError, CreatedAt: op.CreatedAt, UpdatedAt: op.UpdatedAt}
}

func notificationQueueItem(v controlplane.NotificationDelivery) controlplane.OperationsQueueItem {
	next := v.NextAttemptAt
	return controlplane.OperationsQueueItem{Lane: "notifications", ID: v.ID, Kind: "notification-delivery", State: string(v.State), Attempt: v.Attempt, MaxAttempts: v.MaxAttempts, LeaseOwner: v.ClaimedBy, LeaseExpiresAt: v.ClaimedUntil, NextAttemptAt: &next, LastError: v.LastError, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}

func (s *Server) operationsQueueCenter(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedOperationsCenterLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_LIMIT", err.Error())
		return
	}
	scope, ok := s.resolveRequestedReadScope(w, r)
	if !ok {
		return
	}
	counts, err := s.scopedSummaryCounts(r.Context(), scope)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	operations, err := s.scopedOperationsPage(r.Context(), scope, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	organizations := boolSetIDs(scope.resourceOrganizations)
	projects := boolSetIDs(scope.projects)
	if scope.allResourceOrganizations {
		organizations = boolSetIDs(scope.organizations)
	}
	notificationStates := []controlplane.NotificationDeliveryState{controlplane.NotificationDeliveryPending, controlplane.NotificationDeliveryDelivering, controlplane.NotificationDeliveryRetryWait, controlplane.NotificationDeliveryDeadLetter}
	perStateLimit := limit / len(notificationStates)
	if perStateLimit < 10 {
		perStateLimit = 10
	}
	if perStateLimit > 50 {
		perStateLimit = 50
	}
	var deliveries []controlplane.NotificationDelivery
	if scope.allOrganizationsAndProjects && scope.allResourceOrganizations {
		for _, state := range notificationStates {
			values, pageErr := s.store.ListNotificationDeliveries(r.Context(), "", "", state, perStateLimit)
			if pageErr != nil {
				writeStoreError(w, pageErr)
				return
			}
			deliveries = append(deliveries, values...)
		}
	} else if pager, ok := s.store.(notificationScopedDeliveryPageStore); ok {
		for _, state := range notificationStates {
			values, pageErr := pager.ListNotificationDeliveriesPageByScopes(r.Context(), organizations, projects, state, perStateLimit)
			if pageErr != nil {
				writeStoreError(w, pageErr)
				return
			}
			deliveries = append(deliveries, values...)
		}
	} else {
		// Development fallback only; scoped runtime stores implement the pager.
		for _, state := range notificationStates {
			for _, projectID := range projects {
				values, pageErr := s.store.ListNotificationDeliveries(r.Context(), "", projectID, state, perStateLimit)
				if pageErr != nil {
					writeStoreError(w, pageErr)
					return
				}
				deliveries = append(deliveries, values...)
			}
		}
	}

	now := time.Now().UTC()
	opStates := map[string]int{}
	operationLane := queueLaneView{ID: "operations", Label: "Durable operations", States: opStates}
	for state, count := range counts.OperationStates {
		opStates[string(state)] = count
		if operationIsPending(state) {
			operationLane.Pending += count
		}
		if operationIsExecuting(state) {
			operationLane.Executing += count
		}
		if state == controlplane.OperationRetryWait {
			operationLane.RetryWait += count
		}
		if operationIsAttention(state) {
			operationLane.Attention += count
		}
	}
	items := make([]controlplane.OperationsQueueItem, 0, limit+len(deliveries))
	for _, op := range operations {
		if operationIsTerminal(op.State) {
			continue
		}
		item := operationQueueItem(op)
		items = append(items, item)
		operationLane.LoadedItems++
		if op.LeaseExpiresAt != nil && op.LeaseExpiresAt.Before(now) && (operationIsExecuting(op.State) || op.State == controlplane.OperationQueued) {
			operationLane.ExpiredClaims++
		}
		if operationLane.OldestLoadedAt == nil || op.CreatedAt.Before(*operationLane.OldestLoadedAt) {
			stamp := op.CreatedAt
			operationLane.OldestLoadedAt = &stamp
		}
	}
	exactOperationActive := operationLane.Pending + operationLane.Executing + operationLane.Attention
	operationLane.Truncated = exactOperationActive > operationLane.LoadedItems

	notificationLane := queueLaneView{ID: "notifications", Label: "Notification delivery", States: map[string]int{}}
	for state, count := range counts.NotificationDeliveryStates {
		notificationLane.States[string(state)] = count
		switch state {
		case controlplane.NotificationDeliveryPending:
			notificationLane.Pending += count
		case controlplane.NotificationDeliveryDelivering:
			notificationLane.Executing += count
		case controlplane.NotificationDeliveryRetryWait:
			notificationLane.RetryWait += count
		case controlplane.NotificationDeliveryDeadLetter:
			notificationLane.DeadLetter += count
			notificationLane.Attention += count
		}
	}
	for _, delivery := range deliveries {
		items = append(items, notificationQueueItem(delivery))
		notificationLane.LoadedItems++
		if delivery.ClaimedUntil != nil && delivery.ClaimedUntil.Before(now) && delivery.ClaimedBy != "" && delivery.State != controlplane.NotificationDeliverySucceeded {
			notificationLane.ExpiredClaims++
		}
		if notificationLane.OldestLoadedAt == nil || delivery.CreatedAt.Before(*notificationLane.OldestLoadedAt) {
			stamp := delivery.CreatedAt
			notificationLane.OldestLoadedAt = &stamp
		}
	}
	exactNotificationActive := notificationLane.Pending + notificationLane.Executing + notificationLane.RetryWait + notificationLane.DeadLetter
	notificationLane.Truncated = exactNotificationActive > notificationLane.LoadedItems

	outboxLane := queueLaneView{ID: "outbox", Label: "Transactional outbox", Pending: counts.UnpublishedOutbox, LoadedItems: 0, Truncated: counts.UnpublishedOutbox > 0, States: map[string]int{"UNPUBLISHED": counts.UnpublishedOutbox}}

	agentCounts := controlplane.AgentTaskQueueCounts{States: map[string]int{}}
	if counter, supported := s.store.(agentTaskQueueCounter); supported {
		agentCounts, err = counter.AgentTaskQueueCounts(r.Context(), boolSetIDs(scope.projects), scope.allOrganizationsAndProjects)
		if err != nil {
			writeStoreError(w, err)
			return
		}
	}
	agentLane := queueLaneView{
		ID: "agent-tasks", Label: "Agent task execution", Pending: agentCounts.Pending, Executing: agentCounts.Executing,
		Attention: agentCounts.Attention, ExpiredClaims: agentCounts.ExpiredClaims, Retried: agentCounts.Retried, MaxAttempt: agentCounts.MaxAttempt,
		OldestPendingAt: agentCounts.OldestPendingAt, OldestExecutingAt: agentCounts.OldestExecutingAt, LoadedItems: 0,
		Truncated: agentCounts.Pending+agentCounts.Executing+agentCounts.Attention > 0, States: agentCounts.States,
	}

	sort.Slice(items, func(i, j int) bool {
		if !items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		return items[i].ID > items[j].ID
	})
	if len(items) > limit {
		items = items[:limit]
	}
	w.Header().Set("X-Result-Limit", strconv.Itoa(limit))
	writeJSON(w, http.StatusOK, operationsQueueCenterView{
		Authority:   operationsQueueCenterAuthority,
		GeneratedAt: now,
		Backend:     s.store.Backend(),
		Limit:       limit,
		Lanes:       []queueLaneView{operationLane, agentLane, notificationLane, outboxLane},
		Items:       items,
		Safety:      map[string]any{"readOnly": true, "rawWorkerControls": false, "scopeBeforeLimit": true, "itemWindowBounded": true, "outboxItemsExposed": false, "agentTaskItemsExposed": false, "agentTaskPayloadsExposed": false},
	})
}

func sourceSet(raw string) map[string]bool {
	if strings.TrimSpace(raw) == "" {
		return map[string]bool{"operation": true, "audit": true, "notification": true}
	}
	out := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "operation" || item == "audit" || item == "notification" {
			out[item] = true
		}
	}
	return out
}

func logLevelAllowed(level, requested string) bool {
	requested = strings.ToUpper(strings.TrimSpace(requested))
	return requested == "" || requested == "ALL" || strings.ToUpper(level) == requested
}

func logMatches(entry productLogEntry, q string) bool {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{entry.Source, entry.Level, entry.ProjectID, entry.OperationID, entry.ResourceType, entry.ResourceID, entry.EventType, entry.Message, entry.ActorID, entry.RequestID, entry.StepKey, entry.Phase, entry.TargetRef}, " "))
	return strings.Contains(haystack, q)
}

func notificationLogLevel(severity controlplane.NotificationSeverity) string {
	switch severity {
	case controlplane.NotificationCritical:
		return "ERROR"
	case controlplane.NotificationWarning:
		return "WARN"
	default:
		return "INFO"
	}
}

func (s *Server) productLogs(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedOperationsCenterLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_LIMIT", err.Error())
		return
	}
	scope, ok := s.resolveRequestedReadScope(w, r)
	if !ok {
		return
	}
	sources := sourceSet(r.URL.Query().Get("source"))
	if len(sources) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_SOURCE", "source must include operation, audit or notification")
		return
	}
	requestedLevel := strings.TrimSpace(r.URL.Query().Get("level"))
	if requestedLevel != "" {
		switch strings.ToUpper(requestedLevel) {
		case "ALL", "DEBUG", "INFO", "WARN", "ERROR":
		default:
			writeError(w, http.StatusBadRequest, "INVALID_LEVEL", "level must be DEBUG, INFO, WARN, ERROR or ALL")
			return
		}
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 200 {
		writeError(w, http.StatusBadRequest, "INVALID_QUERY", "q must not exceed 200 characters")
		return
	}
	operationID := strings.TrimSpace(r.URL.Query().Get("operationId"))
	projectIDs := boolSetIDs(scope.projects)
	organizationIDs := boolSetIDs(scope.resourceOrganizations)
	if scope.allResourceOrganizations {
		organizationIDs = boolSetIDs(scope.organizations)
	}
	entries := make([]productLogEntry, 0, limit*3)
	windowTruncated := false
	windowCounts := map[string]int{}

	if sources["operation"] {
		var traces []controlplane.ScopedOperationTrace
		var traceErr error
		if scope.allOrganizationsAndProjects {
			pager, ok := s.store.(operationTracePageStore)
			if !ok {
				writeError(w, http.StatusServiceUnavailable, "LOG_AUTHORITY_UNAVAILABLE", "operation trace pager is unavailable")
				return
			}
			traces, traceErr = pager.ListOperationTracesPage(r.Context(), operationID, limit)
		} else {
			pager, ok := s.store.(operationTraceScopedPageStore)
			if !ok {
				writeError(w, http.StatusServiceUnavailable, "LOG_AUTHORITY_UNAVAILABLE", "operation trace pager is unavailable")
				return
			}
			traces, traceErr = pager.ListOperationTracesPageByProjects(r.Context(), projectIDs, operationID, limit)
		}
		if traceErr != nil {
			writeStoreError(w, traceErr)
			return
		}
		windowCounts["operation"] = len(traces)
		windowTruncated = windowTruncated || len(traces) == limit
		for _, trace := range traces {
			entry := productLogEntry{ID: trace.ID, Timestamp: trace.CreatedAt, Source: "operation", Level: string(trace.Level), ProjectID: trace.ProjectID, OperationID: trace.OperationID, ResourceType: "operation", ResourceID: trace.OperationID, EventType: trace.EventType, Message: trace.Message, StepKey: trace.StepKey, Phase: string(trace.Phase), Attempt: trace.Attempt, EvidenceID: trace.EvidenceID, EvidenceDigest: trace.EvidenceDigest, TargetRef: trace.TargetRef}
			if logLevelAllowed(entry.Level, requestedLevel) && logMatches(entry, q) {
				entries = append(entries, entry)
			}
		}
	}
	if operationID == "" && sources["audit"] {
		var audit []controlplane.AuditEvent
		var auditErr error
		if scope.allOrganizationsAndProjects && scope.allResourceOrganizations {
			audit, auditErr = s.store.ListAudit(r.Context(), limit)
		} else {
			pager, ok := s.store.(auditScopedPageStore)
			if !ok {
				writeError(w, http.StatusServiceUnavailable, "LOG_AUTHORITY_UNAVAILABLE", "audit pager is unavailable")
				return
			}
			audit, auditErr = pager.ListAuditPageByScopes(r.Context(), organizationIDs, projectIDs, limit)
		}
		if auditErr != nil {
			writeStoreError(w, auditErr)
			return
		}
		windowCounts["audit"] = len(audit)
		windowTruncated = windowTruncated || len(audit) == limit
		for _, event := range audit {
			entry := productLogEntry{ID: event.ID, Timestamp: event.OccurredAt, Source: "audit", Level: "INFO", ResourceType: event.ResourceType, ResourceID: event.ResourceID, EventType: event.Action, Message: event.Action + " · " + event.ResourceType + "/" + event.ResourceID, ActorID: event.ActorID, RequestID: event.RequestID}
			if projectID, ok := event.Metadata["projectId"].(string); ok {
				entry.ProjectID = projectID
			}
			if organizationID, ok := event.Metadata["organizationId"].(string); ok {
				entry.OrganizationID = organizationID
			}
			if logLevelAllowed(entry.Level, requestedLevel) && logMatches(entry, q) {
				entries = append(entries, entry)
			}
		}
	}
	if operationID == "" && sources["notification"] {
		var events []controlplane.NotificationEvent
		var eventErr error
		if scope.allOrganizationsAndProjects && scope.allResourceOrganizations {
			events, eventErr = s.store.ListNotificationEvents(r.Context(), "", "", limit)
		} else {
			pager, ok := s.store.(notificationScopedEventPageStore)
			if !ok {
				writeError(w, http.StatusServiceUnavailable, "LOG_AUTHORITY_UNAVAILABLE", "notification event pager is unavailable")
				return
			}
			events, eventErr = pager.ListNotificationEventsPageByScopes(r.Context(), organizationIDs, projectIDs, limit)
		}
		if eventErr != nil {
			writeStoreError(w, eventErr)
			return
		}
		windowCounts["notification"] = len(events)
		windowTruncated = windowTruncated || len(events) == limit
		for _, event := range events {
			entry := productLogEntry{ID: event.ID, Timestamp: event.OccurredAt, Source: "notification", Level: notificationLogLevel(event.Severity), ProjectID: event.ProjectID, OrganizationID: event.OrganizationID, ResourceType: event.AggregateType, ResourceID: event.AggregateID, EventType: event.EventType, Message: strings.TrimSpace(event.Title + " · " + event.Summary)}
			if logLevelAllowed(entry.Level, requestedLevel) && logMatches(entry, q) {
				entries = append(entries, entry)
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].Timestamp.Equal(entries[j].Timestamp) {
			return entries[i].Timestamp.After(entries[j].Timestamp)
		}
		return entries[i].ID > entries[j].ID
	})
	resultTruncated := len(entries) > limit
	if resultTruncated {
		entries = entries[:limit]
	}
	w.Header().Set("X-Result-Limit", strconv.Itoa(limit))
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":           productLogCenterAuthority,
		"generatedAt":         time.Now().UTC(),
		"backend":             s.store.Backend(),
		"entries":             entries,
		"limit":               limit,
		"windowCounts":        windowCounts,
		"windowTruncated":     windowTruncated,
		"resultTruncated":     resultTruncated,
		"searchComplete":      q == "" || !windowTruncated,
		"searchSemantics":     "LATEST_AUTHORIZED_PRODUCT_LOG_WINDOWS_V1",
		"payloadPolicy":       "METADATA_AND_REDACTED_MESSAGES_ONLY",
		"runtimeWorkloadTail": true,
	})
}
