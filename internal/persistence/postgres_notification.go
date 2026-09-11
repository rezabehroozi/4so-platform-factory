package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const notificationDestinationColumns = `id,organization_id,revision,name,kind,endpoint,authorization_env,hmac_secret_env,allow_http,timeout_seconds,state,created_by,disabled_by,disabled_at,created_at,updated_at`
const notificationRouteColumns = `id,organization_id,COALESCE(project_id,''),revision,name,enabled,event_patterns,minimum_severity,destination_ids,created_by,created_at,updated_at`
const notificationEventColumns = `id,organization_id,COALESCE(project_id,''),revision,source_event_id,aggregate_type,aggregate_id,event_type,severity,title,summary,payload,occurred_at,created_at,updated_at`
const notificationDeliveryColumns = `id,event_id,route_id,destination_id,revision,state,attempt,max_attempts,next_attempt_at,claimed_by,claimed_until,last_status_code,last_error,delivered_at,created_at,updated_at`
const notificationAttemptColumns = `id,delivery_id,revision,attempt,started_at,finished_at,success,retryable,status_code,error,response_digest,duration_millis,created_at,updated_at`

func scanNotificationDestination(row interface{ Scan(...any) error }) (controlplane.NotificationDestination, error) {
	var v controlplane.NotificationDestination
	var kind, state string
	err := row.Scan(&v.ID, &v.OrganizationID, &v.Revision, &v.Name, &kind, &v.Endpoint, &v.AuthorizationEnv, &v.HMACSecretEnv, &v.AllowHTTP, &v.TimeoutSeconds, &state, &v.CreatedBy, &v.DisabledBy, &v.DisabledAt, &v.CreatedAt, &v.UpdatedAt)
	v.Kind = controlplane.NotificationDestinationKind(kind)
	v.State = controlplane.NotificationDestinationState(state)
	return v, err
}

func scanNotificationRoute(row interface{ Scan(...any) error }) (controlplane.NotificationRoute, error) {
	var v controlplane.NotificationRoute
	var patterns, destinations []byte
	var severity string
	err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.Revision, &v.Name, &v.Enabled, &patterns, &severity, &destinations, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	if err == nil {
		err = decodeJSONColumn(patterns, &v.EventPatterns, "notification_routes.event_patterns")
	}
	if err == nil {
		err = decodeJSONColumn(destinations, &v.DestinationIDs, "notification_routes.destination_ids")
	}
	v.MinimumSeverity = controlplane.NotificationSeverity(severity)
	return v, err
}

func scanNotificationEvent(row interface{ Scan(...any) error }) (controlplane.NotificationEvent, error) {
	var v controlplane.NotificationEvent
	var severity string
	err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.Revision, &v.SourceEventID, &v.AggregateType, &v.AggregateID, &v.EventType, &severity, &v.Title, &v.Summary, &v.Payload, &v.OccurredAt, &v.CreatedAt, &v.UpdatedAt)
	v.Severity = controlplane.NotificationSeverity(severity)
	return v, err
}

func scanNotificationDelivery(row interface{ Scan(...any) error }) (controlplane.NotificationDelivery, error) {
	var v controlplane.NotificationDelivery
	var state string
	err := row.Scan(&v.ID, &v.EventID, &v.RouteID, &v.DestinationID, &v.Revision, &state, &v.Attempt, &v.MaxAttempts, &v.NextAttemptAt, &v.ClaimedBy, &v.ClaimedUntil, &v.LastStatusCode, &v.LastError, &v.DeliveredAt, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.NotificationDeliveryState(state)
	return v, err
}

func scanNotificationAttempt(row interface{ Scan(...any) error }) (controlplane.NotificationDeliveryAttempt, error) {
	var v controlplane.NotificationDeliveryAttempt
	err := row.Scan(&v.ID, &v.DeliveryID, &v.Revision, &v.Attempt, &v.StartedAt, &v.FinishedAt, &v.Success, &v.Retryable, &v.StatusCode, &v.Error, &v.ResponseDigest, &v.DurationMillis, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func (s *PostgresStore) CreateNotificationDestination(ctx context.Context, v controlplane.NotificationDestination, actor string) (controlplane.NotificationDestination, error) {
	v = controlplane.NormalizeNotificationDestinationInput(v)
	if err := controlplane.ValidateNotificationDestinationInput(v); err != nil {
		return controlplane.NotificationDestination{}, err
	}
	var out controlplane.NotificationDestination
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if _, e := scanOrganization(tx.QueryRowContext(ctx, `SELECT `+organizationColumns+` FROM organizations WHERE id=$1 FOR SHARE`, v.OrganizationID)); e != nil {
			return mapDBError(e)
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ntd"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.NotificationDestinationActive
		v.CreatedBy = strings.TrimSpace(actor)
		var e error
		out, e = scanNotificationDestination(tx.QueryRowContext(ctx, `INSERT INTO notification_destinations(id,organization_id,revision,name,kind,endpoint,authorization_env,hmac_secret_env,allow_http,timeout_seconds,state,created_by,disabled_by,disabled_at,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,'ACTIVE',$10,'',NULL,$11,$11) RETURNING `+notificationDestinationColumns, v.ID, v.OrganizationID, v.Name, string(v.Kind), v.Endpoint, v.AuthorizationEnv, v.HMACSecretEnv, v.AllowHTTP, v.TimeoutSeconds, v.CreatedBy, now))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, actor, "notification_destination.created", "notificationDestination", out.ID, out.Revision, "", map[string]any{"organizationId": out.OrganizationID, "kind": out.Kind})
	})
	return out, err
}

func (s *PostgresStore) UpdateNotificationDestination(ctx context.Context, id string, expected int64, input controlplane.NotificationDestination, actor string) (controlplane.NotificationDestination, error) {
	var out controlplane.NotificationDestination
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, e := scanNotificationDestination(tx.QueryRowContext(ctx, `SELECT `+notificationDestinationColumns+` FROM notification_destinations WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		if cur.State != controlplane.NotificationDestinationActive {
			return controlplane.ErrInvalidTransition
		}
		input.OrganizationID, input.State, input.CreatedBy = cur.OrganizationID, cur.State, cur.CreatedBy
		input = controlplane.NormalizeNotificationDestinationInput(input)
		if e = controlplane.ValidateNotificationDestinationInput(input); e != nil {
			return e
		}
		now := utcNow(s.now)
		out, e = scanNotificationDestination(tx.QueryRowContext(ctx, `UPDATE notification_destinations SET revision=revision+1,name=$2,kind=$3,endpoint=$4,authorization_env=$5,hmac_secret_env=$6,allow_http=$7,timeout_seconds=$8,updated_at=$9 WHERE id=$1 RETURNING `+notificationDestinationColumns, cur.ID, input.Name, string(input.Kind), input.Endpoint, input.AuthorizationEnv, input.HMACSecretEnv, input.AllowHTTP, input.TimeoutSeconds, now))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, actor, "notification_destination.updated", "notificationDestination", out.ID, out.Revision, "", map[string]any{"kind": out.Kind})
	})
	return out, err
}

func (s *PostgresStore) DisableNotificationDestination(ctx context.Context, id string, expected int64, actor string) (controlplane.NotificationDestination, error) {
	var out controlplane.NotificationDestination
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, e := scanNotificationDestination(tx.QueryRowContext(ctx, `SELECT `+notificationDestinationColumns+` FROM notification_destinations WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		if cur.State != controlplane.NotificationDestinationActive {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		out, e = scanNotificationDestination(tx.QueryRowContext(ctx, `UPDATE notification_destinations SET revision=revision+1,state='DISABLED',disabled_by=$2,disabled_at=$3,updated_at=$3 WHERE id=$1 RETURNING `+notificationDestinationColumns, cur.ID, strings.TrimSpace(actor), now))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, actor, "notification_destination.disabled", "notificationDestination", out.ID, out.Revision, "", nil)
	})
	return out, err
}

func (s *PostgresStore) GetNotificationDestination(ctx context.Context, id string) (controlplane.NotificationDestination, error) {
	v, err := scanNotificationDestination(s.db.QueryRowContext(ctx, `SELECT `+notificationDestinationColumns+` FROM notification_destinations WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListNotificationDestinations(ctx context.Context, organizationID string) ([]controlplane.NotificationDestination, error) {
	q := `SELECT ` + notificationDestinationColumns + ` FROM notification_destinations`
	args := []any{}
	if strings.TrimSpace(organizationID) != "" {
		q += ` WHERE organization_id=$1`
		args = append(args, strings.TrimSpace(organizationID))
	}
	q += ` ORDER BY organization_id,name,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.NotificationDestination{}
	for rows.Next() {
		v, e := scanNotificationDestination(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func validateNotificationRouteDB(ctx context.Context, tx *sql.Tx, v controlplane.NotificationRoute) error {
	if err := controlplane.ValidateNotificationRouteSyntax(v); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, v.OrganizationID).Scan(&exists); err != nil || !exists {
		if err != nil {
			return err
		}
		return controlplane.ErrNotFound
	}
	if v.ProjectID != "" {
		var org string
		if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1`, v.ProjectID).Scan(&org); err != nil {
			return mapDBError(err)
		}
		if org != v.OrganizationID {
			return fmt.Errorf("%w: project is outside route organization", controlplane.ErrValidation)
		}
	}
	for _, id := range v.DestinationIDs {
		var org, state string
		if err := tx.QueryRowContext(ctx, `SELECT organization_id,state FROM notification_destinations WHERE id=$1`, id).Scan(&org, &state); err != nil {
			return mapDBError(err)
		}
		if org != v.OrganizationID || state != string(controlplane.NotificationDestinationActive) {
			return fmt.Errorf("%w: destination %s is not active in this organization", controlplane.ErrValidation, id)
		}
	}
	return nil
}

func (s *PostgresStore) CreateNotificationRoute(ctx context.Context, v controlplane.NotificationRoute, actor string) (controlplane.NotificationRoute, error) {
	v = controlplane.NormalizeNotificationRouteInput(v)
	var out controlplane.NotificationRoute
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := validateNotificationRouteDB(ctx, tx, v); e != nil {
			return e
		}
		patterns, _ := json.Marshal(v.EventPatterns)
		destinations, _ := json.Marshal(v.DestinationIDs)
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ntr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.CreatedBy = strings.TrimSpace(actor)
		var project any = nil
		if v.ProjectID != "" {
			project = v.ProjectID
		}
		var e error
		out, e = scanNotificationRoute(tx.QueryRowContext(ctx, `INSERT INTO notification_routes(id,organization_id,project_id,revision,name,enabled,event_patterns,minimum_severity,destination_ids,created_by,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6::jsonb,$7,$8::jsonb,$9,$10,$10) RETURNING `+notificationRouteColumns, v.ID, v.OrganizationID, project, v.Name, v.Enabled, patterns, string(v.MinimumSeverity), destinations, v.CreatedBy, now))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, actor, "notification_route.created", "notificationRoute", out.ID, out.Revision, "", map[string]any{"organizationId": out.OrganizationID, "projectId": out.ProjectID})
	})
	return out, err
}

func (s *PostgresStore) UpdateNotificationRoute(ctx context.Context, id string, expected int64, input controlplane.NotificationRoute, actor string) (controlplane.NotificationRoute, error) {
	var out controlplane.NotificationRoute
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, e := scanNotificationRoute(tx.QueryRowContext(ctx, `SELECT `+notificationRouteColumns+` FROM notification_routes WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		input.OrganizationID = cur.OrganizationID
		input = controlplane.NormalizeNotificationRouteInput(input)
		if e = validateNotificationRouteDB(ctx, tx, input); e != nil {
			return e
		}
		patterns, _ := json.Marshal(input.EventPatterns)
		destinations, _ := json.Marshal(input.DestinationIDs)
		var project any = nil
		if input.ProjectID != "" {
			project = input.ProjectID
		}
		now := utcNow(s.now)
		out, e = scanNotificationRoute(tx.QueryRowContext(ctx, `UPDATE notification_routes SET revision=revision+1,project_id=$2,name=$3,enabled=$4,event_patterns=$5::jsonb,minimum_severity=$6,destination_ids=$7::jsonb,updated_at=$8 WHERE id=$1 RETURNING `+notificationRouteColumns, cur.ID, project, input.Name, input.Enabled, patterns, string(input.MinimumSeverity), destinations, now))
		if e != nil {
			return mapDBError(e)
		}
		return s.appendAuditTx(ctx, tx, actor, "notification_route.updated", "notificationRoute", out.ID, out.Revision, "", map[string]any{"enabled": out.Enabled})
	})
	return out, err
}
func (s *PostgresStore) GetNotificationRoute(ctx context.Context, id string) (controlplane.NotificationRoute, error) {
	v, e := scanNotificationRoute(s.db.QueryRowContext(ctx, `SELECT `+notificationRouteColumns+` FROM notification_routes WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListNotificationRoutes(ctx context.Context, organizationID, projectID string) ([]controlplane.NotificationRoute, error) {
	q := `SELECT ` + notificationRouteColumns + ` FROM notification_routes WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(organizationID) != "" {
		args = append(args, strings.TrimSpace(organizationID))
		q += fmt.Sprintf(" AND organization_id=$%d", len(args))
	}
	if strings.TrimSpace(projectID) != "" {
		args = append(args, strings.TrimSpace(projectID))
		q += fmt.Sprintf(" AND (project_id IS NULL OR project_id=$%d)", len(args))
	}
	q += ` ORDER BY organization_id,name,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.NotificationRoute{}
	for rows.Next() {
		v, e := scanNotificationRoute(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func normalizeNotificationEventInput(event controlplane.NotificationEvent, now time.Time) (controlplane.NotificationEvent, error) {
	event.OrganizationID = strings.TrimSpace(event.OrganizationID)
	event.ProjectID = strings.TrimSpace(event.ProjectID)
	event.SourceEventID = strings.TrimSpace(event.SourceEventID)
	event.EventType = strings.ToLower(strings.TrimSpace(event.EventType))
	event.Title = strings.TrimSpace(event.Title)
	event.Summary = strings.TrimSpace(event.Summary)
	if event.OrganizationID == "" || event.SourceEventID == "" || event.EventType == "" || event.Title == "" || (event.Severity != controlplane.NotificationInfo && event.Severity != controlplane.NotificationWarning && event.Severity != controlplane.NotificationCritical) {
		return controlplane.NotificationEvent{}, fmt.Errorf("%w: notification event organizationId, sourceEventId, eventType, severity and title are required", controlplane.ErrValidation)
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = now
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	if len(event.Payload) == 0 {
		event.Payload = []byte(`{}`)
	}
	if !json.Valid(event.Payload) {
		return controlplane.NotificationEvent{}, fmt.Errorf("%w: notification event payload must be valid JSON", controlplane.ErrValidation)
	}
	return event, nil
}

func listNotificationDeliveriesForEventTx(ctx context.Context, tx *sql.Tx, eventID string) ([]controlplane.NotificationDelivery, error) {
	rows, e := tx.QueryContext(ctx, `SELECT `+notificationDeliveryColumns+` FROM notification_deliveries WHERE event_id=$1 ORDER BY id`, eventID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.NotificationDelivery{}
	for rows.Next() {
		v, e := scanNotificationDelivery(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RouteNotificationEvent(ctx context.Context, event controlplane.NotificationEvent, actor string) (controlplane.NotificationEvent, []controlplane.NotificationDelivery, bool, error) {
	var out controlplane.NotificationEvent
	var deliveries []controlplane.NotificationDelivery
	duplicate := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		attemptDeliveries := []controlplane.NotificationDelivery{}
		duplicate = false
		now := utcNow(s.now)
		var e error
		event, e = normalizeNotificationEventInput(event, now)
		if e != nil {
			return e
		}
		existing, e := scanNotificationEvent(tx.QueryRowContext(ctx, `SELECT `+notificationEventColumns+` FROM notification_events WHERE source_event_id=$1 FOR SHARE`, event.SourceEventID))
		if e == nil {
			out = existing
			duplicate = true
			deliveries, e = listNotificationDeliveriesForEventTx(ctx, tx, out.ID)
			return e
		}
		if e != sql.ErrNoRows {
			return e
		}
		var exists bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, event.OrganizationID).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return controlplane.ErrNotFound
		}
		var project any = nil
		if event.ProjectID != "" {
			var org string
			if e = tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1`, event.ProjectID).Scan(&org); e != nil {
				return mapDBError(e)
			}
			if org != event.OrganizationID {
				return controlplane.ErrValidation
			}
			project = event.ProjectID
		}
		event.ResourceMeta = controlplane.ResourceMeta{ID: s.id("nte"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		out, e = scanNotificationEvent(tx.QueryRowContext(ctx, `INSERT INTO notification_events(id,organization_id,project_id,revision,source_event_id,aggregate_type,aggregate_id,event_type,severity,title,summary,payload,occurred_at,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$13) RETURNING `+notificationEventColumns, event.ID, event.OrganizationID, project, event.SourceEventID, event.AggregateType, event.AggregateID, event.EventType, string(event.Severity), event.Title, event.Summary, event.Payload, event.OccurredAt, now))
		if e != nil {
			return mapDBError(e)
		}
		rows, e := tx.QueryContext(ctx, `SELECT `+notificationRouteColumns+` FROM notification_routes WHERE organization_id=$1 AND enabled=true AND (project_id IS NULL OR project_id=$2) ORDER BY id`, event.OrganizationID, project)
		if e != nil {
			return e
		}
		routes := []controlplane.NotificationRoute{}
		for rows.Next() {
			v, se := scanNotificationRoute(rows)
			if se != nil {
				rows.Close()
				return se
			}
			routes = append(routes, v)
		}
		if e = rows.Close(); e != nil {
			return e
		}
		for _, route := range routes {
			if !controlplane.NotificationRouteMatches(route, out) {
				continue
			}
			for _, destinationID := range route.DestinationIDs {
				var org, state string
				if e = tx.QueryRowContext(ctx, `SELECT organization_id,state FROM notification_destinations WHERE id=$1`, destinationID).Scan(&org, &state); e != nil {
					if e == sql.ErrNoRows {
						continue
					}
					return e
				}
				if org != out.OrganizationID || state != string(controlplane.NotificationDestinationActive) {
					continue
				}
				d := controlplane.NotificationDelivery{ResourceMeta: controlplane.ResourceMeta{ID: s.id("ndl"), Revision: 1, CreatedAt: now, UpdatedAt: now}, EventID: out.ID, RouteID: route.ID, DestinationID: destinationID, State: controlplane.NotificationDeliveryPending, MaxAttempts: 5, NextAttemptAt: now}
				inserted, se := scanNotificationDelivery(tx.QueryRowContext(ctx, `INSERT INTO notification_deliveries(id,event_id,route_id,destination_id,revision,state,attempt,max_attempts,next_attempt_at,claimed_by,claimed_until,last_status_code,last_error,delivered_at,created_at,updated_at) VALUES($1,$2,$3,$4,1,'PENDING',0,5,$5,'',NULL,0,'',NULL,$5,$5) RETURNING `+notificationDeliveryColumns, d.ID, d.EventID, d.RouteID, d.DestinationID, now))
				if se != nil {
					return mapDBError(se)
				}
				attemptDeliveries = append(attemptDeliveries, inserted)
			}
		}
		if e = s.appendAuditTx(ctx, tx, actor, "notification_event.routed", "notificationEvent", out.ID, out.Revision, "", map[string]any{"eventType": out.EventType, "deliveryCount": len(attemptDeliveries), "sourceEventId": out.SourceEventID}); e != nil {
			return e
		}
		deliveries = attemptDeliveries
		return nil
	})
	return out, deliveries, duplicate, err
}

func (s *PostgresStore) GetNotificationEvent(ctx context.Context, id string) (controlplane.NotificationEvent, error) {
	v, e := scanNotificationEvent(s.db.QueryRowContext(ctx, `SELECT `+notificationEventColumns+` FROM notification_events WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListNotificationEvents(ctx context.Context, organizationID, projectID string, limit int) ([]controlplane.NotificationEvent, error) {
	q := `SELECT ` + notificationEventColumns + ` FROM notification_events WHERE 1=1`
	args := []any{}
	if organizationID != "" {
		args = append(args, organizationID)
		q += fmt.Sprintf(" AND organization_id=$%d", len(args))
	}
	if projectID != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	q += ` ORDER BY occurred_at DESC,id DESC`
	if limit > 0 {
		args = append(args, limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.NotificationEvent{}
	for rows.Next() {
		v, e := scanNotificationEvent(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListNotificationEventsPageByScopes applies tenant authorization before LIMIT
// so unrelated tenant traffic cannot force a scoped principal to scan the full
// notification history or evict older authorized rows from the requested page.
func (s *PostgresStore) ListNotificationEventsPageByScopes(ctx context.Context, organizationIDs, projectIDs []string, limit int) ([]controlplane.NotificationEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	organizations := normalizedScopeIDs(organizationIDs)
	projects := normalizedScopeIDs(projectIDs)
	conditions := make([]string, 0, 2)
	args := make([]any, 0, 3)
	const separator = "\x1f"
	if len(projects) > 0 {
		args = append(args, strings.Join(projects, separator))
		conditions = append(conditions, fmt.Sprintf("project_id = ANY(string_to_array($%d, chr(31)))", len(args)))
	}
	if len(organizations) > 0 {
		args = append(args, strings.Join(organizations, separator))
		conditions = append(conditions, fmt.Sprintf("(project_id IS NULL AND organization_id = ANY(string_to_array($%d, chr(31))))", len(args)))
	}
	if len(conditions) == 0 {
		return []controlplane.NotificationEvent{}, nil
	}
	args = append(args, limit)
	q := `SELECT ` + notificationEventColumns + ` FROM notification_events WHERE (` + strings.Join(conditions, ` OR `) + `) ORDER BY occurred_at DESC,id DESC LIMIT $` + fmt.Sprint(len(args))
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.NotificationEvent{}
	for rows.Next() {
		v, scanErr := scanNotificationEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) GetNotificationDelivery(ctx context.Context, id string) (controlplane.NotificationDelivery, error) {
	v, e := scanNotificationDelivery(s.db.QueryRowContext(ctx, `SELECT `+notificationDeliveryColumns+` FROM notification_deliveries WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListNotificationDeliveries(ctx context.Context, organizationID, projectID string, state controlplane.NotificationDeliveryState, limit int) ([]controlplane.NotificationDelivery, error) {
	q := `SELECT d.` + strings.ReplaceAll(notificationDeliveryColumns, `,`, `,d.`) + ` FROM notification_deliveries d JOIN notification_events e ON e.id=d.event_id WHERE 1=1`
	args := []any{}
	if organizationID != "" {
		args = append(args, organizationID)
		q += fmt.Sprintf(" AND e.organization_id=$%d", len(args))
	}
	if projectID != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND e.project_id=$%d", len(args))
	}
	if state != "" {
		args = append(args, string(state))
		q += fmt.Sprintf(" AND d.state=$%d", len(args))
	}
	q += ` ORDER BY d.created_at DESC,d.id DESC`
	if limit > 0 {
		args = append(args, limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.NotificationDelivery{}
	for rows.Next() {
		v, e := scanNotificationDelivery(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListNotificationDeliveriesPageByScopes joins notification_events once inside
// PostgreSQL and applies authorization before LIMIT, eliminating the API's
// historical per-delivery GetNotificationEvent N+1 lookup pattern.
func (s *PostgresStore) ListNotificationDeliveriesPageByScopes(ctx context.Context, organizationIDs, projectIDs []string, state controlplane.NotificationDeliveryState, limit int) ([]controlplane.NotificationDelivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	organizations := normalizedScopeIDs(organizationIDs)
	projects := normalizedScopeIDs(projectIDs)
	conditions := make([]string, 0, 2)
	args := make([]any, 0, 4)
	const separator = "\x1f"
	if len(projects) > 0 {
		args = append(args, strings.Join(projects, separator))
		conditions = append(conditions, fmt.Sprintf("e.project_id = ANY(string_to_array($%d, chr(31)))", len(args)))
	}
	if len(organizations) > 0 {
		args = append(args, strings.Join(organizations, separator))
		conditions = append(conditions, fmt.Sprintf("(e.project_id IS NULL AND e.organization_id = ANY(string_to_array($%d, chr(31))))", len(args)))
	}
	if len(conditions) == 0 {
		return []controlplane.NotificationDelivery{}, nil
	}
	q := `SELECT d.` + strings.ReplaceAll(notificationDeliveryColumns, `,`, `,d.`) + ` FROM notification_deliveries d JOIN notification_events e ON e.id=d.event_id WHERE (` + strings.Join(conditions, ` OR `) + `)`
	if state != "" {
		args = append(args, string(state))
		q += fmt.Sprintf(" AND d.state=$%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY d.created_at DESC,d.id DESC LIMIT $%d", len(args))
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.NotificationDelivery{}
	for rows.Next() {
		v, scanErr := scanNotificationDelivery(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListNotificationHealthCandidates pages only clusters whose health inputs
// changed after the durable/in-process cursor. The query is bounded before
// materialization so large fleets no longer require a fleet-wide recomputation
// on every notification health interval.
func (s *PostgresStore) ListNotificationHealthCandidates(ctx context.Context, after time.Time, afterID string, limit int) ([]controlplane.NotificationHealthCandidate, bool, error) {
	if limit <= 0 || limit > 500 {
		return nil, false, fmt.Errorf("%w: health candidate limit must be between 1 and 500", controlplane.ErrValidation)
	}
	after = after.UTC()
	afterID = strings.TrimSpace(afterID)
	rows, err := s.db.QueryContext(ctx, `
WITH changed AS (
  SELECT c.id,
         GREATEST(
           c.updated_at,
           COALESCE((SELECT MAX(i.updated_at) FROM cluster_inventory_snapshots i WHERE i.cluster_id=c.id), c.updated_at),
           COALESCE((SELECT MAX(a.updated_at) FROM agent_certificates a WHERE a.cluster_id=c.id), c.updated_at)
         ) AS changed_at
  FROM managed_clusters c
)
SELECT id,changed_at
FROM changed
WHERE changed_at > $1 OR (changed_at = $1 AND id > $2)
ORDER BY changed_at,id
LIMIT $3`, after, afterID, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([]controlplane.NotificationHealthCandidate, 0, limit+1)
	for rows.Next() {
		var v controlplane.NotificationHealthCandidate
		if err = rows.Scan(&v.ClusterID, &v.ChangedAt); err != nil {
			return nil, false, err
		}
		v.ChangedAt = v.ChangedAt.UTC()
		out = append(out, v)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func (s *PostgresStore) ClaimNotificationHealthScanLease(ctx context.Context, worker string, ttl time.Duration, at time.Time) (bool, error) {
	worker = strings.TrimSpace(worker)
	if worker == "" || ttl <= 0 {
		return false, fmt.Errorf("%w: worker and positive ttl are required", controlplane.ErrValidation)
	}
	at = at.UTC()
	until := at.Add(ttl)
	var claimedBy string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO notification_health_scan_leases(lease_name,claimed_by,claimed_until,updated_at)
		VALUES('fleet-health', $1, $2, $3)
		ON CONFLICT (lease_name) DO UPDATE SET
			claimed_by=EXCLUDED.claimed_by,
			claimed_until=EXCLUDED.claimed_until,
			updated_at=EXCLUDED.updated_at
		WHERE notification_health_scan_leases.claimed_until <= $3
		   OR notification_health_scan_leases.claimed_by = $1
		RETURNING claimed_by`, worker, until, at).Scan(&claimedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return claimedBy == worker, nil
}

func (s *PostgresStore) ClaimNotificationDeliveries(ctx context.Context, worker string, limit int, ttl time.Duration, at time.Time) ([]controlplane.NotificationDelivery, error) {
	worker = strings.TrimSpace(worker)
	if worker == "" || limit <= 0 || ttl <= 0 {
		return nil, fmt.Errorf("%w: worker, positive limit and ttl are required", controlplane.ErrValidation)
	}
	at = at.UTC()
	out := []controlplane.NotificationDelivery{}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		attemptOut := make([]controlplane.NotificationDelivery, 0, limit)
		rows, e := tx.QueryContext(ctx, `SELECT `+notificationDeliveryColumns+` FROM notification_deliveries WHERE state IN ('PENDING','RETRY_WAIT','DELIVERING') AND next_attempt_at <= $1 AND (claimed_until IS NULL OR claimed_until <= $1) ORDER BY next_attempt_at,created_at,id LIMIT $3 FOR UPDATE SKIP LOCKED`, at, worker, limit)
		if e != nil {
			return e
		}
		candidates := []controlplane.NotificationDelivery{}
		for rows.Next() {
			v, se := scanNotificationDelivery(rows)
			if se != nil {
				rows.Close()
				return se
			}
			candidates = append(candidates, v)
		}
		if e = rows.Close(); e != nil {
			return e
		}
		until := at.Add(ttl)
		now := utcNow(s.now)
		for _, v := range candidates {
			updated, se := scanNotificationDelivery(tx.QueryRowContext(ctx, `UPDATE notification_deliveries SET revision=revision+1,state='DELIVERING',attempt=attempt+1,claimed_by=$2,claimed_until=$3,updated_at=$4 WHERE id=$1 RETURNING `+notificationDeliveryColumns, v.ID, worker, until, now))
			if se != nil {
				return se
			}
			attemptOut = append(attemptOut, updated)
		}
		out = attemptOut
		return nil
	})
	return out, err
}

func notificationRetryDelayPG(attempt int) time.Duration {
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
func (s *PostgresStore) ReportNotificationDelivery(ctx context.Context, id, worker string, at time.Time, result controlplane.NotificationDeliveryResult) (controlplane.NotificationDelivery, controlplane.NotificationDeliveryAttempt, error) {
	var out controlplane.NotificationDelivery
	var attemptOut controlplane.NotificationDeliveryAttempt
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, e := scanNotificationDelivery(tx.QueryRowContext(ctx, `SELECT `+notificationDeliveryColumns+` FROM notification_deliveries WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		at = at.UTC()
		if cur.State != controlplane.NotificationDeliveryDelivering || cur.ClaimedBy != worker || cur.ClaimedUntil == nil || !cur.ClaimedUntil.After(at) {
			return controlplane.ErrStaleFence
		}
		now := utcNow(s.now)
		started := cur.UpdatedAt
		if started.After(now) {
			started = now
		}
		attempt := controlplane.NotificationDeliveryAttempt{ResourceMeta: controlplane.ResourceMeta{ID: s.id("nda"), Revision: 1, CreatedAt: now, UpdatedAt: now}, DeliveryID: cur.ID, Attempt: cur.Attempt, StartedAt: started, FinishedAt: now, Success: result.Success, Retryable: result.Retryable, StatusCode: result.StatusCode, Error: strings.TrimSpace(result.Error), ResponseDigest: strings.TrimSpace(result.ResponseDigest), DurationMillis: result.DurationMillis}
		attemptOut, e = scanNotificationAttempt(tx.QueryRowContext(ctx, `INSERT INTO notification_delivery_attempts(id,delivery_id,revision,attempt,started_at,finished_at,success,retryable,status_code,error,response_digest,duration_millis,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$5,$5) RETURNING `+notificationAttemptColumns, attempt.ID, attempt.DeliveryID, attempt.Attempt, attempt.StartedAt, attempt.FinishedAt, attempt.Success, attempt.Retryable, attempt.StatusCode, attempt.Error, attempt.ResponseDigest, attempt.DurationMillis))
		if e != nil {
			return mapDBError(e)
		}
		state := controlplane.NotificationDeliveryDeadLetter
		var delivered any = nil
		next := cur.NextAttemptAt
		lastError := strings.TrimSpace(result.Error)
		if result.Success {
			state = controlplane.NotificationDeliverySucceeded
			delivered = now
			lastError = ""
		} else if result.Retryable && cur.Attempt < cur.MaxAttempts {
			state = controlplane.NotificationDeliveryRetryWait
			next = now.Add(notificationRetryDelayPG(cur.Attempt))
		}
		out, e = scanNotificationDelivery(tx.QueryRowContext(ctx, `UPDATE notification_deliveries SET revision=revision+1,state=$2,next_attempt_at=$3,claimed_by='',claimed_until=NULL,last_status_code=$4,last_error=$5,delivered_at=$6,updated_at=$7 WHERE id=$1 RETURNING `+notificationDeliveryColumns, cur.ID, string(state), next, result.StatusCode, lastError, delivered, now))
		if e != nil {
			return e
		}
		action := "notification_delivery.failed"
		if state == controlplane.NotificationDeliverySucceeded {
			action = "notification_delivery.succeeded"
		} else if state == controlplane.NotificationDeliveryRetryWait {
			action = "notification_delivery.retry_scheduled"
		} else if state == controlplane.NotificationDeliveryDeadLetter {
			action = "notification_delivery.dead_lettered"
		}
		return s.appendAuditTx(ctx, tx, "notification-worker", action, "notificationDelivery", out.ID, out.Revision, "", map[string]any{"attempt": out.Attempt, "statusCode": out.LastStatusCode, "retryable": result.Retryable})
	})
	return out, attemptOut, err
}
func (s *PostgresStore) ListNotificationDeliveryAttempts(ctx context.Context, deliveryID string) ([]controlplane.NotificationDeliveryAttempt, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT `+notificationAttemptColumns+` FROM notification_delivery_attempts WHERE delivery_id=$1 ORDER BY attempt,id`, strings.TrimSpace(deliveryID))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.NotificationDeliveryAttempt{}
	for rows.Next() {
		v, e := scanNotificationAttempt(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
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
	return out, rows.Err()
}

func (s *PostgresStore) RetryNotificationDelivery(ctx context.Context, id string, expected int64, actor string) (controlplane.NotificationDelivery, error) {
	var out controlplane.NotificationDelivery
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, e := scanNotificationDelivery(tx.QueryRowContext(ctx, `SELECT `+notificationDeliveryColumns+` FROM notification_deliveries WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		if cur.State != controlplane.NotificationDeliveryDeadLetter {
			return controlplane.ErrInvalidTransition
		}
		var destinationState string
		if e = tx.QueryRowContext(ctx, `SELECT state FROM notification_destinations WHERE id=$1`, cur.DestinationID).Scan(&destinationState); e != nil {
			return mapDBError(e)
		}
		if destinationState != string(controlplane.NotificationDestinationActive) {
			return fmt.Errorf("%w: notification destination must be active before retry", controlplane.ErrPrerequisite)
		}
		now := utcNow(s.now)
		out, e = scanNotificationDelivery(tx.QueryRowContext(ctx, `UPDATE notification_deliveries SET revision=revision+1,state='PENDING',attempt=0,next_attempt_at=$2,claimed_by='',claimed_until=NULL,last_status_code=0,last_error='',delivered_at=NULL,updated_at=$2 WHERE id=$1 RETURNING `+notificationDeliveryColumns, cur.ID, now))
		if e != nil {
			return e
		}
		return s.appendAuditTx(ctx, tx, actor, "notification_delivery.requeued", "notificationDelivery", out.ID, out.Revision, "", nil)
	})
	return out, err
}
