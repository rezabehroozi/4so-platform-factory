package persistence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const oidcGroupMappingColumns = `id,revision,group_name,product_role,COALESCE(organization_id,''),COALESCE(organization_role,''),COALESCE(project_id,''),COALESCE(project_role,''),state,created_by,revoked_by,revoked_at,created_at,updated_at`

func scanOIDCGroupMapping(row interface{ Scan(...any) error }) (controlplane.OIDCGroupMapping, error) {
	var v controlplane.OIDCGroupMapping
	var orgRole, state string
	err := row.Scan(&v.ID, &v.Revision, &v.Group, &v.ProductRole, &v.OrganizationID, &orgRole, &v.ProjectID, &v.ProjectRole, &state, &v.CreatedBy, &v.RevokedBy, &v.RevokedAt, &v.CreatedAt, &v.UpdatedAt)
	v.OrganizationRole = controlplane.OrganizationMembershipRole(orgRole)
	v.State = controlplane.OIDCGroupMappingState(state)
	return v, err
}

func (s *PostgresStore) CreateOIDCGroupMapping(ctx context.Context, v controlplane.OIDCGroupMapping, actor string) (controlplane.OIDCGroupMapping, error) {
	v.Group = strings.TrimSpace(v.Group)
	v.ProductRole = strings.TrimSpace(v.ProductRole)
	v.OrganizationID = strings.TrimSpace(v.OrganizationID)
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ProjectRole = strings.TrimSpace(v.ProjectRole)
	if err := controlplane.ValidateOIDCGroupMapping(v); err != nil {
		return controlplane.OIDCGroupMapping{}, err
	}
	now := utcNow(s.now)
	v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ogm"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = controlplane.OIDCGroupMappingActive
	v.CreatedBy = strings.TrimSpace(actor)
	var out controlplane.OIDCGroupMapping
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if v.OrganizationID != "" {
			if _, e := scanOrganization(tx.QueryRowContext(ctx, `SELECT `+organizationColumns+` FROM organizations WHERE id=$1 FOR SHARE`, v.OrganizationID)); e != nil {
				return mapDBError(e)
			}
		}
		if v.ProjectID != "" {
			var orgID string
			if e := tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1 FOR SHARE`, v.ProjectID).Scan(&orgID); e != nil {
				return mapDBError(e)
			}
			if v.OrganizationID != "" && orgID != v.OrganizationID {
				return fmt.Errorf("%w: project does not belong to organization", controlplane.ErrValidation)
			}
		}
		var orgID any
		if v.OrganizationID != "" {
			orgID = v.OrganizationID
		}
		var orgRole any
		if v.OrganizationRole != "" {
			orgRole = string(v.OrganizationRole)
		}
		var projectID any
		if v.ProjectID != "" {
			projectID = v.ProjectID
		}
		var projectRole any
		if v.ProjectRole != "" {
			projectRole = v.ProjectRole
		}
		var e error
		out, e = scanOIDCGroupMapping(tx.QueryRowContext(ctx, `INSERT INTO oidc_group_mappings(id,revision,group_name,product_role,organization_id,organization_role,project_id,project_role,state,created_by,revoked_by,revoked_at,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,'ACTIVE',$8,'',NULL,$9,$9) RETURNING `+oidcGroupMappingColumns, v.ID, v.Group, v.ProductRole, orgID, orgRole, projectID, projectRole, v.CreatedBy, now))
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "oidc_group_mapping.created", "oidcGroupMapping", out.ID, out.Revision, "", map[string]any{"group": out.Group, "productRole": out.ProductRole, "organizationId": out.OrganizationID, "projectId": out.ProjectID}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "oidcGroupMapping", out.ID, "oidc_group_mapping.created", out)
	})
	return out, err
}
func (s *PostgresStore) ListOIDCGroupMappings(ctx context.Context, state controlplane.OIDCGroupMappingState) ([]controlplane.OIDCGroupMapping, error) {
	q := `SELECT ` + oidcGroupMappingColumns + ` FROM oidc_group_mappings`
	args := []any{}
	if state != "" {
		q += ` WHERE state=$1`
		args = append(args, string(state))
	}
	q += ` ORDER BY group_name,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.OIDCGroupMapping{}
	for rows.Next() {
		v, e := scanOIDCGroupMapping(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) RevokeOIDCGroupMapping(ctx context.Context, id string, expected int64, actor string) (controlplane.OIDCGroupMapping, error) {
	var out controlplane.OIDCGroupMapping
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		cur, e := scanOIDCGroupMapping(tx.QueryRowContext(ctx, `SELECT `+oidcGroupMappingColumns+` FROM oidc_group_mappings WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if cur.Revision != expected {
			return controlplane.ErrConflict
		}
		if cur.State == controlplane.OIDCGroupMappingRevoked {
			out = cur
			return nil
		}
		now := utcNow(s.now)
		out, e = scanOIDCGroupMapping(tx.QueryRowContext(ctx, `UPDATE oidc_group_mappings SET revision=revision+1,state='REVOKED',revoked_by=$2,revoked_at=$3,updated_at=$3 WHERE id=$1 RETURNING `+oidcGroupMappingColumns, cur.ID, strings.TrimSpace(actor), now))
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "oidc_group_mapping.revoked", "oidcGroupMapping", out.ID, out.Revision, "", map[string]any{"group": out.Group}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "oidcGroupMapping", out.ID, "oidc_group_mapping.revoked", out)
	})
	return out, err
}
func (s *PostgresStore) ResolveOIDCGroups(ctx context.Context, groups []string) (controlplane.OIDCGroupResolution, error) {
	// OIDC group resolution is on the authentication hot path. Query only the
	// groups asserted by the current identity instead of scanning every active
	// mapping in the platform on every request.
	seen := map[string]struct{}{}
	clean := make([]string, 0, len(groups))
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		clean = append(clean, group)
	}
	if len(clean) == 0 {
		return controlplane.ResolveOIDCGroupMappings(nil, nil), nil
	}
	placeholders := make([]string, len(clean))
	args := make([]any, len(clean))
	for i, group := range clean {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = group
	}
	q := `SELECT ` + oidcGroupMappingColumns + ` FROM oidc_group_mappings WHERE state='ACTIVE' AND group_name IN (` + strings.Join(placeholders, ",") + `) ORDER BY group_name,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return controlplane.OIDCGroupResolution{}, err
	}
	defer rows.Close()
	mappings := make([]controlplane.OIDCGroupMapping, 0)
	for rows.Next() {
		v, scanErr := scanOIDCGroupMapping(rows)
		if scanErr != nil {
			return controlplane.OIDCGroupResolution{}, scanErr
		}
		mappings = append(mappings, v)
	}
	if err = rows.Err(); err != nil {
		return controlplane.OIDCGroupResolution{}, err
	}
	return controlplane.ResolveOIDCGroupMappings(mappings, clean), nil
}

type securityAuditResult struct {
	event controlplane.SecurityAuditEvent
	err   error
}

type securityAuditRequest struct {
	input  controlplane.SecurityAuditInput
	result chan securityAuditResult
}

const (
	securityAuditBatchMax     = 64
	securityAuditQueueMax     = 4096
	securityAuditBatchWindow  = 2 * time.Millisecond
	securityAuditBatchTimeout = 15 * time.Second
)

func (s *PostgresStore) AppendSecurityAudit(ctx context.Context, in controlplane.SecurityAuditInput) (controlplane.SecurityAuditEvent, error) {
	if strings.TrimSpace(in.Category) == "" || strings.TrimSpace(in.Decision) == "" {
		return controlplane.SecurityAuditEvent{}, fmt.Errorf("%w: security audit category and decision are required", controlplane.ErrValidation)
	}
	req := &securityAuditRequest{input: in, result: make(chan securityAuditResult, 1)}
	s.securityAuditMu.Lock()
	if len(s.securityAuditQueue) >= securityAuditQueueMax {
		s.securityAuditMu.Unlock()
		return controlplane.SecurityAuditEvent{}, fmt.Errorf("security audit backpressure: pending queue capacity %d exhausted", securityAuditQueueMax)
	}
	s.securityAuditQueue = append(s.securityAuditQueue, req)
	startProcessor := !s.securityAuditProcessing
	if startProcessor {
		s.securityAuditProcessing = true
	}
	s.securityAuditMu.Unlock()
	if startProcessor {
		go s.processSecurityAuditQueue()
	}
	select {
	case result := <-req.result:
		return result.event, result.err
	case <-ctx.Done():
		// The audit request intentionally remains queued after client/request
		// cancellation. Once an authentication/authorization decision occurred,
		// cancellation must not erase its immutable audit evidence. The caller
		// still receives its own context error and cannot treat the request as
		// successfully audited.
		return controlplane.SecurityAuditEvent{}, ctx.Err()
	}
}

// DrainSecurityAudit waits until every security-audit request admitted by this
// replica has either committed or failed its canonical PostgreSQL append. It is
// intended for graceful process shutdown after HTTP admission has stopped.
func (s *PostgresStore) DrainSecurityAudit(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.securityAuditMu.Lock()
		done := len(s.securityAuditQueue) == 0 && !s.securityAuditProcessing
		s.securityAuditMu.Unlock()
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("drain security audit backlog: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s *PostgresStore) processSecurityAuditQueue() {
	for {
		timer := time.NewTimer(securityAuditBatchWindow)
		<-timer.C
		s.securityAuditMu.Lock()
		if len(s.securityAuditQueue) == 0 {
			s.securityAuditProcessing = false
			s.securityAuditMu.Unlock()
			return
		}
		n := len(s.securityAuditQueue)
		if n > securityAuditBatchMax {
			n = securityAuditBatchMax
		}
		batch := append([]*securityAuditRequest(nil), s.securityAuditQueue[:n]...)
		s.securityAuditQueue = s.securityAuditQueue[n:]
		s.securityAuditMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), securityAuditBatchTimeout)
		events, err := s.appendSecurityAuditBatch(ctx, batch)
		cancel()
		if err != nil {
			// serializable() already exhausted its transient retry budget. Reject
			// the backlog admitted before this durable failure so thousands of
			// waiting request goroutines do not remain pinned behind a dead DB.
			// No protected request can continue because every waiter receives the
			// same fail-closed audit error. New arrivals after this point may form
			// a fresh batch and observe DB recovery.
			s.securityAuditMu.Lock()
			rejected := append([]*securityAuditRequest(nil), s.securityAuditQueue...)
			s.securityAuditQueue = nil
			s.securityAuditMu.Unlock()
			for _, req := range batch {
				req.result <- securityAuditResult{err: err}
			}
			for _, req := range rejected {
				req.result <- securityAuditResult{err: err}
			}
			continue
		}
		for i, req := range batch {
			req.result <- securityAuditResult{event: events[i]}
		}
	}
}

func (s *PostgresStore) appendSecurityAuditBatch(ctx context.Context, batch []*securityAuditRequest) ([]controlplane.SecurityAuditEvent, error) {
	if len(batch) == 0 {
		return nil, nil
	}
	var out []controlplane.SecurityAuditEvent
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(680068)`); e != nil {
			return e
		}
		var seq int64
		var prev string
		e := tx.QueryRowContext(ctx, `SELECT sequence,event_digest FROM security_audit_events ORDER BY sequence DESC LIMIT 1`).Scan(&seq, &prev)
		if errors.Is(e, sql.ErrNoRows) {
			seq = 0
			prev = ""
		} else if e != nil {
			return e
		}
		candidate := make([]controlplane.SecurityAuditEvent, 0, len(batch))
		for _, req := range batch {
			seq++
			event := controlplane.SecurityAuditEvent{ID: s.id("sau"), Sequence: seq, OccurredAt: utcNow(s.now), MethodVersion: controlplane.SecurityAuditMethod, SecurityAuditInput: req.input, PreviousDigest: prev}
			if strings.TrimSpace(event.ActorID) == "" {
				event.ActorID = "anonymous"
			}
			event.Digest = controlplane.SecurityAuditEventDigest(event)
			if _, e = tx.ExecContext(ctx, `INSERT INTO security_audit_events(sequence,id,occurred_at,method_version,category,decision,actor_id,authentication,request_method,request_path,status_code,reason_code,request_id,scope_type,scope_id,effective_role,mapping_digest,previous_digest,event_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, event.Sequence, event.ID, event.OccurredAt, event.MethodVersion, event.Category, event.Decision, event.ActorID, event.Authentication, event.Method, event.Path, event.StatusCode, event.ReasonCode, event.RequestID, event.ScopeType, event.ScopeID, event.EffectiveRole, event.MappingDigest, event.PreviousDigest, event.Digest); e != nil {
				return e
			}
			candidate = append(candidate, event)
			prev = event.Digest
		}
		out = candidate
		return nil
	})
	return out, err
}

func (s *PostgresStore) ListSecurityAudit(ctx context.Context, limit int) ([]controlplane.SecurityAuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence,id,occurred_at,method_version,category,decision,actor_id,authentication,request_method,request_path,status_code,reason_code,request_id,scope_type,scope_id,effective_role,mapping_digest,previous_digest,event_digest FROM security_audit_events ORDER BY sequence DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.SecurityAuditEvent{}
	for rows.Next() {
		var v controlplane.SecurityAuditEvent
		if e := rows.Scan(&v.Sequence, &v.ID, &v.OccurredAt, &v.MethodVersion, &v.Category, &v.Decision, &v.ActorID, &v.Authentication, &v.Method, &v.Path, &v.StatusCode, &v.ReasonCode, &v.RequestID, &v.ScopeType, &v.ScopeID, &v.EffectiveRole, &v.MappingDigest, &v.PreviousDigest, &v.Digest); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out, rows.Err()
}
