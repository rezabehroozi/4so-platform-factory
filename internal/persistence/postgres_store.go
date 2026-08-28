package persistence

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

// PostgresStore is the production authority implementation boundary. It uses
// database/sql so the concrete PostgreSQL driver can be admitted, pinned and
// supplied by the distribution layer without coupling domain code to a driver.
// Every resource mutation that emits audit/outbox records is committed in one
// serializable transaction.
type PostgresStore struct {
	db  *sql.DB
	now func() time.Time
	id  func(string) string

	// Security-audit appenders are micro-batched per replica before entering the
	// global PostgreSQL hash-chain lock. The chain remains globally serialized
	// and fail-closed, but a traffic burst no longer performs one advisory-lock
	// acquisition and one last-sequence lookup per audit event.
	securityAuditMu         sync.Mutex
	securityAuditQueue      []*securityAuditRequest
	securityAuditProcessing bool
}

func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	return NewPostgresStoreWith(db, time.Now, randomID)
}

// NewPostgresStoreWith permits deterministic clocks and identifiers in repository contract tests.
func NewPostgresStoreWith(db *sql.DB, now func() time.Time, id func(string) string) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle is nil")
	}
	if now == nil {
		now = time.Now
	}
	if id == nil {
		id = randomID
	}
	return &PostgresStore{db: db, now: now, id: id}, nil
}

func randomID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func utcNow(now func() time.Time) time.Time { return now().UTC().Truncate(time.Microsecond) }
func normalizedName(value string) string    { return strings.ToLower(strings.TrimSpace(value)) }

func normalizedScopeIDs(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func decodeJSONColumn(raw []byte, target any, column string) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode PostgreSQL JSON column %s: %w", column, err)
	}
	return nil
}

func (s *PostgresStore) Backend() string { return "postgresql" }

func (s *PostgresStore) Health(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("postgres ping: %w", err)
	}
	var one int
	if err := s.db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return fmt.Errorf("postgres readiness query: %w", err)
	}
	if one != 1 {
		return fmt.Errorf("postgres readiness query returned %d", one)
	}
	return nil
}

func (s *PostgresStore) serializable(ctx context.Context, fn func(*sql.Tx) error) error {
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return fmt.Errorf("begin serializable transaction: %w", err)
		}
		if err = fn(tx); err != nil {
			_ = tx.Rollback()
			if isRetryableTransactionError(err) && attempt < maxAttempts {
				if err := waitRetry(ctx, attempt); err != nil {
					return err
				}
				continue
			}
			return err
		}
		if err = tx.Commit(); err != nil {
			if isRetryableTransactionError(err) && attempt < maxAttempts {
				if err := waitRetry(ctx, attempt); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("commit transaction: %w", err)
		}
		return nil
	}
	return fmt.Errorf("serializable transaction retry budget exhausted")
}

func waitRetry(ctx context.Context, attempt int) error {
	timer := time.NewTimer(time.Duration(attempt*10) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isRetryableTransactionError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "sqlstate 40001") ||
		strings.Contains(message, "sqlstate 40p01") ||
		strings.Contains(message, "serialization failure") ||
		strings.Contains(message, "could not serialize access") ||
		strings.Contains(message, "deadlock detected")
}

func marshalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal event payload: %w", err)
	}
	return raw, nil
}

func (s *PostgresStore) appendAuditTx(ctx context.Context, tx *sql.Tx, actor, action, resourceType, resourceID string, revision int64, requestID string, metadata map[string]any) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", controlplane.ErrValidation)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	raw, err := marshalJSON(metadata)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_events(id,occurred_at,actor_id,action,resource_type,resource_id,resource_revision,request_id,metadata)
		VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9::jsonb)`,
		s.id("aud"), utcNow(s.now), actor, action, resourceType, resourceID, revision, requestID, raw)
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

func (s *PostgresStore) appendOutboxTx(ctx context.Context, tx *sql.Tx, aggregateType, aggregateID, eventType string, payload any) error {
	raw, err := marshalJSON(payload)
	if err != nil {
		return err
	}
	now := utcNow(s.now)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO outbox_events(id,revision,aggregate_type,aggregate_id,event_type,payload,available_at,attempt,created_at,updated_at)
		VALUES($1,1,$2,$3,$4,$5::jsonb,$6,0,$6,$6)`,
		s.id("evt"), aggregateType, aggregateID, eventType, raw, now)
	if err != nil {
		return fmt.Errorf("append outbox event: %w", err)
	}
	return nil
}

func mapDBError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return controlplane.ErrNotFound
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "duplicate key"), strings.Contains(msg, "unique constraint"), strings.Contains(msg, "unique violation"):
		return fmt.Errorf("%w: %v", controlplane.ErrDuplicateName, err)
	case strings.Contains(msg, "foreign key"), strings.Contains(msg, "violates foreign"):
		return fmt.Errorf("%w: %v", controlplane.ErrNotFound, err)
	case strings.Contains(msg, "check constraint"), strings.Contains(msg, "invalid input value for enum"):
		return fmt.Errorf("%w: %v", controlplane.ErrValidation, err)
	default:
		return err
	}
}

func operationDigest(request controlplane.OperationRequest) string {
	raw, _ := json.Marshal(request)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func scanOrganization(row interface{ Scan(...any) error }) (controlplane.Organization, error) {
	var value controlplane.Organization
	err := row.Scan(&value.ID, &value.Revision, &value.Name, &value.DisplayName, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

func scanProject(row interface{ Scan(...any) error }) (controlplane.Project, error) {
	var value controlplane.Project
	err := row.Scan(&value.ID, &value.OrganizationID, &value.Revision, &value.Name, &value.DisplayName, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

func scanOrganizationMembership(row interface{ Scan(...any) error }) (controlplane.OrganizationMembership, error) {
	var value controlplane.OrganizationMembership
	err := row.Scan(&value.ID, &value.OrganizationID, &value.Revision, &value.Subject, &value.Role, &value.State, &value.GrantedBy, &value.RevokedBy, &value.RevokedAt, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

func scanBlueprintRevision(row interface{ Scan(...any) error }) (controlplane.BlueprintRevision, error) {
	var value controlplane.BlueprintRevision
	err := row.Scan(&value.ID, &value.ProjectID, &value.Revision, &value.BlueprintName, &value.BlueprintVersion, &value.BlueprintDigest, &value.CatalogDigest, &value.BaseBlueprintDigest, &value.OverlayDigest, &value.OwnershipDigest, &value.ProviderOverlayID, &value.EnvironmentOverlayID, &value.BasePayload, &value.ResolutionPayload, &value.Payload, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

func scanAssignment(row interface{ Scan(...any) error }) (controlplane.Assignment, error) {
	var value controlplane.Assignment
	err := row.Scan(&value.ID, &value.ProjectID, &value.Revision, &value.TargetRef, &value.BlueprintRevisionID, &value.DesiredGeneration, &value.ObservedGeneration, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

func scanOperation(row interface{ Scan(...any) error }) (controlplane.Operation, error) {
	var value controlplane.Operation
	var state, class, failureClass string
	var retryPolicy []byte
	err := row.Scan(
		&value.ID, &value.ProjectID, &value.Revision, &value.Kind, &value.TargetRef, &value.DesiredRevision,
		&state, &value.Risk, &class, &retryPolicy, &value.Attempt, &value.NextAttemptAt, &failureClass, &value.RetryExhausted,
		&value.RecoveryCheckpointID, &value.RecoveryEvidenceDigest, &value.RecoveryInventoryDigest,
		&value.CancelRequestedBy, &value.CancelRequestedAt, &value.CancelReason,
		&value.IdempotencyKey, &value.RequestDigest, &value.ActorID,
		&value.LeaseOwner, &value.LeaseExpiresAt, &value.FenceToken, &value.LastError,
		&value.CompensationPlanDigest, &value.CompensationStepCount, &value.CompensationCursor, &value.CompensationStartedAt, &value.CompensationFinishedAt, &value.CompensationFailureStep,
		&value.CreatedAt, &value.UpdatedAt,
	)
	value.State = controlplane.OperationState(state)
	value.Class = controlplane.OperationClass(class)
	value.LastFailureClass = controlplane.OperationFailureClass(failureClass)
	if err != nil {
		return value, err
	}
	if err = decodeJSONColumn(retryPolicy, &value.RetryPolicy, "operations.retry_policy"); err != nil {
		return value, err
	}
	return value, nil
}

func scanStep(row interface{ Scan(...any) error }) (controlplane.OperationStep, error) {
	var value controlplane.OperationStep
	var state string
	err := row.Scan(&value.ID, &value.OperationID, &value.Revision, &value.StepKey, &state, &value.Attempt, &value.FenceToken, &value.StartedAt, &value.FinishedAt, &value.LastError, &value.CreatedAt, &value.UpdatedAt)
	value.State = controlplane.OperationState(state)
	return value, err
}

func scanCompensationStep(row interface{ Scan(...any) error }) (controlplane.OperationCompensationStep, error) {
	var value controlplane.OperationCompensationStep
	var strategy, state string
	err := row.Scan(&value.ID, &value.OperationID, &value.Revision, &value.StepKey, &value.ForwardOrder, &strategy, &value.Action, &value.InputDigest, &value.MaxAttempts, &value.ForwardCompleted, &value.ForwardCompletedAt, &state, &value.Attempt, &value.FenceToken, &value.StartedAt, &value.FinishedAt, &value.EvidenceDigest, &value.LastError, &value.CreatedAt, &value.UpdatedAt)
	value.Strategy = controlplane.CompensationStrategy(strategy)
	value.State = controlplane.CompensationStepState(state)
	return value, err
}

func scanOutbox(row interface{ Scan(...any) error }) (controlplane.OutboxEvent, error) {
	var value controlplane.OutboxEvent
	err := row.Scan(&value.ID, &value.Revision, &value.AggregateType, &value.AggregateID, &value.EventType, &value.Payload, &value.AvailableAt, &value.ClaimedBy, &value.ClaimedUntil, &value.Attempt, &value.PublishedAt, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

func scanEvidence(row interface{ Scan(...any) error }) (controlplane.EvidenceMetadata, error) {
	var value controlplane.EvidenceMetadata
	var phase string
	err := row.Scan(&value.ID, &value.OperationID, &value.Revision, &phase, &value.StepKey, &value.Attempt, &value.TraceID, &value.Kind, &value.Digest, &value.MediaType, &value.Location, &value.Size, &value.HasPayload, &value.Sealed, &value.CreatedAt, &value.UpdatedAt)
	value.Phase = controlplane.OperationStepPhase(phase)
	return value, err
}

const organizationColumns = `id,revision,name,display_name,created_at,updated_at`
const organizationMembershipColumns = `id,organization_id,revision,subject,role,state,granted_by,revoked_by,revoked_at,created_at,updated_at`
const projectColumns = `id,organization_id,revision,name,display_name,created_at,updated_at`
const blueprintRevisionColumns = `id,project_id,revision,blueprint_name,blueprint_version,blueprint_digest,catalog_digest,base_blueprint_digest,overlay_digest,ownership_digest,COALESCE(provider_overlay_id,''),COALESCE(environment_overlay_id,''),base_payload,resolution_payload,payload,created_at,updated_at`
const assignmentColumns = `id,project_id,revision,target_ref,blueprint_revision_id,desired_generation,observed_generation,created_at,updated_at`
const operationColumns = `id,project_id,revision,kind,target_ref,desired_revision,state::text,risk,operation_class,retry_policy,attempt,next_attempt_at,last_failure_class,retry_exhausted,COALESCE(recovery_checkpoint_id,''),recovery_evidence_digest,recovery_inventory_digest,cancel_requested_by,cancel_requested_at,cancel_reason,idempotency_key,request_digest,actor_id,COALESCE(lease_owner,''),lease_expires_at,fence_token,last_error,compensation_plan_digest,compensation_step_count,compensation_cursor,compensation_started_at,compensation_finished_at,compensation_failure_step,created_at,updated_at`
const stepColumns = `id,operation_id,revision,step_key,state::text,attempt,fence_token,started_at,finished_at,last_error,created_at,updated_at`
const compensationStepColumns = `id,operation_id,revision,step_key,forward_order,strategy,action,input_digest,max_attempts,forward_completed,forward_completed_at,state,attempt,fence_token,started_at,finished_at,evidence_digest,last_error,created_at,updated_at`
const outboxColumns = `id,revision,aggregate_type,aggregate_id,event_type,payload,available_at,COALESCE(claimed_by,''),claimed_until,attempt,published_at,created_at,updated_at`
const outboxReturningColumns = `e.id,e.revision,e.aggregate_type,e.aggregate_id,e.event_type,e.payload,e.available_at,COALESCE(e.claimed_by,''),e.claimed_until,e.attempt,e.published_at,e.created_at,e.updated_at`
const evidenceColumns = `id,operation_id,revision,step_phase,step_key,attempt,trace_id,kind,digest,media_type,location,size_bytes,has_payload,sealed,created_at,updated_at`

func (s *PostgresStore) CreateOrganization(ctx context.Context, org controlplane.Organization, actor string) (controlplane.Organization, error) {
	org.Name = normalizedName(org.Name)
	org.DisplayName = strings.TrimSpace(org.DisplayName)
	if org.Name == "" || org.DisplayName == "" {
		return controlplane.Organization{}, fmt.Errorf("%w: organization name and displayName are required", controlplane.ErrValidation)
	}
	now := utcNow(s.now)
	org.ResourceMeta = controlplane.ResourceMeta{ID: s.id("org"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		created, err := scanOrganization(tx.QueryRowContext(ctx, `INSERT INTO organizations(id,revision,name,display_name,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5) RETURNING `+organizationColumns, org.ID, org.Revision, org.Name, org.DisplayName, now))
		if err != nil {
			return mapDBError(err)
		}
		org = created
		if strings.TrimSpace(actor) != "" {
			membership := controlplane.OrganizationMembership{
				ResourceMeta:   controlplane.ResourceMeta{ID: s.id("mem"), Revision: 1, CreatedAt: now, UpdatedAt: now},
				OrganizationID: org.ID, Subject: strings.TrimSpace(actor), Role: controlplane.OrganizationAdmin, State: controlplane.OrganizationMembershipActive, GrantedBy: strings.TrimSpace(actor),
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO organization_memberships(id,organization_id,revision,subject,role,state,granted_by,revoked_by,revoked_at,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,'',NULL,$7,$7)`, membership.ID, membership.OrganizationID, membership.Subject, membership.Role, membership.State, membership.GrantedBy, now); err != nil {
				return mapDBError(err)
			}
			if err := s.appendAuditTx(ctx, tx, actor, "organization_membership.granted", "organizationMembership", membership.ID, 1, "", map[string]any{"organizationId": org.ID, "subject": membership.Subject, "role": membership.Role}); err != nil {
				return err
			}
			if err := s.appendOutboxTx(ctx, tx, "organizationMembership", membership.ID, "organization_membership.granted", membership); err != nil {
				return err
			}
		}
		if err := s.appendAuditTx(ctx, tx, actor, "organization.created", "organization", org.ID, org.Revision, "", nil); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "organization", org.ID, "organization.created", org)
	})
	return org, err
}

func (s *PostgresStore) UpdateOrganization(ctx context.Context, id string, expected int64, displayName, name, actor string) (controlplane.Organization, error) {
	name = normalizedName(name)
	displayName = strings.TrimSpace(displayName)
	var updated controlplane.Organization
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanOrganization(tx.QueryRowContext(ctx, `SELECT `+organizationColumns+` FROM organizations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if name != "" {
			current.Name = name
		}
		if displayName != "" {
			current.DisplayName = displayName
		}
		if current.Name == "" || current.DisplayName == "" {
			return fmt.Errorf("%w: organization name and displayName are required", controlplane.ErrValidation)
		}
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if _, err := tx.ExecContext(ctx, `UPDATE organizations SET revision=$2,name=$3,display_name=$4,updated_at=$5 WHERE id=$1 AND revision=$6`, id, current.Revision, current.Name, current.DisplayName, current.UpdatedAt, expected); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "organization.updated", "organization", id, current.Revision, "", nil); err != nil {
			return err
		}
		if err := s.appendOutboxTx(ctx, tx, "organization", id, "organization.updated", current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}

func (s *PostgresStore) GetOrganization(ctx context.Context, id string) (controlplane.Organization, error) {
	value, err := scanOrganization(s.db.QueryRowContext(ctx, `SELECT `+organizationColumns+` FROM organizations WHERE id=$1`, id))
	return value, mapDBError(err)
}

func (s *PostgresStore) ListOrganizations(ctx context.Context) ([]controlplane.Organization, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+organizationColumns+` FROM organizations ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []controlplane.Organization
	for rows.Next() {
		value, err := scanOrganization(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *PostgresStore) CreateProject(ctx context.Context, project controlplane.Project, actor string) (controlplane.Project, error) {
	project.Name = normalizedName(project.Name)
	project.DisplayName = strings.TrimSpace(project.DisplayName)
	if project.OrganizationID == "" || project.Name == "" || project.DisplayName == "" {
		return controlplane.Project{}, fmt.Errorf("%w: organizationId, project name and displayName are required", controlplane.ErrValidation)
	}
	now := utcNow(s.now)
	project.ResourceMeta = controlplane.ResourceMeta{ID: s.id("prj"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO projects(id,organization_id,revision,name,display_name,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$6)`, project.ID, project.OrganizationID, project.Revision, project.Name, project.DisplayName, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "project.created", "project", project.ID, project.Revision, "", map[string]any{"organizationId": project.OrganizationID}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "project", project.ID, "project.created", project)
	})
	return project, err
}

func (s *PostgresStore) GetProject(ctx context.Context, id string) (controlplane.Project, error) {
	value, err := scanProject(s.db.QueryRowContext(ctx, `SELECT `+projectColumns+` FROM projects WHERE id=$1`, id))
	return value, mapDBError(err)
}

func (s *PostgresStore) ListProjects(ctx context.Context, organizationID string) ([]controlplane.Project, error) {
	query := `SELECT ` + projectColumns + ` FROM projects`
	args := []any{}
	if organizationID != "" {
		query += ` WHERE organization_id=$1`
		args = append(args, organizationID)
	}
	query += ` ORDER BY organization_id,name,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []controlplane.Project
	for rows.Next() {
		value, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func validMembershipRole(role controlplane.OrganizationMembershipRole) bool {
	switch role {
	case controlplane.OrganizationAdmin, controlplane.OrganizationOperator, controlplane.OrganizationViewer:
		return true
	default:
		return false
	}
}

func (s *PostgresStore) UpsertOrganizationMembership(ctx context.Context, membership controlplane.OrganizationMembership, expected int64, actor string) (controlplane.OrganizationMembership, error) {
	membership.OrganizationID = strings.TrimSpace(membership.OrganizationID)
	membership.Subject = strings.TrimSpace(membership.Subject)
	if membership.OrganizationID == "" || membership.Subject == "" || !validMembershipRole(membership.Role) {
		return controlplane.OrganizationMembership{}, fmt.Errorf("%w: organizationId, subject and valid role are required", controlplane.ErrValidation)
	}
	var out controlplane.OrganizationMembership
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if _, err := scanOrganization(tx.QueryRowContext(ctx, `SELECT `+organizationColumns+` FROM organizations WHERE id=$1 FOR SHARE`, membership.OrganizationID)); err != nil {
			return mapDBError(err)
		}
		current, err := scanOrganizationMembership(tx.QueryRowContext(ctx, `SELECT `+organizationMembershipColumns+` FROM organization_memberships WHERE organization_id=$1 AND subject=$2 FOR UPDATE`, membership.OrganizationID, membership.Subject))
		now := utcNow(s.now)
		if err == nil {
			if expected <= 0 || current.Revision != expected {
				return controlplane.ErrConflict
			}
			current.Revision++
			current.Role = membership.Role
			current.State = controlplane.OrganizationMembershipActive
			current.GrantedBy = strings.TrimSpace(actor)
			current.RevokedBy = ""
			current.RevokedAt = nil
			current.UpdatedAt = now
			row := tx.QueryRowContext(ctx, `UPDATE organization_memberships SET revision=$3,role=$4,state=$5,granted_by=$6,revoked_by='',revoked_at=NULL,updated_at=$7 WHERE organization_id=$1 AND subject=$2 RETURNING `+organizationMembershipColumns, current.OrganizationID, current.Subject, current.Revision, current.Role, current.State, current.GrantedBy, now)
			out, err = scanOrganizationMembership(row)
		} else if errors.Is(err, sql.ErrNoRows) {
			if expected != 0 {
				return controlplane.ErrConflict
			}
			membership.ResourceMeta = controlplane.ResourceMeta{ID: s.id("mem"), Revision: 1, CreatedAt: now, UpdatedAt: now}
			membership.State = controlplane.OrganizationMembershipActive
			membership.GrantedBy = strings.TrimSpace(actor)
			membership.RevokedBy = ""
			membership.RevokedAt = nil
			out, err = scanOrganizationMembership(tx.QueryRowContext(ctx, `INSERT INTO organization_memberships(id,organization_id,revision,subject,role,state,granted_by,revoked_by,revoked_at,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,'',NULL,$7,$7) RETURNING `+organizationMembershipColumns, membership.ID, membership.OrganizationID, membership.Subject, membership.Role, membership.State, membership.GrantedBy, now))
		} else {
			return mapDBError(err)
		}
		if err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "organization_membership.granted", "organizationMembership", out.ID, out.Revision, "", map[string]any{"organizationId": out.OrganizationID, "subject": out.Subject, "role": out.Role}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "organizationMembership", out.ID, "organization_membership.granted", out)
	})
	return out, err
}

func (s *PostgresStore) GetOrganizationMembership(ctx context.Context, organizationID, subject string) (controlplane.OrganizationMembership, error) {
	v, err := scanOrganizationMembership(s.db.QueryRowContext(ctx, `SELECT `+organizationMembershipColumns+` FROM organization_memberships WHERE organization_id=$1 AND subject=$2`, strings.TrimSpace(organizationID), strings.TrimSpace(subject)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListOrganizationMemberships(ctx context.Context, organizationID string) ([]controlplane.OrganizationMembership, error) {
	query := `SELECT ` + organizationMembershipColumns + ` FROM organization_memberships`
	args := []any{}
	if strings.TrimSpace(organizationID) != "" {
		query += ` WHERE organization_id=$1`
		args = append(args, strings.TrimSpace(organizationID))
	}
	query += ` ORDER BY organization_id,subject,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.OrganizationMembership{}
	for rows.Next() {
		v, e := scanOrganizationMembership(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListSubjectOrganizationMemberships(ctx context.Context, subject string) ([]controlplane.OrganizationMembership, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+organizationMembershipColumns+` FROM organization_memberships WHERE subject=$1 AND state='ACTIVE' ORDER BY organization_id,id`, strings.TrimSpace(subject))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.OrganizationMembership{}
	for rows.Next() {
		v, e := scanOrganizationMembership(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeOrganizationMembership(ctx context.Context, organizationID, subject string, expected int64, actor string) (controlplane.OrganizationMembership, error) {
	organizationID, subject = strings.TrimSpace(organizationID), strings.TrimSpace(subject)
	var out controlplane.OrganizationMembership
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanOrganizationMembership(tx.QueryRowContext(ctx, `SELECT `+organizationMembershipColumns+` FROM organization_memberships WHERE organization_id=$1 AND subject=$2 FOR UPDATE`, organizationID, subject))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if current.State == controlplane.OrganizationMembershipRevoked {
			out = current
			return nil
		}
		if current.Role == controlplane.OrganizationAdmin {
			var admins int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM organization_memberships WHERE organization_id=$1 AND state='ACTIVE' AND role='organization-admin'`, organizationID).Scan(&admins); err != nil {
				return err
			}
			if admins <= 1 {
				return fmt.Errorf("%w: the last active organization-admin cannot be revoked", controlplane.ErrValidation)
			}
		}
		now := utcNow(s.now)
		out, err = scanOrganizationMembership(tx.QueryRowContext(ctx, `UPDATE organization_memberships SET revision=revision+1,state='REVOKED',revoked_by=$3,revoked_at=$4,updated_at=$4 WHERE organization_id=$1 AND subject=$2 RETURNING `+organizationMembershipColumns, organizationID, subject, strings.TrimSpace(actor), now))
		if err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "organization_membership.revoked", "organizationMembership", out.ID, out.Revision, "", map[string]any{"organizationId": organizationID, "subject": subject}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "organizationMembership", out.ID, "organization_membership.revoked", out)
	})
	return out, err
}

func prepareBlueprintRevisionDB(revision controlplane.BlueprintRevision) (controlplane.BlueprintRevision, error) {
	revision = controlplane.NormalizeBlueprintRevisionResolution(revision)
	if revision.ProjectID == "" || revision.BlueprintName == "" || revision.BlueprintVersion == "" || !strings.HasPrefix(revision.BlueprintDigest, "sha256:") || !strings.HasPrefix(revision.CatalogDigest, "sha256:") || !strings.HasPrefix(revision.BaseBlueprintDigest, "sha256:") || !strings.HasPrefix(revision.OverlayDigest, "sha256:") || !strings.HasPrefix(revision.OwnershipDigest, "sha256:") || len(revision.Payload) == 0 || !json.Valid(revision.Payload) || len(revision.BasePayload) == 0 || !json.Valid(revision.BasePayload) || len(revision.ResolutionPayload) == 0 || !json.Valid(revision.ResolutionPayload) {
		return controlplane.BlueprintRevision{}, fmt.Errorf("%w: immutable base/resolved Blueprint payloads and sha256 resolution digests are required", controlplane.ErrValidation)
	}
	return revision, nil
}

func (s *PostgresStore) createBlueprintRevisionTx(ctx context.Context, tx *sql.Tx, revision controlplane.BlueprintRevision, actor string) (controlplane.BlueprintRevision, bool, error) {
	validateOverlay := func(id string, want controlplane.BlueprintOverlayScope) error {
		if id == "" {
			return nil
		}
		var projectID, scope string
		if err := tx.QueryRowContext(ctx, `SELECT project_id,scope::text FROM blueprint_overlays WHERE id=$1`, id).Scan(&projectID, &scope); err != nil {
			return mapDBError(err)
		}
		if projectID != revision.ProjectID || scope != string(want) {
			return fmt.Errorf("%w: blueprint overlay %s must belong to the same project and have %s scope", controlplane.ErrValidation, id, want)
		}
		return nil
	}
	if err := validateOverlay(revision.ProviderOverlayID, controlplane.BlueprintOverlayProvider); err != nil {
		return controlplane.BlueprintRevision{}, false, err
	}
	if err := validateOverlay(revision.EnvironmentOverlayID, controlplane.BlueprintOverlayEnvironment); err != nil {
		return controlplane.BlueprintRevision{}, false, err
	}
	existing, err := scanBlueprintRevision(tx.QueryRowContext(ctx, `SELECT `+blueprintRevisionColumns+` FROM blueprint_revisions WHERE project_id=$1 AND blueprint_digest=$2 AND catalog_digest=$3 AND base_blueprint_digest=$4 AND overlay_digest=$5 AND ownership_digest=$6`, revision.ProjectID, revision.BlueprintDigest, revision.CatalogDigest, revision.BaseBlueprintDigest, revision.OverlayDigest, revision.OwnershipDigest))
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return controlplane.BlueprintRevision{}, false, err
	}
	now := utcNow(s.now)
	revision.ResourceMeta = controlplane.ResourceMeta{ID: s.id("bpr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := tx.ExecContext(ctx, `INSERT INTO blueprint_revisions(id,project_id,revision,blueprint_name,blueprint_version,blueprint_digest,catalog_digest,base_blueprint_digest,overlay_digest,ownership_digest,provider_overlay_id,environment_overlay_id,base_payload,resolution_payload,payload,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,''),NULLIF($11,''),$12::jsonb,$13::jsonb,$14::jsonb,$15,$15)`, revision.ID, revision.ProjectID, revision.BlueprintName, revision.BlueprintVersion, revision.BlueprintDigest, revision.CatalogDigest, revision.BaseBlueprintDigest, revision.OverlayDigest, revision.OwnershipDigest, revision.ProviderOverlayID, revision.EnvironmentOverlayID, revision.BasePayload, revision.ResolutionPayload, revision.Payload, now); err != nil {
		return controlplane.BlueprintRevision{}, false, mapDBError(err)
	}
	if err := s.appendAuditTx(ctx, tx, actor, "blueprint_revision.created", "blueprintRevision", revision.ID, 1, "", map[string]any{"projectId": revision.ProjectID}); err != nil {
		return controlplane.BlueprintRevision{}, false, err
	}
	if err := s.appendOutboxTx(ctx, tx, "blueprintRevision", revision.ID, "blueprint_revision.created", revision); err != nil {
		return controlplane.BlueprintRevision{}, false, err
	}
	return revision, true, nil
}

func (s *PostgresStore) CreateBlueprintRevision(ctx context.Context, revision controlplane.BlueprintRevision, actor string) (controlplane.BlueprintRevision, error) {
	prepared, err := prepareBlueprintRevisionDB(revision)
	if err != nil {
		return controlplane.BlueprintRevision{}, err
	}
	var created controlplane.BlueprintRevision
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		var e error
		created, _, e = s.createBlueprintRevisionTx(ctx, tx, prepared, actor)
		return e
	})
	if errors.Is(err, controlplane.ErrDuplicateName) {
		existing, lookupErr := scanBlueprintRevision(s.db.QueryRowContext(ctx, `SELECT `+blueprintRevisionColumns+` FROM blueprint_revisions WHERE project_id=$1 AND blueprint_digest=$2 AND catalog_digest=$3 AND base_blueprint_digest=$4 AND overlay_digest=$5 AND ownership_digest=$6`, prepared.ProjectID, prepared.BlueprintDigest, prepared.CatalogDigest, prepared.BaseBlueprintDigest, prepared.OverlayDigest, prepared.OwnershipDigest))
		if lookupErr == nil {
			return existing, nil
		}
	}
	return created, err
}

func (s *PostgresStore) GetBlueprintRevision(ctx context.Context, id string) (controlplane.BlueprintRevision, error) {
	value, err := scanBlueprintRevision(s.db.QueryRowContext(ctx, `SELECT `+blueprintRevisionColumns+` FROM blueprint_revisions WHERE id=$1`, id))
	return value, mapDBError(err)
}

func (s *PostgresStore) CreateAssignment(ctx context.Context, assignment controlplane.Assignment, actor string) (controlplane.Assignment, error) {
	if assignment.ProjectID == "" || assignment.BlueprintRevisionID == "" || strings.TrimSpace(assignment.TargetRef) == "" {
		return controlplane.Assignment{}, fmt.Errorf("%w: projectId, blueprintRevisionId and targetRef are required", controlplane.ErrValidation)
	}
	now := utcNow(s.now)
	assignment.ResourceMeta = controlplane.ResourceMeta{ID: s.id("asn"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	assignment.TargetRef = strings.TrimSpace(assignment.TargetRef)
	assignment.DesiredGeneration = 1
	assignment.ObservedGeneration = 0
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO assignments(id,project_id,revision,target_ref,blueprint_revision_id,desired_generation,observed_generation,created_at,updated_at) VALUES($1,$2,1,$3,$4,1,0,$5,$5)`, assignment.ID, assignment.ProjectID, assignment.TargetRef, assignment.BlueprintRevisionID, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "assignment.created", "assignment", assignment.ID, 1, "", nil); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "assignment", assignment.ID, "assignment.created", assignment)
	})
	return assignment, err
}

func (s *PostgresStore) UpdateAssignment(ctx context.Context, id string, expected int64, revisionID string, generation int64, actor string) (controlplane.Assignment, error) {
	var updated controlplane.Assignment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanAssignment(tx.QueryRowContext(ctx, `SELECT `+assignmentColumns+` FROM assignments WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if generation <= current.DesiredGeneration {
			return fmt.Errorf("%w: desired generation must increase", controlplane.ErrValidation)
		}
		current.BlueprintRevisionID = revisionID
		current.DesiredGeneration = generation
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if _, err := tx.ExecContext(ctx, `UPDATE assignments SET revision=$2,blueprint_revision_id=$3,desired_generation=$4,updated_at=$5 WHERE id=$1 AND revision=$6`, id, current.Revision, revisionID, generation, current.UpdatedAt, expected); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "assignment.updated", "assignment", id, current.Revision, "", map[string]any{"desiredGeneration": generation}); err != nil {
			return err
		}
		if err := s.appendOutboxTx(ctx, tx, "assignment", id, "assignment.updated", current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}

func (s *PostgresStore) GetAssignment(ctx context.Context, id string) (controlplane.Assignment, error) {
	value, err := scanAssignment(s.db.QueryRowContext(ctx, `SELECT `+assignmentColumns+` FROM assignments WHERE id=$1`, id))
	return value, mapDBError(err)
}

func (s *PostgresStore) CreateOperation(ctx context.Context, request controlplane.OperationRequest, key, actor, requestID string) (controlplane.Operation, bool, error) {
	key = strings.TrimSpace(key)
	actor = strings.TrimSpace(actor)
	if key == "" || len(key) > 200 || actor == "" {
		return controlplane.Operation{}, false, fmt.Errorf("%w: bounded idempotency key and actor are required", controlplane.ErrValidation)
	}
	if request.Risk != "low" && request.Risk != "medium" && request.Risk != "high" && request.Risk != "critical" {
		return controlplane.Operation{}, false, fmt.Errorf("%w: invalid operation risk", controlplane.ErrValidation)
	}
	class, classErr := controlplane.NormalizeOperationClass(request.Class)
	if classErr != nil {
		return controlplane.Operation{}, false, classErr
	}
	request.Class = class
	if request.ProjectID == "" || request.Kind == "" || request.TargetRef == "" || request.DesiredRevision == "" {
		return controlplane.Operation{}, false, fmt.Errorf("%w: projectId, kind, targetRef and desiredRevision are required", controlplane.ErrValidation)
	}
	digest := operationDigest(request)
	var result controlplane.Operation
	var replay bool
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, request.ProjectID, key))
		if err == nil {
			if existing.RequestDigest != digest {
				return controlplane.ErrIdempotencyConflict
			}
			result, replay = existing, true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now := utcNow(s.now)
		result = controlplane.Operation{
			ResourceMeta: controlplane.ResourceMeta{ID: s.id("op"), Revision: 1, CreatedAt: now, UpdatedAt: now},
			ProjectID:    request.ProjectID, Kind: request.Kind, TargetRef: request.TargetRef, DesiredRevision: request.DesiredRevision, State: controlplane.OperationDraft,
			Risk: request.Risk, Class: class, RetryPolicy: controlplane.RetryPolicyForOperationClass(class), RecoveryCheckpointID: strings.TrimSpace(request.RecoveryCheckpointID), IdempotencyKey: key, RequestDigest: digest, ActorID: actor,
		}
		if class == controlplane.OperationClassDestructive {
			if err := s.bindDestructiveRecoveryTx(ctx, tx, &result, now); err != nil {
				return err
			}
		}
		retryPolicy, _ := json.Marshal(result.RetryPolicy)
		if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,project_id,revision,kind,target_ref,desired_revision,state,risk,operation_class,retry_policy,attempt,retry_exhausted,recovery_checkpoint_id,recovery_evidence_digest,recovery_inventory_digest,idempotency_key,request_digest,actor_id,fence_token,last_error,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9::jsonb,0,false,NULLIF($10,''),$11,$12,$13,$14,$15,0,'',$16,$16)`, result.ID, result.ProjectID, result.Kind, result.TargetRef, result.DesiredRevision, string(result.State), result.Risk, string(result.Class), retryPolicy, result.RecoveryCheckpointID, result.RecoveryEvidenceDigest, result.RecoveryInventoryDigest, result.IdempotencyKey, result.RequestDigest, result.ActorID, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "operation.created", "operation", result.ID, 1, requestID, map[string]any{"state": result.State}); err != nil {
			return err
		}
		return s.appendOutboxTx(ctx, tx, "operation", result.ID, "operation.created", result)
	})
	if errors.Is(err, controlplane.ErrDuplicateName) {
		existing, lookupErr := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE project_id=$1 AND idempotency_key=$2`, request.ProjectID, key))
		if lookupErr == nil {
			if existing.RequestDigest != digest {
				return controlplane.Operation{}, false, controlplane.ErrIdempotencyConflict
			}
			return existing, true, nil
		}
	}
	return result, replay, err
}

func (s *PostgresStore) GetOperation(ctx context.Context, id string) (controlplane.Operation, error) {
	value, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1`, id))
	return value, mapDBError(err)
}

func (s *PostgresStore) ListOperations(ctx context.Context, projectID string) ([]controlplane.Operation, error) {
	query := `SELECT ` + operationColumns + ` FROM operations`
	args := []any{}
	if projectID != "" {
		query += ` WHERE project_id=$1`
		args = append(args, projectID)
	}
	query += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []controlplane.Operation
	for rows.Next() {
		value, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// ListOperationsPage is the bounded runtime collection path used by the
// operator console. The legacy ListOperations method remains unbounded for
// internal reconciliation/snapshot callers whose semantics require the full
// set.
func (s *PostgresStore) ListOperationsPage(ctx context.Context, projectID string, limit int) ([]controlplane.Operation, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	query := `SELECT ` + operationColumns + ` FROM operations`
	args := []any{}
	if projectID != "" {
		query += ` WHERE project_id=$1`
		args = append(args, projectID)
	}
	args = append(args, limit)
	query += fmt.Sprintf(` ORDER BY updated_at DESC,created_at DESC,id DESC LIMIT $%d`, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]controlplane.Operation, 0, limit)
	for rows.Next() {
		value, scanErr := scanOperation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// ListOperationsPageByProjects applies project authorization inside the bounded
// PostgreSQL query. Filtering a global LIMIT result in the API is incorrect for
// scoped principals because newer foreign rows can evict older authorized rows
// before authorization is applied.
func (s *PostgresStore) ListOperationsPageByProjects(ctx context.Context, projectIDs []string, limit int) ([]controlplane.Operation, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	seen := make(map[string]bool, len(projectIDs))
	ids := make([]string, 0, len(projectIDs))
	for _, projectID := range projectIDs {
		projectID = strings.TrimSpace(projectID)
		if projectID == "" || seen[projectID] {
			continue
		}
		seen[projectID] = true
		ids = append(ids, projectID)
	}
	if len(ids) == 0 {
		return []controlplane.Operation{}, nil
	}
	// Project identifiers are product-generated opaque IDs and cannot contain
	// the unit separator. Encoding the set into one PostgreSQL text[] parameter
	// avoids a parameter-per-project ceiling for large organizations.
	const separator = "\x1f"
	rows, err := s.db.QueryContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE project_id = ANY(string_to_array($1, chr(31))) ORDER BY updated_at DESC,created_at DESC,id DESC LIMIT $2`, strings.Join(ids, separator), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]controlplane.Operation, 0, limit)
	for rows.Next() {
		value, scanErr := scanOperation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *PostgresStore) TransitionOperation(ctx context.Context, id string, expected int64, to controlplane.OperationState, lastError, actor string) (controlplane.Operation, error) {
	var updated controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if !controlplane.CanTransition(current.State, to) {
			return controlplane.ErrInvalidTransition
		}
		if to == controlplane.OperationRollingBack {
			return fmt.Errorf("%w: ROLLING_BACK is compensation-authority controlled; use BeginOperationCompensation", controlplane.ErrPrerequisite)
		}
		if current.State == controlplane.OperationFailed && to == controlplane.OperationQueued && current.Attempt > 0 {
			return fmt.Errorf("%w: bounded retry budget cannot be bypassed; create a new idempotent operation or recover explicitly", controlplane.ErrPrerequisite)
		}
		current.State = to
		current.LastError = lastError
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if controlplane.IsTerminal(to) {
			current.LeaseOwner = ""
			current.LeaseExpiresAt = nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,last_error=$4,lease_owner=NULLIF($5,''),lease_expires_at=$6,updated_at=$7 WHERE id=$1 AND revision=$8`, id, current.Revision, string(current.State), current.LastError, current.LeaseOwner, current.LeaseExpiresAt, current.UpdatedAt, expected); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "operation.transitioned", "operation", id, current.Revision, "", map[string]any{"state": to}); err != nil {
			return err
		}
		if err := s.appendOutboxTx(ctx, tx, "operation", id, "operation.transitioned", current); err != nil {
			return err
		}
		updated = current
		return nil
	})
	return updated, err
}

func claimable(state controlplane.OperationState) bool {
	switch state {
	case controlplane.OperationQueued, controlplane.OperationRunning, controlplane.OperationVerifying, controlplane.OperationRollingBack, controlplane.OperationCancelRequested:
		return true
	default:
		return false
	}
}

func (s *PostgresStore) ClaimOperation(ctx context.Context, id, worker string, ttl time.Duration, at time.Time) (controlplane.ClaimResult, error) {
	if strings.TrimSpace(worker) == "" || ttl <= 0 {
		return controlplane.ClaimResult{}, fmt.Errorf("%w: worker and positive ttl are required", controlplane.ErrValidation)
	}
	at = at.UTC()
	var result controlplane.ClaimResult
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.State == controlplane.OperationRetryWait {
			if current.NextAttemptAt == nil || current.NextAttemptAt.After(at) {
				return controlplane.ErrNotClaimable
			}
			current.State = controlplane.OperationQueued
			current.NextAttemptAt = nil
			current.Revision++
			current.UpdatedAt = utcNow(s.now)
			if _, err := tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,next_attempt_at=NULL,updated_at=$4 WHERE id=$1`, id, current.Revision, string(current.State), current.UpdatedAt); err != nil {
				return err
			}
			if err := s.appendAuditTx(ctx, tx, worker, "operation.retry_due_queued", "operation", id, current.Revision, "", map[string]any{"attempt": current.Attempt + 1}); err != nil {
				return err
			}
			if err := s.appendOutboxTx(ctx, tx, "operation", id, "operation.retry_due_queued", current); err != nil {
				return err
			}
		}
		if !claimable(current.State) {
			return controlplane.ErrNotClaimable
		}
		if current.LeaseExpiresAt != nil && current.LeaseExpiresAt.After(at) && current.LeaseOwner != worker {
			return controlplane.ErrLeaseHeld
		}
		expires := at.Add(ttl)
		current.LeaseOwner = worker
		current.LeaseExpiresAt = &expires
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if err := tx.QueryRowContext(ctx, `UPDATE operations SET revision=$2,lease_owner=$3,lease_expires_at=$4,fence_token=fence_token+1,updated_at=$5 WHERE id=$1 RETURNING fence_token`, id, current.Revision, worker, expires, current.UpdatedAt).Scan(&current.FenceToken); err != nil {
			return err
		}
		if err := s.appendAuditTx(ctx, tx, worker, "operation.claimed", "operation", id, current.Revision, "", map[string]any{"fenceToken": current.FenceToken}); err != nil {
			return err
		}
		result = controlplane.ClaimResult{OperationID: id, LeaseOwner: worker, LeaseExpiresAt: expires, FenceToken: current.FenceToken}
		return nil
	})
	return result, err
}

func (s *PostgresStore) RenewOperationLease(ctx context.Context, id, worker string, fence int64, ttl time.Duration, at time.Time) (controlplane.ClaimResult, error) {
	if ttl <= 0 {
		return controlplane.ClaimResult{}, fmt.Errorf("%w: positive lease ttl is required", controlplane.ErrValidation)
	}
	at = at.UTC()
	var result controlplane.ClaimResult
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.FenceToken != fence || current.LeaseOwner != worker {
			return controlplane.ErrStaleFence
		}
		if current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.After(at) {
			return controlplane.ErrLeaseHeld
		}
		expires := at.Add(ttl)
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		if _, err := tx.ExecContext(ctx, `UPDATE operations SET revision=$2,lease_expires_at=$3,updated_at=$4 WHERE id=$1 AND lease_owner=$5 AND fence_token=$6`, id, current.Revision, expires, current.UpdatedAt, worker, fence); err != nil {
			return err
		}
		result = controlplane.ClaimResult{OperationID: id, LeaseOwner: worker, LeaseExpiresAt: expires, FenceToken: fence}
		return nil
	})
	return result, err
}

func (s *PostgresStore) ReleaseOperationLease(ctx context.Context, id, worker string, fence int64) error {
	return s.serializable(ctx, func(tx *sql.Tx) error {
		current, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return mapDBError(err)
		}
		if current.FenceToken != fence || current.LeaseOwner != worker {
			return controlplane.ErrStaleFence
		}
		current.Revision++
		current.UpdatedAt = utcNow(s.now)
		_, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,lease_owner=NULL,lease_expires_at=NULL,updated_at=$3 WHERE id=$1 AND lease_owner=$4 AND fence_token=$5`, id, current.Revision, current.UpdatedAt, worker, fence)
		return err
	})
}

func (s *PostgresStore) AppendOperationStep(ctx context.Context, step controlplane.OperationStep, actor string) (controlplane.OperationStep, error) {
	if step.OperationID == "" || step.StepKey == "" || step.FenceToken <= 0 {
		return controlplane.OperationStep{}, fmt.Errorf("%w: operationId, stepKey and positive fenceToken are required", controlplane.ErrValidation)
	}
	var result controlplane.OperationStep
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var currentFence int64
		var currentAttempt int
		if err := tx.QueryRowContext(ctx, `SELECT fence_token,attempt FROM operations WHERE id=$1 FOR UPDATE`, step.OperationID).Scan(&currentFence, &currentAttempt); err != nil {
			return mapDBError(err)
		}
		if currentFence != step.FenceToken {
			return controlplane.ErrStaleFence
		}
		if currentAttempt < 1 {
			return fmt.Errorf("%w: operation attempt has not started", controlplane.ErrPrerequisite)
		}
		step.Attempt = currentAttempt
		existing, err := scanStep(tx.QueryRowContext(ctx, `SELECT `+stepColumns+` FROM operation_steps WHERE operation_id=$1 AND attempt=$2 AND step_key=$3`, step.OperationID, step.Attempt, step.StepKey))
		if err == nil {
			result = existing
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now := utcNow(s.now)
		step.ResourceMeta = controlplane.ResourceMeta{ID: s.id("stp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_steps(id,operation_id,revision,step_key,state,attempt,fence_token,started_at,finished_at,last_error,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$10)`, step.ID, step.OperationID, step.StepKey, string(step.State), step.Attempt, step.FenceToken, step.StartedAt, step.FinishedAt, step.LastError, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "operation_step.appended", "operationStep", step.ID, 1, "", map[string]any{"operationId": step.OperationID, "stepKey": step.StepKey}); err != nil {
			return err
		}
		if err := s.appendOutboxTx(ctx, tx, "operationStep", step.ID, "operation_step.appended", step); err != nil {
			return err
		}
		result = step
		return nil
	})
	if errors.Is(err, controlplane.ErrDuplicateName) {
		existing, lookupErr := scanStep(s.db.QueryRowContext(ctx, `SELECT `+stepColumns+` FROM operation_steps WHERE operation_id=$1 AND step_key=$2`, step.OperationID, step.StepKey))
		if lookupErr == nil {
			return existing, nil
		}
	}
	return result, err
}

func (s *PostgresStore) ListOperationSteps(ctx context.Context, operationID string) ([]controlplane.OperationStep, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+stepColumns+` FROM operation_steps WHERE operation_id=$1 ORDER BY step_key,id`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []controlplane.OperationStep
	for rows.Next() {
		value, err := scanStep(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *PostgresStore) ClaimOutbox(ctx context.Context, worker string, limit int, ttl time.Duration, at time.Time) ([]controlplane.OutboxEvent, error) {
	if strings.TrimSpace(worker) == "" || limit <= 0 || ttl <= 0 {
		return nil, fmt.Errorf("%w: worker, positive limit and ttl are required", controlplane.ErrValidation)
	}
	at = at.UTC()
	until := at.Add(ttl)
	rows, err := s.db.QueryContext(ctx, `
		WITH candidates AS (
			SELECT id FROM outbox_events
			WHERE published_at IS NULL AND available_at <= $1
			  AND (claimed_until IS NULL OR claimed_until <= $1)
			ORDER BY available_at,id
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		UPDATE outbox_events AS e
		SET claimed_by=$2,claimed_until=$4,attempt=e.attempt+1,revision=e.revision+1,updated_at=$1
		FROM candidates c
		WHERE e.id=c.id
		RETURNING `+outboxReturningColumns, at, worker, limit, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []controlplane.OutboxEvent
	for rows.Next() {
		value, err := scanOutbox(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// UPDATE ... RETURNING does not guarantee result-row order even though the
	// candidate CTE is ordered. Preserve the same scheduler contract exposed by
	// Memory/FileStore and by the candidate selection itself.
	sort.Slice(values, func(i, j int) bool {
		if values[i].AvailableAt.Equal(values[j].AvailableAt) {
			return values[i].ID < values[j].ID
		}
		return values[i].AvailableAt.Before(values[j].AvailableAt)
	})
	return values, nil
}

func (s *PostgresStore) MarkOutboxPublished(ctx context.Context, id, worker string, at time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE outbox_events SET published_at=$3,claimed_by=NULL,claimed_until=NULL,revision=revision+1,updated_at=$3 WHERE id=$1 AND claimed_by=$2 AND claimed_until>$3 AND published_at IS NULL`, id, worker, at.UTC())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return controlplane.ErrStaleFence
	}
	return nil
}

func (s *PostgresStore) AppendEvidence(ctx context.Context, evidence controlplane.EvidenceMetadata, actor string) (controlplane.EvidenceMetadata, error) {
	if evidence.OperationID == "" || !strings.HasPrefix(evidence.Digest, "sha256:") || evidence.MediaType == "" || evidence.Location == "" || evidence.Size < 0 {
		return controlplane.EvidenceMetadata{}, fmt.Errorf("%w: operationId, sha256 digest, mediaType, location and non-negative size are required", controlplane.ErrValidation)
	}
	var result controlplane.EvidenceMetadata
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		existing, err := scanEvidence(tx.QueryRowContext(ctx, `SELECT `+evidenceColumns+` FROM evidence_metadata WHERE operation_id=$1 AND digest=$2`, evidence.OperationID, evidence.Digest))
		if err == nil {
			result = existing
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now := utcNow(s.now)
		evidence.ResourceMeta = controlplane.ResourceMeta{ID: s.id("evd"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		evidence.Sealed = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_metadata(id,operation_id,revision,kind,digest,media_type,location,size_bytes,sealed,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,true,$8,$8)`, evidence.ID, evidence.OperationID, evidence.Kind, evidence.Digest, evidence.MediaType, evidence.Location, evidence.Size, now); err != nil {
			return mapDBError(err)
		}
		if err := s.appendAuditTx(ctx, tx, actor, "evidence.sealed", "evidence", evidence.ID, 1, "", map[string]any{"operationId": evidence.OperationID, "digest": evidence.Digest}); err != nil {
			return err
		}
		if err := s.appendOutboxTx(ctx, tx, "evidence", evidence.ID, "evidence.sealed", evidence); err != nil {
			return err
		}
		result = evidence
		return nil
	})
	if errors.Is(err, controlplane.ErrDuplicateName) {
		existing, lookupErr := scanEvidence(s.db.QueryRowContext(ctx, `SELECT `+evidenceColumns+` FROM evidence_metadata WHERE operation_id=$1 AND digest=$2`, evidence.OperationID, evidence.Digest))
		if lookupErr == nil {
			return existing, nil
		}
	}
	return result, err
}

func (s *PostgresStore) ListEvidence(ctx context.Context, operationID string) ([]controlplane.EvidenceMetadata, error) {
	query := `SELECT ` + evidenceColumns + ` FROM evidence_metadata`
	args := []any{}
	if operationID != "" {
		query += ` WHERE operation_id=$1`
		args = append(args, operationID)
	}
	query += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []controlplane.EvidenceMetadata
	for rows.Next() {
		value, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *PostgresStore) ListAudit(ctx context.Context, limit int) ([]controlplane.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,occurred_at,actor_id,action,resource_type,resource_id,resource_revision,COALESCE(request_id,''),metadata FROM audit_events ORDER BY occurred_at DESC,id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []controlplane.AuditEvent
	for rows.Next() {
		var value controlplane.AuditEvent
		var metadata []byte
		if err := rows.Scan(&value.ID, &value.OccurredAt, &value.ActorID, &value.Action, &value.ResourceType, &value.ResourceID, &value.Revision, &value.RequestID, &metadata); err != nil {
			return nil, err
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &value.Metadata); err != nil {
				return nil, err
			}
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *PostgresStore) ReadinessCounts(ctx context.Context) (int, int, error) {
	var organizations, operations int
	err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM organizations),(SELECT COUNT(*) FROM operations)`).Scan(&organizations, &operations)
	return organizations, operations, err
}

func (s *PostgresStore) Snapshot(ctx context.Context) (controlplane.Snapshot, error) {
	var snapshot controlplane.Snapshot
	organizations, err := s.ListOrganizations(ctx)
	if err != nil {
		return snapshot, err
	}
	projects, err := s.ListProjects(ctx, "")
	if err != nil {
		return snapshot, err
	}
	memberships, err := s.ListOrganizationMemberships(ctx, "")
	if err != nil {
		return snapshot, err
	}
	groupMappings, err := s.ListOIDCGroupMappings(ctx, "")
	if err != nil {
		return snapshot, err
	}
	securityAudit, err := s.snapshotSecurityAudit(ctx)
	if err != nil {
		return snapshot, err
	}
	serviceAccounts, err := s.ListServiceAccounts(ctx, "")
	if err != nil {
		return snapshot, err
	}
	apiTokens, err := s.ListAPITokens(ctx, "")
	if err != nil {
		return snapshot, err
	}
	operations, err := s.ListOperations(ctx, "")
	if err != nil {
		return snapshot, err
	}
	evidence, err := s.ListEvidence(ctx, "")
	if err != nil {
		return snapshot, err
	}
	audit, err := s.snapshotAudit(ctx)
	if err != nil {
		return snapshot, err
	}
	snapshot.Organizations = organizations
	snapshot.OrganizationMemberships = memberships
	snapshot.OIDCGroupMappings = groupMappings
	snapshot.SecurityAudit = securityAudit
	snapshot.ServiceAccounts = serviceAccounts
	snapshot.APITokens = apiTokens
	snapshot.Projects = projects
	snapshot.Operations = operations
	snapshot.Evidence = evidence
	snapshot.Audit = audit

	overlays, err := s.ListBlueprintOverlays(ctx, "", "")
	if err != nil {
		return snapshot, err
	}
	snapshot.BlueprintOverlays = overlays

	revisionRows, err := s.db.QueryContext(ctx, `SELECT `+blueprintRevisionColumns+` FROM blueprint_revisions ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for revisionRows.Next() {
		value, err := scanBlueprintRevision(revisionRows)
		if err != nil {
			revisionRows.Close()
			return snapshot, err
		}
		snapshot.Revisions = append(snapshot.Revisions, value)
	}
	if err := revisionRows.Close(); err != nil {
		return snapshot, err
	}

	blueprintReleases, err := s.ListBlueprintReleases(ctx, "")
	if err != nil {
		return snapshot, err
	}
	snapshot.BlueprintReleases = blueprintReleases

	catalogTrustKeys, err := s.ListCatalogTrustKeys(ctx, "")
	if err != nil {
		return snapshot, err
	}
	catalogReleases, err := s.ListCatalogReleases(ctx, "")
	if err != nil {
		return snapshot, err
	}
	catalogRevisionRows, err := s.db.QueryContext(ctx, `SELECT `+catalogRevisionColumns+` FROM catalog_revisions ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for catalogRevisionRows.Next() {
		value, scanErr := scanCatalogRevision(catalogRevisionRows)
		if scanErr != nil {
			catalogRevisionRows.Close()
			return snapshot, scanErr
		}
		snapshot.CatalogRevisions = append(snapshot.CatalogRevisions, value)
	}
	if err := catalogRevisionRows.Close(); err != nil {
		return snapshot, err
	}
	snapshot.CatalogTrustKeys = catalogTrustKeys
	snapshot.CatalogReleases = catalogReleases

	assignmentRows, err := s.db.QueryContext(ctx, `SELECT `+assignmentColumns+` FROM assignments ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for assignmentRows.Next() {
		value, err := scanAssignment(assignmentRows)
		if err != nil {
			assignmentRows.Close()
			return snapshot, err
		}
		snapshot.Assignments = append(snapshot.Assignments, value)
	}
	if err := assignmentRows.Close(); err != nil {
		return snapshot, err
	}

	stepRows, err := s.db.QueryContext(ctx, `SELECT `+stepColumns+` FROM operation_steps ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for stepRows.Next() {
		value, err := scanStep(stepRows)
		if err != nil {
			stepRows.Close()
			return snapshot, err
		}
		snapshot.Steps = append(snapshot.Steps, value)
	}
	if err := stepRows.Close(); err != nil {
		return snapshot, err
	}

	traceRows, err := s.db.QueryContext(ctx, `SELECT `+operationStepTraceColumns+` FROM operation_step_traces ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for traceRows.Next() {
		value, scanErr := scanOperationStepTrace(traceRows)
		if scanErr != nil {
			traceRows.Close()
			return snapshot, scanErr
		}
		snapshot.StepTraces = append(snapshot.StepTraces, value)
	}
	if err := traceRows.Close(); err != nil {
		return snapshot, err
	}

	payloadRows, err := s.db.QueryContext(ctx, `SELECT evidence_id,payload FROM operation_evidence_payloads ORDER BY evidence_id`)
	if err != nil {
		return snapshot, err
	}
	for payloadRows.Next() {
		var value controlplane.EvidencePayload
		if scanErr := payloadRows.Scan(&value.EvidenceID, &value.Payload); scanErr != nil {
			payloadRows.Close()
			return snapshot, scanErr
		}
		value.Payload = append([]byte(nil), value.Payload...)
		snapshot.EvidencePayloads = append(snapshot.EvidencePayloads, value)
	}
	if err := payloadRows.Close(); err != nil {
		return snapshot, err
	}

	compensationRows, err := s.db.QueryContext(ctx, `SELECT `+compensationStepColumns+` FROM operation_compensation_steps ORDER BY operation_id,forward_order,id`)
	if err != nil {
		return snapshot, err
	}
	for compensationRows.Next() {
		value, err := scanCompensationStep(compensationRows)
		if err != nil {
			compensationRows.Close()
			return snapshot, err
		}
		snapshot.CompensationSteps = append(snapshot.CompensationSteps, value)
	}
	if err := compensationRows.Close(); err != nil {
		return snapshot, err
	}

	outboxRows, err := s.db.QueryContext(ctx, `SELECT `+outboxColumns+` FROM outbox_events ORDER BY id`)
	if err != nil {
		return snapshot, err
	}
	for outboxRows.Next() {
		value, err := scanOutbox(outboxRows)
		if err != nil {
			outboxRows.Close()
			return snapshot, err
		}
		snapshot.Outbox = append(snapshot.Outbox, value)
	}
	if err := outboxRows.Close(); err != nil {
		return snapshot, err
	}
	imports, err := s.ListClusterImports(ctx, "")
	if err != nil {
		return snapshot, err
	}
	clusters, err := s.ListManagedClusters(ctx, "")
	if err != nil {
		return snapshot, err
	}
	deployments, err := s.ListBaselineDeployments(ctx, "", "")
	if err != nil {
		return snapshot, err
	}
	snapshot.ClusterImports = imports
	snapshot.ManagedClusters = clusters
	if err := populateSupplementalSnapshot(ctx, s, &snapshot, organizations, imports); err != nil {
		return snapshot, err
	}
	for _, cluster := range clusters {
		if profile, profileErr := s.GetClusterMaintenanceProfile(ctx, cluster.ID); profileErr == nil {
			snapshot.ClusterMaintenanceProfiles = append(snapshot.ClusterMaintenanceProfiles, profile)
		} else if !errors.Is(profileErr, controlplane.ErrNotFound) {
			return snapshot, profileErr
		}
		windows, windowErr := s.ListClusterMaintenanceWindows(ctx, cluster.ID)
		if windowErr != nil {
			return snapshot, windowErr
		}
		snapshot.ClusterMaintenanceWindows = append(snapshot.ClusterMaintenanceWindows, windows...)
		runs, runErr := s.ListClusterMaintenanceRuns(ctx, cluster.ID)
		if runErr != nil {
			return snapshot, runErr
		}
		snapshot.ClusterMaintenanceRuns = append(snapshot.ClusterMaintenanceRuns, runs...)
	}
	snapshot.BaselineDeployments = deployments
	runtimeVerifications, err := s.ListRuntimeVerifications(ctx, "", "", "")
	if err != nil {
		return snapshot, err
	}
	runtimeCertifications, err := s.ListRuntimeCertifications(ctx, "", "")
	if err != nil {
		return snapshot, err
	}
	fleetGroups, err := s.ListFleetGroups(ctx, "")
	if err != nil {
		return snapshot, err
	}
	driftScans, err := s.ListDriftScans(ctx, "", "")
	if err != nil {
		return snapshot, err
	}
	upgradeCampaigns, err := s.ListUpgradeCampaigns(ctx, "", "")
	if err != nil {
		return snapshot, err
	}
	aiRuns, err := s.ListAIRuns(ctx, "")
	if err != nil {
		return snapshot, err
	}
	marketplaceRecommendations, err := s.ListMarketplaceRecommendations(ctx, "", "")
	if err != nil {
		return snapshot, err
	}
	runtimeClosureCampaigns, err := s.ListRuntimeClosureCampaigns(ctx, "", "")
	if err != nil {
		return snapshot, err
	}
	snapshot.RuntimeVerifications = runtimeVerifications
	snapshot.RuntimeCertifications = runtimeCertifications
	snapshot.FleetGroups = fleetGroups
	snapshot.DriftScans = driftScans
	snapshot.UpgradeCampaigns = upgradeCampaigns
	snapshot.AIRuns = aiRuns
	snapshot.MarketplaceRecommendations = marketplaceRecommendations
	snapshot.RuntimeClosureCampaigns = runtimeClosureCampaigns
	for _, cluster := range clusters {
		if inv, invErr := s.GetLatestClusterInventory(ctx, cluster.ID); invErr == nil {
			snapshot.ClusterInventories = append(snapshot.ClusterInventories, inv)
		} else if !errors.Is(invErr, controlplane.ErrNotFound) {
			return snapshot, invErr
		}
	}
	controlplane.CanonicalizeSnapshot(&snapshot)
	return snapshot, nil
}

var _ controlplane.Store = (*PostgresStore)(nil)
