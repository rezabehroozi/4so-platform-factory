package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const samlBrokerColumns = `id,revision,organization_id,alias,keycloak_alias,display_name,entity_id,single_sign_on_service_url,single_logout_service_url,signing_certificate,name_id_policy_format,want_authn_requests_signed,enabled,state,desired_digest,observed_digest,requested_by,last_error,created_at,updated_at`
const identityAdminJobColumns = `id,revision,organization_id,broker_id,broker_revision,kind,state,idempotency_key,request_digest,desired_digest,requested_by,approved_by,approved_at,task_attempt,task_fence_token,task_lease_owner,task_lease_expires_at,started_at,finished_at,evidence_digest,last_error,created_at,updated_at`

func scanSAMLBroker(row interface{ Scan(...any) error }) (controlplane.SAMLBroker, error) {
	var v controlplane.SAMLBroker
	var state string
	err := row.Scan(&v.ID, &v.Revision, &v.OrganizationID, &v.Alias, &v.KeycloakAlias, &v.DisplayName, &v.EntityID, &v.SingleSignOnServiceURL, &v.SingleLogoutServiceURL, &v.SigningCertificate, &v.NameIDPolicyFormat, &v.WantAuthnRequestsSigned, &v.Enabled, &state, &v.DesiredDigest, &v.ObservedDigest, &v.RequestedBy, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.SAMLBrokerState(state)
	return v, err
}

func scanIdentityAdminJob(row interface{ Scan(...any) error }) (controlplane.IdentityAdminJob, error) {
	var v controlplane.IdentityAdminJob
	var kind, state string
	err := row.Scan(&v.ID, &v.Revision, &v.OrganizationID, &v.BrokerID, &v.BrokerRevision, &kind, &state, &v.IdempotencyKey, &v.RequestDigest, &v.DesiredDigest, &v.RequestedBy, &v.ApprovedBy, &v.ApprovedAt, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskLeaseOwner, &v.TaskLeaseExpiresAt, &v.StartedAt, &v.FinishedAt, &v.EvidenceDigest, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	v.Kind = controlplane.IdentityAdminJobKind(kind)
	v.State = controlplane.IdentityAdminJobState(state)
	return v, err
}

func (s *PostgresStore) RequestSAMLBrokerUpsert(ctx context.Context, input controlplane.SAMLBroker, expected int64, idempotencyKey, requestDigest, actor string) (controlplane.SAMLBroker, controlplane.IdentityAdminJob, bool, error) {
	var outBroker controlplane.SAMLBroker
	var outJob controlplane.IdentityAdminJob
	var replay bool
	idempotencyKey, requestDigest, actor = strings.TrimSpace(idempotencyKey), strings.TrimSpace(requestDigest), strings.TrimSpace(actor)
	if idempotencyKey == "" || !strings.HasPrefix(requestDigest, "sha256:") || actor == "" {
		return outBroker, outJob, false, controlplane.ErrValidation
	}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		isUpdate := strings.TrimSpace(input.ID) != ""
		var existing controlplane.SAMLBroker
		var e error
		if isUpdate {
			existing, e = scanSAMLBroker(tx.QueryRowContext(ctx, `SELECT `+samlBrokerColumns+` FROM saml_brokers WHERE id=$1 FOR UPDATE`, input.ID))
			if e != nil {
				return mapDBError(e)
			}
			if existing.Revision != expected || existing.State == controlplane.SAMLBrokerDeleted {
				return controlplane.ErrConflict
			}
			if input.OrganizationID == "" {
				input.OrganizationID = existing.OrganizationID
			}
			if input.OrganizationID != existing.OrganizationID {
				return controlplane.ErrConflict
			}
		} else if expected != 0 {
			return controlplane.ErrValidation
		}
		if strings.TrimSpace(input.OrganizationID) == "" {
			return controlplane.ErrValidation
		}
		var organizationExists int
		if e = tx.QueryRowContext(ctx, `SELECT 1 FROM organizations WHERE id=$1`, input.OrganizationID).Scan(&organizationExists); e != nil {
			return mapDBError(e)
		}
		normalized, e := controlplane.NormalizeSAMLBroker(input)
		if e != nil {
			return e
		}
		input = normalized
		existingJob, e := scanIdentityAdminJob(tx.QueryRowContext(ctx, `SELECT `+identityAdminJobColumns+` FROM identity_admin_jobs WHERE organization_id=$1 AND idempotency_key=$2`, input.OrganizationID, idempotencyKey))
		if e == nil {
			if existingJob.RequestDigest != requestDigest {
				return controlplane.ErrConflict
			}
			broker, getErr := scanSAMLBroker(tx.QueryRowContext(ctx, `SELECT `+samlBrokerColumns+` FROM saml_brokers WHERE id=$1`, existingJob.BrokerID))
			if getErr != nil {
				return mapDBError(getErr)
			}
			outBroker, outJob, replay = broker, existingJob, true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		now := utcNow(s.now)
		if isUpdate {
			input.ResourceMeta = existing.ResourceMeta
			input.Revision++
			input.UpdatedAt = now
		} else {
			input.ResourceMeta = controlplane.ResourceMeta{ID: s.id("saml"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		}
		input.State = controlplane.SAMLBrokerPendingApproval
		input.DesiredDigest = controlplane.SAMLBrokerDesiredDigest(input)
		input.ObservedDigest = ""
		input.RequestedBy = actor
		input.LastError = ""
		if isUpdate {
			_, e = tx.ExecContext(ctx, `UPDATE saml_brokers SET revision=$2,alias=$3,keycloak_alias=$4,display_name=$5,entity_id=$6,single_sign_on_service_url=$7,single_logout_service_url=$8,signing_certificate=$9,name_id_policy_format=$10,want_authn_requests_signed=$11,enabled=$12,state=$13,desired_digest=$14,observed_digest='',requested_by=$15,last_error='',updated_at=$16 WHERE id=$1`, input.ID, input.Revision, input.Alias, input.KeycloakAlias, input.DisplayName, input.EntityID, input.SingleSignOnServiceURL, input.SingleLogoutServiceURL, input.SigningCertificate, input.NameIDPolicyFormat, input.WantAuthnRequestsSigned, input.Enabled, string(input.State), input.DesiredDigest, actor, now)
		} else {
			_, e = tx.ExecContext(ctx, `INSERT INTO saml_brokers(id,revision,organization_id,alias,keycloak_alias,display_name,entity_id,single_sign_on_service_url,single_logout_service_url,signing_certificate,name_id_policy_format,want_authn_requests_signed,enabled,state,desired_digest,observed_digest,requested_by,last_error,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'',$15,'',$16,$16)`, input.ID, input.OrganizationID, input.Alias, input.KeycloakAlias, input.DisplayName, input.EntityID, input.SingleSignOnServiceURL, input.SingleLogoutServiceURL, input.SigningCertificate, input.NameIDPolicyFormat, input.WantAuthnRequestsSigned, input.Enabled, string(input.State), input.DesiredDigest, actor, now)
		}
		if e != nil {
			return mapDBError(e)
		}
		job := controlplane.IdentityAdminJob{ResourceMeta: controlplane.ResourceMeta{ID: s.id("idjob"), Revision: 1, CreatedAt: now, UpdatedAt: now}, OrganizationID: input.OrganizationID, BrokerID: input.ID, BrokerRevision: input.Revision, Kind: controlplane.IdentityAdminUpsertSAML, State: controlplane.IdentityAdminAwaitingApproval, IdempotencyKey: idempotencyKey, RequestDigest: requestDigest, DesiredDigest: input.DesiredDigest, RequestedBy: actor}
		_, e = tx.ExecContext(ctx, `INSERT INTO identity_admin_jobs(id,revision,organization_id,broker_id,broker_revision,kind,state,idempotency_key,request_digest,desired_digest,requested_by,approved_by,task_attempt,task_fence_token,task_lease_owner,evidence_digest,last_error,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'',0,0,'','','',$11,$11)`, job.ID, job.OrganizationID, job.BrokerID, job.BrokerRevision, string(job.Kind), string(job.State), job.IdempotencyKey, job.RequestDigest, job.DesiredDigest, job.RequestedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "saml_broker.change_requested", "samlBroker", input.ID, input.Revision, "", map[string]any{"jobId": job.ID, "desiredDigest": input.DesiredDigest, "authority": controlplane.KeycloakSAMLBrokerAuthority}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "identityAdminJob", job.ID, "identity_admin.requested", job); e != nil {
			return e
		}
		outBroker, outJob = input, job
		return nil
	})
	return outBroker, outJob, replay, err
}

func (s *PostgresStore) RequestSAMLBrokerDelete(ctx context.Context, id string, expected int64, idempotencyKey, requestDigest, actor string) (controlplane.SAMLBroker, controlplane.IdentityAdminJob, bool, error) {
	var outBroker controlplane.SAMLBroker
	var outJob controlplane.IdentityAdminJob
	var replay bool
	idempotencyKey, requestDigest, actor = strings.TrimSpace(idempotencyKey), strings.TrimSpace(requestDigest), strings.TrimSpace(actor)
	if idempotencyKey == "" || !strings.HasPrefix(requestDigest, "sha256:") || actor == "" {
		return outBroker, outJob, false, controlplane.ErrValidation
	}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanSAMLBroker(tx.QueryRowContext(ctx, `SELECT `+samlBrokerColumns+` FROM saml_brokers WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected || v.State == controlplane.SAMLBrokerDeleted {
			return controlplane.ErrConflict
		}
		existingJob, e := scanIdentityAdminJob(tx.QueryRowContext(ctx, `SELECT `+identityAdminJobColumns+` FROM identity_admin_jobs WHERE organization_id=$1 AND idempotency_key=$2`, v.OrganizationID, idempotencyKey))
		if e == nil {
			if existingJob.RequestDigest != requestDigest {
				return controlplane.ErrConflict
			}
			outBroker, outJob, replay = v, existingJob, true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		now := utcNow(s.now)
		v.Revision++
		v.State = controlplane.SAMLBrokerPendingApproval
		v.RequestedBy = actor
		v.LastError = ""
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE saml_brokers SET revision=$2,state=$3,requested_by=$4,last_error='',updated_at=$5 WHERE id=$1`, v.ID, v.Revision, string(v.State), actor, now)
		if e != nil {
			return e
		}
		job := controlplane.IdentityAdminJob{ResourceMeta: controlplane.ResourceMeta{ID: s.id("idjob"), Revision: 1, CreatedAt: now, UpdatedAt: now}, OrganizationID: v.OrganizationID, BrokerID: v.ID, BrokerRevision: v.Revision, Kind: controlplane.IdentityAdminDeleteSAML, State: controlplane.IdentityAdminAwaitingApproval, IdempotencyKey: idempotencyKey, RequestDigest: requestDigest, DesiredDigest: v.DesiredDigest, RequestedBy: actor}
		_, e = tx.ExecContext(ctx, `INSERT INTO identity_admin_jobs(id,revision,organization_id,broker_id,broker_revision,kind,state,idempotency_key,request_digest,desired_digest,requested_by,approved_by,task_attempt,task_fence_token,task_lease_owner,evidence_digest,last_error,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'',0,0,'','','',$11,$11)`, job.ID, job.OrganizationID, job.BrokerID, job.BrokerRevision, string(job.Kind), string(job.State), job.IdempotencyKey, job.RequestDigest, job.DesiredDigest, job.RequestedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "saml_broker.delete_requested", "samlBroker", v.ID, v.Revision, "", map[string]any{"jobId": job.ID, "authority": controlplane.KeycloakSAMLBrokerAuthority}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "identityAdminJob", job.ID, "identity_admin.requested", job); e != nil {
			return e
		}
		outBroker, outJob = v, job
		return nil
	})
	return outBroker, outJob, replay, err
}

func (s *PostgresStore) GetSAMLBroker(ctx context.Context, id string) (controlplane.SAMLBroker, error) {
	v, err := scanSAMLBroker(s.db.QueryRowContext(ctx, `SELECT `+samlBrokerColumns+` FROM saml_brokers WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListSAMLBrokers(ctx context.Context, organizationID string) ([]controlplane.SAMLBroker, error) {
	q := `SELECT ` + samlBrokerColumns + ` FROM saml_brokers`
	args := []any{}
	if strings.TrimSpace(organizationID) != "" {
		q += ` WHERE organization_id=$1`
		args = append(args, strings.TrimSpace(organizationID))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.SAMLBroker{}
	for rows.Next() {
		v, e := scanSAMLBroker(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetIdentityAdminJob(ctx context.Context, id string) (controlplane.IdentityAdminJob, error) {
	v, err := scanIdentityAdminJob(s.db.QueryRowContext(ctx, `SELECT `+identityAdminJobColumns+` FROM identity_admin_jobs WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListIdentityAdminJobs(ctx context.Context, organizationID string) ([]controlplane.IdentityAdminJob, error) {
	q := `SELECT ` + identityAdminJobColumns + ` FROM identity_admin_jobs`
	args := []any{}
	if strings.TrimSpace(organizationID) != "" {
		q += ` WHERE organization_id=$1`
		args = append(args, strings.TrimSpace(organizationID))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.IdentityAdminJob{}
	for rows.Next() {
		v, e := scanIdentityAdminJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ApproveIdentityAdminJob(ctx context.Context, id string, expected int64, actor string) (controlplane.IdentityAdminJob, error) {
	var out controlplane.IdentityAdminJob
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		job, e := scanIdentityAdminJob(tx.QueryRowContext(ctx, `SELECT `+identityAdminJobColumns+` FROM identity_admin_jobs WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		actor = strings.TrimSpace(actor)
		if job.Revision != expected {
			return controlplane.ErrConflict
		}
		if job.State != controlplane.IdentityAdminAwaitingApproval || actor == "" || actor == job.RequestedBy {
			return controlplane.ErrPrerequisite
		}
		broker, e := scanSAMLBroker(tx.QueryRowContext(ctx, `SELECT `+samlBrokerColumns+` FROM saml_brokers WHERE id=$1 FOR UPDATE`, job.BrokerID))
		if e != nil {
			return mapDBError(e)
		}
		if broker.Revision != job.BrokerRevision || broker.DesiredDigest != job.DesiredDigest {
			return controlplane.ErrConflict
		}
		now := utcNow(s.now)
		job.State = controlplane.IdentityAdminQueued
		job.ApprovedBy = actor
		t := now
		job.ApprovedAt = &t
		job.Revision++
		job.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE identity_admin_jobs SET revision=$2,state='QUEUED',approved_by=$3,approved_at=$4,updated_at=$4 WHERE id=$1`, job.ID, job.Revision, actor, now)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE saml_brokers SET state='QUEUED',updated_at=$2 WHERE id=$1`, broker.ID, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "identity_admin.approved", "identityAdminJob", job.ID, job.Revision, "", map[string]any{"brokerId": job.BrokerID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "identityAdminJob", job.ID, "identity_admin.approved", job); e != nil {
			return e
		}
		out = job
		return nil
	})
	return out, err
}

func (s *PostgresStore) ClaimIdentityAdminTask(ctx context.Context, owner string, lease time.Duration, now time.Time) (controlplane.IdentityAdminTask, error) {
	var task controlplane.IdentityAdminTask
	owner = strings.TrimSpace(owner)
	if owner == "" || lease <= 0 {
		return task, controlplane.ErrValidation
	}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		job, e := scanIdentityAdminJob(tx.QueryRowContext(ctx, `SELECT `+identityAdminJobColumns+` FROM identity_admin_jobs WHERE state IN ('QUEUED','RUNNING') AND (task_lease_expires_at IS NULL OR task_lease_expires_at <= $1 OR task_lease_owner=$2) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`, now.UTC(), owner))
		if e != nil {
			return mapDBError(e)
		}
		broker, e := scanSAMLBroker(tx.QueryRowContext(ctx, `SELECT `+samlBrokerColumns+` FROM saml_brokers WHERE id=$1 FOR UPDATE`, job.BrokerID))
		if e != nil {
			return mapDBError(e)
		}
		if broker.Revision != job.BrokerRevision || broker.DesiredDigest != job.DesiredDigest {
			return controlplane.ErrConflict
		}
		until := now.UTC().Add(lease)
		job.State = controlplane.IdentityAdminRunning
		job.TaskAttempt++
		job.TaskFenceToken++
		job.TaskLeaseOwner = owner
		job.TaskLeaseExpiresAt = &until
		if job.StartedAt == nil {
			t := now.UTC()
			job.StartedAt = &t
		}
		job.Revision++
		job.UpdatedAt = now.UTC()
		broker.State = controlplane.SAMLBrokerReconciling
		if job.Kind == controlplane.IdentityAdminDeleteSAML {
			broker.State = controlplane.SAMLBrokerDeleting
		}
		broker.UpdatedAt = now.UTC()
		_, e = tx.ExecContext(ctx, `UPDATE identity_admin_jobs SET revision=$2,state='RUNNING',task_attempt=$3,task_fence_token=$4,task_lease_owner=$5,task_lease_expires_at=$6,started_at=COALESCE(started_at,$7),updated_at=$7 WHERE id=$1`, job.ID, job.Revision, job.TaskAttempt, job.TaskFenceToken, owner, until, now.UTC())
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE saml_brokers SET state=$2,updated_at=$3 WHERE id=$1`, broker.ID, string(broker.State), now.UTC())
		if e != nil {
			return e
		}
		task = controlplane.IdentityAdminTask{Job: job, Broker: broker, FenceToken: job.TaskFenceToken, LeaseExpires: until}
		return nil
	})
	return task, err
}

func (s *PostgresStore) CompleteIdentityAdminTask(ctx context.Context, id, owner string, fence int64, observedDigest, actor string) (controlplane.IdentityAdminJob, controlplane.SAMLBroker, error) {
	var outJob controlplane.IdentityAdminJob
	var outBroker controlplane.SAMLBroker
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		job, e := scanIdentityAdminJob(tx.QueryRowContext(ctx, `SELECT `+identityAdminJobColumns+` FROM identity_admin_jobs WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		broker, e := scanSAMLBroker(tx.QueryRowContext(ctx, `SELECT `+samlBrokerColumns+` FROM saml_brokers WHERE id=$1 FOR UPDATE`, job.BrokerID))
		if e != nil {
			return mapDBError(e)
		}
		if job.State != controlplane.IdentityAdminRunning || job.TaskLeaseOwner != owner || job.TaskFenceToken != fence || broker.Revision != job.BrokerRevision || !strings.HasPrefix(strings.TrimSpace(observedDigest), "sha256:") {
			return controlplane.ErrConflict
		}
		now := utcNow(s.now)
		job.State = controlplane.IdentityAdminSucceeded
		job.TaskLeaseOwner = ""
		job.TaskLeaseExpiresAt = nil
		job.EvidenceDigest = controlplane.IdentityAdminEvidenceDigest(job, broker, observedDigest)
		t := now
		job.FinishedAt = &t
		job.Revision++
		job.UpdatedAt = now
		broker.ObservedDigest = strings.TrimSpace(observedDigest)
		broker.LastError = ""
		broker.State = controlplane.SAMLBrokerReady
		if job.Kind == controlplane.IdentityAdminDeleteSAML {
			broker.State = controlplane.SAMLBrokerDeleted
		}
		broker.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE identity_admin_jobs SET revision=$2,state='SUCCEEDED',task_lease_owner='',task_lease_expires_at=NULL,evidence_digest=$3,finished_at=$4,updated_at=$4 WHERE id=$1`, job.ID, job.Revision, job.EvidenceDigest, now)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE saml_brokers SET state=$2,observed_digest=$3,last_error='',updated_at=$4 WHERE id=$1`, broker.ID, string(broker.State), broker.ObservedDigest, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "identity_admin.completed", "identityAdminJob", job.ID, job.Revision, "", map[string]any{"brokerId": broker.ID, "evidenceDigest": job.EvidenceDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "identityAdminJob", job.ID, "identity_admin.completed", job); e != nil {
			return e
		}
		outJob, outBroker = job, broker
		return nil
	})
	return outJob, outBroker, err
}

func (s *PostgresStore) FailIdentityAdminTask(ctx context.Context, id, owner string, fence int64, message, actor string) (controlplane.IdentityAdminJob, controlplane.SAMLBroker, error) {
	var outJob controlplane.IdentityAdminJob
	var outBroker controlplane.SAMLBroker
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		job, e := scanIdentityAdminJob(tx.QueryRowContext(ctx, `SELECT `+identityAdminJobColumns+` FROM identity_admin_jobs WHERE id=$1 FOR UPDATE`, strings.TrimSpace(id)))
		if e != nil {
			return mapDBError(e)
		}
		broker, e := scanSAMLBroker(tx.QueryRowContext(ctx, `SELECT `+samlBrokerColumns+` FROM saml_brokers WHERE id=$1 FOR UPDATE`, job.BrokerID))
		if e != nil {
			return mapDBError(e)
		}
		if job.State != controlplane.IdentityAdminRunning || job.TaskLeaseOwner != owner || job.TaskFenceToken != fence {
			return controlplane.ErrConflict
		}
		message = strings.TrimSpace(message)
		if len(message) > 1000 {
			message = message[:1000]
		}
		now := utcNow(s.now)
		job.State = controlplane.IdentityAdminFailed
		job.LastError = message
		job.TaskLeaseOwner = ""
		job.TaskLeaseExpiresAt = nil
		t := now
		job.FinishedAt = &t
		job.Revision++
		job.UpdatedAt = now
		broker.State = controlplane.SAMLBrokerError
		broker.LastError = message
		broker.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE identity_admin_jobs SET revision=$2,state='FAILED',last_error=$3,task_lease_owner='',task_lease_expires_at=NULL,finished_at=$4,updated_at=$4 WHERE id=$1`, job.ID, job.Revision, message, now)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE saml_brokers SET state='ERROR',last_error=$2,updated_at=$3 WHERE id=$1`, broker.ID, message, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "identity_admin.failed", "identityAdminJob", job.ID, job.Revision, "", map[string]any{"brokerId": broker.ID, "reason": message}); e != nil {
			return e
		}
		outJob, outBroker = job, broker
		return nil
	})
	return outJob, outBroker, err
}

func identityAdminStoreContract(_ controlplane.Store) {}

func (s *PostgresStore) identityAdminDebugSummary(ctx context.Context) (string, error) {
	var queued int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM identity_admin_jobs WHERE state IN ('QUEUED','RUNNING')`).Scan(&queued); err != nil {
		return "", err
	}
	return fmt.Sprintf("identity-admin-pending=%d", queued), nil
}
