package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/compliance"
	"platform.4so.io/factory/internal/controlplane"
)

const complianceProfileColumns = `id,revision,project_id,name,baseline_authority,minimum_severity,state,desired_digest,created_by,created_at,updated_at`
const complianceScanColumns = `id,revision,project_id,cluster_id,profile_id,baseline_authority,inventory_digest,state,idempotency_key,request_digest,findings,result_digest,evidence_digest,requested_by,task_attempt,task_fence_token,task_lease_owner,task_lease_expires_at,started_at,finished_at,last_error,created_at,updated_at`
const complianceFindingColumns = `id,revision,run_id,project_id,cluster_id,fingerprint,rule_id,severity,kind,namespace,name,summary,evidence_digest,created_at,updated_at`
const complianceWaiverColumns = `id,revision,project_id,fingerprint,reason,state,requested_by,approved_by,approved_at,revoked_by,revoked_at,expires_at,created_at,updated_at`

func scanComplianceProfile(row interface{ Scan(...any) error }) (controlplane.ComplianceProfile, error) {
	var v controlplane.ComplianceProfile
	var sev, state string
	err := row.Scan(&v.ID, &v.Revision, &v.ProjectID, &v.Name, &v.BaselineAuthority, &sev, &state, &v.DesiredDigest, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	v.MinimumSeverity = compliance.Severity(sev)
	v.State = controlplane.ComplianceProfileState(state)
	return v, err
}
func scanComplianceScan(row interface{ Scan(...any) error }) (controlplane.ComplianceScanRun, error) {
	var v controlplane.ComplianceScanRun
	var state string
	err := row.Scan(&v.ID, &v.Revision, &v.ProjectID, &v.ClusterID, &v.ProfileID, &v.BaselineAuthority, &v.InventoryDigest, &state, &v.IdempotencyKey, &v.RequestDigest, &v.Findings, &v.ResultDigest, &v.EvidenceDigest, &v.RequestedBy, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskLeaseOwner, &v.TaskLeaseExpiresAt, &v.StartedAt, &v.FinishedAt, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.ComplianceScanState(state)
	return v, err
}
func scanComplianceFinding(row interface{ Scan(...any) error }) (controlplane.ComplianceFindingRecord, error) {
	var v controlplane.ComplianceFindingRecord
	var sev string
	err := row.Scan(&v.ID, &v.Revision, &v.RunID, &v.ProjectID, &v.ClusterID, &v.Fingerprint, &v.RuleID, &sev, &v.Kind, &v.Namespace, &v.Name, &v.Summary, &v.EvidenceDigest, &v.CreatedAt, &v.UpdatedAt)
	v.Severity = compliance.Severity(sev)
	return v, err
}
func scanComplianceWaiver(row interface{ Scan(...any) error }) (controlplane.ComplianceWaiver, error) {
	var v controlplane.ComplianceWaiver
	var state string
	err := row.Scan(&v.ID, &v.Revision, &v.ProjectID, &v.Fingerprint, &v.Reason, &state, &v.RequestedBy, &v.ApprovedBy, &v.ApprovedAt, &v.RevokedBy, &v.RevokedAt, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.ComplianceWaiverState(state)
	return v, err
}

func (s *PostgresStore) CreateComplianceProfile(ctx context.Context, v controlplane.ComplianceProfile, actor string) (controlplane.ComplianceProfile, error) {
	mem := controlplane.NewMemoryStoreWith(s.now, s.id) // normalization helper without duplicating domain rules
	// seed only the project so the domain validator can run; DB still owns truth.
	project, err := s.GetProject(ctx, v.ProjectID)
	if err != nil {
		return v, err
	}
	snap := controlplane.Snapshot{Projects: []controlplane.Project{project}}
	_ = mem.Restore(snap)
	normalized, err := mem.CreateComplianceProfile(ctx, v, actor)
	if err != nil {
		return v, err
	}
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `INSERT INTO compliance_profiles(id,revision,project_id,name,baseline_authority,minimum_severity,state,desired_digest,created_by,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, normalized.ID, normalized.ProjectID, normalized.Name, normalized.BaselineAuthority, string(normalized.MinimumSeverity), string(normalized.State), normalized.DesiredDigest, normalized.CreatedBy, normalized.CreatedAt)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "compliance_profile.created", "complianceProfile", normalized.ID, 1, "", map[string]any{"projectId": normalized.ProjectID, "digest": normalized.DesiredDigest}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "complianceProfile", normalized.ID, "compliance_profile.created", normalized)
	})
	return normalized, err
}
func (s *PostgresStore) GetComplianceProfile(ctx context.Context, id string) (controlplane.ComplianceProfile, error) {
	v, err := scanComplianceProfile(s.db.QueryRowContext(ctx, `SELECT `+complianceProfileColumns+` FROM compliance_profiles WHERE id=$1`, id))
	return v, mapDBError(err)
}
func (s *PostgresStore) ListComplianceProfiles(ctx context.Context, projectID string) ([]controlplane.ComplianceProfile, error) {
	q := `SELECT ` + complianceProfileColumns + ` FROM compliance_profiles`
	args := []any{}
	if strings.TrimSpace(projectID) != "" {
		q += ` WHERE project_id=$1`
		args = append(args, projectID)
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.ComplianceProfile{}
	for rows.Next() {
		v, e := scanComplianceProfile(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateComplianceScanRun(ctx context.Context, v controlplane.ComplianceScanRun, actor string) (controlplane.ComplianceScanRun, bool, error) {
	var out controlplane.ComplianceScanRun
	var replay bool
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		profile, e := scanComplianceProfile(tx.QueryRowContext(ctx, `SELECT `+complianceProfileColumns+` FROM compliance_profiles WHERE id=$1 FOR SHARE`, v.ProfileID))
		if e != nil {
			return mapDBError(e)
		}
		cluster, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR SHARE`, v.ClusterID))
		if e != nil {
			return mapDBError(e)
		}
		if profile.ProjectID != v.ProjectID || cluster.ProjectID != v.ProjectID || profile.State != controlplane.ComplianceProfileActive || !strings.HasPrefix(cluster.InventoryDigest, "sha256:") {
			return controlplane.ErrPrerequisite
		}
		v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
		v.RequestDigest = strings.TrimSpace(v.RequestDigest)
		if v.IdempotencyKey == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") {
			return controlplane.ErrValidation
		}
		existing, e := scanComplianceScan(tx.QueryRowContext(ctx, `SELECT `+complianceScanColumns+` FROM compliance_scan_runs WHERE project_id=$1 AND idempotency_key=$2`, v.ProjectID, v.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != v.RequestDigest {
				return controlplane.ErrConflict
			}
			out = existing
			replay = true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("cscan"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.BaselineAuthority = profile.BaselineAuthority
		v.InventoryDigest = cluster.InventoryDigest
		v.State = controlplane.ComplianceScanQueued
		v.RequestedBy = strings.TrimSpace(actor)
		_, e = tx.ExecContext(ctx, `INSERT INTO compliance_scan_runs(id,revision,project_id,cluster_id,profile_id,baseline_authority,inventory_digest,state,idempotency_key,request_digest,findings,result_digest,evidence_digest,requested_by,task_attempt,task_fence_token,task_lease_owner,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,0,'','',$10,0,0,'',$11,$11)`, v.ID, v.ProjectID, v.ClusterID, v.ProfileID, v.BaselineAuthority, v.InventoryDigest, string(v.State), v.IdempotencyKey, v.RequestDigest, v.RequestedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "compliance_scan.requested", "complianceScan", v.ID, 1, "", map[string]any{"clusterId": v.ClusterID, "inventoryDigest": v.InventoryDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "complianceScan", v.ID, "compliance_scan.requested", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}
func (s *PostgresStore) GetComplianceScanRun(ctx context.Context, id string) (controlplane.ComplianceScanRun, error) {
	v, err := scanComplianceScan(s.db.QueryRowContext(ctx, `SELECT `+complianceScanColumns+` FROM compliance_scan_runs WHERE id=$1`, id))
	return v, mapDBError(err)
}
func (s *PostgresStore) ListComplianceScanRuns(ctx context.Context, projectID, clusterID string) ([]controlplane.ComplianceScanRun, error) {
	q := `SELECT ` + complianceScanColumns + ` FROM compliance_scan_runs WHERE 1=1`
	args := []any{}
	if projectID != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	if clusterID != "" {
		args = append(args, clusterID)
		q += fmt.Sprintf(" AND cluster_id=$%d", len(args))
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.ComplianceScanRun{}
	for rows.Next() {
		v, e := scanComplianceScan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ClaimComplianceScanTask(ctx context.Context, clusterID, owner string, lease time.Duration, now time.Time) (controlplane.ComplianceScanTask, error) {
	var task controlplane.ComplianceScanTask
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+complianceScanColumns+` FROM compliance_scan_runs WHERE cluster_id=$1 AND state IN ('QUEUED','RUNNING') AND (task_lease_expires_at IS NULL OR task_lease_expires_at <= $2 OR task_lease_owner=$3) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`, clusterID, now.UTC(), owner)
		v, e := scanComplianceScan(row)
		if e != nil {
			return mapDBError(e)
		}
		until := now.UTC().Add(lease)
		v.State = controlplane.ComplianceScanRunning
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseOwner = owner
		v.TaskLeaseExpiresAt = &until
		if v.StartedAt == nil {
			t := now.UTC()
			v.StartedAt = &t
		}
		v.Revision++
		v.UpdatedAt = now.UTC()
		_, e = tx.ExecContext(ctx, `UPDATE compliance_scan_runs SET revision=$2,state='RUNNING',task_attempt=$3,task_fence_token=$4,task_lease_owner=$5,task_lease_expires_at=$6,started_at=COALESCE(started_at,$7),updated_at=$7 WHERE id=$1`, v.ID, v.Revision, v.TaskAttempt, v.TaskFenceToken, owner, until, now.UTC())
		if e != nil {
			return e
		}
		task = controlplane.ComplianceScanTask{RunID: v.ID, RunRevision: v.Revision, ProjectID: v.ProjectID, ClusterID: v.ClusterID, BaselineAuthority: v.BaselineAuthority, InventoryDigest: v.InventoryDigest, Attempt: v.TaskAttempt, FenceToken: v.TaskFenceToken, LeaseExpiresAt: until}
		return nil
	})
	return task, err
}
func (s *PostgresStore) CompleteComplianceScan(ctx context.Context, id, owner string, fence int64, findings []compliance.Finding, actor string) (controlplane.ComplianceScanRun, error) {
	var out controlplane.ComplianceScanRun
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanComplianceScan(tx.QueryRowContext(ctx, `SELECT `+complianceScanColumns+` FROM compliance_scan_runs WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.State != controlplane.ComplianceScanRunning || v.TaskLeaseOwner != owner || v.TaskFenceToken != fence {
			return controlplane.ErrConflict
		}
		profile, e := scanComplianceProfile(tx.QueryRowContext(ctx, `SELECT `+complianceProfileColumns+` FROM compliance_profiles WHERE id=$1 FOR SHARE`, v.ProfileID))
		if e != nil {
			return mapDBError(e)
		}
		if profile.ProjectID != v.ProjectID || profile.BaselineAuthority != v.BaselineAuthority {
			return controlplane.ErrPrerequisite
		}
		now := utcNow(s.now)
		byFingerprint := make(map[string]controlplane.ComplianceFindingRecord)
		for _, f := range findings {
			if !compliance.ValidateFindingIdentity(f) {
				return controlplane.ErrValidation
			}
			if controlplane.ComplianceSeverityRank(f.Severity) < controlplane.ComplianceSeverityRank(profile.MinimumSeverity) {
				continue
			}
			if _, exists := byFingerprint[f.Fingerprint]; exists {
				continue
			}
			byFingerprint[f.Fingerprint] = controlplane.ComplianceFindingRecord{ResourceMeta: controlplane.ResourceMeta{ID: s.id("cfind"), Revision: 1, CreatedAt: now, UpdatedAt: now}, RunID: v.ID, ProjectID: v.ProjectID, ClusterID: v.ClusterID, Fingerprint: f.Fingerprint, RuleID: f.RuleID, Severity: f.Severity, Kind: f.Kind, Namespace: f.Namespace, Name: f.Name, Summary: f.Summary, EvidenceDigest: controlplane.ComplianceFindingEvidenceDigest(f)}
		}
		records := make([]controlplane.ComplianceFindingRecord, 0, len(byFingerprint))
		for _, r := range byFingerprint {
			records = append(records, r)
		}
		sort.Slice(records, func(i, j int) bool { return records[i].Fingerprint < records[j].Fingerprint })
		for _, r := range records {
			_, e = tx.ExecContext(ctx, `INSERT INTO compliance_findings(id,revision,run_id,project_id,cluster_id,fingerprint,rule_id,severity,kind,namespace,name,summary,evidence_digest,created_at,updated_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13) ON CONFLICT(run_id,fingerprint) DO NOTHING`, r.ID, r.RunID, r.ProjectID, r.ClusterID, r.Fingerprint, r.RuleID, string(r.Severity), r.Kind, r.Namespace, r.Name, r.Summary, r.EvidenceDigest, now)
			if e != nil {
				return e
			}
		}
		digest := controlplane.ComplianceScanResultDigest(v, records)
		v.State = controlplane.ComplianceScanSucceeded
		v.Findings = len(records)
		v.ResultDigest = digest
		v.EvidenceDigest = digest
		v.TaskLeaseOwner = ""
		v.TaskLeaseExpiresAt = nil
		t := now
		v.FinishedAt = &t
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE compliance_scan_runs SET revision=$2,state='SUCCEEDED',findings=$3,result_digest=$4,evidence_digest=$4,task_lease_owner='',task_lease_expires_at=NULL,finished_at=$5,updated_at=$5 WHERE id=$1`, v.ID, v.Revision, v.Findings, digest, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "compliance_scan.completed", "complianceScan", v.ID, v.Revision, "", map[string]any{"findings": v.Findings, "resultDigest": digest}); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) FailComplianceScan(ctx context.Context, id, owner string, fence int64, message, actor string) (controlplane.ComplianceScanRun, error) {
	var out controlplane.ComplianceScanRun
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanComplianceScan(tx.QueryRowContext(ctx, `SELECT `+complianceScanColumns+` FROM compliance_scan_runs WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.State != controlplane.ComplianceScanRunning || v.TaskLeaseOwner != owner || v.TaskFenceToken != fence {
			return controlplane.ErrConflict
		}
		message = strings.TrimSpace(message)
		if len(message) > 1000 {
			message = message[:1000]
		}
		now := utcNow(s.now)
		v.State = controlplane.ComplianceScanFailed
		v.LastError = message
		v.TaskLeaseOwner = ""
		v.TaskLeaseExpiresAt = nil
		t := now
		v.FinishedAt = &t
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE compliance_scan_runs SET revision=$2,state='FAILED',last_error=$3,task_lease_owner='',task_lease_expires_at=NULL,finished_at=$4,updated_at=$4 WHERE id=$1`, id, v.Revision, message, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "compliance_scan.failed", "complianceScan", v.ID, v.Revision, "", map[string]any{"reason": message}); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) ListComplianceFindings(ctx context.Context, projectID, runID string) ([]controlplane.ComplianceFindingRecord, error) {
	q := `SELECT ` + complianceFindingColumns + ` FROM compliance_findings WHERE 1=1`
	args := []any{}
	if projectID != "" {
		args = append(args, projectID)
		q += fmt.Sprintf(" AND project_id=$%d", len(args))
	}
	if runID != "" {
		args = append(args, runID)
		q += fmt.Sprintf(" AND run_id=$%d", len(args))
	}
	q += ` ORDER BY CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 1 ELSE 0 END DESC,rule_id,fingerprint`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.ComplianceFindingRecord{}
	for rows.Next() {
		v, e := scanComplianceFinding(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) CreateComplianceWaiver(ctx context.Context, v controlplane.ComplianceWaiver, actor string) (controlplane.ComplianceWaiver, error) {
	if _, err := s.GetProject(ctx, v.ProjectID); err != nil {
		return v, err
	}
	v.Fingerprint = strings.TrimSpace(v.Fingerprint)
	v.Reason = strings.TrimSpace(v.Reason)
	if len(v.Fingerprint) != 64 || v.Reason == "" || len(v.Reason) > 1000 {
		return v, controlplane.ErrValidation
	}
	now := utcNow(s.now)
	v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("cwv"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = controlplane.ComplianceWaiverPending
	v.RequestedBy = strings.TrimSpace(actor)
	_, err := s.db.ExecContext(ctx, `INSERT INTO compliance_waivers(id,revision,project_id,fingerprint,reason,state,requested_by,approved_by,revoked_by,expires_at,created_at,updated_at) VALUES($1,1,$2,$3,$4,'PENDING_APPROVAL',$5,'','',$6,$7,$7)`, v.ID, v.ProjectID, v.Fingerprint, v.Reason, v.RequestedBy, v.ExpiresAt, now)
	return v, mapDBError(err)
}
func (s *PostgresStore) GetComplianceWaiver(ctx context.Context, id string) (controlplane.ComplianceWaiver, error) {
	v, err := scanComplianceWaiver(s.db.QueryRowContext(ctx, `SELECT `+complianceWaiverColumns+` FROM compliance_waivers WHERE id=$1`, strings.TrimSpace(id)))
	return v, mapDBError(err)
}

func (s *PostgresStore) ApproveComplianceWaiver(ctx context.Context, id string, expected int64, actor string) (controlplane.ComplianceWaiver, error) {
	var out controlplane.ComplianceWaiver
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanComplianceWaiver(tx.QueryRowContext(ctx, `SELECT `+complianceWaiverColumns+` FROM compliance_waivers WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		actor = strings.TrimSpace(actor)
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ComplianceWaiverPending || actor == "" || actor == v.RequestedBy {
			return controlplane.ErrPrerequisite
		}
		now := utcNow(s.now)
		v.State = controlplane.ComplianceWaiverActive
		v.ApprovedBy = actor
		t := now
		v.ApprovedAt = &t
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE compliance_waivers SET revision=$2,state='ACTIVE',approved_by=$3,approved_at=$4,updated_at=$4 WHERE id=$1`, id, v.Revision, actor, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "compliance_waiver.approved", "complianceWaiver", v.ID, v.Revision, "", nil); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) RevokeComplianceWaiver(ctx context.Context, id string, expected int64, actor string) (controlplane.ComplianceWaiver, error) {
	var out controlplane.ComplianceWaiver
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanComplianceWaiver(tx.QueryRowContext(ctx, `SELECT `+complianceWaiverColumns+` FROM compliance_waivers WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State == controlplane.ComplianceWaiverRevoked {
			out = v
			return nil
		}
		now := utcNow(s.now)
		v.State = controlplane.ComplianceWaiverRevoked
		v.RevokedBy = strings.TrimSpace(actor)
		t := now
		v.RevokedAt = &t
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE compliance_waivers SET revision=$2,state='REVOKED',revoked_by=$3,revoked_at=$4,updated_at=$4 WHERE id=$1`, id, v.Revision, v.RevokedBy, now)
		if e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) ListComplianceWaivers(ctx context.Context, projectID string) ([]controlplane.ComplianceWaiver, error) {
	q := `SELECT ` + complianceWaiverColumns + ` FROM compliance_waivers`
	args := []any{}
	if projectID != "" {
		q += ` WHERE project_id=$1`
		args = append(args, projectID)
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.ComplianceWaiver{}
	for rows.Next() {
		v, e := scanComplianceWaiver(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
