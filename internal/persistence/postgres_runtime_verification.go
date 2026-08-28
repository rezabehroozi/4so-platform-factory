package persistence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
)

const runtimeVerificationColumns = `id,project_id,cluster_id,baseline_deployment_id,revision,state::text,desired_digest,observed_digest,probe_image,request_digest,idempotency_key,requested_by,started_at,finished_at,checks,report_digest,last_error,task_attempt,task_fence_token,task_lease_expires_at,created_at,updated_at`

func scanRuntimeVerification(row interface{ Scan(...any) error }) (controlplane.RuntimeVerification, error) {
	var v controlplane.RuntimeVerification
	var state string
	var checksRaw []byte
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.BaselineDeploymentID, &v.Revision, &state, &v.DesiredDigest, &v.ObservedDigest, &v.ProbeImage, &v.RequestDigest, &v.IdempotencyKey, &v.RequestedBy, &v.StartedAt, &v.FinishedAt, &checksRaw, &v.ReportDigest, &v.LastError, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskLeaseExpiresAt, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.RuntimeVerificationState(state)
	if len(checksRaw) > 0 {
		if decodeErr := decodeJSONColumn(checksRaw, &v.Checks, "postgres_runtime_verification.Checks"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}

func (s *PostgresStore) CreateRuntimeVerification(ctx context.Context, v controlplane.RuntimeVerification, actor string) (controlplane.RuntimeVerification, bool, error) {
	var out controlplane.RuntimeVerification
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanRuntimeVerification(tx.QueryRowContext(ctx, `SELECT `+runtimeVerificationColumns+` FROM runtime_verifications WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != v.RequestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			out, replay = existing, true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		baseline, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1 FOR SHARE`, v.BaselineDeploymentID))
		if e != nil {
			return mapDBError(e)
		}
		if baseline.ProjectID != v.ProjectID || baseline.ClusterID != v.ClusterID {
			return controlplane.ErrNotFound
		}
		if !controlplane.BaselineCompletionEvidenceReady(baseline, utcNow(s.now)) {
			return controlplane.ErrInvalidTransition
		}
		desired := baseline.DesiredDigest
		if !strings.Contains(v.ProbeImage, "@sha256:") || !strings.HasPrefix(v.RequestDigest, "sha256:") || strings.TrimSpace(v.IdempotencyKey) == "" {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("rtv"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.RuntimeVerificationQueued
		v.DesiredDigest = desired
		v.RequestedBy = actor
		_, e = tx.ExecContext(ctx, `INSERT INTO runtime_verifications(id,project_id,cluster_id,baseline_deployment_id,revision,state,desired_digest,probe_image,request_digest,idempotency_key,requested_by,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$11)`, v.ID, v.ProjectID, v.ClusterID, v.BaselineDeploymentID, string(v.State), v.DesiredDigest, v.ProbeImage, v.RequestDigest, v.IdempotencyKey, actor, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "runtime_verification.queued", "runtimeVerification", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "baselineDeploymentId": v.BaselineDeploymentID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "runtimeVerification", v.ID, "runtime_verification.queued", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}
func (s *PostgresStore) GetRuntimeVerification(ctx context.Context, id string) (controlplane.RuntimeVerification, error) {
	v, e := scanRuntimeVerification(s.db.QueryRowContext(ctx, `SELECT `+runtimeVerificationColumns+` FROM runtime_verifications WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListRuntimeVerifications(ctx context.Context, projectID, clusterID, baselineID string) ([]controlplane.RuntimeVerification, error) {
	q := `SELECT ` + runtimeVerificationColumns + ` FROM runtime_verifications WHERE 1=1`
	args := []any{}
	for _, f := range []struct{ v, col string }{{projectID, "project_id"}, {clusterID, "cluster_id"}, {baselineID, "baseline_deployment_id"}} {
		if f.v != "" {
			args = append(args, f.v)
			q += fmt.Sprintf(" AND %s=$%d", f.col, len(args))
		}
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.RuntimeVerification{}
	for rows.Next() {
		v, e := scanRuntimeVerification(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) RetryRuntimeVerification(ctx context.Context, id string, expected int64, actor string) (controlplane.RuntimeVerification, error) {
	var out controlplane.RuntimeVerification
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanRuntimeVerification(tx.QueryRowContext(ctx, `SELECT `+runtimeVerificationColumns+` FROM runtime_verifications WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.RuntimeVerificationFailed {
			return controlplane.ErrInvalidTransition
		}
		baseline, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1 FOR SHARE`, v.BaselineDeploymentID))
		if e != nil {
			return mapDBError(e)
		}
		if !controlplane.BaselineCompletionEvidenceReady(baseline, utcNow(s.now)) || baseline.DesiredDigest != v.DesiredDigest {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.State = controlplane.RuntimeVerificationQueued
		v.ObservedDigest = ""
		v.Checks = nil
		v.ReportDigest = ""
		v.LastError = ""
		v.StartedAt = nil
		v.FinishedAt = nil
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE runtime_verifications SET revision=$2,state='QUEUED',observed_digest='',checks='[]'::jsonb,report_digest='',last_error='',started_at=NULL,finished_at=NULL,updated_at=$3 WHERE id=$1`, v.ID, v.Revision, now); e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "runtime_verification.retried", "runtimeVerification", v.ID, v.Revision, "", map[string]any{"attempt": v.TaskAttempt + 1}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "runtimeVerification", v.ID, "runtime_verification.retried", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) NextRuntimeVerificationTask(ctx context.Context, clusterID, tokenDigest string) (controlplane.RuntimeVerification, error) {
	var out controlplane.RuntimeVerification
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		now := utcNow(s.now)
		v, e := scanRuntimeVerification(tx.QueryRowContext(ctx, `SELECT `+runtimeVerificationColumns+` FROM runtime_verifications WHERE cluster_id=$1 AND (state='QUEUED' OR (state='RUNNING' AND (task_lease_expires_at IS NULL OR task_lease_expires_at<=$2))) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, clusterID, now))
		if e != nil {
			return mapDBError(e)
		}
		if v.State == controlplane.RuntimeVerificationQueued {
			v.State = controlplane.RuntimeVerificationRunning
			v.StartedAt = &now
		}
		lease := now.Add(controlplane.AgentTaskLeaseDuration)
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseExpiresAt = &lease
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE runtime_verifications SET revision=$2,state=$3,task_attempt=$4,task_fence_token=$5,task_lease_expires_at=$6,started_at=$7,updated_at=$8 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.TaskAttempt, v.TaskFenceToken, lease, v.StartedAt, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "runtime_verification.claimed", "runtimeVerification", v.ID, v.Revision, "", map[string]any{"attempt": v.TaskAttempt, "taskFenceToken": v.TaskFenceToken, "leaseExpiresAt": lease}); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) ReportRuntimeVerificationTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result controlplane.RuntimeVerificationResult) (controlplane.RuntimeVerification, error) {
	var out controlplane.RuntimeVerification
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		v, e := scanRuntimeVerification(tx.QueryRowContext(ctx, `SELECT `+runtimeVerificationColumns+` FROM runtime_verifications WHERE id=$1 FOR UPDATE`, result.VerificationID))
		if e != nil {
			return mapDBError(e)
		}
		if v.ClusterID != clusterID {
			return controlplane.ErrNotFound
		}
		now := utcNow(s.now)
		if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.RuntimeVerificationRunning {
			return controlplane.ErrInvalidTransition
		}
		allPass := len(result.Checks) > 0
		for _, c := range result.Checks {
			if c.Status != "PASS" {
				allPass = false
			}
		}
		v.Checks = append([]controlplane.RuntimeCheck(nil), result.Checks...)
		v.ObservedDigest = result.ObservedDigest
		if result.Success && allPass && result.ObservedDigest == v.DesiredDigest {
			v.State = controlplane.RuntimeVerificationSucceeded
			v.LastError = ""
		} else {
			v.State = controlplane.RuntimeVerificationFailed
			v.LastError = strings.TrimSpace(result.Error)
			if v.LastError == "" {
				v.LastError = "runtime verification checks or digest equality failed"
			}
		}
		v.FinishedAt = &now
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		v.ReportDigest = runtimeVerificationDigest(v)
		raw, _ := json.Marshal(v.Checks)
		if _, e = tx.ExecContext(ctx, `UPDATE runtime_verifications SET revision=$2,state=$3,observed_digest=$4,checks=$5::jsonb,report_digest=$6,last_error=$7,finished_at=$8,task_lease_expires_at=NULL,updated_at=$8 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.ObservedDigest, raw, v.ReportDigest, v.LastError, now); e != nil {
			return e
		}
		action := "runtime_verification." + strings.ToLower(string(v.State))
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", action, "runtimeVerification", v.ID, v.Revision, "", map[string]any{"reportDigest": v.ReportDigest, "taskFenceToken": result.TaskFenceToken}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "runtimeVerification", v.ID, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func runtimeVerificationDigest(v controlplane.RuntimeVerification) string {
	raw, _ := json.Marshal(struct {
		ID       string                      `json:"id"`
		Cluster  string                      `json:"clusterId"`
		Baseline string                      `json:"baselineDeploymentId"`
		Desired  string                      `json:"desiredDigest"`
		Observed string                      `json:"observedDigest"`
		Checks   []controlplane.RuntimeCheck `json:"checks"`
	}{v.ID, v.ClusterID, v.BaselineDeploymentID, v.DesiredDigest, v.ObservedDigest, v.Checks})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
