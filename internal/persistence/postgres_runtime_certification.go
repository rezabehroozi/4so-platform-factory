package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const runtimeCertificationColumns = `id,project_id,cluster_id,catalog_release_id,catalog_revision_id,revision,profile,state,phase,namespace,inventory_digest,environment_fingerprint,manifest_digest,source_lock_digest,rendered_digest,resource_count,checks,cleanup_generations,install_checkpoint_digest,evidence_digest,requested_by,idempotency_key,request_digest,task_attempt,task_fence_token,task_lease_expires_at,started_at,install_checkpoint_at,finished_at,expires_at,revoked_by,revoked_at,last_error,created_at,updated_at`

func scanRuntimeCertification(row interface{ Scan(...any) error }) (controlplane.RuntimeCertificationRun, error) {
	var v controlplane.RuntimeCertificationRun
	var profile, state, phase string
	var checksRaw, cleanupRaw []byte
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.CatalogReleaseID, &v.CatalogRevisionID, &v.Revision, &profile, &state, &phase, &v.Namespace, &v.InventoryDigest, &v.EnvironmentFingerprint, &v.ManifestDigest, &v.SourceLockDigest, &v.RenderedDigest, &v.ResourceCount, &checksRaw, &cleanupRaw, &v.InstallCheckpointDigest, &v.EvidenceDigest, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskLeaseExpiresAt, &v.StartedAt, &v.InstallCheckpointAt, &v.FinishedAt, &v.ExpiresAt, &v.RevokedBy, &v.RevokedAt, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	v.Profile = controlplane.RuntimeCertificationProfile(profile)
	v.State = controlplane.RuntimeCertificationState(state)
	v.Phase = controlplane.RuntimeCertificationPhase(phase)
	if len(checksRaw) > 0 {
		if decodeErr := decodeJSONColumn(checksRaw, &v.Checks, "postgres_runtime_certification.Checks"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(cleanupRaw) > 0 {
		if decodeErr := decodeJSONColumn(cleanupRaw, &v.CleanupGenerations, "postgres_runtime_certification.CleanupGenerations"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}

func (s *PostgresStore) CreateRuntimeCertification(ctx context.Context, v controlplane.RuntimeCertificationRun, actor string) (controlplane.RuntimeCertificationRun, bool, error) {
	cluster, err := s.GetManagedCluster(ctx, v.ClusterID)
	if err != nil || cluster.ProjectID != v.ProjectID {
		return controlplane.RuntimeCertificationRun{}, false, controlplane.ErrNotFound
	}
	inv, err := s.GetLatestClusterInventory(ctx, v.ClusterID)
	if err != nil || cluster.InventoryDigest == "" || cluster.InventoryDigest != inv.Digest {
		return controlplane.RuntimeCertificationRun{}, false, controlplane.ErrInvalidTransition
	}
	release, err := s.GetCatalogRelease(ctx, v.CatalogReleaseID)
	if err != nil {
		return controlplane.RuntimeCertificationRun{}, false, err
	}
	if release.State != controlplane.CatalogPublished || (release.Channel != controlplane.CatalogChannelRender && release.Channel != controlplane.CatalogChannelRuntime && release.Channel != controlplane.CatalogChannelProduction) {
		return controlplane.RuntimeCertificationRun{}, false, controlplane.ErrInvalidTransition
	}
	key, err := s.GetCatalogTrustKey(ctx, release.SigningKeyID)
	if err != nil || controlplane.VerifyCatalogReleaseSignature(release, key) != nil {
		return controlplane.RuntimeCertificationRun{}, false, controlplane.ErrInvalidTransition
	}
	if release.CurrentRevisionID != v.CatalogRevisionID || release.ManifestDigest != v.ManifestDigest || v.InventoryDigest != inv.Digest || v.EnvironmentFingerprint != controlplane.RuntimeEnvironmentFingerprint(inv) || v.ResourceCount <= 0 {
		return controlplane.RuntimeCertificationRun{}, false, controlplane.ErrValidation
	}
	if v.Profile != controlplane.RuntimeCertificationFoundationV1 && v.Profile != controlplane.RuntimeCertificationObservabilityV1 && v.Profile != controlplane.RuntimeCertificationTargetV1 {
		return controlplane.RuntimeCertificationRun{}, false, controlplane.ErrValidation
	}
	var out controlplane.RuntimeCertificationRun
	replay := false
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		// Checks are product-generated evidence, never caller-owned mutable input.
		// Reset them for every serializable attempt so a rolled-back attempt cannot
		// leak capability findings into a retry.
		v.Checks = nil
		existing, e := scanRuntimeCertification(tx.QueryRowContext(ctx, `SELECT `+runtimeCertificationColumns+` FROM runtime_certification_runs WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
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
		var currentInventory string
		if e = tx.QueryRowContext(ctx, `SELECT inventory_digest FROM managed_clusters WHERE id=$1 AND project_id=$2 FOR UPDATE`, v.ClusterID, v.ProjectID).Scan(&currentInventory); e != nil {
			return mapDBError(e)
		}
		if currentInventory != v.InventoryDigest {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("rtc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.RuntimeCertificationQueued
		v.Phase = controlplane.RuntimeCertificationPhaseInstall
		v.RequestedBy = actor
		missing := map[string]bool{}
		for _, cap := range controlplane.RuntimeCertificationRequiredCapabilities(v.Profile) {
			missing[cap] = true
		}
		for _, cap := range inv.Capabilities {
			delete(missing, strings.TrimSpace(cap))
		}
		if len(missing) > 0 {
			v.State = controlplane.RuntimeCertificationBlocked
			v.FinishedAt = &now
			keys := make([]string, 0, len(missing))
			for cap := range missing {
				keys = append(keys, cap)
			}
			sort.Strings(keys)
			for _, cap := range keys {
				v.Checks = append(v.Checks, controlplane.RuntimeCheck{Key: "capability/" + cap, Status: "BLOCKED", Detail: "capability is absent from the authoritative cluster inventory"})
			}
			v.LastError = "required runtime certification capabilities are missing"
		}
		checksRaw, _ := json.Marshal(v.Checks)
		_, e = tx.ExecContext(ctx, `INSERT INTO runtime_certification_runs(id,project_id,cluster_id,catalog_release_id,catalog_revision_id,revision,profile,state,phase,namespace,inventory_digest,environment_fingerprint,manifest_digest,source_lock_digest,rendered_digest,resource_count,checks,cleanup_generations,requested_by,idempotency_key,request_digest,started_at,finished_at,last_error,created_at,updated_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17::jsonb,$18,$19,$20,$21,$22,$23,$24,$24)`, v.ID, v.ProjectID, v.ClusterID, v.CatalogReleaseID, v.CatalogRevisionID, string(v.Profile), string(v.State), string(v.Phase), v.Namespace, v.InventoryDigest, v.EnvironmentFingerprint, v.ManifestDigest, v.SourceLockDigest, v.RenderedDigest, v.ResourceCount, checksRaw, []byte("[]"), actor, v.IdempotencyKey, v.RequestDigest, v.StartedAt, v.FinishedAt, v.LastError, now)
		if e != nil {
			return mapDBError(e)
		}
		action := "runtime_certification.queued"
		if v.State == controlplane.RuntimeCertificationBlocked {
			action = "runtime_certification.blocked"
		}
		if e = s.appendAuditTx(ctx, tx, actor, action, "runtimeCertification", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "profile": v.Profile}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "runtimeCertification", v.ID, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}

func (s *PostgresStore) GetRuntimeCertification(ctx context.Context, id string) (controlplane.RuntimeCertificationRun, error) {
	v, err := scanRuntimeCertification(s.db.QueryRowContext(ctx, `SELECT `+runtimeCertificationColumns+` FROM runtime_certification_runs WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListRuntimeCertifications(ctx context.Context, projectID, clusterID string) ([]controlplane.RuntimeCertificationRun, error) {
	q := `SELECT ` + runtimeCertificationColumns + ` FROM runtime_certification_runs WHERE 1=1`
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
	out := []controlplane.RuntimeCertificationRun{}
	for rows.Next() {
		v, e := scanRuntimeCertification(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) NextRuntimeCertificationTask(ctx context.Context, clusterID, tokenDigest string) (controlplane.RuntimeCertificationRun, error) {
	var out controlplane.RuntimeCertificationRun
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		now := utcNow(s.now)
		v, e := scanRuntimeCertification(tx.QueryRowContext(ctx, `SELECT `+runtimeCertificationColumns+` FROM runtime_certification_runs WHERE cluster_id=$1 AND (state='QUEUED' OR (state IN ('INSTALLING','VERIFYING') AND (task_lease_expires_at IS NULL OR task_lease_expires_at<=$2))) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, clusterID, now))
		if e != nil {
			return mapDBError(e)
		}
		var currentInventory string
		if e = tx.QueryRowContext(ctx, `SELECT inventory_digest FROM managed_clusters WHERE id=$1`, clusterID).Scan(&currentInventory); e != nil {
			return mapDBError(e)
		}
		if currentInventory != v.InventoryDigest {
			v.State = controlplane.RuntimeCertificationFailed
			v.LastError = "cluster inventory changed after certification was queued; create a new certification run"
			v.FinishedAt = &now
			v.TaskLeaseExpiresAt = nil
			v.Revision++
			v.UpdatedAt = now
			_, e = tx.ExecContext(ctx, `UPDATE runtime_certification_runs SET revision=$2,state='FAILED',last_error=$3,task_lease_expires_at=NULL,finished_at=$4,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, v.LastError, now)
			if e != nil {
				return e
			}
			if e = s.appendAuditTx(ctx, tx, "cluster-agent", "runtime_certification.context_stale", "runtimeCertification", v.ID, v.Revision, "", map[string]any{"inventoryDigest": currentInventory}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "runtimeCertification", v.ID, "runtime_certification.failed", v); e != nil {
				return e
			}
			out = v
			return nil
		}
		if v.State == controlplane.RuntimeCertificationQueued {
			v.State = controlplane.RuntimeCertificationInstalling
			v.Phase = controlplane.RuntimeCertificationPhaseInstall
			v.StartedAt = &now
		} else if v.State == controlplane.RuntimeCertificationVerifying {
			v.Phase = controlplane.RuntimeCertificationPhaseVerify
		}
		lease := now.Add(controlplane.AgentTaskLeaseDuration)
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseExpiresAt = &lease
		v.CleanupGenerations = append(v.CleanupGenerations, controlplane.RuntimeCertificationCleanupGeneration{TaskAttempt: v.TaskAttempt, Phase: v.Phase, Token: controlplane.RuntimeCertificationCleanupToken(v.ID, v.TaskAttempt, v.TaskFenceToken)})
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE runtime_certification_runs SET revision=$2,state=$3,phase=$4,task_attempt=$5,task_fence_token=$6,task_lease_expires_at=$7,cleanup_generations=$8::jsonb,started_at=$9,updated_at=$10 WHERE id=$1`, v.ID, v.Revision, string(v.State), string(v.Phase), v.TaskAttempt, v.TaskFenceToken, lease, mustJSON(v.CleanupGenerations), v.StartedAt, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "runtime_certification.task_claimed", "runtimeCertification", v.ID, v.Revision, "", map[string]any{"phase": v.Phase, "attempt": v.TaskAttempt, "taskFenceToken": v.TaskFenceToken, "leaseExpiresAt": lease}); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) ReportRuntimeCertificationTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result controlplane.RuntimeCertificationResult) (controlplane.RuntimeCertificationRun, error) {
	var out controlplane.RuntimeCertificationRun
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		v, e := scanRuntimeCertification(tx.QueryRowContext(ctx, `SELECT `+runtimeCertificationColumns+` FROM runtime_certification_runs WHERE id=$1 FOR UPDATE`, result.RunID))
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
		if result.InventoryDigest != v.InventoryDigest || result.RenderedDigest != v.RenderedDigest || result.Phase != v.Phase {
			return controlplane.ErrValidation
		}
		if (v.Phase == controlplane.RuntimeCertificationPhaseInstall && v.State != controlplane.RuntimeCertificationInstalling) || (v.Phase == controlplane.RuntimeCertificationPhaseVerify && v.State != controlplane.RuntimeCertificationVerifying) {
			return controlplane.ErrInvalidTransition
		}
		if e = controlplane.ValidateRuntimeCertificationResultShape(v, result); e != nil {
			return e
		}
		v.Checks = append(v.Checks, result.Checks...)
		allPass := len(result.Checks) > 0
		for _, c := range result.Checks {
			if c.Status != "PASS" {
				allPass = false
			}
		}
		if !result.Success || !allPass {
			if result.Blocked {
				v.State = controlplane.RuntimeCertificationBlocked
			} else {
				v.State = controlplane.RuntimeCertificationFailed
			}
			v.LastError = strings.TrimSpace(result.Error)
			if v.LastError == "" {
				v.LastError = "runtime certification checks failed"
			}
			v.FinishedAt = &now
		} else if v.Phase == controlplane.RuntimeCertificationPhaseInstall {
			v.InstallCheckpointDigest = controlplane.RuntimeCertificationCheckpointDigest(v, result.Checks)
			v.InstallCheckpointAt = &now
			v.State = controlplane.RuntimeCertificationVerifying
			v.Phase = controlplane.RuntimeCertificationPhaseVerify
			v.LastError = ""
		} else {
			if v.InstallCheckpointDigest == "" || v.InstallCheckpointAt == nil {
				return controlplane.ErrInvalidTransition
			}
			v.State = controlplane.RuntimeCertificationSucceeded
			v.LastError = ""
			v.FinishedAt = &now
			expires := now.Add(controlplane.RuntimeCertificationValidity)
			v.ExpiresAt = &expires
			v.EvidenceDigest = controlplane.RuntimeCertificationEvidenceDigest(v)
		}
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		checksRaw, _ := json.Marshal(v.Checks)
		_, e = tx.ExecContext(ctx, `UPDATE runtime_certification_runs SET revision=$2,state=$3,phase=$4,checks=$5::jsonb,install_checkpoint_digest=$6,evidence_digest=$7,install_checkpoint_at=$8,finished_at=$9,expires_at=$10,last_error=$11,task_lease_expires_at=NULL,updated_at=$12 WHERE id=$1`, v.ID, v.Revision, string(v.State), string(v.Phase), checksRaw, v.InstallCheckpointDigest, v.EvidenceDigest, v.InstallCheckpointAt, v.FinishedAt, v.ExpiresAt, v.LastError, now)
		if e != nil {
			return e
		}
		action := "runtime_certification.install_checkpointed"
		if v.State == controlplane.RuntimeCertificationSucceeded {
			action = "runtime_certification.succeeded"
		} else if v.State == controlplane.RuntimeCertificationBlocked {
			action = "runtime_certification.blocked"
		} else if v.State == controlplane.RuntimeCertificationFailed {
			action = "runtime_certification.failed"
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", action, "runtimeCertification", v.ID, v.Revision, "", map[string]any{"phase": result.Phase, "evidenceDigest": v.EvidenceDigest, "taskFenceToken": result.TaskFenceToken}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "runtimeCertification", v.ID, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) RevokeRuntimeCertification(ctx context.Context, id string, expected int64, actor string) (controlplane.RuntimeCertificationRun, error) {
	var out controlplane.RuntimeCertificationRun
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanRuntimeCertification(tx.QueryRowContext(ctx, `SELECT `+runtimeCertificationColumns+` FROM runtime_certification_runs WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.RuntimeCertificationSucceeded {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.State = controlplane.RuntimeCertificationRevoked
		v.RevokedBy = actor
		v.RevokedAt = &now
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE runtime_certification_runs SET revision=$2,state='REVOKED',revoked_by=$3,revoked_at=$4,updated_at=$4 WHERE id=$1`, id, v.Revision, actor, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "runtime_certification.revoked", "runtimeCertification", v.ID, v.Revision, "", map[string]any{"evidenceDigest": v.EvidenceDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "runtimeCertification", v.ID, "runtime_certification.revoked", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
