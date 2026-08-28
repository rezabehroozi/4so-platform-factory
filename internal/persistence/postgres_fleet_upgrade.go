package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"sort"
	"strings"
	"time"
)

const fleetGroupColumns = `id,project_id,revision,name,display_name,cluster_ids,requested_by,idempotency_key,request_digest,created_at,updated_at`
const driftScanColumns = `id,project_id,COALESCE(fleet_group_id,''),revision,state::text,targets,requested_by,idempotency_key,request_digest,started_at,finished_at,summary,created_at,updated_at`
const upgradeCampaignColumns = `id,project_id,fleet_group_id,revision,baseline_id,target_version,state::text,canary_count,wave_size,halt_after_failures,current_wave,targets,requested_by,approved_by,approved_at,started_at,finished_at,idempotency_key,request_digest,maintenance_window_start,maintenance_window_end,recovery_checkpoint_ids,target_inventory_digests,plan_context_digest,plan_created_at,plan_expires_at,plan_revalidation_count,paused_by,paused_at,pause_count,cancel_requested_by,cancel_requested_at,cancelled_by,cancelled_at,control_reason,summary,created_at,updated_at`

func scanFleetGroup(row interface{ Scan(...any) error }) (controlplane.FleetGroup, error) {
	var v controlplane.FleetGroup
	var clusters []byte
	err := row.Scan(&v.ID, &v.ProjectID, &v.Revision, &v.Name, &v.DisplayName, &clusters, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest, &v.CreatedAt, &v.UpdatedAt)
	if len(clusters) > 0 {
		if decodeErr := decodeJSONColumn(clusters, &v.ClusterIDs, "postgres_fleet_upgrade.ClusterIDs"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}
func scanDriftScan(row interface{ Scan(...any) error }) (controlplane.DriftScan, error) {
	var v controlplane.DriftScan
	var state string
	var targets []byte
	err := row.Scan(&v.ID, &v.ProjectID, &v.FleetGroupID, &v.Revision, &state, &targets, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest, &v.StartedAt, &v.FinishedAt, &v.Summary, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.DriftScanState(state)
	if len(targets) > 0 {
		if decodeErr := decodeJSONColumn(targets, &v.Targets, "postgres_fleet_upgrade.Targets"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}
func scanUpgradeCampaign(row interface{ Scan(...any) error }) (controlplane.UpgradeCampaign, error) {
	var v controlplane.UpgradeCampaign
	var state string
	var targets, checkpoints, inventory []byte
	var windowStart, windowEnd sql.NullTime
	err := row.Scan(&v.ID, &v.ProjectID, &v.FleetGroupID, &v.Revision, &v.BaselineID, &v.TargetVersion, &state, &v.CanaryCount, &v.WaveSize, &v.HaltAfterFailures, &v.CurrentWave, &targets, &v.RequestedBy, &v.ApprovedBy, &v.ApprovedAt, &v.StartedAt, &v.FinishedAt, &v.IdempotencyKey, &v.RequestDigest, &windowStart, &windowEnd, &checkpoints, &inventory, &v.PlanContextDigest, &v.PlanCreatedAt, &v.PlanExpiresAt, &v.PlanRevalidationCount, &v.PausedBy, &v.PausedAt, &v.PauseCount, &v.CancelRequestedBy, &v.CancelRequestedAt, &v.CancelledBy, &v.CancelledAt, &v.ControlReason, &v.Summary, &v.CreatedAt, &v.UpdatedAt)
	if windowStart.Valid {
		v.MaintenanceWindowStart = windowStart.Time
	}
	if windowEnd.Valid {
		v.MaintenanceWindowEnd = windowEnd.Time
	}
	v.State = controlplane.UpgradeCampaignState(state)
	if len(targets) > 0 {
		if decodeErr := decodeJSONColumn(targets, &v.Targets, "postgres_fleet_upgrade.Targets"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(checkpoints) > 0 {
		if decodeErr := decodeJSONColumn(checkpoints, &v.RecoveryCheckpointIDs, "postgres_fleet_upgrade.RecoveryCheckpointIDs"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(inventory) > 0 {
		if decodeErr := decodeJSONColumn(inventory, &v.TargetInventoryDigests, "postgres_fleet_upgrade.TargetInventoryDigests"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if v.TargetInventoryDigests == nil {
		v.TargetInventoryDigests = map[string]string{}
	}
	return v, err
}

func uniqueUpgradeStrings(values []string) ([]string, bool) {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return nil, false
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, true
}

func (s *PostgresStore) prepareUpgradeSafetyTx(ctx context.Context, tx *sql.Tx, v *controlplane.UpgradeCampaign, checkpointIDs []string, now time.Time) error {
	if v.MaintenanceWindowStart.IsZero() || v.MaintenanceWindowEnd.IsZero() || !v.MaintenanceWindowEnd.After(v.MaintenanceWindowStart) || !v.MaintenanceWindowEnd.After(now) || v.MaintenanceWindowEnd.Sub(v.MaintenanceWindowStart) > 24*time.Hour {
		return fmt.Errorf("%w: maintenance window must end in the future, be ordered, and be at most 24 hours", controlplane.ErrValidation)
	}
	ids, ok := uniqueUpgradeStrings(checkpointIDs)
	if !ok || len(ids) != len(v.Targets) {
		return fmt.Errorf("%w: exactly one recovery checkpoint is required for every target cluster", controlplane.ErrPrerequisite)
	}
	cpByCluster := map[string]controlplane.RecoveryCheckpoint{}
	for _, id := range ids {
		cp, e := scanRecoveryCheckpoint(tx.QueryRowContext(ctx, `SELECT `+recoveryCheckpointColumns+` FROM recovery_checkpoints WHERE id=$1 FOR SHARE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if cp.ProjectID != v.ProjectID {
			return fmt.Errorf("%w: recovery checkpoint %s is unavailable", controlplane.ErrPrerequisite, id)
		}
		if _, exists := cpByCluster[cp.ClusterID]; exists {
			return fmt.Errorf("%w: duplicate recovery checkpoint cluster", controlplane.ErrPrerequisite)
		}
		cpByCluster[cp.ClusterID] = cp
	}
	inventory := map[string]string{}
	for clusterID, digest := range v.TargetInventoryDigests {
		inventory[clusterID] = digest
	}
	for _, target := range v.Targets {
		if target.State != controlplane.UpgradeTargetPending {
			continue
		}
		var projectID, inventoryDigest string
		if e := tx.QueryRowContext(ctx, `SELECT project_id,inventory_digest FROM managed_clusters WHERE id=$1 FOR SHARE`, target.ClusterID).Scan(&projectID, &inventoryDigest); e != nil {
			return mapDBError(e)
		}
		if projectID != v.ProjectID || strings.TrimSpace(inventoryDigest) == "" {
			return fmt.Errorf("%w: target cluster %s requires fresh inventory", controlplane.ErrPrerequisite, target.ClusterID)
		}
		cp, exists := cpByCluster[target.ClusterID]
		if !exists || cp.State != controlplane.RecoveryCheckpointVerified || !cp.ExpiresAt.After(v.MaintenanceWindowEnd) || cp.InventoryDigest != inventoryDigest {
			return fmt.Errorf("%w: target cluster %s requires a verified recovery checkpoint captured against current inventory and valid through the maintenance window", controlplane.ErrPrerequisite, target.ClusterID)
		}
		latest, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE project_id=$1 AND cluster_id=$2 AND baseline_id=$3 AND state='SUCCEEDED' AND desired_digest=observed_digest ORDER BY created_at DESC,id DESC LIMIT 1 FOR SHARE`, v.ProjectID, target.ClusterID, v.BaselineID))
		if e != nil {
			return mapDBError(e)
		}
		if !controlplane.BaselineCompletionEvidenceReady(latest, now) || latest.ID != target.PreviousBaselineDeploymentID {
			return fmt.Errorf("%w: source baseline changed for cluster %s; create a new campaign", controlplane.ErrPlanStale, target.ClusterID)
		}
		inventory[target.ClusterID] = inventoryDigest
	}
	v.TargetInventoryDigests = inventory
	v.RecoveryCheckpointIDs = ids
	v.PlanCreatedAt = &now
	expires := now.Add(controlplane.ExecutionPlanTTL)
	v.PlanExpiresAt = &expires
	v.PlanContextDigest = controlplane.UpgradeCampaignContextDigest(*v)
	return nil
}

func (s *PostgresStore) validateUpgradeSafetyTx(ctx context.Context, tx *sql.Tx, v controlplane.UpgradeCampaign, now time.Time, requireOpenWindow bool) error {
	if v.PlanCreatedAt == nil || v.PlanExpiresAt == nil || !now.Before(*v.PlanExpiresAt) {
		return controlplane.ErrPlanStale
	}
	if requireOpenWindow && (now.Before(v.MaintenanceWindowStart) || !now.Before(v.MaintenanceWindowEnd)) {
		return controlplane.ErrMaintenanceWindow
	}
	copy := v
	copy.Targets = append([]controlplane.UpgradeCampaignTarget(nil), v.Targets...)
	copy.RecoveryCheckpointIDs = append([]string(nil), v.RecoveryCheckpointIDs...)
	if e := s.prepareUpgradeSafetyTx(ctx, tx, &copy, v.RecoveryCheckpointIDs, now); e != nil {
		return e
	}
	if copy.PlanContextDigest != v.PlanContextDigest {
		return controlplane.ErrPlanStale
	}
	return nil
}

func (s *PostgresStore) CreateFleetGroup(ctx context.Context, v controlplane.FleetGroup, actor string) (controlplane.FleetGroup, bool, error) {
	var out controlplane.FleetGroup
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanFleetGroup(tx.QueryRowContext(ctx, `SELECT `+fleetGroupColumns+` FROM fleet_groups WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
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
		if len(v.ClusterIDs) == 0 || normalizedName(v.Name) == "" || strings.TrimSpace(v.DisplayName) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") || strings.TrimSpace(v.IdempotencyKey) == "" {
			return controlplane.ErrValidation
		}
		ids := append([]string(nil), v.ClusterIDs...)
		sort.Strings(ids)
		for i, id := range ids {
			if id == "" || (i > 0 && ids[i-1] == id) {
				return controlplane.ErrValidation
			}
			var project string
			if e = tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1`, id).Scan(&project); e != nil {
				return mapDBError(e)
			}
			if project != v.ProjectID {
				return controlplane.ErrNotFound
			}
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("flg"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.Name = normalizedName(v.Name)
		v.ClusterIDs = ids
		v.RequestedBy = actor
		raw, _ := json.Marshal(ids)
		_, e = tx.ExecContext(ctx, `INSERT INTO fleet_groups(id,project_id,revision,name,display_name,cluster_ids,requested_by,idempotency_key,request_digest,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5::jsonb,$6,$7,$8,$9,$9)`, v.ID, v.ProjectID, v.Name, v.DisplayName, raw, actor, v.IdempotencyKey, v.RequestDigest, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "fleet_group.created", "fleetGroup", v.ID, v.Revision, "", map[string]any{"clusters": len(ids)}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "fleetGroup", v.ID, "fleet_group.created", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}
func (s *PostgresStore) GetFleetGroup(ctx context.Context, id string) (controlplane.FleetGroup, error) {
	v, e := scanFleetGroup(s.db.QueryRowContext(ctx, `SELECT `+fleetGroupColumns+` FROM fleet_groups WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListFleetGroups(ctx context.Context, projectID string) ([]controlplane.FleetGroup, error) {
	q := `SELECT ` + fleetGroupColumns + ` FROM fleet_groups`
	args := []any{}
	if projectID != "" {
		q += ` WHERE project_id=$1`
		args = append(args, projectID)
	}
	q += ` ORDER BY name,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.FleetGroup{}
	for rows.Next() {
		v, e := scanFleetGroup(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateDriftScan(ctx context.Context, v controlplane.DriftScan, actor string) (controlplane.DriftScan, bool, error) {
	var out controlplane.DriftScan
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanDriftScan(tx.QueryRowContext(ctx, `SELECT `+driftScanColumns+` FROM drift_scans WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
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
		if len(v.Targets) == 0 || !strings.HasPrefix(v.RequestDigest, "sha256:") || strings.TrimSpace(v.IdempotencyKey) == "" {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		for i := range v.Targets {
			t := &v.Targets[i]
			baseline, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE id=$1 FOR SHARE`, t.BaselineDeploymentID))
			if e != nil {
				return mapDBError(e)
			}
			if baseline.ProjectID != v.ProjectID || baseline.ClusterID != t.ClusterID || !controlplane.BaselineCompletionEvidenceReady(baseline, now) || baseline.DesiredDigest != t.DesiredDigest {
				return controlplane.ErrValidation
			}
			t.BaselineID, t.BaselineVersion, t.State = baseline.BaselineID, baseline.BaselineVersion, controlplane.DriftTargetPending
		}
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("drf"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.DriftScanQueued
		v.RequestedBy = actor
		raw, _ := json.Marshal(v.Targets)
		_, e = tx.ExecContext(ctx, `INSERT INTO drift_scans(id,project_id,fleet_group_id,revision,state,targets,requested_by,idempotency_key,request_digest,created_at,updated_at) VALUES($1,$2,NULLIF($3,''),1,$4,$5::jsonb,$6,$7,$8,$9,$9)`, v.ID, v.ProjectID, v.FleetGroupID, string(v.State), raw, actor, v.IdempotencyKey, v.RequestDigest, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "drift_scan.created", "driftScan", v.ID, v.Revision, "", map[string]any{"targets": len(v.Targets)}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "driftScan", v.ID, "drift_scan.queued", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}
func (s *PostgresStore) GetDriftScan(ctx context.Context, id string) (controlplane.DriftScan, error) {
	v, e := scanDriftScan(s.db.QueryRowContext(ctx, `SELECT `+driftScanColumns+` FROM drift_scans WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListDriftScans(ctx context.Context, projectID, groupID string) ([]controlplane.DriftScan, error) {
	q := `SELECT ` + driftScanColumns + ` FROM drift_scans WHERE 1=1`
	args := []any{}
	for _, f := range []struct{ v, c string }{{projectID, "project_id"}, {groupID, "fleet_group_id"}} {
		if f.v != "" {
			args = append(args, f.v)
			q += fmt.Sprintf(" AND %s=$%d", f.c, len(args))
		}
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.DriftScan{}
	for rows.Next() {
		v, e := scanDriftScan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) NextDriftTask(ctx context.Context, clusterID, tokenDigest string) (controlplane.DriftScan, controlplane.DriftScanTarget, error) {
	var out controlplane.DriftScan
	var target controlplane.DriftScanTarget
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		needle, _ := json.Marshal([]map[string]string{{"clusterId": clusterID}})
		v, e := scanDriftScan(tx.QueryRowContext(ctx, `SELECT `+driftScanColumns+` FROM drift_scans WHERE state IN ('QUEUED','RUNNING') AND targets @> $1::jsonb ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, needle))
		if e != nil {
			return mapDBError(e)
		}
		now := utcNow(s.now)
		found := false
		for i := range v.Targets {
			if v.Targets[i].ClusterID == clusterID && (v.Targets[i].State == controlplane.DriftTargetPending || v.Targets[i].State == controlplane.DriftTargetRunning) {
				if v.Targets[i].State == controlplane.DriftTargetPending {
					v.Targets[i].State = controlplane.DriftTargetRunning
					v.Targets[i].Attempt++
					v.Targets[i].StartedAt = &now
					if v.StartedAt == nil {
						v.StartedAt = &now
					}
					v.State = controlplane.DriftScanRunning
					v.Revision++
					v.UpdatedAt = now
					raw, _ := json.Marshal(v.Targets)
					if _, e = tx.ExecContext(ctx, `UPDATE drift_scans SET revision=$2,state=$3,targets=$4::jsonb,started_at=COALESCE(started_at,$5),updated_at=$5 WHERE id=$1`, v.ID, v.Revision, string(v.State), raw, now); e != nil {
						return e
					}
				}
				target = v.Targets[i]
				found = true
				break
			}
		}
		if !found {
			return controlplane.ErrNotFound
		}
		out = v
		return nil
	})
	return out, target, err
}
func (s *PostgresStore) ReportDriftTask(ctx context.Context, clusterID, tokenDigest string, expected int64, result controlplane.DriftTaskResult) (controlplane.DriftScan, error) {
	var out controlplane.DriftScan
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, tokenDigest); e != nil {
			return e
		}
		v, e := scanDriftScan(tx.QueryRowContext(ctx, `SELECT `+driftScanColumns+` FROM drift_scans WHERE id=$1 FOR UPDATE`, result.ScanID))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		now := utcNow(s.now)
		prior := []controlplane.DriftScan{}
		rows, historyErr := tx.QueryContext(ctx, `SELECT `+driftScanColumns+` FROM drift_scans WHERE project_id=$1 AND id<>$2 ORDER BY created_at,id`, v.ProjectID, v.ID)
		if historyErr != nil {
			return historyErr
		}
		for rows.Next() {
			previous, scanErr := scanDriftScan(rows)
			if scanErr != nil {
				rows.Close()
				return scanErr
			}
			prior = append(prior, previous)
		}
		if historyErr = rows.Err(); historyErr != nil {
			rows.Close()
			return historyErr
		}
		rows.Close()
		found := false
		for i := range v.Targets {
			t := &v.Targets[i]
			if t.ClusterID == clusterID && t.State == controlplane.DriftTargetRunning {
				found = true
				t.ObservedDigest = result.ObservedDigest
				t.Changes = append([]controlplane.BaselinePlanChange(nil), result.Changes...)
				if t.Git != nil {
					t.Git = controlplane.ClassifyGitDrift(t.Git, result.GitObservedDigest)
				}
				t.Comparison, t.Findings = controlplane.RuntimeDriftFindings(*t, result, prior, now)
				t.FinishedAt = &now
				if !result.Success {
					t.State = controlplane.DriftTargetFailed
					t.LastError = strings.TrimSpace(result.Error)
				} else {
					drifted := result.ObservedDigest != t.DesiredDigest
					if t.Git != nil && t.Git.Classification != controlplane.GitDriftInSync && t.Git.Classification != controlplane.GitDriftNotRequested {
						drifted = true
					}
					for _, c := range result.Changes {
						if strings.ToUpper(c.Action) != "NOOP" {
							drifted = true
						}
					}
					if drifted {
						t.State = controlplane.DriftTargetDrifted
					} else {
						t.State = controlplane.DriftTargetInSync
					}
					t.LastError = ""
				}
				break
			}
		}
		if !found {
			return controlplane.ErrInvalidTransition
		}
		allDone, failed, drifted := true, false, false
		for _, t := range v.Targets {
			switch t.State {
			case controlplane.DriftTargetPending, controlplane.DriftTargetRunning:
				allDone = false
			case controlplane.DriftTargetFailed:
				failed = true
			case controlplane.DriftTargetDrifted:
				drifted = true
			}
		}
		if allDone {
			v.FinishedAt = &now
			if failed {
				v.State = controlplane.DriftScanFailed
				v.Summary = "one or more cluster drift checks failed"
			} else if drifted {
				v.State = controlplane.DriftScanDrifted
				v.Summary = "managed baseline or Git three-way drift was detected"
			} else {
				v.State = controlplane.DriftScanInSync
				v.Summary = "all managed baseline resources are in sync"
			}
		}
		v.Revision++
		v.UpdatedAt = now
		raw, _ := json.Marshal(v.Targets)
		if _, e = tx.ExecContext(ctx, `UPDATE drift_scans SET revision=$2,state=$3,targets=$4::jsonb,finished_at=$5,summary=$6,updated_at=$7 WHERE id=$1`, v.ID, v.Revision, string(v.State), raw, v.FinishedAt, v.Summary, now); e != nil {
			return e
		}
		action := "drift_scan." + strings.ToLower(string(v.State))
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", action, "driftScan", v.ID, v.Revision, "", map[string]any{"clusterId": clusterID}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "driftScan", v.ID, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) CreateUpgradeCampaign(ctx context.Context, v controlplane.UpgradeCampaign, actor string) (controlplane.UpgradeCampaign, bool, error) {
	var out controlplane.UpgradeCampaign
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanUpgradeCampaign(tx.QueryRowContext(ctx, `SELECT `+upgradeCampaignColumns+` FROM upgrade_campaigns WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
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
		var groupProject string
		if e = tx.QueryRowContext(ctx, `SELECT project_id FROM fleet_groups WHERE id=$1`, v.FleetGroupID).Scan(&groupProject); e != nil {
			return mapDBError(e)
		}
		if groupProject != v.ProjectID || len(v.Targets) == 0 || v.CanaryCount < 1 || v.WaveSize < 1 || v.HaltAfterFailures < 1 || strings.TrimSpace(v.TargetVersion) == "" || strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		if e = s.prepareUpgradeSafetyTx(ctx, tx, &v, v.RecoveryCheckpointIDs, now); e != nil {
			return e
		}
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("upg"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.UpgradeCampaignAwaitingApproval
		v.RequestedBy = actor
		v.CurrentWave = 0
		targets, _ := json.Marshal(v.Targets)
		checkpoints, _ := json.Marshal(v.RecoveryCheckpointIDs)
		inventory, _ := json.Marshal(v.TargetInventoryDigests)
		_, e = tx.ExecContext(ctx, `INSERT INTO upgrade_campaigns(id,project_id,fleet_group_id,revision,baseline_id,target_version,state,canary_count,wave_size,halt_after_failures,current_wave,targets,requested_by,idempotency_key,request_digest,maintenance_window_start,maintenance_window_end,recovery_checkpoint_ids,target_inventory_digests,plan_context_digest,plan_created_at,plan_expires_at,plan_revalidation_count,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,0,$10::jsonb,$11,$12,$13,$14,$15,$16::jsonb,$17::jsonb,$18,$19,$20,0,$21,$21)`, v.ID, v.ProjectID, v.FleetGroupID, v.BaselineID, v.TargetVersion, string(v.State), v.CanaryCount, v.WaveSize, v.HaltAfterFailures, targets, actor, v.IdempotencyKey, v.RequestDigest, v.MaintenanceWindowStart, v.MaintenanceWindowEnd, checkpoints, inventory, v.PlanContextDigest, v.PlanCreatedAt, v.PlanExpiresAt, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "upgrade_campaign.created", "upgradeCampaign", v.ID, v.Revision, "", map[string]any{"targets": len(v.Targets), "targetVersion": v.TargetVersion, "maintenanceWindowStart": v.MaintenanceWindowStart, "maintenanceWindowEnd": v.MaintenanceWindowEnd}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "upgradeCampaign", v.ID, "upgrade_campaign.awaiting_approval", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, replay, err
}
func (s *PostgresStore) GetUpgradeCampaign(ctx context.Context, id string) (controlplane.UpgradeCampaign, error) {
	v, e := scanUpgradeCampaign(s.db.QueryRowContext(ctx, `SELECT `+upgradeCampaignColumns+` FROM upgrade_campaigns WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListUpgradeCampaigns(ctx context.Context, projectID, groupID string) ([]controlplane.UpgradeCampaign, error) {
	q := `SELECT ` + upgradeCampaignColumns + ` FROM upgrade_campaigns WHERE 1=1`
	args := []any{}
	for _, f := range []struct{ v, c string }{{projectID, "project_id"}, {groupID, "fleet_group_id"}} {
		if f.v != "" {
			args = append(args, f.v)
			q += fmt.Sprintf(" AND %s=$%d", f.c, len(args))
		}
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.UpgradeCampaign{}
	for rows.Next() {
		v, e := scanUpgradeCampaign(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) ApproveUpgradeCampaign(ctx context.Context, id string, expected int64, actor string) (controlplane.UpgradeCampaign, error) {
	var out controlplane.UpgradeCampaign
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanUpgradeCampaign(tx.QueryRowContext(ctx, `SELECT `+upgradeCampaignColumns+` FROM upgrade_campaigns WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.UpgradeCampaignAwaitingApproval {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		if e = s.validateUpgradeSafetyTx(ctx, tx, v, now, false); e != nil {
			return e
		}
		v.State = controlplane.UpgradeCampaignQueued
		v.ApprovedBy, v.ApprovedAt = actor, &now
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE upgrade_campaigns SET revision=$2,state=$3,approved_by=$4,approved_at=$5,updated_at=$5 WHERE id=$1`, id, v.Revision, string(v.State), actor, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "upgrade_campaign.approved", "upgradeCampaign", id, v.Revision, "", map[string]any{"planContextDigest": v.PlanContextDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "upgradeCampaign", id, "upgrade_campaign.queued", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func postgresUpgradeCampaignHasActiveTarget(v controlplane.UpgradeCampaign) bool {
	for _, target := range v.Targets {
		switch target.State {
		case controlplane.UpgradeTargetPlanning, controlplane.UpgradeTargetApplying, controlplane.UpgradeTargetVerifying, controlplane.UpgradeTargetRollingBack:
			return true
		}
	}
	return false
}

func (s *PostgresStore) PauseUpgradeCampaign(ctx context.Context, id string, expected int64, actor, reason string) (controlplane.UpgradeCampaign, error) {
	var out controlplane.UpgradeCampaign
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanUpgradeCampaign(tx.QueryRowContext(ctx, `SELECT `+upgradeCampaignColumns+` FROM upgrade_campaigns WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.UpgradeCampaignRunning {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		reason = strings.TrimSpace(reason)
		if reason == "" {
			reason = "operator requested pause"
		}
		v.PausedBy, v.ControlReason, v.PauseCount = actor, reason, v.PauseCount+1
		if postgresUpgradeCampaignHasActiveTarget(v) {
			v.State, v.PausedAt = controlplane.UpgradeCampaignPauseRequested, nil
		} else {
			v.State, v.PausedAt = controlplane.UpgradeCampaignPaused, &now
		}
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE upgrade_campaigns SET revision=$2,state=$3,paused_by=$4,paused_at=$5,pause_count=$6,control_reason=$7,updated_at=$8 WHERE id=$1`, id, v.Revision, string(v.State), v.PausedBy, v.PausedAt, v.PauseCount, v.ControlReason, now)
		if e != nil {
			return e
		}
		action := "upgrade_campaign.pause_requested"
		if v.State == controlplane.UpgradeCampaignPaused {
			action = "upgrade_campaign.paused"
		}
		if e = s.appendAuditTx(ctx, tx, actor, action, "upgradeCampaign", id, v.Revision, "", map[string]any{"wave": v.CurrentWave, "reason": reason}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "upgradeCampaign", id, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) ResumeUpgradeCampaign(ctx context.Context, id string, expected int64, actor string) (controlplane.UpgradeCampaign, error) {
	var out controlplane.UpgradeCampaign
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanUpgradeCampaign(tx.QueryRowContext(ctx, `SELECT `+upgradeCampaignColumns+` FROM upgrade_campaigns WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.UpgradeCampaignPaused {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		if e = s.validateUpgradeSafetyTx(ctx, tx, v, now, true); e != nil {
			return e
		}
		v.State, v.PausedAt, v.ControlReason = controlplane.UpgradeCampaignQueued, nil, ""
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE upgrade_campaigns SET revision=$2,state=$3,paused_at=NULL,control_reason='',updated_at=$4 WHERE id=$1`, id, v.Revision, string(v.State), now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "upgrade_campaign.resumed", "upgradeCampaign", id, v.Revision, "", map[string]any{"wave": v.CurrentWave, "startedAtPreserved": v.StartedAt != nil}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "upgradeCampaign", id, "upgrade_campaign.queued", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) CancelUpgradeCampaign(ctx context.Context, id string, expected int64, actor, reason string) (controlplane.UpgradeCampaign, error) {
	var out controlplane.UpgradeCampaign
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanUpgradeCampaign(tx.QueryRowContext(ctx, `SELECT `+upgradeCampaignColumns+` FROM upgrade_campaigns WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		switch v.State {
		case controlplane.UpgradeCampaignSucceeded, controlplane.UpgradeCampaignFailed, controlplane.UpgradeCampaignCancelled, controlplane.UpgradeCampaignCancelRequested:
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		reason = strings.TrimSpace(reason)
		if reason == "" {
			reason = "operator requested cancel"
		}
		v.CancelRequestedBy, v.CancelRequestedAt, v.ControlReason = actor, &now, reason
		if postgresUpgradeCampaignHasActiveTarget(v) {
			switch v.State {
			case controlplane.UpgradeCampaignRunning, controlplane.UpgradeCampaignPauseRequested, controlplane.UpgradeCampaignCancelRequested, controlplane.UpgradeCampaignHalted:
				v.State = controlplane.UpgradeCampaignCancelRequested
			default:
				return controlplane.ErrInvalidTransition
			}
		} else {
			v.State, v.CancelledBy, v.CancelledAt, v.FinishedAt = controlplane.UpgradeCampaignCancelled, actor, &now, &now
		}
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE upgrade_campaigns SET revision=$2,state=$3,cancel_requested_by=$4,cancel_requested_at=$5,cancelled_by=$6,cancelled_at=$7,finished_at=$8,control_reason=$9,updated_at=$10 WHERE id=$1`, id, v.Revision, string(v.State), v.CancelRequestedBy, v.CancelRequestedAt, v.CancelledBy, v.CancelledAt, v.FinishedAt, v.ControlReason, now)
		if e != nil {
			return e
		}
		action := "upgrade_campaign.cancel_requested"
		if v.State == controlplane.UpgradeCampaignCancelled {
			action = "upgrade_campaign.cancelled"
		}
		if e = s.appendAuditTx(ctx, tx, actor, action, "upgradeCampaign", id, v.Revision, "", map[string]any{"wave": v.CurrentWave, "reason": reason}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "upgradeCampaign", id, action, v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) RevalidateUpgradeCampaign(ctx context.Context, id string, expected int64, input controlplane.UpgradeCampaignRevalidation, actor string) (controlplane.UpgradeCampaign, error) {
	var out controlplane.UpgradeCampaign
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanUpgradeCampaign(tx.QueryRowContext(ctx, `SELECT `+upgradeCampaignColumns+` FROM upgrade_campaigns WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.UpgradeCampaignAwaitingApproval && v.State != controlplane.UpgradeCampaignQueued && v.State != controlplane.UpgradeCampaignRunning && v.State != controlplane.UpgradeCampaignPaused {
			return controlplane.ErrInvalidTransition
		}
		if v.State == controlplane.UpgradeCampaignRunning {
			for _, target := range v.Targets {
				if target.State == controlplane.UpgradeTargetPlanning || target.State == controlplane.UpgradeTargetApplying || target.State == controlplane.UpgradeTargetVerifying || target.State == controlplane.UpgradeTargetRollingBack {
					return fmt.Errorf("%w: running campaign can only be revalidated between waves", controlplane.ErrInvalidTransition)
				}
			}
		}
		checkpointIDs := input.RecoveryCheckpointIDs
		if len(checkpointIDs) == 0 {
			checkpointIDs = v.RecoveryCheckpointIDs
		}
		if !input.MaintenanceWindowStart.IsZero() {
			v.MaintenanceWindowStart = input.MaintenanceWindowStart
		}
		if !input.MaintenanceWindowEnd.IsZero() {
			v.MaintenanceWindowEnd = input.MaintenanceWindowEnd
		}
		now := utcNow(s.now)
		if e = s.prepareUpgradeSafetyTx(ctx, tx, &v, checkpointIDs, now); e != nil {
			return e
		}
		v.State = controlplane.UpgradeCampaignAwaitingApproval
		v.ApprovedBy, v.ApprovedAt = "", nil
		v.ControlReason = ""
		v.PlanRevalidationCount++
		v.Revision++
		v.UpdatedAt = now
		checkpoints, _ := json.Marshal(v.RecoveryCheckpointIDs)
		inventory, _ := json.Marshal(v.TargetInventoryDigests)
		if _, e = tx.ExecContext(ctx, `UPDATE upgrade_campaigns SET revision=$2,state=$3,approved_by='',approved_at=NULL,recovery_checkpoint_ids=$4::jsonb,target_inventory_digests=$5::jsonb,plan_context_digest=$6,plan_created_at=$7,plan_expires_at=$8,plan_revalidation_count=$9,maintenance_window_start=$10,maintenance_window_end=$11,control_reason='',updated_at=$12 WHERE id=$1`, id, v.Revision, string(v.State), checkpoints, inventory, v.PlanContextDigest, v.PlanCreatedAt, v.PlanExpiresAt, v.PlanRevalidationCount, v.MaintenanceWindowStart, v.MaintenanceWindowEnd, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "upgrade_campaign.revalidated", "upgradeCampaign", id, v.Revision, "", map[string]any{"planContextDigest": v.PlanContextDigest, "revalidationCount": v.PlanRevalidationCount}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "upgradeCampaign", id, "upgrade_campaign.awaiting_approval", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, err
}
func (s *PostgresStore) validateUpgradeTargetStartsTx(ctx context.Context, tx *sql.Tx, current, next controlplane.UpgradeCampaign, now time.Time) error {
	starts := map[string]bool{}
	for i, before := range current.Targets {
		if i < len(next.Targets) && before.State == controlplane.UpgradeTargetPending && next.Targets[i].State != controlplane.UpgradeTargetPending {
			starts[before.ClusterID] = true
		}
	}
	if len(starts) == 0 {
		return nil
	}
	if now.Before(current.MaintenanceWindowStart) || !now.Before(current.MaintenanceWindowEnd) {
		return controlplane.ErrMaintenanceWindow
	}
	cpByCluster := map[string]controlplane.RecoveryCheckpoint{}
	for _, id := range current.RecoveryCheckpointIDs {
		cp, e := scanRecoveryCheckpoint(tx.QueryRowContext(ctx, `SELECT `+recoveryCheckpointColumns+` FROM recovery_checkpoints WHERE id=$1 FOR SHARE`, id))
		if e != nil {
			return mapDBError(e)
		}
		cpByCluster[cp.ClusterID] = cp
	}
	for _, target := range current.Targets {
		if !starts[target.ClusterID] {
			continue
		}
		var projectID, inventoryDigest string
		if e := tx.QueryRowContext(ctx, `SELECT project_id,inventory_digest FROM managed_clusters WHERE id=$1 FOR SHARE`, target.ClusterID).Scan(&projectID, &inventoryDigest); e != nil {
			return mapDBError(e)
		}
		cp, ok := cpByCluster[target.ClusterID]
		if projectID != current.ProjectID || strings.TrimSpace(inventoryDigest) == "" || !ok || cp.ProjectID != current.ProjectID || cp.State != controlplane.RecoveryCheckpointVerified || !cp.ExpiresAt.After(current.MaintenanceWindowEnd) || cp.InventoryDigest != inventoryDigest || current.TargetInventoryDigests[target.ClusterID] != inventoryDigest {
			return fmt.Errorf("%w: target cluster %s requires campaign revalidation with current recovery evidence", controlplane.ErrPrerequisite, target.ClusterID)
		}
		latest, e := scanBaselineDeployment(tx.QueryRowContext(ctx, `SELECT `+baselineDeploymentColumns+` FROM baseline_deployments WHERE project_id=$1 AND cluster_id=$2 AND baseline_id=$3 AND state='SUCCEEDED' AND desired_digest=observed_digest ORDER BY created_at DESC,id DESC LIMIT 1 FOR SHARE`, current.ProjectID, target.ClusterID, current.BaselineID))
		if e != nil {
			return mapDBError(e)
		}
		if !controlplane.BaselineCompletionEvidenceReady(latest, utcNow(s.now)) || latest.ID != target.PreviousBaselineDeploymentID {
			return fmt.Errorf("%w: source baseline changed for cluster %s", controlplane.ErrPlanStale, target.ClusterID)
		}
	}
	return nil
}

func (s *PostgresStore) UpdateUpgradeCampaign(ctx context.Context, next controlplane.UpgradeCampaign, expected int64, actor string) (controlplane.UpgradeCampaign, error) {
	var out controlplane.UpgradeCampaign
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		current, e := scanUpgradeCampaign(tx.QueryRowContext(ctx, `SELECT `+upgradeCampaignColumns+` FROM upgrade_campaigns WHERE id=$1 FOR UPDATE`, next.ID))
		if e != nil {
			return mapDBError(e)
		}
		if current.Revision != expected {
			return controlplane.ErrConflict
		}
		if next.ProjectID != current.ProjectID || next.FleetGroupID != current.FleetGroupID || next.BaselineID != current.BaselineID || next.TargetVersion != current.TargetVersion || next.IdempotencyKey != current.IdempotencyKey || next.RequestDigest != current.RequestDigest || next.PlanContextDigest != current.PlanContextDigest || !next.MaintenanceWindowStart.Equal(current.MaintenanceWindowStart) || !next.MaintenanceWindowEnd.Equal(current.MaintenanceWindowEnd) {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		if current.State == controlplane.UpgradeCampaignQueued && next.State == controlplane.UpgradeCampaignRunning {
			if e = s.validateUpgradeSafetyTx(ctx, tx, current, now, true); e != nil {
				return e
			}
		}
		if e = s.validateUpgradeTargetStartsTx(ctx, tx, current, next, now); e != nil {
			return e
		}
		next.ResourceMeta = current.ResourceMeta
		next.Revision = current.Revision + 1
		next.UpdatedAt = now
		targets, _ := json.Marshal(next.Targets)
		checkpoints, _ := json.Marshal(next.RecoveryCheckpointIDs)
		inventory, _ := json.Marshal(next.TargetInventoryDigests)
		_, e = tx.ExecContext(ctx, `UPDATE upgrade_campaigns SET revision=$2,state=$3,current_wave=$4,targets=$5::jsonb,approved_by=$6,approved_at=$7,started_at=$8,finished_at=$9,summary=$10,recovery_checkpoint_ids=$11::jsonb,target_inventory_digests=$12::jsonb,plan_context_digest=$13,plan_created_at=$14,plan_expires_at=$15,plan_revalidation_count=$16,paused_by=$17,paused_at=$18,pause_count=$19,cancel_requested_by=$20,cancel_requested_at=$21,cancelled_by=$22,cancelled_at=$23,control_reason=$24,updated_at=$25 WHERE id=$1`, next.ID, next.Revision, string(next.State), next.CurrentWave, targets, next.ApprovedBy, next.ApprovedAt, next.StartedAt, next.FinishedAt, next.Summary, checkpoints, inventory, next.PlanContextDigest, next.PlanCreatedAt, next.PlanExpiresAt, next.PlanRevalidationCount, next.PausedBy, next.PausedAt, next.PauseCount, next.CancelRequestedBy, next.CancelRequestedAt, next.CancelledBy, next.CancelledAt, next.ControlReason, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "upgrade_campaign.progressed", "upgradeCampaign", next.ID, next.Revision, "", map[string]any{"state": next.State, "wave": next.CurrentWave}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "upgradeCampaign", next.ID, "upgrade_campaign.progressed", next); e != nil {
			return e
		}
		out = next
		return nil
	})
	return out, err
}
