package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const maintenanceProfileColumns = `id,project_id,cluster_id,revision,environment,default_drain_timeout_seconds,updated_by,created_at,updated_at`
const maintenanceWindowColumns = `id,project_id,cluster_id,revision,name,starts_at,ends_at,max_unavailable,drain_timeout_seconds,state,created_by,cancelled_by,cancelled_at,created_at,updated_at`
const maintenanceRunColumns = `id,project_id,cluster_id,window_id,operation_id,revision,state,action,node_names,node_uids,inventory_digest,max_unavailable,drain_timeout_seconds,host_action_timeout_seconds,requested_by,approved_by,approved_at,started_at,finished_at,results,last_error,idempotency_key,request_digest,created_at,updated_at`

func maintenanceLeaseDurationPG(v controlplane.ClusterMaintenanceRun) time.Duration {
	nodes := len(v.NodeNames)
	if nodes < 1 {
		nodes = 1
	}
	secondsPerNode := int64(v.DrainTimeoutSeconds)
	if v.Action == controlplane.TargetNodeActionOSPatch {
		host := v.HostActionTimeoutSeconds
		if host <= 0 {
			host = 3600
		}
		secondsPerNode += int64(host)
	}
	seconds := int64(nodes) * secondsPerNode
	if seconds < 30 {
		seconds = 30
	}
	return time.Duration(seconds)*time.Second + 2*time.Minute
}

func inventoryHasCapabilityPG(inv controlplane.ClusterInventory, wanted string) bool {
	for _, capability := range inv.Capabilities {
		if capability == wanted {
			return true
		}
	}
	return false
}

func (s *PostgresStore) expireStaleClusterMaintenanceTx(ctx context.Context, tx *sql.Tx, clusterID string, now time.Time) error {
	owner := "cluster-maintenance-agent:" + clusterID
	for {
		var runID string
		err := tx.QueryRowContext(ctx, `SELECT r.id
FROM cluster_maintenance_runs r
JOIN operations o ON o.id=r.operation_id
WHERE r.cluster_id=$1 AND r.state='RUNNING'
  AND (o.state<>'RUNNING' OR COALESCE(o.lease_owner,'')<>$2 OR o.lease_expires_at IS NULL OR o.lease_expires_at<=$3)
ORDER BY r.created_at,r.id
FOR UPDATE OF r,o SKIP LOCKED
LIMIT 1`, clusterID, owner, now).Scan(&runID)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return mapDBError(err)
		}
		v, err := scanMaintenanceRun(tx.QueryRowContext(ctx, `SELECT `+maintenanceRunColumns+` FROM cluster_maintenance_runs WHERE id=$1 FOR UPDATE`, runID))
		if err != nil {
			return mapDBError(err)
		}
		op, err := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, v.OperationID))
		if err != nil {
			return mapDBError(err)
		}
		message := "maintenance agent lease expired or ownership changed before task completion; operator recovery is required"
		v.State = controlplane.ClusterMaintenanceNeedsOperator
		v.LastError = message
		v.FinishedAt = &now
		v.Revision++
		v.UpdatedAt = now
		op.State = controlplane.OperationNeedsOperator
		op.LastError = message
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
		op.Revision++
		op.UpdatedAt = now
		if _, err = tx.ExecContext(ctx, `UPDATE cluster_maintenance_runs SET revision=$2,state='NEEDS_OPERATOR',last_error=$3,finished_at=$4,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, message, now); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state='NEEDS_OPERATOR',lease_owner='',lease_expires_at=NULL,last_error=$3,updated_at=$4 WHERE id=$1`, op.ID, op.Revision, message, now); err != nil {
			return err
		}
		if err = s.appendAuditTx(ctx, tx, "cluster-agent", "cluster_maintenance.run_lease_expired", "clusterMaintenanceRun", v.ID, v.Revision, "", map[string]any{"operationId": op.ID, "error": message}); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "clusterMaintenanceRun", v.ID, "cluster_maintenance.needs_operator", v); err != nil {
			return err
		}
		if err = s.appendOutboxTx(ctx, tx, "operation", op.ID, "operation.needs_operator", op); err != nil {
			return err
		}
	}
}

func (s *PostgresStore) failQueuedClusterMaintenanceTx(ctx context.Context, tx *sql.Tx, v controlplane.ClusterMaintenanceRun, op controlplane.Operation, message string, now time.Time) error {
	v.State = controlplane.ClusterMaintenanceFailed
	v.LastError = message
	v.FinishedAt = &now
	v.Revision++
	v.UpdatedAt = now
	op.State = controlplane.OperationFailed
	op.LastError = message
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	op.Revision++
	op.UpdatedAt = now
	if _, err := tx.ExecContext(ctx, `UPDATE cluster_maintenance_runs SET revision=$2,state='FAILED',last_error=$3,finished_at=$4,updated_at=$4 WHERE id=$1`, v.ID, v.Revision, message, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state='FAILED',lease_owner='',lease_expires_at=NULL,last_error=$3,updated_at=$4 WHERE id=$1`, op.ID, op.Revision, message, now); err != nil {
		return err
	}
	if err := s.appendAuditTx(ctx, tx, "cluster-agent", "cluster_maintenance.run_failed_before_claim", "clusterMaintenanceRun", v.ID, v.Revision, "", map[string]any{"error": message, "operationId": op.ID}); err != nil {
		return err
	}
	return s.appendOutboxTx(ctx, tx, "clusterMaintenanceRun", v.ID, "cluster_maintenance.run_failed", v)
}

func scanMaintenanceProfile(row interface{ Scan(...any) error }) (controlplane.ClusterMaintenanceProfile, error) {
	var v controlplane.ClusterMaintenanceProfile
	var env string
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.Revision, &env, &v.DefaultDrainTimeoutSeconds, &v.UpdatedBy, &v.CreatedAt, &v.UpdatedAt)
	v.Environment = controlplane.ClusterEnvironment(env)
	return v, err
}
func scanMaintenanceWindow(row interface{ Scan(...any) error }) (controlplane.ClusterMaintenanceWindow, error) {
	var v controlplane.ClusterMaintenanceWindow
	var state string
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.Revision, &v.Name, &v.StartsAt, &v.EndsAt, &v.MaxUnavailable, &v.DrainTimeoutSeconds, &state, &v.CreatedBy, &v.CancelledBy, &v.CancelledAt, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.ClusterMaintenanceWindowState(state)
	return v, err
}
func scanMaintenanceRun(row interface{ Scan(...any) error }) (controlplane.ClusterMaintenanceRun, error) {
	var v controlplane.ClusterMaintenanceRun
	var state, action string
	var nodes, nodeUIDs, results []byte
	err := row.Scan(&v.ID, &v.ProjectID, &v.ClusterID, &v.WindowID, &v.OperationID, &v.Revision, &state, &action, &nodes, &nodeUIDs, &v.InventoryDigest, &v.MaxUnavailable, &v.DrainTimeoutSeconds, &v.HostActionTimeoutSeconds, &v.RequestedBy, &v.ApprovedBy, &v.ApprovedAt, &v.StartedAt, &v.FinishedAt, &results, &v.LastError, &v.IdempotencyKey, &v.RequestDigest, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.ClusterMaintenanceRunState(state)
	v.Action = controlplane.TargetNodeLifecycleAction(action)
	if len(nodes) > 0 {
		if decodeErr := decodeJSONColumn(nodes, &v.NodeNames, "postgres_cluster_maintenance.NodeNames"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(nodeUIDs) > 0 {
		if decodeErr := decodeJSONColumn(nodeUIDs, &v.NodeUIDs, "postgres_cluster_maintenance.NodeUIDs"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(results) > 0 {
		if decodeErr := decodeJSONColumn(results, &v.Results, "postgres_cluster_maintenance.Results"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}

func validMaintenanceEnvironment(v controlplane.ClusterEnvironment) bool {
	switch v {
	case controlplane.ClusterEnvironmentDevelopment, controlplane.ClusterEnvironmentStaging, controlplane.ClusterEnvironmentProduction:
		return true
	default:
		return false
	}
}
func validMaintenanceDrainTimeout(v int) bool { return v >= 30 && v <= 3600 }

func (s *PostgresStore) UpsertClusterMaintenanceProfile(ctx context.Context, v controlplane.ClusterMaintenanceProfile, expected int64, actor string) (controlplane.ClusterMaintenanceProfile, error) {
	var out controlplane.ClusterMaintenanceProfile
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var projectID string
		if e := tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1 FOR UPDATE`, v.ClusterID).Scan(&projectID); e != nil {
			return mapDBError(e)
		}
		if strings.TrimSpace(v.ProjectID) != "" && v.ProjectID != projectID {
			return controlplane.ErrNotFound
		}
		v.ProjectID = projectID
		v.Environment = controlplane.ClusterEnvironment(strings.ToUpper(strings.TrimSpace(string(v.Environment))))
		if !validMaintenanceEnvironment(v.Environment) || !validMaintenanceDrainTimeout(v.DefaultDrainTimeoutSeconds) {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		existing, e := scanMaintenanceProfile(tx.QueryRowContext(ctx, `SELECT `+maintenanceProfileColumns+` FROM cluster_maintenance_profiles WHERE cluster_id=$1 FOR UPDATE`, v.ClusterID))
		if e == sql.ErrNoRows {
			if expected != 0 {
				return controlplane.ErrConflict
			}
			v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("cmp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		} else if e != nil {
			return e
		} else {
			if expected == 0 || existing.Revision != expected {
				return controlplane.ErrConflict
			}
			v.ResourceMeta = existing.ResourceMeta
			v.Revision++
			v.UpdatedAt = now
		}
		v.UpdatedBy = strings.TrimSpace(actor)
		_, e = tx.ExecContext(ctx, `INSERT INTO cluster_maintenance_profiles(id,project_id,cluster_id,revision,environment,default_drain_timeout_seconds,updated_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(cluster_id) DO UPDATE SET revision=EXCLUDED.revision,environment=EXCLUDED.environment,default_drain_timeout_seconds=EXCLUDED.default_drain_timeout_seconds,updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at`, v.ID, v.ProjectID, v.ClusterID, v.Revision, string(v.Environment), v.DefaultDrainTimeoutSeconds, v.UpdatedBy, v.CreatedAt, v.UpdatedAt)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_maintenance.profile_upserted", "clusterMaintenanceProfile", v.ID, v.Revision, "", map[string]any{"clusterId": v.ClusterID, "environment": v.Environment, "method": controlplane.ClusterMaintenanceAuthorityMethod}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "clusterMaintenanceProfile", v.ID, "cluster_maintenance.profile_upserted", v)
	})
	return out, err
}
func (s *PostgresStore) GetClusterMaintenanceProfile(ctx context.Context, clusterID string) (controlplane.ClusterMaintenanceProfile, error) {
	v, e := scanMaintenanceProfile(s.db.QueryRowContext(ctx, `SELECT `+maintenanceProfileColumns+` FROM cluster_maintenance_profiles WHERE cluster_id=$1`, clusterID))
	return v, mapDBError(e)
}

func (s *PostgresStore) CreateClusterMaintenanceWindow(ctx context.Context, v controlplane.ClusterMaintenanceWindow, actor string) (controlplane.ClusterMaintenanceWindow, error) {
	var out controlplane.ClusterMaintenanceWindow
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var projectID string
		if e := tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1 FOR UPDATE`, v.ClusterID).Scan(&projectID); e != nil {
			return mapDBError(e)
		}
		if strings.TrimSpace(v.ProjectID) != "" && v.ProjectID != projectID {
			return controlplane.ErrNotFound
		}
		var profileID string
		if e := tx.QueryRowContext(ctx, `SELECT id FROM cluster_maintenance_profiles WHERE cluster_id=$1`, v.ClusterID).Scan(&profileID); e != nil {
			return fmt.Errorf("%w: cluster maintenance profile must be configured first", controlplane.ErrPrerequisite)
		}
		v.ProjectID = projectID
		v.Name = strings.TrimSpace(v.Name)
		v.StartsAt = v.StartsAt.UTC().Truncate(time.Microsecond)
		v.EndsAt = v.EndsAt.UTC().Truncate(time.Microsecond)
		if v.MaxUnavailable == 0 {
			v.MaxUnavailable = 1
		}
		if v.Name == "" || v.StartsAt.IsZero() || !v.EndsAt.After(v.StartsAt) || !v.EndsAt.After(utcNow(s.now)) || v.MaxUnavailable != 1 || !validMaintenanceDrainTimeout(v.DrainTimeoutSeconds) {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("cmw"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.ClusterMaintenanceWindowActive
		v.CreatedBy = strings.TrimSpace(actor)
		_, e := tx.ExecContext(ctx, `INSERT INTO cluster_maintenance_windows(id,project_id,cluster_id,revision,name,starts_at,ends_at,max_unavailable,drain_timeout_seconds,state,created_by,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$11)`, v.ID, v.ProjectID, v.ClusterID, v.Name, v.StartsAt, v.EndsAt, v.MaxUnavailable, v.DrainTimeoutSeconds, string(v.State), v.CreatedBy, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_maintenance.window_created", "clusterMaintenanceWindow", v.ID, 1, "", map[string]any{"clusterId": v.ClusterID, "startsAt": v.StartsAt, "endsAt": v.EndsAt, "maxUnavailable": v.MaxUnavailable}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "clusterMaintenanceWindow", v.ID, "cluster_maintenance.window_created", v)
	})
	return out, err
}
func (s *PostgresStore) GetClusterMaintenanceWindow(ctx context.Context, id string) (controlplane.ClusterMaintenanceWindow, error) {
	v, e := scanMaintenanceWindow(s.db.QueryRowContext(ctx, `SELECT `+maintenanceWindowColumns+` FROM cluster_maintenance_windows WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListClusterMaintenanceWindows(ctx context.Context, clusterID string) ([]controlplane.ClusterMaintenanceWindow, error) {
	q := `SELECT ` + maintenanceWindowColumns + ` FROM cluster_maintenance_windows`
	args := []any{}
	if clusterID != "" {
		q += ` WHERE cluster_id=$1`
		args = append(args, clusterID)
	}
	q += ` ORDER BY starts_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.ClusterMaintenanceWindow{}
	for rows.Next() {
		v, e := scanMaintenanceWindow(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *PostgresStore) CancelClusterMaintenanceWindow(ctx context.Context, id string, expected int64, actor string) (controlplane.ClusterMaintenanceWindow, error) {
	var out controlplane.ClusterMaintenanceWindow
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanMaintenanceWindow(tx.QueryRowContext(ctx, `SELECT `+maintenanceWindowColumns+` FROM cluster_maintenance_windows WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ClusterMaintenanceWindowActive {
			return controlplane.ErrInvalidTransition
		}
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM cluster_maintenance_runs WHERE window_id=$1 AND state IN ('AWAITING_APPROVAL','QUEUED','RUNNING','RESTORING')`, id).Scan(&count); e != nil {
			return e
		}
		if count > 0 {
			return fmt.Errorf("%w: active maintenance run is bound to this window", controlplane.ErrPrerequisite)
		}
		now := utcNow(s.now)
		v.State = controlplane.ClusterMaintenanceWindowCancelled
		v.CancelledBy = actor
		v.CancelledAt = &now
		v.Revision++
		v.UpdatedAt = now
		if _, e = tx.ExecContext(ctx, `UPDATE cluster_maintenance_windows SET revision=$2,state='CANCELLED',cancelled_by=$3,cancelled_at=$4,updated_at=$4 WHERE id=$1`, id, v.Revision, actor, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_maintenance.window_cancelled", "clusterMaintenanceWindow", id, v.Revision, "", map[string]any{"clusterId": v.ClusterID}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "clusterMaintenanceWindow", id, "cluster_maintenance.window_cancelled", v)
	})
	return out, err
}

func latestInventoryTx(ctx context.Context, tx *sql.Tx, clusterID string) (controlplane.ClusterInventory, error) {
	var v controlplane.ClusterInventory
	var nodes, addons, storageClasses, capacity, certificates, networking, workloadExplorer, apiResources, crds, caps []byte
	e := tx.QueryRowContext(ctx, `SELECT id,revision,cluster_id,observed_at,distribution,distribution_evidence_method,distribution_evidence_uid,distribution_evidence_version,kubernetes_version,nodes,addons,storage_classes,capacity,certificates,networking,workload_explorer,api_resources,crds,api_discovery_complete,crd_discovery_complete,schema_discovery_version,schema_discovery_digest,schema_discovery_complete,capabilities,digest,created_at,updated_at FROM cluster_inventory_snapshots WHERE cluster_id=$1 ORDER BY observed_at DESC,id DESC LIMIT 1`, clusterID).Scan(&v.ID, &v.Revision, &v.ClusterID, &v.ObservedAt, &v.Distribution, &v.DistributionEvidenceMethod, &v.DistributionEvidenceUID, &v.DistributionEvidenceVersion, &v.KubernetesVersion, &nodes, &addons, &storageClasses, &capacity, &certificates, &networking, &workloadExplorer, &apiResources, &crds, &v.APIDiscoveryComplete, &v.CRDDiscoveryComplete, &v.SchemaDiscoveryVersion, &v.SchemaDiscoveryDigest, &v.SchemaDiscoveryComplete, &caps, &v.Digest, &v.CreatedAt, &v.UpdatedAt)
	if e != nil {
		return v, mapDBError(e)
	}
	if decodeErr := decodeJSONColumn(nodes, &v.Nodes, "postgres_cluster_maintenance.Nodes"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(addons, &v.AddOns, "postgres_cluster_maintenance.AddOns"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(storageClasses, &v.StorageClasses, "postgres_cluster_maintenance.StorageClasses"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(capacity, &v.Capacity, "postgres_cluster_maintenance.Capacity"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(certificates, &v.Certificates, "postgres_cluster_maintenance.Certificates"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(networking, &v.Networking, "postgres_cluster_maintenance.Networking"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(workloadExplorer, &v.WorkloadExplorer, "postgres_cluster_maintenance.WorkloadExplorer"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(apiResources, &v.APIResources, "postgres_cluster_maintenance.APIResources"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(crds, &v.CRDs, "postgres_cluster_maintenance.CRDs"); decodeErr != nil {
		return v, decodeErr
	}
	if decodeErr := decodeJSONColumn(caps, &v.Capabilities, "postgres_cluster_maintenance.Capabilities"); decodeErr != nil {
		return v, decodeErr
	}
	return v, nil
}
func validateMaintenanceNodesPG(inv controlplane.ClusterInventory, names []string) ([]string, map[string]string, error) {
	if len(names) == 0 {
		return nil, nil, controlplane.ErrValidation
	}
	nodes := map[string]controlplane.ClusterNode{}
	for _, n := range inv.Nodes {
		nodes[n.Name] = n
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(names))
	uids := make(map[string]string, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" || seen[name] {
			return nil, nil, controlplane.ErrValidation
		}
		node, ok := nodes[name]
		if !ok {
			return nil, nil, controlplane.ErrValidation
		}
		if !node.Ready || strings.TrimSpace(node.UID) == "" {
			return nil, nil, controlplane.ErrPrerequisite
		}
		seen[name] = true
		out = append(out, name)
		uids[name] = strings.TrimSpace(node.UID)
	}
	return out, uids, nil
}

func maintenanceNodeIdentityMatchesPG(inv controlplane.ClusterInventory, names []string, expected map[string]string) error {
	_, current, err := validateMaintenanceNodesPG(inv, names)
	if err != nil {
		return err
	}
	if len(expected) != len(current) {
		return controlplane.ErrPrerequisite
	}
	for name, uid := range current {
		if strings.TrimSpace(expected[name]) != uid {
			return controlplane.ErrPrerequisite
		}
	}
	return nil
}

func normalizeMaintenanceActionPG(action controlplane.TargetNodeLifecycleAction) (controlplane.TargetNodeLifecycleAction, bool) {
	action = controlplane.TargetNodeLifecycleAction(strings.ToUpper(strings.TrimSpace(string(action))))
	if action == "" {
		action = controlplane.TargetNodeActionDrain
	}
	switch action {
	case controlplane.TargetNodeActionDrain, controlplane.TargetNodeActionOSPatch:
		return action, true
	default:
		return action, false
	}
}

func admitMaintenanceActionPG(v *controlplane.ClusterMaintenanceRun, inv controlplane.ClusterInventory) error {
	action, ok := normalizeMaintenanceActionPG(v.Action)
	if !ok {
		return fmt.Errorf("%w: maintenance action %q is not executable through cluster maintenance authority", controlplane.ErrValidation, v.Action)
	}
	v.Action = action
	if action == controlplane.TargetNodeActionOSPatch {
		d := controlplane.DescribeTargetNodeLifecycleAction(action, inv)
		if !d.Executable {
			blockers := append([]string(nil), d.Blockers...)
			for _, missing := range d.MissingCapabilities {
				blockers = append(blockers, "TARGET_CAPABILITY_MISSING:"+missing)
			}
			return fmt.Errorf("%w: OS patch executor is not admitted: %s", controlplane.ErrPrerequisite, strings.Join(blockers, "; "))
		}
		v.HostActionTimeoutSeconds = 3600
	} else {
		v.HostActionTimeoutSeconds = 0
	}
	return nil
}

func (s *PostgresStore) CreateClusterMaintenanceRun(ctx context.Context, v controlplane.ClusterMaintenanceRun, actor string) (controlplane.ClusterMaintenanceRun, bool, error) {
	var out controlplane.ClusterMaintenanceRun
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanMaintenanceRun(tx.QueryRowContext(ctx, `SELECT `+maintenanceRunColumns+` FROM cluster_maintenance_runs WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != v.RequestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			out = existing
			replay = true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}
		if strings.TrimSpace(v.IdempotencyKey) == "" || len(v.IdempotencyKey) > 200 || !strings.HasPrefix(v.RequestDigest, "sha256:") {
			return controlplane.ErrValidation
		}
		var projectID, inventoryDigest string
		if e = tx.QueryRowContext(ctx, `SELECT project_id,inventory_digest FROM managed_clusters WHERE id=$1 FOR UPDATE`, v.ClusterID).Scan(&projectID, &inventoryDigest); e != nil {
			return mapDBError(e)
		}
		if projectID != v.ProjectID {
			return controlplane.ErrNotFound
		}
		window, e := scanMaintenanceWindow(tx.QueryRowContext(ctx, `SELECT `+maintenanceWindowColumns+` FROM cluster_maintenance_windows WHERE id=$1 FOR UPDATE`, v.WindowID))
		if e != nil {
			return mapDBError(e)
		}
		if window.ClusterID != v.ClusterID || window.State != controlplane.ClusterMaintenanceWindowActive || !window.EndsAt.After(utcNow(s.now)) {
			return controlplane.ErrMaintenanceWindow
		}
		inv, e := latestInventoryTx(ctx, tx, v.ClusterID)
		if e != nil {
			return e
		}
		if inv.Digest == "" || inv.Digest != inventoryDigest {
			return controlplane.ErrPrerequisite
		}
		nodes, nodeUIDs, e := validateMaintenanceNodesPG(inv, v.NodeNames)
		if e != nil {
			return e
		}
		if e = admitMaintenanceActionPG(&v, inv); e != nil {
			return e
		}
		op, e := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, v.OperationID))
		if e != nil {
			return mapDBError(e)
		}
		if op.ProjectID != v.ProjectID || op.Kind != "CLUSTER_MAINTENANCE" || op.TargetRef != "cluster/"+v.ClusterID || op.State != controlplane.OperationAwaitingApproval {
			return controlplane.ErrPrerequisite
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("cmr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.ClusterMaintenanceAwaitingApproval
		v.NodeNames = nodes
		v.NodeUIDs = nodeUIDs
		v.InventoryDigest = inv.Digest
		v.MaxUnavailable = window.MaxUnavailable
		v.DrainTimeoutSeconds = window.DrainTimeoutSeconds
		v.RequestedBy = actor
		if e = controlplane.ValidateDay2CampaignContract(controlplane.Day2ContractForMaintenance(v, window)); e != nil {
			return e
		}
		nodesRaw, _ := json.Marshal(v.NodeNames)
		nodeUIDsRaw, _ := json.Marshal(v.NodeUIDs)
		resultsRaw, _ := json.Marshal(v.Results)
		_, e = tx.ExecContext(ctx, `INSERT INTO cluster_maintenance_runs(id,project_id,cluster_id,window_id,operation_id,revision,state,action,node_names,node_uids,inventory_digest,max_unavailable,drain_timeout_seconds,host_action_timeout_seconds,requested_by,results,last_error,idempotency_key,request_digest,created_at,updated_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14,$15::jsonb,'',$16,$17,$18,$18)`, v.ID, v.ProjectID, v.ClusterID, v.WindowID, v.OperationID, string(v.State), string(v.Action), nodesRaw, nodeUIDsRaw, v.InventoryDigest, v.MaxUnavailable, v.DrainTimeoutSeconds, v.HostActionTimeoutSeconds, actor, resultsRaw, v.IdempotencyKey, v.RequestDigest, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_maintenance.run_requested", "clusterMaintenanceRun", v.ID, 1, "", map[string]any{"clusterId": v.ClusterID, "windowId": v.WindowID, "operationId": v.OperationID, "nodes": v.NodeNames, "inventoryDigest": v.InventoryDigest}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "clusterMaintenanceRun", v.ID, "cluster_maintenance.run_requested", v)
	})
	return out, replay, err
}
func (s *PostgresStore) CreateClusterMaintenanceRunRequest(ctx context.Context, v controlplane.ClusterMaintenanceRun, opRequest controlplane.OperationRequest, opKey, actor, requestID string) (controlplane.ClusterMaintenanceRun, controlplane.Operation, bool, error) {
	actor = strings.TrimSpace(actor)
	opKey = strings.TrimSpace(opKey)
	if actor == "" || opKey == "" || len(opKey) > 200 {
		return controlplane.ClusterMaintenanceRun{}, controlplane.Operation{}, false, fmt.Errorf("%w: bounded operation idempotency key and actor are required", controlplane.ErrValidation)
	}
	if strings.TrimSpace(v.IdempotencyKey) == "" || len(v.IdempotencyKey) > 200 || !strings.HasPrefix(v.RequestDigest, "sha256:") {
		return controlplane.ClusterMaintenanceRun{}, controlplane.Operation{}, false, fmt.Errorf("%w: idempotencyKey and requestDigest are required", controlplane.ErrValidation)
	}
	if opRequest.ProjectID != v.ProjectID || opRequest.Kind != "CLUSTER_MAINTENANCE" || opRequest.TargetRef != "cluster/"+v.ClusterID || opRequest.DesiredRevision != v.RequestDigest {
		return controlplane.ClusterMaintenanceRun{}, controlplane.Operation{}, false, fmt.Errorf("%w: maintenance operation authority does not match the run request", controlplane.ErrValidation)
	}
	if opRequest.Risk != "low" && opRequest.Risk != "medium" && opRequest.Risk != "high" && opRequest.Risk != "critical" {
		return controlplane.ClusterMaintenanceRun{}, controlplane.Operation{}, false, fmt.Errorf("%w: invalid operation risk", controlplane.ErrValidation)
	}
	class, err := controlplane.NormalizeOperationClass(opRequest.Class)
	if err != nil {
		return controlplane.ClusterMaintenanceRun{}, controlplane.Operation{}, false, err
	}
	opRequest.Class = class
	opDigest := operationDigest(opRequest)
	var out controlplane.ClusterMaintenanceRun
	var op controlplane.Operation
	replay := false
	err = s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanMaintenanceRun(tx.QueryRowContext(ctx, `SELECT `+maintenanceRunColumns+` FROM cluster_maintenance_runs WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
		if e == nil {
			if existing.RequestDigest != v.RequestDigest {
				return controlplane.ErrIdempotencyConflict
			}
			linked, linkedErr := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, existing.OperationID))
			if linkedErr != nil {
				return mapDBError(linkedErr)
			}
			out, op, replay = existing, linked, true
			return nil
		}
		if e != sql.ErrNoRows {
			return e
		}

		var projectID, inventoryDigest string
		if e = tx.QueryRowContext(ctx, `SELECT project_id,inventory_digest FROM managed_clusters WHERE id=$1 FOR UPDATE`, v.ClusterID).Scan(&projectID, &inventoryDigest); e != nil {
			return mapDBError(e)
		}
		if projectID != v.ProjectID {
			return controlplane.ErrNotFound
		}
		window, e := scanMaintenanceWindow(tx.QueryRowContext(ctx, `SELECT `+maintenanceWindowColumns+` FROM cluster_maintenance_windows WHERE id=$1 FOR UPDATE`, v.WindowID))
		if e != nil {
			return mapDBError(e)
		}
		now := utcNow(s.now)
		if window.ClusterID != v.ClusterID || window.State != controlplane.ClusterMaintenanceWindowActive || !window.EndsAt.After(now) {
			return controlplane.ErrMaintenanceWindow
		}
		inv, e := latestInventoryTx(ctx, tx, v.ClusterID)
		if e != nil {
			return e
		}
		if inv.Digest == "" || inv.Digest != inventoryDigest {
			return controlplane.ErrPrerequisite
		}
		nodes, nodeUIDs, e := validateMaintenanceNodesPG(inv, v.NodeNames)
		if e != nil {
			return e
		}
		if e = admitMaintenanceActionPG(&v, inv); e != nil {
			return e
		}

		op, e = scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, opRequest.ProjectID, opKey))
		if e == nil {
			if op.RequestDigest != opDigest {
				return controlplane.ErrIdempotencyConflict
			}
		} else if e == sql.ErrNoRows {
			op = controlplane.Operation{
				ResourceMeta: controlplane.ResourceMeta{ID: s.id("op"), Revision: 1, CreatedAt: now, UpdatedAt: now},
				ProjectID:    opRequest.ProjectID, Kind: opRequest.Kind, TargetRef: opRequest.TargetRef, DesiredRevision: opRequest.DesiredRevision,
				State: controlplane.OperationDraft, Risk: opRequest.Risk, Class: class, RetryPolicy: controlplane.RetryPolicyForOperationClass(class),
				RecoveryCheckpointID: strings.TrimSpace(opRequest.RecoveryCheckpointID), IdempotencyKey: opKey, RequestDigest: opDigest, ActorID: actor,
			}
			if class == controlplane.OperationClassDestructive {
				if e = s.bindDestructiveRecoveryTx(ctx, tx, &op, now); e != nil {
					return e
				}
			}
			retryPolicy, _ := json.Marshal(op.RetryPolicy)
			if _, e = tx.ExecContext(ctx, `INSERT INTO operations(id,project_id,revision,kind,target_ref,desired_revision,state,risk,operation_class,retry_policy,attempt,retry_exhausted,recovery_checkpoint_id,recovery_evidence_digest,recovery_inventory_digest,idempotency_key,request_digest,actor_id,fence_token,last_error,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9::jsonb,0,false,NULLIF($10,''),$11,$12,$13,$14,$15,0,'',$16,$16)`, op.ID, op.ProjectID, op.Kind, op.TargetRef, op.DesiredRevision, string(op.State), op.Risk, string(op.Class), retryPolicy, op.RecoveryCheckpointID, op.RecoveryEvidenceDigest, op.RecoveryInventoryDigest, op.IdempotencyKey, op.RequestDigest, op.ActorID, now); e != nil {
				return mapDBError(e)
			}
			if e = s.appendAuditTx(ctx, tx, actor, "operation.created", "operation", op.ID, op.Revision, requestID, map[string]any{"state": op.State}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "operation", op.ID, "operation.created", op); e != nil {
				return e
			}
		} else {
			return e
		}

		transition := func(to controlplane.OperationState) error {
			if !controlplane.CanTransition(op.State, to) {
				return controlplane.ErrInvalidTransition
			}
			expected := op.Revision
			op.State = to
			op.LastError = ""
			op.Revision++
			op.UpdatedAt = utcNow(s.now)
			if _, updateErr := tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,last_error='',updated_at=$4 WHERE id=$1 AND revision=$5`, op.ID, op.Revision, string(op.State), op.UpdatedAt, expected); updateErr != nil {
				return mapDBError(updateErr)
			}
			if auditErr := s.appendAuditTx(ctx, tx, actor, "operation.transitioned", "operation", op.ID, op.Revision, "", map[string]any{"state": to}); auditErr != nil {
				return auditErr
			}
			return s.appendOutboxTx(ctx, tx, "operation", op.ID, "operation.transitioned", op)
		}
		if op.State == controlplane.OperationDraft {
			if e = transition(controlplane.OperationPlanning); e != nil {
				return e
			}
		}
		if op.State == controlplane.OperationPlanning {
			if e = transition(controlplane.OperationAwaitingApproval); e != nil {
				return e
			}
		}
		if op.State != controlplane.OperationAwaitingApproval {
			return fmt.Errorf("%w: linked maintenance operation is not awaiting approval", controlplane.ErrPrerequisite)
		}

		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("cmr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.OperationID = op.ID
		v.State = controlplane.ClusterMaintenanceAwaitingApproval
		v.NodeNames = nodes
		v.NodeUIDs = nodeUIDs
		v.InventoryDigest = inv.Digest
		v.MaxUnavailable = window.MaxUnavailable
		v.DrainTimeoutSeconds = window.DrainTimeoutSeconds
		v.RequestedBy = actor
		if e = controlplane.ValidateDay2CampaignContract(controlplane.Day2ContractForMaintenance(v, window)); e != nil {
			return e
		}
		nodesRaw, _ := json.Marshal(v.NodeNames)
		nodeUIDsRaw, _ := json.Marshal(v.NodeUIDs)
		resultsRaw, _ := json.Marshal(v.Results)
		if _, e = tx.ExecContext(ctx, `INSERT INTO cluster_maintenance_runs(id,project_id,cluster_id,window_id,operation_id,revision,state,action,node_names,node_uids,inventory_digest,max_unavailable,drain_timeout_seconds,host_action_timeout_seconds,requested_by,results,last_error,idempotency_key,request_digest,created_at,updated_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14,$15::jsonb,'',$16,$17,$18,$18)`, v.ID, v.ProjectID, v.ClusterID, v.WindowID, v.OperationID, string(v.State), string(v.Action), nodesRaw, nodeUIDsRaw, v.InventoryDigest, v.MaxUnavailable, v.DrainTimeoutSeconds, v.HostActionTimeoutSeconds, actor, resultsRaw, v.IdempotencyKey, v.RequestDigest, now); e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_maintenance.run_requested", "clusterMaintenanceRun", v.ID, 1, "", map[string]any{"clusterId": v.ClusterID, "windowId": v.WindowID, "operationId": v.OperationID, "nodes": v.NodeNames, "inventoryDigest": v.InventoryDigest}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "clusterMaintenanceRun", v.ID, "cluster_maintenance.run_requested", v); e != nil {
			return e
		}
		out = v
		return nil
	})
	return out, op, replay, err
}

func (s *PostgresStore) GetClusterMaintenanceRun(ctx context.Context, id string) (controlplane.ClusterMaintenanceRun, error) {
	v, e := scanMaintenanceRun(s.db.QueryRowContext(ctx, `SELECT `+maintenanceRunColumns+` FROM cluster_maintenance_runs WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListClusterMaintenanceRuns(ctx context.Context, clusterID string) ([]controlplane.ClusterMaintenanceRun, error) {
	q := `SELECT ` + maintenanceRunColumns + ` FROM cluster_maintenance_runs`
	args := []any{}
	if clusterID != "" {
		q += ` WHERE cluster_id=$1`
		args = append(args, clusterID)
	}
	q += ` ORDER BY created_at,id`
	rows, e := s.db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []controlplane.ClusterMaintenanceRun{}
	for rows.Next() {
		v, e := scanMaintenanceRun(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ApproveClusterMaintenanceRun(ctx context.Context, id string, expected int64, actor string) (controlplane.ClusterMaintenanceRun, error) {
	var out controlplane.ClusterMaintenanceRun
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanMaintenanceRun(tx.QueryRowContext(ctx, `SELECT `+maintenanceRunColumns+` FROM cluster_maintenance_runs WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ClusterMaintenanceAwaitingApproval {
			return controlplane.ErrInvalidTransition
		}
		if e = controlplane.ValidateDay2IndependentApproval(v.RequestedBy, actor); e != nil {
			return e
		}
		window, e := scanMaintenanceWindow(tx.QueryRowContext(ctx, `SELECT `+maintenanceWindowColumns+` FROM cluster_maintenance_windows WHERE id=$1 FOR UPDATE`, v.WindowID))
		if e != nil {
			return mapDBError(e)
		}
		if window.State != controlplane.ClusterMaintenanceWindowActive || !window.EndsAt.After(utcNow(s.now)) {
			return controlplane.ErrMaintenanceWindow
		}
		inv, e := latestInventoryTx(ctx, tx, v.ClusterID)
		if e != nil {
			return e
		}
		if inv.Digest != v.InventoryDigest {
			return controlplane.ErrPrerequisite
		}
		if e = maintenanceNodeIdentityMatchesPG(inv, v.NodeNames, v.NodeUIDs); e != nil {
			return e
		}
		op, e := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, v.OperationID))
		if e != nil {
			return mapDBError(e)
		}
		if op.State != controlplane.OperationAwaitingApproval {
			return controlplane.ErrPrerequisite
		}
		now := utcNow(s.now)
		op.State = controlplane.OperationQueued
		op.Revision += 2
		op.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state='QUEUED',updated_at=$3 WHERE id=$1`, op.ID, op.Revision, now)
		if e != nil {
			return e
		}
		v.State = controlplane.ClusterMaintenanceQueued
		v.ApprovedBy = actor
		v.ApprovedAt = &now
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE cluster_maintenance_runs SET revision=$2,state='QUEUED',approved_by=$3,approved_at=$4,updated_at=$4 WHERE id=$1`, id, v.Revision, actor, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "cluster_maintenance.run_approved", "clusterMaintenanceRun", id, v.Revision, "", map[string]any{"operationId": v.OperationID, "windowId": v.WindowID}); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "operation.approved_queued", "operation", op.ID, op.Revision, "", map[string]any{"maintenanceRunId": id}); e != nil {
			return e
		}
		out = v
		if e = s.appendOutboxTx(ctx, tx, "clusterMaintenanceRun", id, "cluster_maintenance.run_queued", v); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "operation", op.ID, "operation.queued", op)
	})
	return out, err
}

func (s *PostgresStore) NextClusterMaintenanceTask(ctx context.Context, clusterID, agentTokenDigest string) (controlplane.ClusterMaintenanceRun, controlplane.Operation, error) {
	var out controlplane.ClusterMaintenanceRun
	var opOut controlplane.Operation
	noTask := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		noTask = false
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, agentTokenDigest); e != nil {
			return e
		}
		now := utcNow(s.now)
		if e := s.expireStaleClusterMaintenanceTx(ctx, tx, clusterID, now); e != nil {
			return e
		}
		inv, e := latestInventoryTx(ctx, tx, clusterID)
		if e != nil {
			return e
		}
		if !inventoryHasCapabilityPG(inv, controlplane.ClusterMaintenanceFencedReportCapability) {
			noTask = true
			return nil
		}
		var clusterDigest string
		if e = tx.QueryRowContext(ctx, `SELECT inventory_digest FROM managed_clusters WHERE id=$1`, clusterID).Scan(&clusterDigest); e != nil {
			return mapDBError(e)
		}
		rows, e := tx.QueryContext(ctx, `SELECT id FROM cluster_maintenance_runs WHERE cluster_id=$1 AND state='QUEUED' ORDER BY created_at,id FOR UPDATE SKIP LOCKED`, clusterID)
		if e != nil {
			return e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return e
		}
		if e = rows.Close(); e != nil {
			return e
		}
		for _, id := range ids {
			v, scanErr := scanMaintenanceRun(tx.QueryRowContext(ctx, `SELECT `+maintenanceRunColumns+` FROM cluster_maintenance_runs WHERE id=$1`, id))
			if scanErr != nil {
				return mapDBError(scanErr)
			}
			window, windowErr := scanMaintenanceWindow(tx.QueryRowContext(ctx, `SELECT `+maintenanceWindowColumns+` FROM cluster_maintenance_windows WHERE id=$1 FOR UPDATE`, v.WindowID))
			if windowErr != nil {
				return mapDBError(windowErr)
			}
			op, opErr := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, v.OperationID))
			if opErr != nil {
				return mapDBError(opErr)
			}
			if op.State != controlplane.OperationQueued {
				if e = s.failQueuedClusterMaintenanceTx(ctx, tx, v, op, "maintenance authority state is inconsistent", now); e != nil {
					return e
				}
				continue
			}
			if window.State != controlplane.ClusterMaintenanceWindowActive {
				if e = s.failQueuedClusterMaintenanceTx(ctx, tx, v, op, "maintenance window is no longer active", now); e != nil {
					return e
				}
				continue
			}
			if e = controlplane.ValidateDay2ExecutionWindow(window.StartsAt, window.EndsAt, now); e != nil {
				if now.Before(window.StartsAt) {
					continue
				}
				if e = s.failQueuedClusterMaintenanceTx(ctx, tx, v, op, "maintenance window expired before task claim", now); e != nil {
					return e
				}
				continue
			}
			if inv.Digest != v.InventoryDigest || clusterDigest != v.InventoryDigest {
				if e = s.failQueuedClusterMaintenanceTx(ctx, tx, v, op, "cluster inventory changed after maintenance approval; submit a new run", now); e != nil {
					return e
				}
				continue
			}
			if validateErr := maintenanceNodeIdentityMatchesPG(inv, v.NodeNames, v.NodeUIDs); validateErr != nil {
				if e = s.failQueuedClusterMaintenanceTx(ctx, tx, v, op, "maintenance node identity changed after approval; submit a new run", now); e != nil {
					return e
				}
				continue
			}
			if v.Action == controlplane.TargetNodeActionOSPatch {
				d := controlplane.DescribeTargetNodeLifecycleAction(v.Action, inv)
				if !d.Executable {
					if e = s.failQueuedClusterMaintenanceTx(ctx, tx, v, op, "OS patch target capability/executor admission changed after approval", now); e != nil {
						return e
					}
					continue
				}
			}
			v.State = controlplane.ClusterMaintenanceRunning
			v.StartedAt = &now
			v.Revision++
			v.UpdatedAt = now
			op.State = controlplane.OperationRunning
			op.Attempt++
			op.FenceToken++
			op.LeaseOwner = "cluster-maintenance-agent:" + clusterID
			lease := now.Add(maintenanceLeaseDurationPG(v))
			op.LeaseExpiresAt = &lease
			op.Revision++
			op.UpdatedAt = now
			if _, e = tx.ExecContext(ctx, `UPDATE cluster_maintenance_runs SET revision=$2,state='RUNNING',started_at=$3,updated_at=$3 WHERE id=$1`, v.ID, v.Revision, now); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state='RUNNING',attempt=$3,fence_token=$4,lease_owner=$5,lease_expires_at=$6,updated_at=$7 WHERE id=$1`, op.ID, op.Revision, op.Attempt, op.FenceToken, op.LeaseOwner, lease, now); e != nil {
				return e
			}
			if e = s.appendAuditTx(ctx, tx, "cluster-agent", "cluster_maintenance.run_claimed", "clusterMaintenanceRun", v.ID, v.Revision, "", map[string]any{"operationId": op.ID, "fenceToken": op.FenceToken}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "clusterMaintenanceRun", v.ID, "cluster_maintenance.run_started", v); e != nil {
				return e
			}
			out, opOut = v, op
			return nil
		}
		noTask = true
		return nil
	})
	if err != nil {
		return controlplane.ClusterMaintenanceRun{}, controlplane.Operation{}, err
	}
	if noTask {
		return controlplane.ClusterMaintenanceRun{}, controlplane.Operation{}, controlplane.ErrNotFound
	}
	return out, opOut, nil
}

func (s *PostgresStore) ReportClusterMaintenanceTask(ctx context.Context, clusterID, runID string, expected int64, result controlplane.ClusterMaintenanceTaskResult) (controlplane.ClusterMaintenanceRun, controlplane.Operation, error) {
	var out controlplane.ClusterMaintenanceRun
	var opOut controlplane.Operation
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanMaintenanceRun(tx.QueryRowContext(ctx, `SELECT `+maintenanceRunColumns+` FROM cluster_maintenance_runs WHERE id=$1 AND cluster_id=$2 FOR UPDATE`, runID, clusterID))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ClusterMaintenanceRunning {
			return controlplane.ErrInvalidTransition
		}
		cluster, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1`, clusterID))
		if e != nil {
			return mapDBError(e)
		}
		if !controlplane.ClusterTaskAdmitted(cluster) {
			return controlplane.ErrPrerequisite
		}
		op, e := scanOperation(tx.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id=$1 FOR UPDATE`, v.OperationID))
		if e != nil {
			return mapDBError(e)
		}
		now := utcNow(s.now)
		if op.State != controlplane.OperationRunning || op.LeaseOwner != "cluster-maintenance-agent:"+clusterID {
			return controlplane.ErrPrerequisite
		}
		if e = controlplane.ValidateDay2Fence(op.FenceToken, result.OperationFenceToken, op.LeaseExpiresAt, now); e != nil {
			return e
		}
		if len(result.Results) == 0 {
			return controlplane.ErrValidation
		}
		selected := map[string]bool{}
		for _, n := range v.NodeNames {
			selected[n] = true
		}
		seen := map[string]bool{}
		needsOperator := false
		allSafe := true
		for _, r := range result.Results {
			if !selected[r.NodeName] || seen[r.NodeName] {
				return controlplane.ErrValidation
			}
			seen[r.NodeName] = true
			if r.Cordoned && !r.Uncordoned {
				needsOperator = true
			}
			if !r.Cordoned || !r.DrainAttempted || !r.Drained || !r.Uncordoned || strings.TrimSpace(r.Error) != "" {
				allSafe = false
			}
			if v.Action == controlplane.TargetNodeActionOSPatch && (!r.HostActionAttempted || !r.HostActionSucceeded || r.HostActionAuthority != "TARGET_NODE_HOST_MAINTENANCE_EXECUTOR_V1" || strings.TrimSpace(r.HostActionEvidence) == "") {
				allSafe = false
			}
		}
		if len(seen) != len(selected) {
			return controlplane.ErrValidation
		}
		if result.Success && !allSafe {
			return controlplane.ErrValidation
		}
		v.Results = append([]controlplane.NodeMaintenanceResult(nil), result.Results...)
		v.FinishedAt = &now
		v.LastError = strings.TrimSpace(result.Error)
		if result.Success {
			v.State = controlplane.ClusterMaintenanceSucceeded
			op.State = controlplane.OperationSucceeded
			op.Revision += 2
			op.LastError = ""
		} else if needsOperator {
			v.State = controlplane.ClusterMaintenanceNeedsOperator
			if v.LastError == "" {
				v.LastError = "one or more nodes could not be restored to schedulable state"
			}
			op.State = controlplane.OperationNeedsOperator
			op.Revision += 2
			op.LastError = v.LastError
		} else {
			v.State = controlplane.ClusterMaintenanceFailed
			if v.LastError == "" {
				v.LastError = "cluster maintenance task failed"
			}
			op.State = controlplane.OperationFailed
			op.Revision++
			op.LastError = v.LastError
		}
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
		op.UpdatedAt = now
		v.Revision++
		v.UpdatedAt = now
		resultsRaw, _ := json.Marshal(v.Results)
		if _, e = tx.ExecContext(ctx, `UPDATE cluster_maintenance_runs SET revision=$2,state=$3,results=$4::jsonb,last_error=$5,finished_at=$6,updated_at=$6 WHERE id=$1`, v.ID, v.Revision, string(v.State), resultsRaw, v.LastError, now); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE operations SET revision=$2,state=$3,lease_owner='',lease_expires_at=NULL,last_error=$4,updated_at=$5 WHERE id=$1`, op.ID, op.Revision, string(op.State), op.LastError, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "cluster_maintenance.run_reported", "clusterMaintenanceRun", runID, v.Revision, "", map[string]any{"operationId": op.ID, "state": v.State, "action": v.Action, "nodes": len(v.Results), "method": controlplane.ClusterMaintenanceAuthorityMethod}); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "clusterMaintenanceRun", runID, "cluster_maintenance.run_completed", v); e != nil {
			return e
		}
		if e = s.appendOutboxTx(ctx, tx, "operation", op.ID, "operation.completed", op); e != nil {
			return e
		}
		out, opOut = v, op
		return nil
	})
	return out, opOut, err
}

var _ = sort.Strings
