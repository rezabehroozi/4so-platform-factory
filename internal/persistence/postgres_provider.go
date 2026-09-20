package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/targetmodel"
)

const providerProfileColumns = `id,project_id,management_cluster_id,revision,name,display_name,adapter,namespace,cluster_class_name,worker_class_name,default_kubernetes_version,kubernetes_series,architectures,distribution_profiles,infrastructure_provider,infrastructure_endpoint,credential_ref,max_worker_replicas,state,desired_digest,observed_digest,requested_by,idempotency_key,request_digest,task_attempt,task_fence_token,task_lease_expires_at,last_error,created_at,updated_at`
const providerClusterColumns = `id,project_id,provider_profile_id,management_cluster_id,revision,name,display_name,resource_name,namespace,state,desired,applied,desired_digest,observed_digest,pending_action,requested_by,approved_by,approved_at,idempotency_key,request_digest,task_attempt,task_fence_token,task_lease_expires_at,phase,COALESCE(destructive_operation_id,''),compatibility_decision,target_node_mutation,last_error,created_at,updated_at`

var providerDNSLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var providerKubeVersion = regexp.MustCompile(`^v1\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
var providerKubeSeries = regexp.MustCompile(`^v1\.[0-9]+$`)

func scanProviderProfile(row interface{ Scan(...any) error }) (controlplane.ProviderProfile, error) {
	var v controlplane.ProviderProfile
	var series, architectures, distributions []byte
	var state string
	err := row.Scan(&v.ID, &v.ProjectID, &v.ManagementClusterID, &v.Revision, &v.Name, &v.DisplayName, &v.Adapter, &v.Namespace, &v.ClusterClassName, &v.WorkerClassName, &v.DefaultKubernetesVersion, &series, &architectures, &distributions, &v.InfrastructureProvider, &v.InfrastructureEndpoint, &v.CredentialRef, &v.MaxWorkerReplicas, &state, &v.DesiredDigest, &v.ObservedDigest, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskLeaseExpiresAt, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.ProviderProfileState(state)
	if len(series) > 0 {
		if decodeErr := decodeJSONColumn(series, &v.KubernetesSeries, "postgres_provider.KubernetesSeries"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(architectures) > 0 {
		if decodeErr := decodeJSONColumn(architectures, &v.Architectures, "postgres_provider.Architectures"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(distributions) > 0 {
		if decodeErr := decodeJSONColumn(distributions, &v.DistributionProfiles, "postgres_provider.DistributionProfiles"); decodeErr != nil {
			return v, decodeErr
		}
	}
	v.DistributionProfiles = targetmodel.CanonicalDistributionSet(v.DistributionProfiles)
	v.DistributionIdentities = append([]string(nil), v.DistributionProfiles...)
	v.ProvisioningMode = targetmodel.ProvisioningModeFromAdapter(v.Adapter)
	if v.InfrastructureProvider == "" {
		v.InfrastructureProvider = targetmodel.InfrastructureUnspecified
	}
	return v, err
}

func normalizeProviderClusterTargetModel(spec *controlplane.ProviderClusterSpec) {
	if spec == nil {
		return
	}
	identity := spec.DistributionIdentity
	if identity == "" {
		identity = spec.Distribution
	}
	spec.DistributionIdentity = targetmodel.CanonicalDistribution(identity)
	spec.Distribution = spec.DistributionIdentity
	if spec.ProvisioningMode == "" {
		spec.ProvisioningMode = targetmodel.ProvisioningClusterAPI
	}
	if spec.InfrastructureProvider == "" {
		spec.InfrastructureProvider = targetmodel.InfrastructureUnspecified
	}
}

func scanProviderCluster(row interface{ Scan(...any) error }) (controlplane.ProviderCluster, error) {
	var v controlplane.ProviderCluster
	var desired, applied, compatRaw, mutationRaw []byte
	var state string
	err := row.Scan(&v.ID, &v.ProjectID, &v.ProviderProfileID, &v.ManagementClusterID, &v.Revision, &v.Name, &v.DisplayName, &v.ResourceName, &v.Namespace, &state, &desired, &applied, &v.DesiredDigest, &v.ObservedDigest, &v.PendingAction, &v.RequestedBy, &v.ApprovedBy, &v.ApprovedAt, &v.IdempotencyKey, &v.RequestDigest, &v.TaskAttempt, &v.TaskFenceToken, &v.TaskLeaseExpiresAt, &v.Phase, &v.DestructiveOperationID, &compatRaw, &mutationRaw, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.ProviderClusterState(state)
	if len(desired) > 0 {
		if decodeErr := decodeJSONColumn(desired, &v.Desired, "postgres_provider.Desired"); decodeErr != nil {
			return v, decodeErr
		}
	}
	normalizeProviderClusterTargetModel(&v.Desired)
	if len(applied) > 0 {
		if decodeErr := decodeJSONColumn(applied, &v.Applied, "postgres_provider.Applied"); decodeErr != nil {
			return v, decodeErr
		}
	}
	normalizeProviderClusterTargetModel(&v.Applied)
	if len(mutationRaw) > 0 {
		if decodeErr := decodeJSONColumn(mutationRaw, &v.TargetNodeMutation, "postgres_provider.TargetNodeMutation"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(compatRaw) > 0 {
		if decodeErr := decodeJSONColumn(compatRaw, &v.Compatibility, "postgres_provider.Compatibility"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}

func normalizeProviderVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func normalizeProviderProfile(v *controlplane.ProviderProfile) error {
	return controlplane.NormalizeAndValidateProviderProfile(v)
}

func providerSpecAdmitted(profile controlplane.ProviderProfile, spec *controlplane.ProviderClusterSpec) error {
	controlplane.NormalizeProviderCompatibility(&profile, spec)
	spec.KubernetesVersion = normalizeProviderVersion(spec.KubernetesVersion)
	if !providerKubeVersion.MatchString(spec.KubernetesVersion) || (spec.ControlPlaneReplicas != 1 && spec.ControlPlaneReplicas != 3) || spec.WorkerReplicas < 1 || spec.WorkerReplicas > profile.MaxWorkerReplicas {
		return controlplane.ErrValidation
	}
	if controlplane.ProviderCompatibilityDecision(profile, *spec).Status != "PASS" {
		return controlplane.ErrValidation
	}
	return nil
}

func postgresProviderResourceName(name, id string) string {
	clean := normalizedName(name)
	var b strings.Builder
	for _, r := range clean {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	clean = strings.Trim(b.String(), "-")
	if clean == "" {
		clean = "cluster"
	}
	suffix := id
	if len(suffix) > 6 {
		suffix = suffix[len(suffix)-6:]
	}
	maxName := 63 - len("pf--") - len(suffix)
	if len(clean) > maxName {
		clean = strings.Trim(clean[:maxName], "-")
	}
	return "pf-" + clean + "-" + suffix
}

func (s *PostgresStore) CreateProviderProfile(ctx context.Context, v controlplane.ProviderProfile, actor string) (controlplane.ProviderProfile, bool, error) {
	var out controlplane.ProviderProfile
	replay := false
	if err := normalizeProviderProfile(&v); err != nil {
		return out, false, err
	}
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
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
		var clusterProject string
		if e = tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1`, v.ManagementClusterID).Scan(&clusterProject); e != nil {
			return mapDBError(e)
		}
		if clusterProject != v.ProjectID {
			return controlplane.ErrNotFound
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("prv"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = controlplane.ProviderProfileVerifyQueued
		v.RequestedBy = actor
		series, _ := json.Marshal(v.KubernetesSeries)
		architectures, _ := json.Marshal(v.Architectures)
		distributions, _ := json.Marshal(v.DistributionProfiles)
		_, e = tx.ExecContext(ctx, `INSERT INTO provider_profiles(id,project_id,management_cluster_id,revision,name,display_name,adapter,namespace,cluster_class_name,worker_class_name,default_kubernetes_version,kubernetes_series,architectures,distribution_profiles,infrastructure_provider,infrastructure_endpoint,credential_ref,max_worker_replicas,state,desired_digest,requested_by,idempotency_key,request_digest,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$24)`, v.ID, v.ProjectID, v.ManagementClusterID, v.Name, v.DisplayName, v.Adapter, v.Namespace, v.ClusterClassName, v.WorkerClassName, v.DefaultKubernetesVersion, series, architectures, distributions, v.InfrastructureProvider, v.InfrastructureEndpoint, v.CredentialRef, v.MaxWorkerReplicas, string(v.State), v.DesiredDigest, actor, v.IdempotencyKey, v.RequestDigest, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "provider_profile.created", "providerProfile", v.ID, 1, "", map[string]any{"managementClusterId": v.ManagementClusterID, "clusterClass": v.ClusterClassName}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerProfile", v.ID, "provider_profile.verify.queued", v)
	})
	return out, replay, err
}

func (s *PostgresStore) GetProviderProfile(ctx context.Context, id string) (controlplane.ProviderProfile, error) {
	v, err := scanProviderProfile(s.db.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListProviderProfiles(ctx context.Context, projectID, clusterID string) ([]controlplane.ProviderProfile, error) {
	q := `SELECT ` + providerProfileColumns + ` FROM provider_profiles WHERE 1=1`
	args := []any{}
	for _, f := range []struct{ value, column string }{{projectID, "project_id"}, {clusterID, "management_cluster_id"}} {
		if f.value != "" {
			args = append(args, f.value)
			q += fmt.Sprintf(" AND %s=$%d", f.column, len(args))
		}
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.ProviderProfile{}
	for rows.Next() {
		v, e := scanProviderProfile(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RetryProviderProfile(ctx context.Context, id string, expected int64, actor string) (controlplane.ProviderProfile, error) {
	var out controlplane.ProviderProfile
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ProviderProfileFailed {
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.State, v.LastError, v.Revision, v.UpdatedAt = controlplane.ProviderProfileVerifyQueued, "", v.Revision+1, now
		_, e = tx.ExecContext(ctx, `UPDATE provider_profiles SET revision=$2,state=$3,last_error='',updated_at=$4 WHERE id=$1`, id, v.Revision, string(v.State), now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "provider_profile.retry.queued", "providerProfile", id, v.Revision, "", nil); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerProfile", id, "provider_profile.verify.queued", v)
	})
	return out, err
}

func (s *PostgresStore) NextProviderProfileTask(ctx context.Context, clusterID, token string) (controlplane.ProviderProfile, error) {
	var out controlplane.ProviderProfile
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, token); e != nil {
			return e
		}
		now := utcNow(s.now)
		v, e := scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE management_cluster_id=$1 AND (state='VERIFY_QUEUED' OR (state='VERIFYING' AND (task_lease_expires_at IS NULL OR task_lease_expires_at<=$2))) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, clusterID, now))
		if e != nil {
			return mapDBError(e)
		}
		lease := now.Add(controlplane.AgentTaskLeaseDuration)
		v.State = controlplane.ProviderProfileVerifying
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseExpiresAt = &lease
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE provider_profiles SET revision=$2,state=$3,task_attempt=$4,task_fence_token=$5,task_lease_expires_at=$6,updated_at=$7 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.TaskAttempt, v.TaskFenceToken, lease, now)
		out = v
		return e
	})
	return out, err
}

func (s *PostgresStore) ReportProviderProfileTask(ctx context.Context, clusterID, token string, expected int64, result controlplane.ProviderProfileTaskResult) (controlplane.ProviderProfile, error) {
	var out controlplane.ProviderProfile
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, token); e != nil {
			return e
		}
		v, e := scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE id=$1 FOR UPDATE`, result.ProfileID))
		if e != nil {
			return mapDBError(e)
		}
		if v.ManagementClusterID != clusterID {
			return controlplane.ErrNotFound
		}
		now := utcNow(s.now)
		if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ProviderProfileVerifying {
			return controlplane.ErrInvalidTransition
		}
		if result.Success && strings.HasPrefix(result.ObservedDigest, "sha256:") {
			v.State, v.ObservedDigest, v.LastError = controlplane.ProviderProfileReady, result.ObservedDigest, ""
		} else {
			v.State, v.LastError = controlplane.ProviderProfileFailed, strings.TrimSpace(result.Error)
			if v.LastError == "" {
				v.LastError = "provider profile verification failed"
			}
		}
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE provider_profiles SET revision=$2,state=$3,observed_digest=$4,last_error=$5,task_lease_expires_at=NULL,updated_at=$6 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.ObservedDigest, v.LastError, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "provider_profile.verify.reported", "providerProfile", v.ID, v.Revision, "", map[string]any{"success": result.Success, "taskFenceToken": result.TaskFenceToken}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerProfile", v.ID, "provider_profile.state.changed", v)
	})
	return out, err
}

func (s *PostgresStore) CreateProviderCluster(ctx context.Context, v controlplane.ProviderCluster, actor string) (controlplane.ProviderCluster, bool, error) {
	var out controlplane.ProviderCluster
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanProviderCluster(tx.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
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
		profile, e := scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE id=$1 FOR UPDATE`, v.ProviderProfileID))
		if e != nil {
			return mapDBError(e)
		}
		if profile.ProjectID != v.ProjectID || profile.State != controlplane.ProviderProfileReady {
			return controlplane.ErrValidation
		}
		v.Name, v.DisplayName = normalizedName(v.Name), strings.TrimSpace(v.DisplayName)
		v.Desired.KubernetesVersion = normalizeProviderVersion(v.Desired.KubernetesVersion)
		controlplane.NormalizeProviderCompatibility(&profile, &v.Desired)
		v.DesiredDigest = controlplane.ProviderClusterDesiredDigest(v.ProviderProfileID, v.Name, v.Desired)
		if v.Name == "" || !providerDNSLabel.MatchString(v.Name) || v.DisplayName == "" || strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") || !strings.HasPrefix(v.DesiredDigest, "sha256:") {
			return controlplane.ErrValidation
		}
		if e = providerSpecAdmitted(profile, &v.Desired); e != nil {
			return e
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("pcl"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.ManagementClusterID, v.Namespace = profile.ManagementClusterID, profile.Namespace
		v.ResourceName = postgresProviderResourceName(v.Name, v.ID)
		v.State, v.PendingAction, v.RequestedBy = controlplane.ProviderClusterAwaitingApproval, "PROVISION", actor
		v.Compatibility = controlplane.ProviderCompatibilityDecision(profile, v.Desired)
		desired, _ := json.Marshal(v.Desired)
		applied, _ := json.Marshal(v.Applied)
		compatRaw, _ := json.Marshal(v.Compatibility)
		_, e = tx.ExecContext(ctx, `INSERT INTO provider_clusters(id,project_id,provider_profile_id,management_cluster_id,revision,name,display_name,resource_name,namespace,state,desired,applied,desired_digest,pending_action,requested_by,idempotency_key,request_digest,compatibility_decision,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14,$15,$16,$17::jsonb,$18,$18)`, v.ID, v.ProjectID, v.ProviderProfileID, v.ManagementClusterID, v.Name, v.DisplayName, v.ResourceName, v.Namespace, string(v.State), desired, applied, v.DesiredDigest, v.PendingAction, actor, v.IdempotencyKey, v.RequestDigest, compatRaw, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "provider_cluster.created", "providerCluster", v.ID, 1, "", map[string]any{"providerProfileId": v.ProviderProfileID, "resourceName": v.ResourceName}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerCluster", v.ID, "provider_cluster.approval.requested", v)
	})
	return out, replay, err
}

func (s *PostgresStore) GetProviderCluster(ctx context.Context, id string) (controlplane.ProviderCluster, error) {
	v, err := scanProviderCluster(s.db.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE id=$1`, id))
	return v, mapDBError(err)
}

func (s *PostgresStore) ListProviderClusters(ctx context.Context, projectID, profileID string) ([]controlplane.ProviderCluster, error) {
	q := `SELECT ` + providerClusterColumns + ` FROM provider_clusters WHERE 1=1`
	args := []any{}
	for _, f := range []struct{ value, column string }{{projectID, "project_id"}, {profileID, "provider_profile_id"}} {
		if f.value != "" {
			args = append(args, f.value)
			q += fmt.Sprintf(" AND %s=$%d", f.column, len(args))
		}
	}
	q += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []controlplane.ProviderCluster{}
	for rows.Next() {
		v, e := scanProviderCluster(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) QueueProviderClusterChange(ctx context.Context, id string, expected int64, action string, desired controlplane.ProviderClusterSpec, desiredDigest, actor, requestDigest, recoveryCheckpointID string) (controlplane.ProviderCluster, error) {
	var out controlplane.ProviderCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanProviderCluster(tx.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		action = strings.ToUpper(strings.TrimSpace(action))
		if action == "DELETE" {
			if v.State != controlplane.ProviderClusterActive && v.State != controlplane.ProviderClusterFailed && v.State != controlplane.ProviderClusterDeleteApproval && v.State != controlplane.ProviderClusterDeleteQueued {
				return controlplane.ErrInvalidTransition
			}
			if v.State == controlplane.ProviderClusterDeleteApproval || v.State == controlplane.ProviderClusterDeleteQueued {
				if e = s.cancelOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, actor, "recovery checkpoint superseded before provider cluster delete claim"); e != nil {
					return e
				}
			}
			op, e := s.createOwnerDestructiveOperationTx(ctx, tx, v.ProjectID, v.ManagementClusterID, controlplane.OwnerOperationProviderClusterDelete, v.ID, v.Revision, v.DesiredDigest, recoveryCheckpointID, actor, requestDigest, true)
			if e != nil {
				return e
			}
			v.DestructiveOperationID = op.ID
			v.RequestDigest = requestDigest
			v.State, v.PendingAction = controlplane.ProviderClusterDeleteApproval, action
		} else {
			if v.State != controlplane.ProviderClusterActive {
				return controlplane.ErrInvalidTransition
			}
			profile, e := scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE id=$1`, v.ProviderProfileID))
			if e != nil {
				return mapDBError(e)
			}
			if e = providerSpecAdmitted(profile, &desired); e != nil {
				return e
			}
			switch action {
			case "SCALE":
				if desired.KubernetesVersion != v.Desired.KubernetesVersion || (desired.ControlPlaneReplicas == v.Desired.ControlPlaneReplicas && desired.WorkerReplicas == v.Desired.WorkerReplicas) {
					return controlplane.ErrValidation
				}
			case "UPGRADE":
				if desired.KubernetesVersion == v.Desired.KubernetesVersion || desired.ControlPlaneReplicas != v.Desired.ControlPlaneReplicas || desired.WorkerReplicas != v.Desired.WorkerReplicas {
					return controlplane.ErrValidation
				}
			}
			if !strings.HasPrefix(requestDigest, "sha256:") {
				return controlplane.ErrValidation
			}
			_ = desiredDigest // caller hint only; authority recomputes after normalization/defaulting.
			v.Desired, v.RequestDigest = desired, requestDigest
			v.DesiredDigest = controlplane.ProviderClusterDesiredDigest(v.ProviderProfileID, v.Name, desired)
			v.Compatibility = controlplane.ProviderCompatibilityDecision(profile, desired)
			v.State, v.PendingAction = controlplane.ProviderClusterAwaitingApproval, action
		}
		now := utcNow(s.now)
		v.RequestedBy = actor
		v.ApprovedBy, v.ApprovedAt, v.LastError, v.Revision, v.UpdatedAt = "", nil, "", v.Revision+1, now
		desiredRaw, _ := json.Marshal(v.Desired)
		compatRaw, _ := json.Marshal(v.Compatibility)
		_, e = tx.ExecContext(ctx, `UPDATE provider_clusters SET revision=$2,state=$3,desired=$4::jsonb,desired_digest=$5,pending_action=$6,request_digest=$7,destructive_operation_id=$8,approved_by='',approved_at=NULL,last_error='',requested_by=$9,compatibility_decision=$10::jsonb,updated_at=$11 WHERE id=$1`, id, v.Revision, string(v.State), desiredRaw, v.DesiredDigest, v.PendingAction, v.RequestDigest, v.DestructiveOperationID, actor, compatRaw, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "provider_cluster."+strings.ToLower(action)+".approval_requested", "providerCluster", id, v.Revision, "", nil); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerCluster", id, "provider_cluster.approval.requested", v)
	})
	return out, err
}

func (s *PostgresStore) QueueTargetNodeProviderMutation(ctx context.Context, id string, expected int64, mutation controlplane.TargetNodeProviderMutation, desired controlplane.ProviderClusterSpec, actor, requestDigest string) (controlplane.ProviderCluster, error) {
	var out controlplane.ProviderCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanProviderCluster(tx.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ProviderClusterActive {
			return controlplane.ErrInvalidTransition
		}
		action := controlplane.TargetNodeLifecycleAction(strings.ToUpper(strings.TrimSpace(string(mutation.Action))))
		if action != controlplane.TargetNodeActionRemove && action != controlplane.TargetNodeActionReplace && action != controlplane.TargetNodeActionCertificateRenewal && action != controlplane.TargetNodeActionRemediate {
			return controlplane.ErrValidation
		}
		managementInventory, e := latestInventoryTx(ctx, tx, v.ManagementClusterID)
		if e != nil {
			return e
		}
		if !inventoryHasCapabilityPG(managementInventory, controlplane.TargetNodeProviderMachineLifecycleCapability) {
			return controlplane.ErrPrerequisite
		}
		now := utcNow(s.now)
		if mutation.Authority != controlplane.TargetNodeProviderMachineLifecycleAuthority || strings.TrimSpace(mutation.TargetClusterID) == "" || strings.TrimSpace(mutation.NodeName) == "" || strings.TrimSpace(mutation.NodeUID) == "" || !strings.HasPrefix(mutation.InventoryDigest, "sha256:") || strings.TrimSpace(mutation.WindowID) == "" || !mutation.WindowEndsAt.After(now) {
			return controlplane.ErrPrerequisite
		}
		window, e := scanMaintenanceWindow(tx.QueryRowContext(ctx, `SELECT `+maintenanceWindowColumns+` FROM cluster_maintenance_windows WHERE id=$1 FOR UPDATE`, mutation.WindowID))
		if e != nil {
			return mapDBError(e)
		}
		if window.ClusterID != mutation.TargetClusterID || window.State != controlplane.ClusterMaintenanceWindowActive || !window.EndsAt.Equal(mutation.WindowEndsAt) || now.Before(window.StartsAt) || !window.EndsAt.After(now) {
			return controlplane.ErrMaintenanceWindow
		}
		inv, e := latestInventoryTx(ctx, tx, mutation.TargetClusterID)
		if e != nil {
			return e
		}
		if inv.Digest != mutation.InventoryDigest {
			return controlplane.ErrConflict
		}
		nodeOK, nodeEligible := false, false
		for _, n := range inv.Nodes {
			if n.Name == mutation.NodeName && n.UID == mutation.NodeUID {
				nodeOK = true
				nodeEligible = controlplane.TargetNodeProviderMutationEligibleFor(action, n)
				break
			}
		}
		if !nodeOK {
			return controlplane.ErrConflict
		}
		if !nodeEligible {
			return controlplane.ErrPrerequisite
		}
		profile, e := scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE id=$1`, v.ProviderProfileID))
		if e != nil {
			return mapDBError(e)
		}
		desired.KubernetesVersion = normalizeProviderVersion(desired.KubernetesVersion)
		if e = providerSpecAdmitted(profile, &desired); e != nil {
			return e
		}
		if action == controlplane.TargetNodeActionRemove {
			if v.Desired.WorkerReplicas <= 1 || desired.WorkerReplicas != v.Desired.WorkerReplicas-1 || desired.ControlPlaneReplicas != v.Desired.ControlPlaneReplicas || desired.KubernetesVersion != v.Desired.KubernetesVersion {
				return controlplane.ErrValidation
			}
		} else if desired != v.Desired {
			return controlplane.ErrValidation
		}
		if !strings.HasPrefix(requestDigest, "sha256:") {
			return controlplane.ErrValidation
		}
		v.Desired = desired
		v.DesiredDigest = controlplane.ProviderClusterDesiredDigest(v.ProviderProfileID, v.Name, desired)
		v.TargetNodeMutation = mutation
		v.PendingAction = "TARGET_NODE_" + string(action)
		v.RequestDigest = requestDigest
		v.RequestedBy = actor
		v.ApprovedBy = ""
		v.ApprovedAt = nil
		v.State = controlplane.ProviderClusterAwaitingApproval
		v.LastError = ""
		v.Revision++
		v.UpdatedAt = now
		desiredRaw, _ := json.Marshal(v.Desired)
		mutationRaw, _ := json.Marshal(v.TargetNodeMutation)
		if _, e = tx.ExecContext(ctx, `UPDATE provider_clusters SET revision=$2,state=$3,desired=$4::jsonb,desired_digest=$5,pending_action=$6,requested_by=$7,approved_by='',approved_at=NULL,request_digest=$8,target_node_mutation=$9::jsonb,last_error='',updated_at=$10 WHERE id=$1`, v.ID, v.Revision, string(v.State), desiredRaw, v.DesiredDigest, v.PendingAction, actor, requestDigest, mutationRaw, now); e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "provider_cluster.target_node_"+strings.ToLower(string(action))+".approval_requested", "providerCluster", id, v.Revision, "", map[string]any{"targetClusterId": mutation.TargetClusterID, "nodeName": mutation.NodeName, "nodeUid": mutation.NodeUID, "inventoryDigest": mutation.InventoryDigest, "windowId": mutation.WindowID}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerCluster", id, "provider_cluster.approval.requested", v)
	})
	return out, err
}

func (s *PostgresStore) ApproveProviderCluster(ctx context.Context, id string, expected int64, actor string) (controlplane.ProviderCluster, error) {
	var out controlplane.ProviderCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanProviderCluster(tx.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		switch v.State {
		case controlplane.ProviderClusterAwaitingApproval:
			v.State = controlplane.ProviderClusterQueued
		case controlplane.ProviderClusterDeleteApproval:
			if _, e = s.approveOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, v.ProjectID, v.ManagementClusterID, actor); e != nil {
				return e
			}
			v.State = controlplane.ProviderClusterDeleteQueued
		default:
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.ApprovedBy, v.ApprovedAt, v.Revision, v.UpdatedAt = actor, &now, v.Revision+1, now
		_, e = tx.ExecContext(ctx, `UPDATE provider_clusters SET revision=$2,state=$3,approved_by=$4,approved_at=$5,updated_at=$5 WHERE id=$1`, id, v.Revision, string(v.State), actor, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "provider_cluster.approved", "providerCluster", id, v.Revision, "", map[string]any{"action": v.PendingAction}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerCluster", id, "provider_cluster.execution.queued", v)
	})
	return out, err
}

func (s *PostgresStore) RetryProviderCluster(ctx context.Context, id string, expected int64, actor string) (controlplane.ProviderCluster, error) {
	var out controlplane.ProviderCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanProviderCluster(tx.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.ProviderClusterFailed {
			return controlplane.ErrInvalidTransition
		}
		if v.PendingAction == "DELETE" {
			return fmt.Errorf("%w: destructive provider cluster delete retry requires a fresh recovery-bound request", controlplane.ErrPrerequisite)
		} else if v.PendingAction == "PROVISION" || v.PendingAction == "SCALE" || v.PendingAction == "UPGRADE" || controlplane.IsTargetNodeProviderPendingAction(v.PendingAction) {
			v.State = controlplane.ProviderClusterQueued
		} else {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		v.LastError, v.Revision, v.UpdatedAt = "", v.Revision+1, now
		_, e = tx.ExecContext(ctx, `UPDATE provider_clusters SET revision=$2,state=$3,last_error='',updated_at=$4 WHERE id=$1`, id, v.Revision, string(v.State), now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "provider_cluster.retry.queued", "providerCluster", id, v.Revision, "", map[string]any{"action": v.PendingAction}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerCluster", id, "provider_cluster.execution.queued", v)
	})
	return out, err
}

func (s *PostgresStore) NextProviderClusterTask(ctx context.Context, clusterID, token string) (controlplane.ProviderCluster, controlplane.ProviderProfile, error) {
	var out controlplane.ProviderCluster
	var profile controlplane.ProviderProfile
	noTask := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		noTask = false
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, token); e != nil {
			return e
		}
		now := utcNow(s.now)
		v, e := scanProviderCluster(tx.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE management_cluster_id=$1 AND (state IN ('QUEUED','DELETE_QUEUED') OR (state IN ('APPLYING','RECONCILING','DELETING') AND (task_lease_expires_at IS NULL OR task_lease_expires_at<=$2))) ORDER BY updated_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, clusterID, now))
		if e != nil {
			return mapDBError(e)
		}
		if controlplane.IsTargetNodeProviderPendingAction(v.PendingAction) {
			m := v.TargetNodeMutation
			inv, ie := latestInventoryTx(ctx, tx, m.TargetClusterID)
			if ie != nil {
				return ie
			}
			window, we := scanMaintenanceWindow(tx.QueryRowContext(ctx, `SELECT `+maintenanceWindowColumns+` FROM cluster_maintenance_windows WHERE id=$1 FOR UPDATE`, m.WindowID))
			if we != nil {
				return mapDBError(we)
			}
			nodeOK := false
			if inv.Digest == m.InventoryDigest {
				for _, n := range inv.Nodes {
					if n.Name == m.NodeName && n.UID == m.NodeUID {
						nodeOK = controlplane.TargetNodeProviderMutationEligibleFor(m.Action, n)
						break
					}
				}
			}
			if !nodeOK || window.State != controlplane.ClusterMaintenanceWindowActive || now.Before(window.StartsAt) || !window.EndsAt.After(now) || !window.EndsAt.Equal(m.WindowEndsAt) {
				v.State = controlplane.ProviderClusterFailed
				v.LastError = "target-node mutation identity/window fence changed before claim"
				v.Revision++
				v.UpdatedAt = now
				mutationRaw, _ := json.Marshal(v.TargetNodeMutation)
				if _, e = tx.ExecContext(ctx, `UPDATE provider_clusters SET revision=$2,state=$3,last_error=$4,target_node_mutation=$5::jsonb,updated_at=$6 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.LastError, mutationRaw, now); e != nil {
					return e
				}
				noTask = true
				return nil
			}
		}
		if v.State == controlplane.ProviderClusterDeleting && v.TaskLeaseExpiresAt != nil {
			message := "provider cluster destructive task lease expired; explicit recovery-bound retry is required"
			if _, e = s.finishOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, false, message, "cluster-agent"); e != nil {
				return e
			}
			v.State, v.LastError, v.TaskLeaseExpiresAt = controlplane.ProviderClusterFailed, message, nil
			v.Revision++
			v.UpdatedAt = now
			if _, e = tx.ExecContext(ctx, `UPDATE provider_clusters SET revision=$2,state=$3,last_error=$4,task_lease_expires_at=NULL,updated_at=$5 WHERE id=$1`, v.ID, v.Revision, string(v.State), message, now); e != nil {
				return e
			}
			if e = s.appendAuditTx(ctx, tx, "cluster-agent", "provider_cluster.task.lease_expired", "providerCluster", v.ID, v.Revision, "", map[string]any{"action": "DELETE", "taskFenceToken": v.TaskFenceToken}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "providerCluster", v.ID, "provider_cluster.state.changed", v); e != nil {
				return e
			}
			noTask = true
			return nil
		}
		switch v.State {
		case controlplane.ProviderClusterQueued:
			v.State = controlplane.ProviderClusterApplying
		case controlplane.ProviderClusterDeleteQueued:
			if _, e = s.startOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, v.ProjectID, v.ManagementClusterID, "cluster-agent"); e != nil {
				return e
			}
			v.State = controlplane.ProviderClusterDeleting
		}
		lease := now.Add(controlplane.AgentTaskLeaseDuration)
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseExpiresAt = &lease
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE provider_clusters SET revision=$2,state=$3,task_attempt=$4,task_fence_token=$5,task_lease_expires_at=$6,updated_at=$7 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.TaskAttempt, v.TaskFenceToken, lease, now)
		if e != nil {
			return e
		}
		profile, e = scanProviderProfile(tx.QueryRowContext(ctx, `SELECT `+providerProfileColumns+` FROM provider_profiles WHERE id=$1`, v.ProviderProfileID))
		if e != nil {
			return mapDBError(e)
		}
		if profile.State != controlplane.ProviderProfileReady {
			return controlplane.ErrValidation
		}
		out = v
		return nil
	})
	if err == nil && noTask {
		return controlplane.ProviderCluster{}, controlplane.ProviderProfile{}, controlplane.ErrNotFound
	}
	return out, profile, err
}

func (s *PostgresStore) ReportProviderClusterTask(ctx context.Context, clusterID, token string, expected int64, result controlplane.ProviderClusterTaskResult) (controlplane.ProviderCluster, error) {
	var out controlplane.ProviderCluster
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, token); e != nil {
			return e
		}
		v, e := scanProviderCluster(tx.QueryRowContext(ctx, `SELECT `+providerClusterColumns+` FROM provider_clusters WHERE id=$1 FOR UPDATE`, result.ProviderClusterID))
		if e != nil {
			return mapDBError(e)
		}
		if v.ManagementClusterID != clusterID {
			return controlplane.ErrNotFound
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		action := strings.ToUpper(strings.TrimSpace(result.Action))
		wasDelete := action == "DELETE" || action == "INSPECT_DELETE"
		switch action {
		case "APPLY":
			if v.State != controlplane.ProviderClusterApplying {
				return controlplane.ErrInvalidTransition
			}
		case "INSPECT":
			if v.State != controlplane.ProviderClusterReconciling {
				return controlplane.ErrInvalidTransition
			}
		case "DELETE", "INSPECT_DELETE":
			if v.State != controlplane.ProviderClusterDeleting {
				return controlplane.ErrInvalidTransition
			}
		default:
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		if result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !controlplane.AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
			return controlplane.ErrConflict
		}
		if !result.Success {
			v.State, v.LastError = controlplane.ProviderClusterFailed, strings.TrimSpace(result.Error)
			if v.LastError == "" {
				v.LastError = "provider cluster task failed"
			}
		} else {
			switch action {
			case "APPLY":
				if controlplane.IsTargetNodeProviderPendingAction(v.PendingAction) {
					m := result.TargetNodeMutation
					if m.Authority != controlplane.TargetNodeProviderMachineLifecycleAuthority || m.NodeName != v.TargetNodeMutation.NodeName || m.NodeUID != v.TargetNodeMutation.NodeUID || m.InventoryDigest != v.TargetNodeMutation.InventoryDigest || strings.TrimSpace(m.MachineName) == "" || strings.TrimSpace(m.MachineUID) == "" || strings.TrimSpace(m.MachineResourceVersion) == "" || strings.TrimSpace(m.MachineSetName) == "" || strings.TrimSpace(m.MachineDeploymentName) == "" || !strings.HasPrefix(m.EvidenceDigest, "sha256:") {
						v.State, v.LastError = controlplane.ProviderClusterFailed, "target-node provider mutation evidence is incomplete"
						break
					}
					v.TargetNodeMutation = m
				}
				if result.ObservedDigest != v.DesiredDigest {
					v.State, v.LastError = controlplane.ProviderClusterFailed, "provider cluster desired/observed digest mismatch"
				} else {
					v.State, v.ObservedDigest, v.Phase, v.LastError = controlplane.ProviderClusterReconciling, result.ObservedDigest, strings.TrimSpace(result.Phase), ""
				}
			case "INSPECT":
				v.ObservedDigest, v.Phase = result.ObservedDigest, strings.TrimSpace(result.Phase)
				if result.Ready {
					if result.ObservedDigest != v.DesiredDigest {
						v.State, v.LastError = controlplane.ProviderClusterFailed, "provider cluster ready with a different desired digest"
					} else {
						v.State, v.Applied, v.PendingAction, v.LastError = controlplane.ProviderClusterActive, v.Desired, "", ""
					}
				}
			case "DELETE", "INSPECT_DELETE":
				v.Phase = strings.TrimSpace(result.Phase)
				if result.Deleted {
					v.State, v.PendingAction, v.ObservedDigest, v.LastError = controlplane.ProviderClusterDeleted, "", "", ""
				}
			default:
				return controlplane.ErrValidation
			}
		}
		if wasDelete && (!result.Success || result.Deleted) {
			if _, e = s.finishOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, result.Success, v.LastError, "cluster-agent"); e != nil {
				return e
			}
		}
		v.TaskLeaseExpiresAt = nil
		v.Revision, v.UpdatedAt = v.Revision+1, now
		applied, _ := json.Marshal(v.Applied)
		mutationRaw, _ := json.Marshal(v.TargetNodeMutation)
		_, e = tx.ExecContext(ctx, `UPDATE provider_clusters SET revision=$2,state=$3,applied=$4::jsonb,observed_digest=$5,pending_action=$6,phase=$7,last_error=$8,task_lease_expires_at=NULL,target_node_mutation=$9::jsonb,updated_at=$10 WHERE id=$1`, v.ID, v.Revision, string(v.State), applied, v.ObservedDigest, v.PendingAction, v.Phase, v.LastError, mutationRaw, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "provider_cluster.task.reported", "providerCluster", v.ID, v.Revision, "", map[string]any{"action": result.Action, "success": result.Success, "ready": result.Ready, "deleted": result.Deleted, "taskFenceToken": result.TaskFenceToken}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "providerCluster", v.ID, "provider_cluster.state.changed", v)
	})
	return out, err
}
