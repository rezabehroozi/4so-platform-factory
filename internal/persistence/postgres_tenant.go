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

const entitlementColumns = `id,organization_id,revision,edition,max_tenants,oem_enabled,features,expires_at,issued_by,created_at,updated_at`
const oemColumns = `id,organization_id,revision,brand_name,product_title,support_url,logo_object_ref,accent_color,custom_domain,default_locale,created_at,updated_at`
const tenantColumns = `id,organization_id,project_id,cluster_id,revision,name,display_name,plan_name,namespace,state,quota,storage_policy,backup_policy,security_policy,evidence,evidence_digest,evidence_sealed_at,desired_digest,pending_plan_name,pending_quota,pending_desired_digest,observed_digest,requested_by,idempotency_key,request_digest,task_attempt,runtime_contract_version,task_fence_token,task_lease_expires_at,pending_action,COALESCE(destructive_operation_id,''),recovery_checkpoint_id,approved_by,approved_at,last_error,created_at,updated_at`

func mustJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }

func scanEntitlement(row interface{ Scan(...any) error }) (controlplane.Entitlement, error) {
	var v controlplane.Entitlement
	var features []byte
	err := row.Scan(&v.ID, &v.OrganizationID, &v.Revision, &v.Edition, &v.MaxTenants, &v.OEMEnabled, &features, &v.ExpiresAt, &v.IssuedBy, &v.CreatedAt, &v.UpdatedAt)
	if len(features) > 0 {
		if decodeErr := decodeJSONColumn(features, &v.Features, "postgres_tenant.Features"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}
func scanOEM(row interface{ Scan(...any) error }) (controlplane.OEMProfile, error) {
	var v controlplane.OEMProfile
	err := row.Scan(&v.ID, &v.OrganizationID, &v.Revision, &v.BrandName, &v.ProductTitle, &v.SupportURL, &v.LogoObjectRef, &v.AccentColor, &v.CustomDomain, &v.DefaultLocale, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}
func scanTenant(row interface{ Scan(...any) error }) (controlplane.TenantEnvironment, error) {
	var v controlplane.TenantEnvironment
	var state string
	var quota, pendingQuota, storagePolicy, backupPolicy, securityPolicy, evidence []byte
	err := row.Scan(&v.ID, &v.OrganizationID, &v.ProjectID, &v.ClusterID, &v.Revision, &v.Name, &v.DisplayName, &v.PlanName, &v.Namespace, &state, &quota, &storagePolicy, &backupPolicy, &securityPolicy, &evidence, &v.EvidenceDigest, &v.EvidenceSealedAt, &v.DesiredDigest, &v.PendingPlanName, &pendingQuota, &v.PendingDesiredDigest, &v.ObservedDigest, &v.RequestedBy, &v.IdempotencyKey, &v.RequestDigest, &v.TaskAttempt, &v.RuntimeContractVersion, &v.TaskFenceToken, &v.TaskLeaseExpiresAt, &v.PendingAction, &v.DestructiveOperationID, &v.RecoveryCheckpointID, &v.ApprovedBy, &v.ApprovedAt, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	v.State = controlplane.TenantState(state)
	if len(quota) > 0 {
		if decodeErr := decodeJSONColumn(quota, &v.Quota, "postgres_tenant.Quota"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(pendingQuota) > 0 {
		if decodeErr := decodeJSONColumn(pendingQuota, &v.PendingQuota, "postgres_tenant.PendingQuota"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(storagePolicy) > 0 {
		if decodeErr := decodeJSONColumn(storagePolicy, &v.StoragePolicy, "postgres_tenant.StoragePolicy"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(backupPolicy) > 0 {
		if decodeErr := decodeJSONColumn(backupPolicy, &v.BackupPolicy, "postgres_tenant.BackupPolicy"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(securityPolicy) > 0 {
		if decodeErr := decodeJSONColumn(securityPolicy, &v.SecurityPolicy, "postgres_tenant.SecurityPolicy"); decodeErr != nil {
			return v, decodeErr
		}
	}
	if len(evidence) > 0 {
		if decodeErr := decodeJSONColumn(evidence, &v.Evidence, "postgres_tenant.Evidence"); decodeErr != nil {
			return v, decodeErr
		}
	}
	return v, err
}

func entitlementEdition(edition string) (int, bool, []string, bool) {
	switch strings.ToLower(strings.TrimSpace(edition)) {
	case "pilot":
		return 5, false, []string{"namespace-tenants"}, true
	case "enterprise":
		return 100, true, []string{"namespace-tenants", "oem-branding"}, true
	case "service-provider":
		return 1000, true, []string{"namespace-tenants", "oem-branding", "white-label"}, true
	default:
		return 0, false, nil, false
	}
}
func tenantNS(name, id string) string {
	name = normalizedName(name)
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	clean := strings.Trim(b.String(), "-")
	if clean == "" {
		clean = "tenant"
	}
	suffix := id
	if len(suffix) > 6 {
		suffix = suffix[len(suffix)-6:]
	}
	max := 63 - len("tenant--") - len(suffix)
	if len(clean) > max {
		clean = strings.Trim(clean[:max], "-")
	}
	return "tenant-" + clean + "-" + suffix
}

func (s *PostgresStore) UpsertEntitlement(ctx context.Context, v controlplane.Entitlement, expected int64, actor string) (controlplane.Entitlement, error) {
	var out controlplane.Entitlement
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		max, oem, features, ok := entitlementEdition(v.Edition)
		if !ok {
			return controlplane.ErrValidation
		}
		var existing controlplane.Entitlement
		existing, e := scanEntitlement(tx.QueryRowContext(ctx, `SELECT `+entitlementColumns+` FROM entitlements WHERE organization_id=$1 FOR UPDATE`, v.OrganizationID))
		now := utcNow(s.now)
		if e == sql.ErrNoRows {
			if expected != 0 {
				return controlplane.ErrConflict
			}
			var one int
			if e = tx.QueryRowContext(ctx, `SELECT 1 FROM organizations WHERE id=$1`, v.OrganizationID).Scan(&one); e != nil {
				return mapDBError(e)
			}
			v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ent"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		} else if e != nil {
			return e
		} else {
			if expected <= 0 || existing.Revision != expected {
				return controlplane.ErrConflict
			}
			v.ResourceMeta = existing.ResourceMeta
			v.Revision++
			v.UpdatedAt = now
		}
		v.Edition = strings.ToLower(strings.TrimSpace(v.Edition))
		v.MaxTenants = max
		v.OEMEnabled = oem
		v.Features = features
		v.IssuedBy = actor
		raw, _ := json.Marshal(features)
		_, e = tx.ExecContext(ctx, `INSERT INTO entitlements(id,organization_id,revision,edition,max_tenants,oem_enabled,features,expires_at,issued_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11) ON CONFLICT(organization_id) DO UPDATE SET revision=EXCLUDED.revision,edition=EXCLUDED.edition,max_tenants=EXCLUDED.max_tenants,oem_enabled=EXCLUDED.oem_enabled,features=EXCLUDED.features,expires_at=EXCLUDED.expires_at,issued_by=EXCLUDED.issued_by,updated_at=EXCLUDED.updated_at`, v.ID, v.OrganizationID, v.Revision, v.Edition, v.MaxTenants, v.OEMEnabled, raw, v.ExpiresAt, actor, v.CreatedAt, v.UpdatedAt)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "entitlement.upserted", "entitlement", v.ID, v.Revision, "", map[string]any{"organizationId": v.OrganizationID, "edition": v.Edition}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "entitlement", v.ID, "entitlement.upserted", v)
	})
	return out, err
}
func (s *PostgresStore) GetEntitlement(ctx context.Context, org string) (controlplane.Entitlement, error) {
	v, e := scanEntitlement(s.db.QueryRowContext(ctx, `SELECT `+entitlementColumns+` FROM entitlements WHERE organization_id=$1`, org))
	return v, mapDBError(e)
}

func (s *PostgresStore) UpsertOEMProfile(ctx context.Context, v controlplane.OEMProfile, expected int64, actor string) (controlplane.OEMProfile, error) {
	var out controlplane.OEMProfile
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		var enabled bool
		var expires sql.NullTime
		if e := tx.QueryRowContext(ctx, `SELECT oem_enabled,expires_at FROM entitlements WHERE organization_id=$1 FOR UPDATE`, v.OrganizationID).Scan(&enabled, &expires); e != nil {
			return mapDBError(e)
		}
		if !enabled || (expires.Valid && expires.Time.Before(utcNow(s.now))) {
			return controlplane.ErrValidation
		}
		v.BrandName = strings.TrimSpace(v.BrandName)
		v.ProductTitle = strings.TrimSpace(v.ProductTitle)
		v.DefaultLocale = strings.TrimSpace(v.DefaultLocale)
		validColor := v.AccentColor == "" || (len(v.AccentColor) == 7 && v.AccentColor[0] == '#' && strings.IndexFunc(v.AccentColor[1:], func(r rune) bool {
			return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))
		}) == -1)
		validDomain := v.CustomDomain == "" || (!strings.Contains(v.CustomDomain, "://") && !strings.ContainsAny(v.CustomDomain, " /\t\r\n"))
		if v.BrandName == "" || v.ProductTitle == "" || (v.DefaultLocale != "fa" && v.DefaultLocale != "en") || (v.SupportURL != "" && !strings.HasPrefix(v.SupportURL, "https://")) || (v.LogoObjectRef != "" && !strings.HasPrefix(v.LogoObjectRef, "object://")) || !validColor || !validDomain {
			return controlplane.ErrValidation
		}
		existing, e := scanOEM(tx.QueryRowContext(ctx, `SELECT `+oemColumns+` FROM oem_profiles WHERE organization_id=$1 FOR UPDATE`, v.OrganizationID))
		now := utcNow(s.now)
		if e == sql.ErrNoRows {
			if expected != 0 {
				return controlplane.ErrConflict
			}
			v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("oem"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		} else if e != nil {
			return e
		} else {
			if expected <= 0 || existing.Revision != expected {
				return controlplane.ErrConflict
			}
			v.ResourceMeta = existing.ResourceMeta
			v.Revision++
			v.UpdatedAt = now
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO oem_profiles(id,organization_id,revision,brand_name,product_title,support_url,logo_object_ref,accent_color,custom_domain,default_locale,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(organization_id) DO UPDATE SET revision=EXCLUDED.revision,brand_name=EXCLUDED.brand_name,product_title=EXCLUDED.product_title,support_url=EXCLUDED.support_url,logo_object_ref=EXCLUDED.logo_object_ref,accent_color=EXCLUDED.accent_color,custom_domain=EXCLUDED.custom_domain,default_locale=EXCLUDED.default_locale,updated_at=EXCLUDED.updated_at`, v.ID, v.OrganizationID, v.Revision, v.BrandName, v.ProductTitle, v.SupportURL, v.LogoObjectRef, v.AccentColor, v.CustomDomain, v.DefaultLocale, v.CreatedAt, v.UpdatedAt)
		if e != nil {
			return mapDBError(e)
		}
		out = v
		if e = s.appendAuditTx(ctx, tx, actor, "oem_profile.upserted", "oemProfile", v.ID, v.Revision, "", map[string]any{"organizationId": v.OrganizationID}); e != nil {
			return e
		}
		return s.appendOutboxTx(ctx, tx, "oemProfile", v.ID, "oem_profile.upserted", v)
	})
	return out, err
}
func (s *PostgresStore) GetOEMProfile(ctx context.Context, org string) (controlplane.OEMProfile, error) {
	v, e := scanOEM(s.db.QueryRowContext(ctx, `SELECT `+oemColumns+` FROM oem_profiles WHERE organization_id=$1`, org))
	return v, mapDBError(e)
}

func (s *PostgresStore) CreateTenant(ctx context.Context, v controlplane.TenantEnvironment, actor string) (controlplane.TenantEnvironment, bool, error) {
	var out controlplane.TenantEnvironment
	replay := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		replay = false
		existing, e := scanTenant(tx.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenant_environments WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE`, v.ProjectID, v.IdempotencyKey))
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
		var org, clusterProject string
		if e = tx.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id=$1`, v.ProjectID).Scan(&org); e != nil {
			return mapDBError(e)
		}
		if e = tx.QueryRowContext(ctx, `SELECT project_id FROM managed_clusters WHERE id=$1`, v.ClusterID).Scan(&clusterProject); e != nil {
			return mapDBError(e)
		}
		if clusterProject != v.ProjectID {
			return controlplane.ErrNotFound
		}
		var max int
		var expires sql.NullTime
		if e = tx.QueryRowContext(ctx, `SELECT max_tenants,expires_at FROM entitlements WHERE organization_id=$1 FOR UPDATE`, org).Scan(&max, &expires); e != nil {
			return mapDBError(e)
		}
		if expires.Valid && expires.Time.Before(utcNow(s.now)) {
			return controlplane.ErrValidation
		}
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM tenant_environments WHERE organization_id=$1 AND state<>'DELETED'`, org).Scan(&count); e != nil {
			return e
		}
		if count >= max {
			return controlplane.ErrValidation
		}
		if normalizedName(v.Name) == "" || strings.TrimSpace(v.DisplayName) == "" || strings.TrimSpace(v.PlanName) == "" || len(v.Quota) == 0 || strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") || !strings.HasPrefix(v.DesiredDigest, "sha256:") || v.StoragePolicy.StorageClass == "" || v.StoragePolicy.RequestQuota == "" || v.StoragePolicy.MaxPVCSize == "" || v.BackupPolicy.Provider != "velero" || v.BackupPolicy.Schedule == "" || v.BackupPolicy.Retention == "" || v.SecurityPolicy.PodSecurityLevel != "restricted" || !v.SecurityPolicy.DefaultDenyIngress || !v.SecurityPolicy.DefaultDenyEgress || !v.SecurityPolicy.AllowDNS {
			return controlplane.ErrValidation
		}
		now := utcNow(s.now)
		v.ResourceMeta = controlplane.ResourceMeta{ID: s.id("ten"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.OrganizationID = org
		v.Name = normalizedName(v.Name)
		v.Namespace = tenantNS(v.Name, v.ID)
		v.State = controlplane.TenantQueued
		v.RequestedBy = actor
		raw, _ := json.Marshal(v.Quota)
		storageRaw, _ := json.Marshal(v.StoragePolicy)
		backupRaw, _ := json.Marshal(v.BackupPolicy)
		securityRaw, _ := json.Marshal(v.SecurityPolicy)
		_, e = tx.ExecContext(ctx, `INSERT INTO tenant_environments(id,organization_id,project_id,cluster_id,revision,name,display_name,plan_name,namespace,state,quota,storage_policy,backup_policy,security_policy,desired_digest,requested_by,idempotency_key,request_digest,pending_action,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15,$16,$17,$18,$19,$19)`, v.ID, org, v.ProjectID, v.ClusterID, v.Name, v.DisplayName, v.PlanName, v.Namespace, string(v.State), raw, storageRaw, backupRaw, securityRaw, v.DesiredDigest, actor, v.IdempotencyKey, v.RequestDigest, v.PendingAction, now)
		if e != nil {
			return mapDBError(e)
		}
		if e = s.appendAuditTx(ctx, tx, actor, "tenant.created", "tenant", v.ID, 1, "", map[string]any{"clusterId": v.ClusterID, "namespace": v.Namespace}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "tenant", v.ID, "tenant.provision.queued", v)
	})
	return out, replay, err
}
func (s *PostgresStore) GetTenant(ctx context.Context, id string) (controlplane.TenantEnvironment, error) {
	v, e := scanTenant(s.db.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenant_environments WHERE id=$1`, id))
	return v, mapDBError(e)
}
func (s *PostgresStore) ListTenants(ctx context.Context, project, cluster string) ([]controlplane.TenantEnvironment, error) {
	q := `SELECT ` + tenantColumns + ` FROM tenant_environments WHERE 1=1`
	args := []any{}
	for _, f := range []struct{ v, c string }{{project, "project_id"}, {cluster, "cluster_id"}} {
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
	out := []controlplane.TenantEnvironment{}
	for rows.Next() {
		v, e := scanTenant(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) QueueTenantResize(ctx context.Context, id string, expected int64, planName string, quota map[string]string, desiredDigest, actor, requestDigest string) (controlplane.TenantEnvironment, error) {
	var out controlplane.TenantEnvironment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanTenant(tx.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenant_environments WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		if v.State != controlplane.TenantActive {
			return controlplane.ErrInvalidTransition
		}
		planName = strings.TrimSpace(planName)
		if planName == "" || planName == v.PlanName || len(quota) == 0 || !strings.HasPrefix(desiredDigest, "sha256:") || !strings.HasPrefix(requestDigest, "sha256:") {
			return controlplane.ErrValidation
		}
		pendingRaw, _ := json.Marshal(quota)
		now := utcNow(s.now)
		v.State = controlplane.TenantResizeApproval
		v.PendingAction = "RESIZE"
		v.PendingPlanName = planName
		v.PendingQuota = quota
		v.PendingDesiredDigest = desiredDigest
		v.RequestDigest = requestDigest
		v.RequestedBy = actor
		v.ApprovedBy = ""
		v.ApprovedAt = nil
		v.LastError = ""
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE tenant_environments SET revision=$2,state=$3,pending_action='RESIZE',pending_plan_name=$4,pending_quota=$5::jsonb,pending_desired_digest=$6,request_digest=$7,requested_by=$8,approved_by='',approved_at=NULL,last_error='',updated_at=$9 WHERE id=$1`, id, v.Revision, string(v.State), planName, pendingRaw, desiredDigest, requestDigest, actor, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "tenant.resize.approval_requested", "tenant", id, v.Revision, "", map[string]any{"fromPlan": v.PlanName, "toPlan": planName, "desiredDigest": desiredDigest}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "tenant", id, "tenant.resize.approval_requested", v)
	})
	return out, err
}

func queueState(state controlplane.TenantState, action string) (controlplane.TenantState, bool) {
	switch strings.ToUpper(action) {
	case "SUSPEND":
		return controlplane.TenantSuspendQueued, state == controlplane.TenantActive
	case "RESUME":
		return controlplane.TenantResumeQueued, state == controlplane.TenantSuspended
	case "DELETE":
		return controlplane.TenantDeleteApproval, state == controlplane.TenantActive || state == controlplane.TenantSuspended || state == controlplane.TenantFailed
	}
	return state, false
}
func queueStateForPending(action string) (controlplane.TenantState, bool) {
	switch action {
	case "PROVISION":
		return controlplane.TenantQueued, true
	case "SUSPEND":
		return controlplane.TenantSuspendQueued, true
	case "RESUME":
		return controlplane.TenantResumeQueued, true
	case "RESIZE":
		return controlplane.TenantResizeQueued, true
	case "DELETE":
		return controlplane.TenantDeleteQueued, true
	default:
		return "", false
	}
}

func (s *PostgresStore) QueueTenantAction(ctx context.Context, id string, expected int64, action, actor, recoveryCheckpointID, requestDigest string) (controlplane.TenantEnvironment, error) {
	var out controlplane.TenantEnvironment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanTenant(tx.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenant_environments WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		normalizedAction := strings.ToUpper(strings.TrimSpace(action))
		var next controlplane.TenantState
		var ok bool
		if normalizedAction == "RETRY" {
			if v.State != controlplane.TenantFailed {
				return controlplane.ErrInvalidTransition
			}
			if strings.EqualFold(v.PendingAction, "DELETE") {
				return fmt.Errorf("%w: destructive tenant delete retry requires a fresh recovery-bound request", controlplane.ErrPrerequisite)
			}
			next, ok = queueStateForPending(v.PendingAction)
			if v.PendingAction == "RESIZE" && (v.PendingPlanName == "" || len(v.PendingQuota) == 0 || !strings.HasPrefix(v.PendingDesiredDigest, "sha256:")) {
				return fmt.Errorf("%w: failed tenant resize has no pending desired state", controlplane.ErrPrerequisite)
			}
		} else {
			if normalizedAction == "DELETE" && (v.State == controlplane.TenantDeleteApproval || v.State == controlplane.TenantDeleteQueued) {
				next, ok = controlplane.TenantDeleteApproval, true
			} else {
				next, ok = queueState(v.State, normalizedAction)
			}
			v.PendingAction = normalizedAction
		}
		if !ok {
			return controlplane.ErrInvalidTransition
		}
		if normalizedAction == "DELETE" {
			if v.State == controlplane.TenantDeleteApproval || v.State == controlplane.TenantDeleteQueued {
				if e = s.cancelOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, actor, "recovery checkpoint superseded before tenant delete approval/claim"); e != nil {
					return e
				}
			}
			op, e := s.createOwnerDestructiveOperationTx(ctx, tx, v.ProjectID, v.ClusterID, controlplane.OwnerOperationTenantDelete, v.ID, v.Revision, v.DesiredDigest, recoveryCheckpointID, actor, requestDigest, true)
			if e != nil {
				return e
			}
			v.DestructiveOperationID = op.ID
			v.RecoveryCheckpointID = recoveryCheckpointID
			v.RequestDigest = requestDigest
			v.RequestedBy = actor
			v.ApprovedBy = ""
			v.ApprovedAt = nil
		}
		now := utcNow(s.now)
		v.State = next
		v.Revision++
		v.UpdatedAt = now
		v.LastError = ""
		_, e = tx.ExecContext(ctx, `UPDATE tenant_environments SET revision=$2,state=$3,pending_action=$4,destructive_operation_id=$5,recovery_checkpoint_id=$6,request_digest=$7,requested_by=$8,approved_by=$9,approved_at=$10,last_error='',updated_at=$11 WHERE id=$1`, id, v.Revision, string(v.State), v.PendingAction, v.DestructiveOperationID, v.RecoveryCheckpointID, v.RequestDigest, v.RequestedBy, v.ApprovedBy, v.ApprovedAt, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "tenant."+strings.ToLower(action)+".queued", "tenant", id, v.Revision, "", nil); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "tenant", id, "tenant."+strings.ToLower(action)+".queued", v)
	})
	return out, err
}

func (s *PostgresStore) ApproveTenantAction(ctx context.Context, id string, expected int64, actor string) (controlplane.TenantEnvironment, error) {
	var out controlplane.TenantEnvironment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		v, e := scanTenant(tx.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenant_environments WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return mapDBError(e)
		}
		if v.Revision != expected {
			return controlplane.ErrConflict
		}
		switch v.State {
		case controlplane.TenantResizeApproval:
			if v.PendingPlanName == "" || len(v.PendingQuota) == 0 || !strings.HasPrefix(v.PendingDesiredDigest, "sha256:") {
				return controlplane.ErrPrerequisite
			}
			v.State = controlplane.TenantResizeQueued
		case controlplane.TenantDeleteApproval:
			if _, e = s.approveOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, v.ProjectID, v.ClusterID, actor); e != nil {
				return e
			}
			v.State = controlplane.TenantDeleteQueued
		default:
			return controlplane.ErrInvalidTransition
		}
		now := utcNow(s.now)
		v.ApprovedBy = actor
		v.ApprovedAt = &now
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE tenant_environments SET revision=$2,state=$3,approved_by=$4,approved_at=$5,updated_at=$5 WHERE id=$1`, id, v.Revision, string(v.State), actor, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, actor, "tenant.approved", "tenant", id, v.Revision, "", map[string]any{"action": v.PendingAction}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "tenant", id, "tenant.execution.queued", v)
	})
	return out, err
}

func runningState(state controlplane.TenantState) (controlplane.TenantState, bool) {
	switch state {
	case controlplane.TenantQueued, controlplane.TenantProvisioning:
		return controlplane.TenantProvisioning, true
	case controlplane.TenantSuspendQueued, controlplane.TenantSuspending:
		return controlplane.TenantSuspending, true
	case controlplane.TenantResumeQueued, controlplane.TenantResuming:
		return controlplane.TenantResuming, true
	case controlplane.TenantResizeQueued, controlplane.TenantResizing:
		return controlplane.TenantResizing, true
	case controlplane.TenantDeleteQueued, controlplane.TenantDeleting:
		return controlplane.TenantDeleting, true
	}
	return state, false
}
func (s *PostgresStore) NextTenantTask(ctx context.Context, clusterID, token string) (controlplane.TenantEnvironment, error) {
	var out controlplane.TenantEnvironment
	noTask := false
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		noTask = false
		if e := s.validateFreshClusterAgentTx(ctx, tx, clusterID, token); e != nil {
			return e
		}
		cluster, e := scanManagedCluster(tx.QueryRowContext(ctx, `SELECT `+managedClusterColumns+` FROM managed_clusters WHERE id=$1 FOR UPDATE`, clusterID))
		if e != nil {
			return mapDBError(e)
		}
		deleteObserved := false
		for _, capability := range cluster.Capabilities {
			if capability == controlplane.TenantDeleteObservedCapability {
				deleteObserved = true
				break
			}
		}
		now := utcNow(s.now)
		v, e := scanTenant(tx.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenant_environments WHERE cluster_id=$1 AND (state IN ('QUEUED','SUSPEND_QUEUED','RESUME_QUEUED','RESIZE_QUEUED','DELETE_QUEUED') OR (state IN ('PROVISIONING','SUSPENDING','RESUMING','RESIZING','DELETING') AND (task_lease_expires_at IS NULL OR task_lease_expires_at<=$3)) OR (state='ACTIVE' AND runtime_contract_version < $4)) AND (state NOT IN ('DELETE_QUEUED','DELETING') OR $2) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, clusterID, deleteObserved, now, controlplane.CurrentTenantRuntimeContractVersion))
		if e != nil {
			return mapDBError(e)
		}
		if v.State == controlplane.TenantDeleting && v.TaskLeaseExpiresAt != nil {
			message := "tenant destructive task lease expired; explicit recovery-bound retry is required"
			if _, e = s.finishOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, false, message, "cluster-agent"); e != nil {
				return e
			}
			v.State, v.LastError, v.TaskLeaseExpiresAt = controlplane.TenantFailed, message, nil
			v.Revision++
			v.UpdatedAt = now
			if _, e = tx.ExecContext(ctx, `UPDATE tenant_environments SET revision=$2,state=$3,last_error=$4,task_lease_expires_at=NULL,updated_at=$5 WHERE id=$1`, v.ID, v.Revision, string(v.State), message, now); e != nil {
				return e
			}
			if e = s.appendAuditTx(ctx, tx, "cluster-agent", "tenant.task.lease_expired", "tenant", v.ID, v.Revision, "", map[string]any{"action": "DELETE", "taskFenceToken": v.TaskFenceToken}); e != nil {
				return e
			}
			if e = s.appendOutboxTx(ctx, tx, "tenant", v.ID, "tenant.state.changed", v); e != nil {
				return e
			}
			noTask = true
			return nil
		}
		next, ok := runningState(v.State)
		if !ok && v.State == controlplane.TenantActive && v.RuntimeContractVersion < controlplane.CurrentTenantRuntimeContractVersion {
			next, ok = controlplane.TenantProvisioning, true
		}
		if !ok {
			return controlplane.ErrNotFound
		}
		if v.State == controlplane.TenantDeleteQueued {
			if _, e = s.startOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, v.ProjectID, v.ClusterID, "cluster-agent"); e != nil {
				return e
			}
		}
		lease := now.Add(controlplane.AgentTaskLeaseDuration)
		v.State = next
		v.TaskAttempt++
		v.TaskFenceToken++
		v.TaskLeaseExpiresAt = &lease
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE tenant_environments SET revision=$2,state=$3,task_attempt=$4,task_fence_token=$5,task_lease_expires_at=$6,updated_at=$7 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.TaskAttempt, v.TaskFenceToken, lease, now)
		out = v
		return e
	})
	if err == nil && noTask {
		return controlplane.TenantEnvironment{}, controlplane.ErrNotFound
	}
	return out, err
}

func (s *PostgresStore) ReportTenantTask(ctx context.Context, clusterID, token string, expected int64, result controlplane.TenantTaskResult) (controlplane.TenantEnvironment, error) {
	var out controlplane.TenantEnvironment
	err := s.serializable(ctx, func(tx *sql.Tx) error {
		if e := s.validateClusterAgentTx(ctx, tx, clusterID, token); e != nil {
			return e
		}
		v, e := scanTenant(tx.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM tenant_environments WHERE id=$1 FOR UPDATE`, result.TenantID))
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
		wasDelete := v.State == controlplane.TenantDeleting
		deleteTerminal := false
		if !result.Success {
			v.State = controlplane.TenantFailed
			v.LastError = strings.TrimSpace(result.Error)
			deleteTerminal = wasDelete
		} else {
			if v.State != controlplane.TenantDeleting {
				if e := controlplane.ValidateTenantTaskEvidence(result); e != nil {
					return e
				}
				v.RuntimeContractVersion = controlplane.CurrentTenantRuntimeContractVersion
			}
			switch v.State {
			case controlplane.TenantProvisioning, controlplane.TenantResuming:
				v.State = controlplane.TenantActive
			case controlplane.TenantResizing:
				v.State = controlplane.TenantActive
				v.PlanName = v.PendingPlanName
				v.Quota = v.PendingQuota
				v.DesiredDigest = v.PendingDesiredDigest
				v.PendingPlanName = ""
				v.PendingQuota = nil
				v.PendingDesiredDigest = ""
			case controlplane.TenantSuspending:
				v.State = controlplane.TenantSuspended
			case controlplane.TenantDeleting:
				if result.Deleted {
					v.State = controlplane.TenantDeleted
					deleteTerminal = true
				}
			default:
				return controlplane.ErrInvalidTransition
			}
			v.ObservedDigest = result.ObservedDigest
			if v.State != controlplane.TenantDeleting && v.State != controlplane.TenantDeleted {
				now := utcNow(s.now)
				v.Evidence = append([]controlplane.TenantEvidenceArtifact(nil), result.Evidence...)
				v.EvidenceDigest = result.EvidenceDigest
				v.EvidenceSealedAt = &now
			}
			if v.State != controlplane.TenantDeleting {
				v.PendingAction = ""
			}
			v.LastError = ""
		}
		if wasDelete && deleteTerminal {
			if _, e = s.finishOwnerDestructiveOperationTx(ctx, tx, v.DestructiveOperationID, result.Success && result.Deleted, v.LastError, "cluster-agent"); e != nil {
				return e
			}
		}
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		_, e = tx.ExecContext(ctx, `UPDATE tenant_environments SET revision=$2,state=$3,plan_name=$4,quota=$5::jsonb,desired_digest=$6,pending_plan_name=$7,pending_quota=$8::jsonb,pending_desired_digest=$9,observed_digest=$10,pending_action=$11,last_error=$12,evidence=$13::jsonb,evidence_digest=$14,evidence_sealed_at=$15,runtime_contract_version=$16,task_lease_expires_at=NULL,updated_at=$17 WHERE id=$1`, v.ID, v.Revision, string(v.State), v.PlanName, mustJSON(v.Quota), v.DesiredDigest, v.PendingPlanName, mustJSON(v.PendingQuota), v.PendingDesiredDigest, v.ObservedDigest, v.PendingAction, v.LastError, mustJSON(v.Evidence), v.EvidenceDigest, v.EvidenceSealedAt, v.RuntimeContractVersion, now)
		if e != nil {
			return e
		}
		if e = s.appendAuditTx(ctx, tx, "cluster-agent", "tenant.task.reported", "tenant", v.ID, v.Revision, "", map[string]any{"action": result.Action, "success": result.Success, "deleted": result.Deleted, "evidenceDigest": result.EvidenceDigest, "evidenceArtifacts": len(result.Evidence), "taskFenceToken": result.TaskFenceToken}); e != nil {
			return e
		}
		out = v
		return s.appendOutboxTx(ctx, tx, "tenant", v.ID, "tenant.state.changed", v)
	})
	return out, err
}

var _ = sort.Strings
