package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var colorPattern = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

func entitlementForEdition(edition string) (max int, oem bool, features []string, ok bool) {
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

func (s *MemoryStore) UpsertEntitlement(_ context.Context, v Entitlement, expected int64, actor string) (Entitlement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.organizations[v.OrganizationID]; !ok {
		return Entitlement{}, ErrNotFound
	}
	max, oem, features, ok := entitlementForEdition(v.Edition)
	if !ok {
		return Entitlement{}, fmt.Errorf("%w: unsupported entitlement edition", ErrValidation)
	}
	now := nowUTC(s.now)
	if existing, found := s.entitlements[v.OrganizationID]; found {
		if expected <= 0 || existing.Revision != expected {
			return Entitlement{}, ErrConflict
		}
		v.ResourceMeta = existing.ResourceMeta
		v.Revision++
		v.UpdatedAt = now
	} else {
		if expected != 0 {
			return Entitlement{}, ErrConflict
		}
		v.ResourceMeta = ResourceMeta{ID: s.id("ent"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	}
	v.Edition = strings.ToLower(strings.TrimSpace(v.Edition))
	v.MaxTenants, v.OEMEnabled, v.Features, v.IssuedBy = max, oem, features, actor
	s.entitlements[v.OrganizationID] = v
	s.appendAuditLocked(actor, "entitlement.upserted", "entitlement", v.ID, v.Revision, map[string]any{"organizationId": v.OrganizationID, "edition": v.Edition})
	s.appendOutboxLocked("entitlement", v.ID, "entitlement.upserted", v)
	return v, nil
}

func (s *MemoryStore) GetEntitlement(_ context.Context, organizationID string) (Entitlement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.entitlements[organizationID]
	if !ok {
		return Entitlement{}, ErrNotFound
	}
	v.Features = append([]string(nil), v.Features...)
	return v, nil
}

func (s *MemoryStore) UpsertOEMProfile(_ context.Context, v OEMProfile, expected int64, actor string) (OEMProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entitlement, ok := s.entitlements[v.OrganizationID]
	if !ok || !entitlement.OEMEnabled || (entitlement.ExpiresAt != nil && entitlement.ExpiresAt.Before(nowUTC(s.now))) {
		return OEMProfile{}, fmt.Errorf("%w: active OEM entitlement is required", ErrValidation)
	}
	v.BrandName = strings.TrimSpace(v.BrandName)
	v.ProductTitle = strings.TrimSpace(v.ProductTitle)
	v.DefaultLocale = strings.TrimSpace(v.DefaultLocale)
	if v.BrandName == "" || v.ProductTitle == "" || (v.DefaultLocale != "fa" && v.DefaultLocale != "en") {
		return OEMProfile{}, fmt.Errorf("%w: brandName, productTitle and defaultLocale fa/en are required", ErrValidation)
	}
	if v.AccentColor != "" && !colorPattern.MatchString(v.AccentColor) {
		return OEMProfile{}, fmt.Errorf("%w: accentColor must be #RRGGBB", ErrValidation)
	}
	if v.LogoObjectRef != "" && !strings.HasPrefix(v.LogoObjectRef, "object://") {
		return OEMProfile{}, fmt.Errorf("%w: logoObjectRef must use object://", ErrValidation)
	}
	if v.SupportURL != "" && !strings.HasPrefix(v.SupportURL, "https://") {
		return OEMProfile{}, fmt.Errorf("%w: supportUrl must use HTTPS", ErrValidation)
	}
	if v.CustomDomain != "" && (strings.Contains(v.CustomDomain, "://") || strings.ContainsAny(v.CustomDomain, " /\t\r\n")) {
		return OEMProfile{}, fmt.Errorf("%w: customDomain must be a hostname without scheme or path", ErrValidation)
	}
	now := nowUTC(s.now)
	if existing, found := s.oemProfiles[v.OrganizationID]; found {
		if expected <= 0 || existing.Revision != expected {
			return OEMProfile{}, ErrConflict
		}
		v.ResourceMeta = existing.ResourceMeta
		v.Revision++
		v.UpdatedAt = now
	} else {
		if expected != 0 {
			return OEMProfile{}, ErrConflict
		}
		v.ResourceMeta = ResourceMeta{ID: s.id("oem"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	}
	s.oemProfiles[v.OrganizationID] = v
	s.appendAuditLocked(actor, "oem_profile.upserted", "oemProfile", v.ID, v.Revision, map[string]any{"organizationId": v.OrganizationID})
	s.appendOutboxLocked("oemProfile", v.ID, "oem_profile.upserted", v)
	return v, nil
}

func (s *MemoryStore) GetOEMProfile(_ context.Context, organizationID string) (OEMProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.oemProfiles[organizationID]
	if !ok {
		return OEMProfile{}, ErrNotFound
	}
	return v, nil
}

const CurrentTenantRuntimeContractVersion = 1

func TenantBackupScheduleName(tenantID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tenantID)))
	return "tenant-platform-backup-" + hex.EncodeToString(sum[:6])
}

func tenantNamespace(name, id string) string {
	name = normalizeName(name)
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
	maxName := 63 - len("tenant--") - len(suffix)
	if len(clean) > maxName {
		clean = strings.Trim(clean[:maxName], "-")
	}
	return "tenant-" + clean + "-" + suffix
}

func (s *MemoryStore) CreateTenant(_ context.Context, v TenantEnvironment, actor string) (TenantEnvironment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	project, ok := s.projects[v.ProjectID]
	if !ok {
		return TenantEnvironment{}, false, ErrNotFound
	}
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || cluster.ProjectID != v.ProjectID {
		return TenantEnvironment{}, false, ErrNotFound
	}
	entitlement, ok := s.entitlements[project.OrganizationID]
	if !ok || (entitlement.ExpiresAt != nil && entitlement.ExpiresAt.Before(nowUTC(s.now))) {
		return TenantEnvironment{}, false, fmt.Errorf("%w: active entitlement is required", ErrValidation)
	}
	if normalizeName(v.Name) == "" || strings.TrimSpace(v.DisplayName) == "" || strings.TrimSpace(v.PlanName) == "" || len(v.Quota) == 0 || strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") || !strings.HasPrefix(v.DesiredDigest, "sha256:") || v.StoragePolicy.StorageClass == "" || v.StoragePolicy.RequestQuota == "" || v.StoragePolicy.MaxPVCSize == "" || v.BackupPolicy.Provider != "velero" || v.BackupPolicy.Schedule == "" || v.BackupPolicy.Retention == "" || v.SecurityPolicy.PodSecurityLevel != "restricted" || !v.SecurityPolicy.DefaultDenyIngress || !v.SecurityPolicy.DefaultDenyEgress || !v.SecurityPolicy.AllowDNS {
		return TenantEnvironment{}, false, fmt.Errorf("%w: tenant identity, plan, quota, idempotency and digests are required", ErrValidation)
	}
	active := 0
	for _, existing := range s.tenants {
		if existing.OrganizationID == project.OrganizationID && existing.State != TenantDeleted {
			active++
		}
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return TenantEnvironment{}, false, ErrIdempotencyConflict
			}
			return cloneTenant(existing), true, nil
		}
		if existing.ProjectID == v.ProjectID && normalizeName(existing.Name) == normalizeName(v.Name) && existing.State != TenantDeleted {
			return TenantEnvironment{}, false, ErrDuplicateName
		}
	}
	if active >= entitlement.MaxTenants {
		return TenantEnvironment{}, false, fmt.Errorf("%w: tenant entitlement limit reached", ErrValidation)
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("ten"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.OrganizationID = project.OrganizationID
	v.Name = normalizeName(v.Name)
	v.Namespace = tenantNamespace(v.Name, v.ID)
	v.State = TenantQueued
	v.PendingAction = "PROVISION"
	v.RequestedBy = actor
	v.Quota = cloneStringMap(v.Quota)
	s.tenants[v.ID] = cloneTenant(v)
	s.appendAuditLocked(actor, "tenant.created", "tenant", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "namespace": v.Namespace, "plan": v.PlanName})
	s.appendOutboxLocked("tenant", v.ID, "tenant.provision.queued", v)
	return cloneTenant(v), false, nil
}

func cloneTenant(v TenantEnvironment) TenantEnvironment {
	v.Quota = cloneStringMap(v.Quota)
	v.PendingQuota = cloneStringMap(v.PendingQuota)
	v.Evidence = append([]TenantEvidenceArtifact(nil), v.Evidence...)
	return v
}

func ValidateTenantTaskEvidence(result TenantTaskResult) error {
	expected := map[string]bool{"resource/Namespace/": false, "resource/ResourceQuota/tenant-quota": false, "resource/LimitRange/tenant-default-limits": false, "resource/NetworkPolicy/tenant-default-deny-all": false, "resource/NetworkPolicy/tenant-allow-dns-egress": false, "resource/Schedule/" + TenantBackupScheduleName(result.TenantID): false, "resource/ConfigMap/tenant-platform-state": false, "security/pod-security-admission-negative": false}
	if result.Action == "SUSPEND" {
		expected["suspension/no-running-pods"] = false
	}
	if len(result.Evidence) != len(expected) || !strings.HasPrefix(result.EvidenceDigest, "sha256:") {
		return fmt.Errorf("%w: tenant completion requires %d sealed evidence artifacts for %s", ErrPrerequisite, len(expected), result.Action)
	}
	for _, item := range result.Evidence {
		if item.Status != "PASS" || !strings.HasPrefix(item.Digest, "sha256:") || item.Authority == "" {
			return fmt.Errorf("%w: tenant evidence artifact is not PASS/sealed", ErrPrerequisite)
		}
		key := item.Key
		if strings.HasPrefix(key, "resource/Namespace/") {
			key = "resource/Namespace/"
		}
		if _, ok := expected[key]; !ok || expected[key] {
			return fmt.Errorf("%w: unexpected or duplicate tenant evidence %s", ErrPrerequisite, item.Key)
		}
		expected[key] = true
	}
	for key, ok := range expected {
		if !ok {
			return fmt.Errorf("%w: missing tenant evidence %s", ErrPrerequisite, key)
		}
	}
	raw, _ := json.Marshal(result.Evidence)
	sum := sha256.Sum256(raw)
	if result.EvidenceDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return fmt.Errorf("%w: tenant evidence digest mismatch", ErrPrerequisite)
	}
	return nil
}

func (s *MemoryStore) GetTenant(_ context.Context, id string) (TenantEnvironment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.tenants[id]
	if !ok {
		return TenantEnvironment{}, ErrNotFound
	}
	return cloneTenant(v), nil
}

func (s *MemoryStore) ListTenants(_ context.Context, projectID, clusterID string) ([]TenantEnvironment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []TenantEnvironment{}
	for _, v := range s.tenants {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) {
			out = append(out, cloneTenant(v))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) QueueTenantResize(_ context.Context, id string, expected int64, planName string, quota map[string]string, desiredDigest, actor, requestDigest string) (TenantEnvironment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.tenants[id]
	if !ok {
		return TenantEnvironment{}, ErrNotFound
	}
	if v.Revision != expected {
		return TenantEnvironment{}, ErrConflict
	}
	if v.State != TenantActive {
		return TenantEnvironment{}, ErrInvalidTransition
	}
	planName = strings.TrimSpace(planName)
	if planName == "" || planName == v.PlanName || len(quota) == 0 || !strings.HasPrefix(desiredDigest, "sha256:") || !strings.HasPrefix(requestDigest, "sha256:") {
		return TenantEnvironment{}, fmt.Errorf("%w: resize requires a different catalog plan, quota and digests", ErrValidation)
	}
	v.State = TenantResizeApproval
	v.PendingAction = "RESIZE"
	v.PendingPlanName = planName
	v.PendingQuota = cloneStringMap(quota)
	v.PendingDesiredDigest = desiredDigest
	v.RequestDigest = requestDigest
	v.RequestedBy = actor
	v.ApprovedBy = ""
	v.ApprovedAt = nil
	v.LastError = ""
	v.Revision++
	v.UpdatedAt = nowUTC(s.now)
	s.tenants[id] = cloneTenant(v)
	s.appendAuditLocked(actor, "tenant.resize.approval_requested", "tenant", id, v.Revision, map[string]any{"fromPlan": v.PlanName, "toPlan": planName, "desiredDigest": desiredDigest})
	s.appendOutboxLocked("tenant", id, "tenant.resize.approval_requested", v)
	return cloneTenant(v), nil
}

func (s *MemoryStore) QueueTenantAction(_ context.Context, id string, expected int64, action, actor, recoveryCheckpointID, requestDigest string) (TenantEnvironment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.tenants[id]
	if !ok {
		return TenantEnvironment{}, ErrNotFound
	}
	if v.Revision != expected {
		return TenantEnvironment{}, ErrConflict
	}
	action = strings.ToUpper(strings.TrimSpace(action))
	switch action {
	case "SUSPEND":
		if v.State != TenantActive {
			return TenantEnvironment{}, ErrInvalidTransition
		}
		v.State = TenantSuspendQueued
		v.PendingAction = action
	case "RESUME":
		if v.State != TenantSuspended {
			return TenantEnvironment{}, ErrInvalidTransition
		}
		v.State = TenantResumeQueued
		v.PendingAction = action
	case "DELETE":
		if v.State != TenantActive && v.State != TenantSuspended && v.State != TenantFailed && v.State != TenantDeleteApproval && v.State != TenantDeleteQueued {
			return TenantEnvironment{}, ErrInvalidTransition
		}
		if v.State == TenantDeleteApproval || v.State == TenantDeleteQueued {
			if err := s.cancelOwnerDestructiveOperationLocked(v.DestructiveOperationID, actor, "recovery checkpoint superseded before tenant delete approval/claim"); err != nil {
				return TenantEnvironment{}, err
			}
		}
		op, err := s.createOwnerDestructiveOperationLocked(v.ProjectID, v.ClusterID, OwnerOperationTenantDelete, v.ID, v.Revision, v.DesiredDigest, recoveryCheckpointID, actor, requestDigest, true)
		if err != nil {
			return TenantEnvironment{}, err
		}
		v.State = TenantDeleteApproval
		v.PendingAction = action
		v.DestructiveOperationID = op.ID
		v.RecoveryCheckpointID = recoveryCheckpointID
		v.RequestDigest = requestDigest
		v.RequestedBy = actor
		v.ApprovedBy = ""
		v.ApprovedAt = nil
	case "RETRY":
		if v.State != TenantFailed {
			return TenantEnvironment{}, ErrInvalidTransition
		}
		switch v.PendingAction {
		case "PROVISION":
			v.State = TenantQueued
		case "SUSPEND":
			v.State = TenantSuspendQueued
		case "RESUME":
			v.State = TenantResumeQueued
		case "RESIZE":
			if v.PendingPlanName == "" || len(v.PendingQuota) == 0 || !strings.HasPrefix(v.PendingDesiredDigest, "sha256:") {
				return TenantEnvironment{}, fmt.Errorf("%w: failed tenant resize has no pending desired state", ErrPrerequisite)
			}
			v.State = TenantResizeQueued
		case "DELETE":
			return TenantEnvironment{}, ownerDestructiveRetryRequiresFreshRequest(v.DestructiveOperationID)
		default:
			return TenantEnvironment{}, fmt.Errorf("%w: failed tenant has no retryable action", ErrValidation)
		}
	default:
		return TenantEnvironment{}, fmt.Errorf("%w: unsupported tenant action", ErrValidation)
	}
	v.Revision++
	v.UpdatedAt = nowUTC(s.now)
	v.LastError = ""
	s.tenants[id] = cloneTenant(v)
	s.appendAuditLocked(actor, "tenant."+strings.ToLower(action)+".queued", "tenant", id, v.Revision, nil)
	s.appendOutboxLocked("tenant", id, "tenant."+strings.ToLower(action)+".queued", v)
	return cloneTenant(v), nil
}

func (s *MemoryStore) ApproveTenantAction(_ context.Context, id string, expected int64, actor string) (TenantEnvironment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.tenants[id]
	if !ok {
		return TenantEnvironment{}, ErrNotFound
	}
	if v.Revision != expected {
		return TenantEnvironment{}, ErrConflict
	}
	switch v.State {
	case TenantResizeApproval:
		if v.PendingPlanName == "" || len(v.PendingQuota) == 0 || !strings.HasPrefix(v.PendingDesiredDigest, "sha256:") {
			return TenantEnvironment{}, fmt.Errorf("%w: pending resize desired state is incomplete", ErrPrerequisite)
		}
		v.State = TenantResizeQueued
	case TenantDeleteApproval:
		if _, err := s.approveOwnerDestructiveOperationLocked(v.DestructiveOperationID, v.ProjectID, v.ClusterID, actor); err != nil {
			return TenantEnvironment{}, err
		}
		v.State = TenantDeleteQueued
	default:
		return TenantEnvironment{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	v.ApprovedBy = actor
	v.ApprovedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.tenants[id] = cloneTenant(v)
	s.appendAuditLocked(actor, "tenant.approved", "tenant", id, v.Revision, map[string]any{"action": v.PendingAction})
	s.appendOutboxLocked("tenant", id, "tenant.execution.queued", v)
	return cloneTenant(v), nil
}

func clusterHasCapability(cluster ManagedCluster, wanted string) bool {
	for _, capability := range cluster.Capabilities {
		if capability == wanted {
			return true
		}
	}
	return false
}

func tenantActionForState(state TenantState) (string, TenantState, bool) {
	switch state {
	case TenantQueued, TenantProvisioning:
		return "PROVISION", TenantProvisioning, true
	case TenantSuspendQueued, TenantSuspending:
		return "SUSPEND", TenantSuspending, true
	case TenantResumeQueued, TenantResuming:
		return "RESUME", TenantResuming, true
	case TenantResizeQueued, TenantResizing:
		return "RESIZE", TenantResizing, true
	case TenantDeleteQueued, TenantDeleting:
		return "DELETE", TenantDeleting, true
	default:
		return "", state, false
	}
}

func (s *MemoryStore) NextTenantTask(_ context.Context, clusterID, agentTokenDigest string) (TenantEnvironment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, agentTokenDigest)
	if err != nil {
		return TenantEnvironment{}, err
	}
	now := nowUTC(s.now)
	ids := []string{}
	for id, v := range s.tenants {
		if v.ClusterID != clusterID {
			continue
		}
		if (v.State == TenantDeleteQueued || v.State == TenantDeleting) && !clusterHasCapability(cluster, TenantDeleteObservedCapability) {
			continue
		}
		reconcile := v.State == TenantActive && v.RuntimeContractVersion < CurrentTenantRuntimeContractVersion
		if _, _, runnable := tenantActionForState(v.State); !runnable && !reconcile {
			continue
		}
		switch v.State {
		case TenantQueued, TenantSuspendQueued, TenantResumeQueued, TenantResizeQueued, TenantDeleteQueued:
			ids = append(ids, id)
		default:
			if !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return TenantEnvironment{}, ErrNotFound
	}
	sort.Slice(ids, func(i, j int) bool {
		left, right := s.tenants[ids[i]], s.tenants[ids[j]]
		if left.CreatedAt.Equal(right.CreatedAt) {
			return left.ID < right.ID
		}
		return left.CreatedAt.Before(right.CreatedAt)
	})
	v := s.tenants[ids[0]]
	if v.State == TenantDeleting && v.TaskLeaseExpiresAt != nil {
		message := "tenant destructive task lease expired; explicit recovery-bound retry is required"
		if _, err := s.finishOwnerDestructiveOperationLocked(v.DestructiveOperationID, false, message, "cluster-agent"); err != nil {
			return TenantEnvironment{}, err
		}
		v.State, v.LastError, v.TaskLeaseExpiresAt = TenantFailed, message, nil
		v.Revision++
		v.UpdatedAt = now
		s.tenants[v.ID] = cloneTenant(v)
		s.appendAuditLocked("cluster-agent", "tenant.task.lease_expired", "tenant", v.ID, v.Revision, map[string]any{"action": "DELETE", "taskFenceToken": v.TaskFenceToken})
		s.appendOutboxLocked("tenant", v.ID, "tenant.state.changed", v)
		return TenantEnvironment{}, ErrNotFound
	}
	if v.State == TenantDeleteQueued {
		if _, err := s.startOwnerDestructiveOperationLocked(v.DestructiveOperationID, v.ProjectID, v.ClusterID, "cluster-agent"); err != nil {
			return TenantEnvironment{}, err
		}
	}
	_, next, runnable := tenantActionForState(v.State)
	if !runnable && v.State == TenantActive && v.RuntimeContractVersion < CurrentTenantRuntimeContractVersion {
		next = TenantProvisioning
	}
	lease := now.Add(AgentTaskLeaseDuration)
	v.State = next
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseExpiresAt = &lease
	v.Revision++
	v.UpdatedAt = now
	s.tenants[v.ID] = cloneTenant(v)
	return cloneTenant(v), nil
}

func (s *MemoryStore) ReportTenantTask(_ context.Context, clusterID, agentTokenDigest string, expected int64, result TenantTaskResult) (TenantEnvironment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.requireClusterTaskAdmissionLocked(clusterID, agentTokenDigest)
	if err != nil {
		return TenantEnvironment{}, err
	}
	v, ok := s.tenants[result.TenantID]
	if !ok || v.ClusterID != clusterID {
		return TenantEnvironment{}, ErrNotFound
	}
	now := nowUTC(s.now)
	if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		return TenantEnvironment{}, ErrConflict
	}
	wasDelete := v.State == TenantDeleting
	deleteTerminal := false
	if !result.Success {
		v.State = TenantFailed
		v.LastError = strings.TrimSpace(result.Error)
		deleteTerminal = wasDelete
	} else {
		if v.State != TenantDeleting {
			if err := ValidateTenantTaskEvidence(result); err != nil {
				return TenantEnvironment{}, err
			}
			v.RuntimeContractVersion = CurrentTenantRuntimeContractVersion
		}
		switch v.State {
		case TenantProvisioning, TenantResuming:
			v.State = TenantActive
		case TenantResizing:
			v.State = TenantActive
			v.PlanName = v.PendingPlanName
			v.Quota = cloneStringMap(v.PendingQuota)
			v.DesiredDigest = v.PendingDesiredDigest
			v.PendingPlanName = ""
			v.PendingQuota = nil
			v.PendingDesiredDigest = ""
		case TenantSuspending:
			v.State = TenantSuspended
		case TenantDeleting:
			if result.Deleted {
				v.State = TenantDeleted
				deleteTerminal = true
			}
		default:
			return TenantEnvironment{}, ErrInvalidTransition
		}
		v.ObservedDigest = result.ObservedDigest
		if v.State != TenantDeleting && v.State != TenantDeleted {
			now := nowUTC(s.now)
			v.Evidence = append([]TenantEvidenceArtifact(nil), result.Evidence...)
			v.EvidenceDigest = result.EvidenceDigest
			v.EvidenceSealedAt = &now
		}
		if v.State != TenantDeleting {
			v.PendingAction = ""
		}
		v.LastError = ""
	}
	if wasDelete && deleteTerminal {
		if _, err := s.finishOwnerDestructiveOperationLocked(v.DestructiveOperationID, result.Success && result.Deleted, v.LastError, "cluster-agent"); err != nil {
			return TenantEnvironment{}, err
		}
	}
	v.TaskLeaseExpiresAt = nil
	v.Revision++
	v.UpdatedAt = now
	s.tenants[v.ID] = cloneTenant(v)
	s.appendAuditLocked("cluster-agent", "tenant.task.reported", "tenant", v.ID, v.Revision, map[string]any{"action": result.Action, "success": result.Success, "deleted": result.Deleted, "evidenceDigest": result.EvidenceDigest, "evidenceArtifacts": len(result.Evidence), "taskFenceToken": result.TaskFenceToken})
	s.appendOutboxLocked("tenant", v.ID, "tenant.state.changed", v)
	return cloneTenant(v), nil
}

var _ = time.Time{}
