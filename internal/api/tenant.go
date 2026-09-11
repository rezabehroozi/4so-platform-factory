package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
)

type entitlementInput struct {
	Edition   string  `json:"edition"`
	ExpiresAt *string `json:"expiresAt,omitempty"`
}
type oemProfileInput struct {
	BrandName     string `json:"brandName"`
	ProductTitle  string `json:"productTitle"`
	SupportURL    string `json:"supportUrl,omitempty"`
	LogoObjectRef string `json:"logoObjectRef,omitempty"`
	AccentColor   string `json:"accentColor,omitempty"`
	CustomDomain  string `json:"customDomain,omitempty"`
	DefaultLocale string `json:"defaultLocale"`
}
type createTenantInput struct {
	ProjectID   string `json:"projectId"`
	ClusterID   string `json:"clusterId"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	PlanName    string `json:"planName"`
}
type resizeTenantInput struct {
	PlanName string `json:"planName"`
}

func hasVerb(verbs []string, wanted string) bool {
	for _, verb := range verbs {
		if verb == wanted {
			return true
		}
	}
	return false
}

func (s *Server) resolveTenantPolicies(r *http.Request, clusterID, preferredStorageClass string, plan catalog.TenantPlan) (controlplane.TenantStoragePolicy, controlplane.TenantBackupPolicy, controlplane.TenantSecurityPolicy, error) {
	inv, err := s.store.GetLatestClusterInventory(r.Context(), clusterID)
	if err != nil {
		return controlplane.TenantStoragePolicy{}, controlplane.TenantBackupPolicy{}, controlplane.TenantSecurityPolicy{}, err
	}
	if time.Since(inv.ObservedAt) > 30*time.Minute {
		return controlplane.TenantStoragePolicy{}, controlplane.TenantBackupPolicy{}, controlplane.TenantSecurityPolicy{}, errors.New("fresh cluster inventory is required for tenant policy planning")
	}
	storageClass := strings.TrimSpace(preferredStorageClass)
	if storageClass == "" {
		for _, sc := range inv.StorageClasses {
			if sc.Default {
				storageClass = sc.Name
				break
			}
		}
		if storageClass == "" && len(inv.StorageClasses) > 0 {
			storageClass = inv.StorageClasses[0].Name
		}
	} else {
		found := false
		for _, sc := range inv.StorageClasses {
			if sc.Name == storageClass {
				found = true
				break
			}
		}
		if !found {
			return controlplane.TenantStoragePolicy{}, controlplane.TenantBackupPolicy{}, controlplane.TenantSecurityPolicy{}, errors.New("tenant storage class is no longer available")
		}
	}
	if storageClass == "" {
		return controlplane.TenantStoragePolicy{}, controlplane.TenantBackupPolicy{}, controlplane.TenantSecurityPolicy{}, errors.New("usable StorageClass is required")
	}
	velero := false
	networkPolicy := false
	for _, ar := range inv.APIResources {
		if ar.APIVersion == "velero.io/v1" && ar.Kind == "Schedule" && ar.Namespaced && hasVerb(ar.Verbs, "get") && hasVerb(ar.Verbs, "patch") {
			velero = true
		}
		if ar.APIVersion == "networking.k8s.io/v1" && ar.Kind == "NetworkPolicy" && ar.Namespaced && hasVerb(ar.Verbs, "get") && hasVerb(ar.Verbs, "patch") {
			networkPolicy = true
		}
	}
	if !velero {
		return controlplane.TenantStoragePolicy{}, controlplane.TenantBackupPolicy{}, controlplane.TenantSecurityPolicy{}, errors.New("Velero Schedule API is required by tenant backup policy")
	}
	if !networkPolicy {
		return controlplane.TenantStoragePolicy{}, controlplane.TenantBackupPolicy{}, controlplane.TenantSecurityPolicy{}, errors.New("NetworkPolicy API is required by tenant security policy")
	}
	storage := controlplane.TenantStoragePolicy{ClassSelector: plan.Storage.ClassSelector, StorageClass: storageClass, RequestQuota: plan.Storage.RequestQuota, MaxPVCSize: plan.Storage.MaxPVCSize}
	backup := controlplane.TenantBackupPolicy{Provider: plan.Backup.Provider, Schedule: plan.Backup.Schedule, Retention: plan.Backup.Retention}
	security := controlplane.TenantSecurityPolicy{PodSecurityLevel: plan.Security.PodSecurityLevel, DefaultDenyIngress: plan.Security.DefaultDenyIngress, DefaultDenyEgress: plan.Security.DefaultDenyEgress, AllowDNS: plan.Security.AllowDNS}
	return storage, backup, security, nil
}

func digestValue(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *Server) upsertEntitlement(w http.ResponseWriter, r *http.Request) {
	if err := s.requireOrganizationAccess(r, r.PathValue("id"), organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	if err = requirePlatformAdmin(r); err != nil {
		writeError(w, 403, "PLATFORM_ADMIN_REQUIRED", err.Error())
		return
	}
	var in entitlementInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	var expires *time.Time
	if in.ExpiresAt != nil && strings.TrimSpace(*in.ExpiresAt) != "" {
		t, e := time.Parse(time.RFC3339, *in.ExpiresAt)
		if e != nil {
			writeError(w, 400, "INVALID_EXPIRY", "expiresAt must be RFC3339")
			return
		}
		u := t.UTC()
		expires = &u
	}
	expected, err := parseAuthorityWritePrecondition(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "AUTHORITY_PRECONDITION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.UpsertEntitlement(r.Context(), controlplane.Entitlement{OrganizationID: r.PathValue("id"), Edition: in.Edition, ExpiresAt: expires}, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) getEntitlement(w http.ResponseWriter, r *http.Request) {
	if err := s.requireOrganizationAccess(r, r.PathValue("id"), organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.GetEntitlement(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) upsertOEMProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.requireOrganizationAccess(r, r.PathValue("id"), organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	if err = requirePlatformAdmin(r); err != nil {
		writeError(w, 403, "PLATFORM_ADMIN_REQUIRED", err.Error())
		return
	}
	var in oemProfileInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	expected, err := parseAuthorityWritePrecondition(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "AUTHORITY_PRECONDITION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.UpsertOEMProfile(r.Context(), controlplane.OEMProfile{OrganizationID: r.PathValue("id"), BrandName: in.BrandName, ProductTitle: in.ProductTitle, SupportURL: in.SupportURL, LogoObjectRef: in.LogoObjectRef, AccentColor: in.AccentColor, CustomDomain: in.CustomDomain, DefaultLocale: in.DefaultLocale}, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) getOEMProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.requireOrganizationAccess(r, r.PathValue("id"), organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	v, err := s.store.GetOEMProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		writeError(w, 400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required")
		return
	}
	var in createTenantInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	plans, err := catalog.LoadTenantPlans()
	if err != nil {
		writeError(w, 500, "TENANT_PLAN_LOAD_FAILED", "tenant plan catalog unavailable")
		return
	}
	plan, ok := plans[strings.TrimSpace(in.PlanName)]
	if !ok {
		writeError(w, 422, "TENANT_PLAN_NOT_AVAILABLE", "only catalog tenant plans are selectable")
		return
	}
	storagePolicy, backupPolicy, securityPolicy, err := s.resolveTenantPolicies(r, in.ClusterID, "", plan)
	if err != nil {
		writeError(w, 422, "TENANT_POLICY_PREREQUISITE_UNAVAILABLE", err.Error())
		return
	}
	requestDigest := digestValue(in)
	desired := digestValue(map[string]any{"projectId": in.ProjectID, "clusterId": in.ClusterID, "name": strings.ToLower(strings.TrimSpace(in.Name)), "plan": plan, "storagePolicy": storagePolicy, "backupPolicy": backupPolicy, "securityPolicy": securityPolicy})
	v, replay, err := s.store.CreateTenant(r.Context(), controlplane.TenantEnvironment{ProjectID: in.ProjectID, ClusterID: in.ClusterID, Name: in.Name, DisplayName: in.DisplayName, PlanName: plan.Name, Quota: plan.Quota, StoragePolicy: storagePolicy, BackupPolicy: backupPolicy, SecurityPolicy: securityPolicy, DesiredDigest: desired, IdempotencyKey: key, RequestDigest: requestDigest}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := 201
	if replay {
		status = 200
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"tenant": v, "idempotentReplay": replay, "next": "agent-provision"})
}
func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.TenantEnvironment, error)
	if pager, ok := s.store.(tenantPageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.TenantEnvironment, error) {
			return pager.ListTenantsPage(r.Context(), ids, all, clusterID, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.TenantEnvironment, error) {
		return s.store.ListTenants(r.Context(), projectID, clusterID)
	}, page, func(item controlplane.TenantEnvironment) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, 200, v)
}
func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) resizeTenant(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in resizeTenantInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	plans, err := catalog.LoadTenantPlans()
	if err != nil {
		writeError(w, 500, "TENANT_PLAN_LOAD_FAILED", "tenant plan catalog unavailable")
		return
	}
	plan, ok := plans[strings.TrimSpace(in.PlanName)]
	if !ok {
		writeError(w, 422, "TENANT_PLAN_NOT_AVAILABLE", "only catalog tenant plans are selectable")
		return
	}
	storagePolicy, backupPolicy, securityPolicy, err := s.resolveTenantPolicies(r, current.ClusterID, current.StoragePolicy.StorageClass, plan)
	if err != nil {
		writeError(w, 422, "TENANT_POLICY_PREREQUISITE_UNAVAILABLE", err.Error())
		return
	}
	desired := digestValue(map[string]any{"projectId": current.ProjectID, "clusterId": current.ClusterID, "name": current.Name, "plan": plan, "storagePolicy": storagePolicy, "backupPolicy": backupPolicy, "securityPolicy": securityPolicy})
	v, err := s.store.QueueTenantResize(r.Context(), current.ID, rev, plan.Name, plan.Quota, desired, actor, digestValue(in))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) approveTenant(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := approvalActor(r, current.RequestedBy)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.ApproveTenantAction(r.Context(), current.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) queueTenantAction(w http.ResponseWriter, r *http.Request, action string) {
	current, lookupErr := s.store.GetTenant(r.Context(), r.PathValue("id"))
	if lookupErr != nil {
		writeStoreError(w, lookupErr)
		return
	}
	if _, lookupErr = s.requireProjectAccess(r, current.ProjectID, organizationWrite); lookupErr != nil {
		writeScopeError(w, lookupErr)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	recoveryCheckpointID, requestDigest := "", ""
	if action == "DELETE" {
		if strings.TrimSpace(r.Header.Get("X-Confirm-Delete")) != "delete-tenant-namespace" {
			writeError(w, 428, "DELETE_CONFIRMATION_REQUIRED", "X-Confirm-Delete: delete-tenant-namespace is required")
			return
		}
		var in destructiveRecoveryInput
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		if err = in.validate(); err != nil {
			writeError(w, http.StatusBadRequest, "RECOVERY_CHECKPOINT_REQUIRED", err.Error())
			return
		}
		recoveryCheckpointID, requestDigest = in.RecoveryCheckpointID, digestValue(in)
	}
	v, err := s.store.QueueTenantAction(r.Context(), r.PathValue("id"), rev, action, actor, recoveryCheckpointID, requestDigest)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) suspendTenant(w http.ResponseWriter, r *http.Request) {
	s.queueTenantAction(w, r, "SUSPEND")
}
func (s *Server) resumeTenant(w http.ResponseWriter, r *http.Request) {
	s.queueTenantAction(w, r, "RESUME")
}
func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	s.queueTenantAction(w, r, "DELETE")
}
func (s *Server) retryTenant(w http.ResponseWriter, r *http.Request) {
	s.queueTenantAction(w, r, "RETRY")
}

func tenantTaskAction(state controlplane.TenantState) string {
	switch state {
	case controlplane.TenantProvisioning:
		return "PROVISION"
	case controlplane.TenantSuspending:
		return "SUSPEND"
	case controlplane.TenantResuming:
		return "RESUME"
	case controlplane.TenantResizing:
		return "RESIZE"
	case controlplane.TenantDeleting:
		return "DELETE"
	}
	return ""
}
func tenantResources(v controlplane.TenantEnvironment, action string) ([]controlplane.BaselineTaskResource, string) {
	desired := v.DesiredDigest
	planName := v.PlanName
	quotaSource := v.Quota
	if action == "RESIZE" {
		desired = v.PendingDesiredDigest
		planName = v.PendingPlanName
		quotaSource = v.PendingQuota
	}
	if action == "SUSPEND" {
		desired = digestValue(map[string]string{"tenant": v.ID, "state": "suspended", "base": v.DesiredDigest})
	}
	labels := map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": v.ID, "platform.4so.io/project-id": v.ProjectID, "platform.4so.io/tenant": "true", "pod-security.kubernetes.io/enforce": v.SecurityPolicy.PodSecurityLevel, "pod-security.kubernetes.io/audit": v.SecurityPolicy.PodSecurityLevel, "pod-security.kubernetes.io/warn": v.SecurityPolicy.PodSecurityLevel, "pod-security.kubernetes.io/enforce-version": "latest"}
	ann := map[string]any{"platform.4so.io/desired-digest": desired, "platform.4so.io/tenant-plan": planName, "platform.4so.io/storage-class": v.StoragePolicy.StorageClass, "platform.4so.io/backup-provider": v.BackupPolicy.Provider}
	namespace := map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": v.Namespace, "labels": labels, "annotations": ann}}
	hard := map[string]any{}
	for k, val := range quotaSource {
		hard[k] = val
	}
	hard["requests.storage"] = v.StoragePolicy.RequestQuota
	hard[v.StoragePolicy.StorageClass+".storageclass.storage.k8s.io/requests.storage"] = v.StoragePolicy.RequestQuota
	if action == "SUSPEND" {
		hard["pods"] = "0"
	}
	quota := map[string]any{"apiVersion": "v1", "kind": "ResourceQuota", "metadata": map[string]any{"name": "tenant-quota", "namespace": v.Namespace, "labels": labels, "annotations": ann}, "spec": map[string]any{"hard": hard}}
	limits := map[string]any{"apiVersion": "v1", "kind": "LimitRange", "metadata": map[string]any{"name": "tenant-default-limits", "namespace": v.Namespace, "labels": labels, "annotations": ann}, "spec": map[string]any{"limits": []any{map[string]any{"type": "Container", "defaultRequest": map[string]any{"cpu": "100m", "memory": "128Mi"}, "default": map[string]any{"cpu": "500m", "memory": "512Mi"}}, map[string]any{"type": "PersistentVolumeClaim", "max": map[string]any{"storage": v.StoragePolicy.MaxPVCSize}}}}}
	denyTypes := []any{"Ingress", "Egress"}
	deny := map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "tenant-default-deny-all", "namespace": v.Namespace, "labels": labels, "annotations": ann}, "spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": denyTypes}}
	dns := map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "tenant-allow-dns-egress", "namespace": v.Namespace, "labels": labels, "annotations": ann}, "spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Egress"}, "egress": []any{map[string]any{"to": []any{map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": "kube-system"}}}}, "ports": []any{map[string]any{"protocol": "UDP", "port": 53}, map[string]any{"protocol": "TCP", "port": 53}}}}}}
	backupScheduleName := controlplane.TenantBackupScheduleName(v.ID)
	backup := map[string]any{"apiVersion": "velero.io/v1", "kind": "Schedule", "metadata": map[string]any{"name": backupScheduleName, "namespace": "velero", "labels": labels, "annotations": ann}, "spec": map[string]any{"schedule": v.BackupPolicy.Schedule, "template": map[string]any{"includedNamespaces": []any{v.Namespace}, "ttl": v.BackupPolicy.Retention, "snapshotVolumes": true}}}
	marker := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "tenant-platform-state", "namespace": v.Namespace, "labels": labels, "annotations": ann}, "data": map[string]any{"tenantId": v.ID, "desiredDigest": desired, "state": strings.ToLower(action), "plan": planName, "storageClass": v.StoragePolicy.StorageClass, "backupProvider": v.BackupPolicy.Provider, "backupSchedule": v.BackupPolicy.Schedule, "podSecurity": v.SecurityPolicy.PodSecurityLevel, "networkPolicy": "default-deny-ingress-egress+dns"}}
	return []controlplane.BaselineTaskResource{
		{APIVersion: "v1", Kind: "Namespace", Name: v.Namespace, Object: namespace},
		{APIVersion: "v1", Kind: "ResourceQuota", Namespace: v.Namespace, Name: "tenant-quota", Object: quota},
		{APIVersion: "v1", Kind: "LimitRange", Namespace: v.Namespace, Name: "tenant-default-limits", Object: limits},
		{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: v.Namespace, Name: "tenant-default-deny-all", Object: deny},
		{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: v.Namespace, Name: "tenant-allow-dns-egress", Object: dns},
		{APIVersion: "velero.io/v1", Kind: "Schedule", Namespace: "velero", Name: backupScheduleName, Object: backup},
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: v.Namespace, Name: "tenant-platform-state", Object: marker},
	}, desired
}

func (s *Server) nextTenantTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, 401, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	v, err := s.store.NextTenantTask(r.Context(), r.PathValue("id"), agentDigest)
	if err != nil {
		if errors.Is(err, controlplane.ErrNotFound) {
			w.WriteHeader(204)
			return
		}
		writeStoreError(w, err)
		return
	}
	action := tenantTaskAction(v.State)
	resources, desired := tenantResources(v, action)
	if action == "DELETE" {
		resources = nil
		desired = ""
	}
	setRevisionETag(w, v.Revision)
	taskPlan := v.PlanName
	if action == "RESIZE" {
		taskPlan = v.PendingPlanName
	}
	writeJSON(w, 200, controlplane.TenantTask{TenantID: v.ID, TenantRevision: v.Revision, TaskFenceToken: v.TaskFenceToken, LeaseExpiresAt: *v.TaskLeaseExpiresAt, Action: action, Namespace: v.Namespace, PlanName: taskPlan, DesiredDigest: desired, Resources: resources, StoragePolicy: v.StoragePolicy, BackupPolicy: v.BackupPolicy, SecurityPolicy: v.SecurityPolicy})
}
func (s *Server) reportTenantTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, 401, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.TenantTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	result.TenantID = r.PathValue("tenantId")
	v, err := s.store.ReportTenantTask(r.Context(), r.PathValue("id"), agentDigest, rev, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
