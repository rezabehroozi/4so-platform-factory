package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func digestTenantTest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func tenantPolicyTest() (TenantStoragePolicy, TenantBackupPolicy, TenantSecurityPolicy) {
	return TenantStoragePolicy{ClassSelector: "default", StorageClass: "replicated", RequestQuota: "1Ti", MaxPVCSize: "100Gi"}, TenantBackupPolicy{Provider: "velero", Schedule: "0 2 * * *", Retention: "336h0m0s"}, TenantSecurityPolicy{PodSecurityLevel: "restricted", DefaultDenyIngress: true, DefaultDenyEgress: true, AllowDNS: true}
}

func tenantEvidenceTestForAction(namespace, tenantID, action string) ([]TenantEvidenceArtifact, string) {
	keys := []string{"resource/Namespace/" + namespace, "resource/ResourceQuota/tenant-quota", "resource/LimitRange/tenant-default-limits", "resource/NetworkPolicy/tenant-default-deny-all", "resource/NetworkPolicy/tenant-allow-dns-egress", "resource/Schedule/" + TenantBackupScheduleName(tenantID), "resource/ConfigMap/tenant-platform-state", "security/pod-security-admission-negative"}
	if action == "SUSPEND" {
		keys = append(keys, "suspension/no-running-pods")
	}
	items := make([]TenantEvidenceArtifact, 0, len(keys))
	for _, key := range keys {
		items = append(items, TenantEvidenceArtifact{Key: key, Authority: "test-authority", Status: "PASS", Digest: digestTenantTest(key)})
	}
	raw, _ := json.Marshal(items)
	sum := sha256.Sum256(raw)
	return items, "sha256:" + hex.EncodeToString(sum[:])
}

func tenantEvidenceTest(namespace, tenantID string) ([]TenantEvidenceArtifact, string) {
	return tenantEvidenceTestForAction(namespace, tenantID, "")
}

func TestTenantBackupScheduleNameStableAndTenantUnique(t *testing.T) {
	a := TenantBackupScheduleName("ten_alpha")
	b := TenantBackupScheduleName("ten_beta")
	if a == b {
		t.Fatalf("tenant backup schedules collided: %s", a)
	}
	if a != TenantBackupScheduleName("ten_alpha") {
		t.Fatalf("tenant backup schedule identity is not stable: %s", a)
	}
	if !strings.HasPrefix(a, "tenant-platform-backup-") || len(a) != len("tenant-platform-backup-")+12 {
		t.Fatalf("unexpected tenant backup schedule name %q", a)
	}
}

func TestTenantEntitlementOEMAndLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	org, err := s.CreateOrganization(ctx, Organization{Name: "provider", DisplayName: "Provider"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "customers", DisplayName: "Customers"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	ent, err := s.UpsertEntitlement(ctx, Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, 0, "admin")
	if err != nil || !ent.OEMEnabled || ent.MaxTenants != 1000 {
		t.Fatalf("entitlement=%#v err=%v", ent, err)
	}
	oem, err := s.UpsertOEMProfile(ctx, OEMProfile{OrganizationID: org.ID, BrandName: "Example Cloud", ProductTitle: "Example Kubernetes", SupportURL: "https://support.example.test", LogoObjectRef: "object://branding/logo.svg", AccentColor: "#3366AA", DefaultLocale: "fa"}, 0, "admin")
	if err != nil || oem.BrandName != "Example Cloud" {
		t.Fatalf("oem=%#v err=%v", oem, err)
	}
	enrollment := "enrollment-token-abcdefghijklmnopqrstuvwxyz"
	agent := "agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "shared", DisplayName: "Shared", TokenDigest: digestTenantTest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = s.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := s.ClaimClusterImport(ctx, imp.ID, digestTenantTest(enrollment), digestTenantTest(agent), "uid-shared", "0.0.16")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, s, ctx, cluster.ID, digestTenantTest(agent), cluster.ExternalUID, ClusterInventory{ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{TargetMutationRBACActiveCapability}})
	if err != nil {
		t.Fatal(err)
	}
	quota := map[string]string{"requests.cpu": "4", "requests.memory": "8Gi", "limits.cpu": "8", "limits.memory": "16Gi", "persistentvolumeclaims": "10"}
	storagePolicy, backupPolicy, securityPolicy := tenantPolicyTest()
	tenant, replay, err := s.CreateTenant(ctx, TenantEnvironment{ProjectID: project.ID, ClusterID: cluster.ID, Name: "customer-a", DisplayName: "Customer A", PlanName: "small", Quota: quota, StoragePolicy: storagePolicy, BackupPolicy: backupPolicy, SecurityPolicy: securityPolicy, DesiredDigest: fmt.Sprintf("sha256:%064d", 1), RequestDigest: fmt.Sprintf("sha256:%064d", 2), IdempotencyKey: "tenant-a"}, "operator")
	if err != nil || replay || tenant.State != TenantQueued || tenant.Namespace == "" {
		t.Fatalf("tenant=%#v replay=%v err=%v", tenant, replay, err)
	}
	claimed, err := s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	if err != nil || claimed.State != TenantProvisioning {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	if _, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "PROVISION", Success: true, ObservedDigest: tenant.DesiredDigest}); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("tenant completion without evidence was accepted: %v", err)
	}
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, func() TenantTaskResult {
		ev, d := tenantEvidenceTest(tenant.Namespace, tenant.ID)
		return TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "PROVISION", Success: true, ObservedDigest: tenant.DesiredDigest, Evidence: ev, EvidenceDigest: d}
	}())
	if err != nil || tenant.State != TenantActive || tenant.RuntimeContractVersion != CurrentTenantRuntimeContractVersion {
		t.Fatalf("active=%#v err=%v", tenant, err)
	}
	// Simulate an ACTIVE tenant persisted by an older release. The normal
	// fenced Agent loop must reconcile it exactly once without an operator
	// mutation request, then seal the current runtime resource contract.
	s.mu.Lock()
	staleRuntime := s.tenants[tenant.ID]
	staleRuntime.RuntimeContractVersion = 0
	s.tenants[tenant.ID] = staleRuntime
	s.mu.Unlock()
	upgradeClaim, err := s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	if err != nil || upgradeClaim.State != TenantProvisioning || upgradeClaim.TaskFenceToken <= claimed.TaskFenceToken {
		t.Fatalf("stale active tenant was not claimed for runtime reconcile: tenant=%#v err=%v", upgradeClaim, err)
	}
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), upgradeClaim.Revision, func() TenantTaskResult {
		ev, d := tenantEvidenceTest(tenant.Namespace, tenant.ID)
		return TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: upgradeClaim.TaskFenceToken, Action: "PROVISION", Success: true, ObservedDigest: tenant.DesiredDigest, Evidence: ev, EvidenceDigest: d}
	}())
	if err != nil || tenant.State != TenantActive || tenant.RuntimeContractVersion != CurrentTenantRuntimeContractVersion {
		t.Fatalf("runtime reconcile did not seal current contract: tenant=%#v err=%v", tenant, err)
	}
	if _, err = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("current runtime contract was reconciled more than once: %v", err)
	}
	mediumQuota := map[string]string{"requests.cpu": "12", "requests.memory": "32Gi", "limits.cpu": "24", "limits.memory": "64Gi", "persistentvolumeclaims": "30"}
	tenant, err = s.QueueTenantResize(ctx, tenant.ID, tenant.Revision, "medium", mediumQuota, digestTenantTest("tenant-medium-desired"), "operator", digestTenantTest("tenant-medium-request"))
	if err != nil || tenant.State != TenantResizeApproval || tenant.PlanName != "small" || tenant.PendingPlanName != "medium" {
		t.Fatalf("resize request=%#v err=%v", tenant, err)
	}
	if _, err = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unapproved resize was claimable: %v", err)
	}
	tenant, err = s.ApproveTenantAction(ctx, tenant.ID, tenant.Revision, "approver")
	if err != nil || tenant.State != TenantResizeQueued {
		t.Fatalf("resize approve=%#v err=%v", tenant, err)
	}
	claimed, err = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	if err != nil || claimed.State != TenantResizing {
		t.Fatalf("resize claim=%#v err=%v", claimed, err)
	}
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, func() TenantTaskResult {
		ev, d := tenantEvidenceTest(tenant.Namespace, tenant.ID)
		return TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "RESIZE", Success: true, ObservedDigest: digestTenantTest("tenant-medium-desired"), Evidence: ev, EvidenceDigest: d}
	}())
	if err != nil || tenant.State != TenantActive || tenant.PlanName != "medium" || tenant.Quota["requests.cpu"] != "12" || tenant.PendingPlanName != "" {
		t.Fatalf("resized=%#v err=%v", tenant, err)
	}
	tenant, err = s.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "SUSPEND", "operator", "", "")
	if err != nil {
		t.Fatal(err)
	}
	claimed, _ = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, func() TenantTaskResult {
		ev, d := tenantEvidenceTestForAction(tenant.Namespace, tenant.ID, "SUSPEND")
		return TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "SUSPEND", Success: true, ObservedDigest: fmt.Sprintf("sha256:%064d", 3), Evidence: ev, EvidenceDigest: d}
	}())
	if err != nil || tenant.State != TenantSuspended {
		t.Fatalf("suspended=%#v err=%v", tenant, err)
	}
	tenant, _ = s.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "RESUME", "operator", "", "")
	claimed, _ = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, func() TenantTaskResult {
		ev, d := tenantEvidenceTest(tenant.Namespace, tenant.ID)
		return TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "RESUME", Success: true, ObservedDigest: tenant.DesiredDigest, Evidence: ev, EvidenceDigest: d}
	}())
	if err != nil || tenant.State != TenantActive {
		t.Fatalf("resumed=%#v err=%v", tenant, err)
	}
	tenant, _ = s.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "SUSPEND", "operator", "", "")
	claimed, _ = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "SUSPEND", Success: false, Error: "simulated transient cluster error"})
	if err != nil || tenant.State != TenantFailed || tenant.PendingAction != "SUSPEND" {
		t.Fatalf("failed tenant=%#v err=%v", tenant, err)
	}
	tenant, err = s.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "RETRY", "operator", "", "")
	if err != nil || tenant.State != TenantSuspendQueued {
		t.Fatalf("retry=%#v err=%v", tenant, err)
	}
	claimed, _ = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, func() TenantTaskResult {
		ev, d := tenantEvidenceTestForAction(tenant.Namespace, tenant.ID, "SUSPEND")
		return TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "SUSPEND", Success: true, ObservedDigest: fmt.Sprintf("sha256:%064d", 4), Evidence: ev, EvidenceDigest: d}
	}())
	if err != nil || tenant.State != TenantSuspended {
		t.Fatalf("retry suspended=%#v err=%v", tenant, err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, s, ctx, cluster.ID, digestTenantTest(agent), cluster.ExternalUID, ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", KubernetesVersion: "v1.33.2", Digest: digestTenantTest("tenant-delete-inventory"), Capabilities: []string{TargetMutationRBACActiveCapability, TenantDeleteObservedCapability}})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "tenant-delete-backup", EvidenceDigest: digestTenantTest("tenant-delete-backup-evidence"), CompletedAt: time.Now().Add(-5 * time.Minute), ExpiresAt: time.Now().Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = s.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "DELETE", "operator", cp.ID, digestTenantTest("tenant-delete-request"))
	if err != nil || tenant.State != TenantDeleteApproval || tenant.RecoveryCheckpointID != cp.ID {
		t.Fatalf("protected delete request=%#v err=%v", tenant, err)
	}
	if _, err = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unapproved delete was claimable: %v", err)
	}
	tenant, err = s.ApproveTenantAction(ctx, tenant.ID, tenant.Revision, "approver")
	if err != nil || tenant.State != TenantDeleteQueued {
		t.Fatalf("delete approve=%#v err=%v", tenant, err)
	}
	claimed, _ = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "DELETE", Success: true, Deleted: false})
	if err != nil || tenant.State != TenantDeleting {
		t.Fatalf("delete should remain in progress until namespace disappears: tenant=%#v err=%v", tenant, err)
	}
	op, err := s.GetOperation(ctx, tenant.DestructiveOperationID)
	if err != nil || op.State != OperationRunning {
		t.Fatalf("destructive operation closed before namespace disappeared: op=%#v err=%v", op, err)
	}
	claimed, err = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	if err != nil || claimed.State != TenantDeleting {
		t.Fatalf("in-progress delete was not re-issued: claimed=%#v err=%v", claimed, err)
	}
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "DELETE", Success: true, Deleted: true})
	if err != nil || tenant.State != TenantDeleted {
		t.Fatalf("deleted=%#v err=%v", tenant, err)
	}
	op, err = s.GetOperation(ctx, tenant.DestructiveOperationID)
	if err != nil || op.State != OperationSucceeded {
		t.Fatalf("destructive operation did not finish with confirmed namespace deletion: op=%#v err=%v", op, err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewMemoryStore()
	if err = restored.Restore(snap); err != nil {
		t.Fatal(err)
	}
	got, err := restored.GetTenant(ctx, tenant.ID)
	if err != nil || got.State != TenantDeleted {
		t.Fatalf("restored=%#v err=%v", got, err)
	}
}

func TestTenantDeleteWaitsForObservedDeleteCapabilityDuringRollingAgentUpgrade(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	org, err := s.CreateOrganization(ctx, Organization{Name: "tenant-upgrade", DisplayName: "Tenant Upgrade"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "runtime", DisplayName: "Runtime"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpsertEntitlement(ctx, Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	enrollment, agent := "tenant-upgrade-enrollment-token-abcdefghijklmnopqrstuvwxyz", "tenant-upgrade-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "tenant-upgrade", DisplayName: "Tenant Upgrade", TokenDigest: digestTenantTest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = s.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := s.ClaimClusterImport(ctx, imp.ID, digestTenantTest(enrollment), digestTenantTest(agent), "uid-tenant-upgrade", "0.0.85")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, s, ctx, cluster.ID, digestTenantTest(agent), cluster.ExternalUID, ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "v1.33.2", Digest: digestTenantTest("tenant-upgrade-old-inventory")})
	if err != nil {
		t.Fatal(err)
	}
	storagePolicy, backupPolicy, securityPolicy := tenantPolicyTest()
	tenant, _, err := s.CreateTenant(ctx, TenantEnvironment{ProjectID: project.ID, ClusterID: cluster.ID, Name: "upgrade-delete", DisplayName: "Upgrade Delete", PlanName: "small", Quota: map[string]string{"requests.cpu": "1", "requests.memory": "1Gi", "limits.cpu": "2", "limits.memory": "2Gi", "persistentvolumeclaims": "2"}, StoragePolicy: storagePolicy, BackupPolicy: backupPolicy, SecurityPolicy: securityPolicy, DesiredDigest: digestTenantTest("upgrade-desired"), RequestDigest: digestTenantTest("upgrade-create"), IdempotencyKey: "upgrade-delete"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, func() TenantTaskResult {
		ev, d := tenantEvidenceTest(tenant.Namespace, tenant.ID)
		return TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "PROVISION", Success: true, ObservedDigest: tenant.DesiredDigest, Evidence: ev, EvidenceDigest: d}
	}())
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "upgrade-delete-backup", EvidenceDigest: digestTenantTest("upgrade-delete-backup"), CompletedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = s.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "DELETE", "operator", cp.ID, digestTenantTest("upgrade-delete-request"))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = s.ApproveTenantAction(ctx, tenant.ID, tenant.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("legacy agent inventory unexpectedly claimed observed-delete task: %v", err)
	}
	queued, err := s.GetTenant(ctx, tenant.ID)
	if err != nil || queued.State != TenantDeleteQueued {
		t.Fatalf("delete did not remain safely queued during rolling agent upgrade: tenant=%#v err=%v", queued, err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, s, ctx, cluster.ID, digestTenantTest(agent), cluster.ExternalUID, ClusterInventory{ObservedAt: time.Now().Add(time.Second), Distribution: "rke2", KubernetesVersion: "v1.33.2", Digest: digestTenantTest("tenant-upgrade-new-inventory"), Capabilities: []string{TargetMutationRBACActiveCapability, TenantDeleteObservedCapability}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent)); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("new inventory should require a fresh recovery checkpoint before delete, got %v", err)
	}
	queued, err = s.GetTenant(ctx, tenant.ID)
	if err != nil || queued.State != TenantDeleteQueued {
		t.Fatalf("stale recovery mutated queued delete: tenant=%#v err=%v", queued, err)
	}
	cp, err = s.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "upgrade-delete-backup-new-inventory", EvidenceDigest: digestTenantTest("upgrade-delete-backup-new-inventory"), CompletedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = s.QueueTenantAction(ctx, queued.ID, queued.Revision, "DELETE", "operator", cp.ID, digestTenantTest("upgrade-delete-request-new-inventory"))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = s.ApproveTenantAction(ctx, tenant.ID, tenant.Revision, "approver-new-inventory")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = s.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	if err != nil || claimed.State != TenantDeleting {
		t.Fatalf("new capability plus fresh recovery did not unblock observed delete: claimed=%#v err=%v", claimed, err)
	}
}

func TestTenantProvisionTaskLeasePreventsConcurrentReissue(t *testing.T) {
	now := time.Now().UTC()
	s := NewMemoryStore()
	s.now = func() time.Time { return now }
	ctx := context.Background()
	org, err := s.CreateOrganization(ctx, Organization{Name: "tenant-retry-org", DisplayName: "Tenant Retry Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "tenant-retry-project", DisplayName: "Tenant Retry Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpsertEntitlement(ctx, Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	enrollment, agent := digestTenantTest("tenant-retry-enrollment"), digestTenantTest("tenant-retry-agent")
	imp, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "retry", DisplayName: "Retry", TokenDigest: enrollment, ExpiresAt: now.Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = s.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := s.ClaimClusterImport(ctx, imp.ID, enrollment, agent, "uid-tenant-retry", "0.0.89")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, s, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2", Capabilities: []string{TargetMutationRBACActiveCapability}})
	if err != nil {
		t.Fatal(err)
	}
	storage, backup, security := tenantPolicyTest()
	tenant, _, err := s.CreateTenant(ctx, TenantEnvironment{ProjectID: project.ID, ClusterID: cluster.ID, Name: "retry-a", DisplayName: "Retry A", PlanName: "small", Quota: map[string]string{"requests.cpu": "1", "requests.memory": "1Gi", "limits.cpu": "2", "limits.memory": "2Gi", "persistentvolumeclaims": "2"}, StoragePolicy: storage, BackupPolicy: backup, SecurityPolicy: security, DesiredDigest: digestTenantTest("tenant-retry-desired"), RequestDigest: digestTenantTest("tenant-retry-request"), IdempotencyKey: "tenant-retry-a"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	type claimResult struct {
		tenant TenantEnvironment
		err    error
	}
	start := make(chan struct{})
	claims := make(chan claimResult, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			claimed, claimErr := s.NextTenantTask(ctx, cluster.ID, agent)
			claims <- claimResult{tenant: claimed, err: claimErr}
		}()
	}
	close(start)
	var first TenantEnvironment
	successes, blocked := 0, 0
	for i := 0; i < 2; i++ {
		result := <-claims
		switch {
		case result.err == nil:
			first = result.tenant
			successes++
		case errors.Is(result.err, ErrNotFound):
			blocked++
		default:
			t.Fatalf("concurrent tenant claim err=%v", result.err)
		}
	}
	if successes != 1 || blocked != 1 || first.State != TenantProvisioning || first.TaskAttempt != 1 || first.TaskFenceToken != 1 || first.TaskLeaseExpiresAt == nil {
		t.Fatalf("concurrent claim ownership successes=%d blocked=%d first=%+v", successes, blocked, first)
	}
	if _, err = s.NextTenantTask(ctx, cluster.ID, agent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active tenant lease was reissued: %v", err)
	}
	now = first.TaskLeaseExpiresAt.Add(time.Second)
	cluster = refreshClusterTaskInventoryAt(t, s, ctx, cluster.ID, agent, now)
	second, err := s.NextTenantTask(ctx, cluster.ID, agent)
	if err != nil || second.TaskAttempt != 2 || second.TaskFenceToken != 2 || second.Revision <= first.Revision {
		t.Fatalf("recovered claim=%+v err=%v", second, err)
	}
	ev, d := tenantEvidenceTest(tenant.Namespace, tenant.ID)
	stale := TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: first.TaskFenceToken, Action: "PROVISION", Success: true, ObservedDigest: tenant.DesiredDigest, Evidence: ev, EvidenceDigest: d}
	if _, err = s.ReportTenantTask(ctx, cluster.ID, agent, first.Revision, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale tenant report err=%v", err)
	}
	current := stale
	current.TaskFenceToken = second.TaskFenceToken
	tenant, err = s.ReportTenantTask(ctx, cluster.ID, agent, second.Revision, current)
	if err != nil || tenant.State != TenantActive {
		t.Fatalf("tenant completion=%+v err=%v", tenant, err)
	}

	cluster, _, err = upsertMutationReadyInventoryForTest(t, s, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2", Digest: digestTenantTest("tenant-lease-delete-inventory"), Capabilities: []string{TargetMutationRBACActiveCapability, TenantDeleteObservedCapability}})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "tenant-lease-delete-backup", EvidenceDigest: digestTenantTest("tenant-lease-delete-backup"), CompletedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = s.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "DELETE", "operator", cp.ID, digestTenantTest("tenant-lease-delete-request"))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = s.ApproveTenantAction(ctx, tenant.ID, tenant.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	deleteClaim, err := s.NextTenantTask(ctx, cluster.ID, agent)
	if err != nil || deleteClaim.State != TenantDeleting || deleteClaim.TaskLeaseExpiresAt == nil {
		t.Fatalf("delete claim=%+v err=%v", deleteClaim, err)
	}
	now = deleteClaim.TaskLeaseExpiresAt.Add(time.Second)
	cluster = refreshClusterTaskInventoryAt(t, s, ctx, cluster.ID, agent, now)
	if _, err = s.NextTenantTask(ctx, cluster.ID, agent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("abandoned destructive tenant task was replayed: %v", err)
	}
	failed, err := s.GetTenant(ctx, tenant.ID)
	if err != nil || failed.State != TenantFailed {
		t.Fatalf("abandoned delete tenant=%+v err=%v", failed, err)
	}
	op, err := s.GetOperation(ctx, failed.DestructiveOperationID)
	if err != nil || op.State != OperationFailed || !op.RetryExhausted {
		t.Fatalf("abandoned delete operation=%+v err=%v", op, err)
	}
}

func TestTenantOrderingMatchesPostgresCreatedAtIDTieBreak(t *testing.T) {
	now := time.Date(2026, 8, 24, 15, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	for i := 63; i >= 0; i-- {
		id := fmt.Sprintf("ten_order_%02d", i)
		store.tenants[id] = TenantEnvironment{
			ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now},
			ProjectID:    "prj_order",
			ClusterID:    "clu_order",
			State:        TenantQueued,
		}
	}
	for attempt := 0; attempt < 8; attempt++ {
		got, err := store.ListTenants(context.Background(), "prj_order", "clu_order")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 64 {
			t.Fatalf("tenants=%d want=64", len(got))
		}
		for i := range got {
			want := fmt.Sprintf("ten_order_%02d", i)
			if got[i].ID != want {
				t.Fatalf("attempt %d tenant ordering[%d]=%q want %q for PostgreSQL ORDER BY created_at,id parity", attempt, i, got[i].ID, want)
			}
		}
	}
}

func TestTenantTaskClaimUsesCreatedAtIDTieBreak(t *testing.T) {
	now := time.Date(2026, 8, 24, 15, 30, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	agentDigest := digestTenantTest("tenant-order-agent")
	store.clusterImports["imp_order"] = ClusterImport{
		ResourceMeta:     ResourceMeta{ID: "imp_order", Revision: 1, CreatedAt: now, UpdatedAt: now},
		State:            ClusterImportClaimed,
		AgentTokenDigest: agentDigest,
	}
	store.managedClusters["clu_order"] = ManagedCluster{
		ResourceMeta:                ResourceMeta{ID: "clu_order", Revision: 1, CreatedAt: now, UpdatedAt: now},
		ImportID:                    "imp_order",
		ProjectID:                   "prj_order",
		ConnectionState:             "CONNECTED",
		Distribution:                "rke2",
		InventoryDigest:             digestTenantTest("tenant-order-inventory"),
		MutationRBACBasisDigest:     digestTenantTest("tenant-order-inventory"),
		MutationRBACIssuedForDigest: digestTenantTest("tenant-order-inventory"),
		Capabilities:                []string{TargetMutationRBACActiveCapability, TargetMutationRBACActivationIssuedCapability},
		LastSeenAt:                  &now,
		InventoryUpdatedAt:          &now,
		InventoryObservedAt:         &now,
	}
	for i := 127; i >= 0; i-- {
		id := fmt.Sprintf("ten_claim_%03d", i)
		store.tenants[id] = TenantEnvironment{
			ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now},
			ProjectID:    "prj_order",
			ClusterID:    "clu_order",
			State:        TenantQueued,
		}
	}
	claimed, err := store.NextTenantTask(context.Background(), "clu_order", agentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != "ten_claim_000" {
		t.Fatalf("claimed tenant=%q want %q for PostgreSQL ORDER BY created_at,id parity", claimed.ID, "ten_claim_000")
	}
}

func TestTenantOrderingSurvivesFileStoreRestart(t *testing.T) {
	now := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	store.MemoryStore.now = func() time.Time { return now }
	for i := 31; i >= 0; i-- {
		id := fmt.Sprintf("ten_restart_%02d", i)
		store.tenants[id] = TenantEnvironment{
			ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now},
			ProjectID:    "prj_restart",
			ClusterID:    "clu_restart",
			State:        TenantQueued,
		}
	}
	if err := store.persist(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.ListTenants(context.Background(), "prj_restart", "clu_restart")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("tenants after restart=%d want=32", len(got))
	}
	for i := range got {
		want := fmt.Sprintf("ten_restart_%02d", i)
		if got[i].ID != want {
			t.Fatalf("tenant ordering after restart[%d]=%q want %q", i, got[i].ID, want)
		}
	}
}
