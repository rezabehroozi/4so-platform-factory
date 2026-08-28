package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOwnerDestructiveRecoveryRevalidationAndRebind(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "recovery-owner", DisplayName: "Recovery Owner"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "runtime", DisplayName: "Runtime"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertEntitlement(ctx, Entitlement{OrganizationID: org.ID, Edition: "service-provider"}, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	enrollment, agent := "owner-recovery-enrollment-token-abcdefghijklmnopqrstuvwxyz", "owner-recovery-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := store.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "owner-runtime", DisplayName: "Owner Runtime", TokenDigest: digestTenantTest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, digestTenantTest(enrollment), digestTenantTest(agent), "uid-owner-recovery", "0.0.59")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, digestTenantTest(agent), cluster.ExternalUID, ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", KubernetesVersion: "v1.33.2", Digest: digestTenantTest("owner-inventory-a"), Capabilities: []string{TargetMutationRBACActiveCapability, TenantDeleteObservedCapability}})
	if err != nil {
		t.Fatal(err)
	}

	storagePolicy, backupPolicy, securityPolicy := tenantPolicyTest()
	tenant, _, err := store.CreateTenant(ctx, TenantEnvironment{ProjectID: project.ID, ClusterID: cluster.ID, Name: "owner-delete", DisplayName: "Owner Delete", PlanName: "small", Quota: map[string]string{"requests.cpu": "4", "requests.memory": "8Gi", "limits.cpu": "8", "limits.memory": "16Gi", "persistentvolumeclaims": "10"}, StoragePolicy: storagePolicy, BackupPolicy: backupPolicy, SecurityPolicy: securityPolicy, DesiredDigest: digestTenantTest("owner-tenant-desired"), RequestDigest: digestTenantTest("owner-tenant-create"), IdempotencyKey: "owner-tenant"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = store.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, func() TenantTaskResult {
		ev, d := tenantEvidenceTest(tenant.Namespace, tenant.ID)
		return TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "PROVISION", Success: true, ObservedDigest: tenant.DesiredDigest, Evidence: ev, EvidenceDigest: d}
	}())
	if err != nil || tenant.State != TenantActive {
		t.Fatalf("active tenant=%#v err=%v", tenant, err)
	}

	now := time.Now()
	cp1, err := store.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "owner-backup-a", EvidenceDigest: digestTenantTest("owner-backup-a"), CompletedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = store.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "DELETE", "operator", cp1.ID, digestTenantTest("owner-delete-a"))
	if err != nil {
		t.Fatal(err)
	}
	if tenant.DestructiveOperationID == "" {
		t.Fatal("delete did not bind a destructive operation")
	}
	op1, err := store.GetOperation(ctx, tenant.DestructiveOperationID)
	if err != nil || op1.State != OperationAwaitingApproval || op1.RecoveryCheckpointID != cp1.ID || tenant.State != TenantDeleteApproval {
		t.Fatalf("approval op=%#v tenant=%#v err=%v", op1, tenant, err)
	}
	tenant, err = store.ApproveTenantAction(ctx, tenant.ID, tenant.Revision, "approver-a")
	if err != nil || tenant.State != TenantDeleteQueued {
		t.Fatalf("approved tenant=%#v err=%v", tenant, err)
	}
	op1, _ = store.GetOperation(ctx, op1.ID)
	if op1.State != OperationQueued {
		t.Fatalf("approved op=%#v", op1)
	}

	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, digestTenantTest(agent), cluster.ExternalUID, ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", KubernetesVersion: "v1.33.3", Digest: digestTenantTest("owner-inventory-b"), Capabilities: []string{TargetMutationRBACActiveCapability, TenantDeleteObservedCapability}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent)); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("expected stale recovery prerequisite, got %v", err)
	}
	stillQueued, err := store.GetTenant(ctx, tenant.ID)
	if err != nil || stillQueued.State != TenantDeleteQueued {
		t.Fatalf("tenant mutated despite stale recovery: %#v err=%v", stillQueued, err)
	}

	cp2, err := store.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "owner-backup-b", EvidenceDigest: digestTenantTest("owner-backup-b"), CompletedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = store.QueueTenantAction(ctx, stillQueued.ID, stillQueued.Revision, "DELETE", "operator", cp2.ID, digestTenantTest("owner-delete-b"))
	if err != nil {
		t.Fatal(err)
	}
	op1, _ = store.GetOperation(ctx, op1.ID)
	if op1.State != OperationCancelled {
		t.Fatalf("superseded operation state=%s", op1.State)
	}
	op2, err := store.GetOperation(ctx, tenant.DestructiveOperationID)
	if err != nil || op2.ID == op1.ID || op2.State != OperationAwaitingApproval || op2.RecoveryCheckpointID != cp2.ID || tenant.State != TenantDeleteApproval {
		t.Fatalf("replacement op=%#v tenant=%#v err=%v", op2, tenant, err)
	}
	tenant, err = store.ApproveTenantAction(ctx, tenant.ID, tenant.Revision, "approver-b")
	if err != nil || tenant.State != TenantDeleteQueued {
		t.Fatalf("replacement approval=%#v err=%v", tenant, err)
	}

	claimed, err = store.NextTenantTask(ctx, cluster.ID, digestTenantTest(agent))
	if err != nil || claimed.State != TenantDeleting {
		t.Fatalf("delete claim=%#v err=%v", claimed, err)
	}
	op2, _ = store.GetOperation(ctx, op2.ID)
	if op2.State != OperationRunning || op2.Attempt != 1 {
		t.Fatalf("running op=%#v", op2)
	}
	tenant, err = store.ReportTenantTask(ctx, cluster.ID, digestTenantTest(agent), claimed.Revision, TenantTaskResult{TenantID: tenant.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "DELETE", Success: false, Error: "simulated provider failure"})
	if err != nil || tenant.State != TenantFailed {
		t.Fatalf("failed delete tenant=%#v err=%v", tenant, err)
	}
	op2, _ = store.GetOperation(ctx, op2.ID)
	if op2.State != OperationFailed || !op2.RetryExhausted {
		t.Fatalf("failed op=%#v", op2)
	}
	if _, err = store.QueueTenantAction(ctx, tenant.ID, tenant.Revision, "RETRY", "operator", "", ""); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("generic destructive retry unexpectedly accepted: %v", err)
	}
}
