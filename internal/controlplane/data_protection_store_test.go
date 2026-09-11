package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDataProtectionAuthorityBackupRestoreApprovalAndDrill(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)
	var err error
	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{
		ObservedAt: now, Distribution: "rke2", KubernetesVersion: "1.33.1", Digest: testDigest(15001),
		Capabilities: []string{TargetMutationRBACActiveCapability, DataProtectionAgentCapability},
		Nodes:        []ClusterNode{{Name: "worker-1", UID: "node-dp-1", Roles: []string{"worker"}, Ready: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := store.UpsertBackupPolicy(ctx, BackupPolicy{ProjectID: project.ID, ClusterID: cluster.ID, Name: "critical", Provider: "velero", BackupStorageLocation: "primary", CredentialRef: "k8s-secret://velero/cloud-credentials", Schedule: "0 */6 * * *", Retention: "168h", IncludedNamespaces: []string{"payments"}}, 0, "operator")
	if err != nil {
		t.Fatal(err)
	}
	backup, replay, err := store.CreateDataProtectionRun(ctx, DataProtectionRun{Kind: DataProtectionBackup, ProjectID: project.ID, ClusterID: cluster.ID, PolicyID: policy.ID, IdempotencyKey: "backup-1", RequestDigest: testDigest(15002)}, "operator")
	if err != nil || replay || backup.State != DataProtectionQueued {
		t.Fatalf("backup=%+v replay=%v err=%v", backup, replay, err)
	}
	claimed, claimedPolicy, err := store.NextDataProtectionTask(ctx, cluster.ID, agent)
	if err != nil || claimed.PolicyDigest != claimedPolicy.DesiredDigest || claimed.TaskFenceToken < 1 {
		t.Fatalf("claimed=%+v policy=%+v err=%v", claimed, claimedPolicy, err)
	}
	result := DataProtectionTaskResult{RunID: claimed.ID, TaskFenceToken: claimed.TaskFenceToken, Success: true, Reference: "velero://" + cluster.ID + "/backup/one", Checks: []RuntimeCheck{{Key: "data-protection/bsl", Status: "PASS"}, {Key: "data-protection/backup", Status: "PASS"}}}
	result.EvidenceDigest = DataProtectionEvidenceDigest(claimed, result)
	backup, err = store.ReportDataProtectionTask(ctx, cluster.ID, agent, claimed.Revision, result)
	if err != nil || backup.State != DataProtectionSucceeded || backup.RecoveryCheckpointID == "" {
		t.Fatalf("backup completion=%+v err=%v", backup, err)
	}
	cp, err := store.GetRecoveryCheckpoint(ctx, backup.RecoveryCheckpointID)
	if err != nil || cp.State != RecoveryCheckpointVerified || cp.EvidenceDigest != backup.EvidenceDigest {
		t.Fatalf("checkpoint=%+v err=%v", cp, err)
	}

	restore, replay, err := store.CreateDataProtectionRun(ctx, DataProtectionRun{Kind: DataProtectionRestore, ProjectID: project.ID, ClusterID: cluster.ID, PolicyID: policy.ID, BackupRunID: backup.ID, IdempotencyKey: "restore-1", RequestDigest: testDigest(15003)}, "operator")
	if err != nil || replay || restore.State != DataProtectionAwaitingApproval {
		t.Fatalf("restore=%+v replay=%v err=%v", restore, replay, err)
	}
	if _, err = store.ApproveDataProtectionRun(ctx, restore.ID, restore.Revision, "operator"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("self approval err=%v", err)
	}
	restore, err = store.ApproveDataProtectionRun(ctx, restore.ID, restore.Revision, "approver")
	if err != nil || restore.State != DataProtectionQueued || restore.ApprovedBy != "approver" {
		t.Fatalf("approved restore=%+v err=%v", restore, err)
	}

	// Finish the queued restore first so the drill claim cannot be starved by FIFO ordering.
	claimed, _, err = store.NextDataProtectionTask(ctx, cluster.ID, agent)
	if err != nil || claimed.ID != restore.ID {
		t.Fatalf("restore claim=%+v err=%v", claimed, err)
	}
	result = DataProtectionTaskResult{RunID: claimed.ID, TaskFenceToken: claimed.TaskFenceToken, Success: true, Reference: "velero://" + cluster.ID + "/restore/one", Checks: []RuntimeCheck{{Key: "data-protection/bsl", Status: "PASS"}, {Key: "data-protection/restore", Status: "PASS"}, {Key: "data-protection/restore-progress", Status: "PASS"}}}
	result.EvidenceDigest = DataProtectionEvidenceDigest(claimed, result)
	if _, err = store.ReportDataProtectionTask(ctx, cluster.ID, agent, claimed.Revision, result); err != nil {
		t.Fatal(err)
	}

	drill, replay, err := store.CreateDataProtectionRun(ctx, DataProtectionRun{Kind: DataProtectionRestoreDrill, ProjectID: project.ID, ClusterID: cluster.ID, PolicyID: policy.ID, BackupRunID: backup.ID, IdempotencyKey: "drill-1", RequestDigest: testDigest(15004)}, "operator")
	if err != nil || replay || drill.State != DataProtectionQueued || drill.TargetNamespace == "" {
		t.Fatalf("drill=%+v replay=%v err=%v", drill, replay, err)
	}
	claimed, _, err = store.NextDataProtectionTask(ctx, cluster.ID, agent)
	if err != nil || claimed.ID != drill.ID {
		t.Fatalf("drill claim=%+v err=%v", claimed, err)
	}
	result = DataProtectionTaskResult{RunID: claimed.ID, TaskFenceToken: claimed.TaskFenceToken, Success: true, Reference: "velero://" + cluster.ID + "/restore-drill/one", Checks: []RuntimeCheck{{Key: "data-protection/bsl", Status: "PASS"}, {Key: "data-protection/restore_drill", Status: "PASS"}, {Key: "data-protection/restore-progress", Status: "PASS"}, {Key: "data-protection/restore-drill-cleanup", Status: "PASS"}}}
	result.EvidenceDigest = DataProtectionEvidenceDigest(claimed, result)
	drill, err = store.ReportDataProtectionTask(ctx, cluster.ID, agent, claimed.Revision, result)
	if err != nil || drill.State != DataProtectionSucceeded || drill.RecoveryCheckpointID == "" {
		t.Fatalf("drill completion=%+v err=%v", drill, err)
	}
}

func TestDataProtectionTaskContextDriftIsDurablyFailed(t *testing.T) {
	now := time.Date(2026, 9, 7, 13, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)
	cluster, _, _ = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "1.33.1", Digest: testDigest(15101), Capabilities: []string{TargetMutationRBACActiveCapability, DataProtectionAgentCapability}, Nodes: []ClusterNode{{Name: "w", UID: "w1", Ready: true}}})
	policy, err := store.UpsertBackupPolicy(ctx, BackupPolicy{ProjectID: project.ID, ClusterID: cluster.ID, Name: "p", Provider: "velero", BackupStorageLocation: "primary", CredentialRef: "k8s-secret://velero/cloud", Schedule: "0 * * * *", Retention: "24h", IncludedNamespaces: []string{"app"}}, 0, "op")
	if err != nil {
		t.Fatal(err)
	}
	run, _, err := store.CreateDataProtectionRun(ctx, DataProtectionRun{Kind: DataProtectionBackup, ProjectID: project.ID, ClusterID: cluster.ID, PolicyID: policy.ID, IdempotencyKey: "one", RequestDigest: testDigest(15102)}, "op")
	if err != nil {
		t.Fatal(err)
	}
	policy.Schedule = "30 * * * *"
	if _, err = store.UpsertBackupPolicy(ctx, policy, policy.Revision, "op"); err != nil {
		t.Fatal(err)
	}
	claimed, _, err := store.NextDataProtectionTask(ctx, cluster.ID, agent)
	if err != nil || claimed.ID != run.ID || claimed.State != DataProtectionFailed {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	persisted, err := store.GetDataProtectionRun(ctx, run.ID)
	if err != nil || persisted.State != DataProtectionFailed || persisted.LastError == "" {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
}

func TestDataProtectionSnapshotRestoreRebuildsIdempotency(t *testing.T) {
	now := time.Date(2026, 9, 7, 14, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	ctx := context.Background()
	project, cluster, agent := seedMaintenanceCluster(t, store, now)
	cluster, _, _ = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agent, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "1.33.1", Digest: testDigest(15201), Capabilities: []string{TargetMutationRBACActiveCapability, DataProtectionAgentCapability}, Nodes: []ClusterNode{{Name: "w", UID: "w1", Ready: true}}})
	policy, err := store.UpsertBackupPolicy(ctx, BackupPolicy{ProjectID: project.ID, ClusterID: cluster.ID, Name: "p", Provider: "velero", BackupStorageLocation: "primary", CredentialRef: "k8s-secret://velero/cloud", Schedule: "0 * * * *", Retention: "24h", IncludedNamespaces: []string{"app"}}, 0, "op")
	if err != nil {
		t.Fatal(err)
	}
	run, replay, err := store.CreateDataProtectionRun(ctx, DataProtectionRun{Kind: DataProtectionBackup, ProjectID: project.ID, ClusterID: cluster.ID, PolicyID: policy.ID, IdempotencyKey: "restart-key", RequestDigest: testDigest(15202)}, "op")
	if err != nil || replay {
		t.Fatalf("run=%+v replay=%v err=%v", run, replay, err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewMemoryStoreWith(func() time.Time { return now }, nil)
	if err = restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	replayed, replay, err := restored.CreateDataProtectionRun(ctx, DataProtectionRun{Kind: DataProtectionBackup, ProjectID: project.ID, ClusterID: cluster.ID, PolicyID: policy.ID, IdempotencyKey: "restart-key", RequestDigest: testDigest(15202)}, "op")
	if err != nil || !replay || replayed.ID != run.ID {
		t.Fatalf("replayed=%+v replay=%v err=%v", replayed, replay, err)
	}
	if _, _, err = restored.CreateDataProtectionRun(ctx, DataProtectionRun{Kind: DataProtectionBackup, ProjectID: project.ID, ClusterID: cluster.ID, PolicyID: policy.ID, IdempotencyKey: "restart-key", RequestDigest: testDigest(15203)}, "op"); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched replay err=%v", err)
	}
}

func TestDataProtectionSuccessfulEvidenceRequiresRestoreProgressAndCleanup(t *testing.T) {
	run := DataProtectionRun{Kind: DataProtectionRestoreDrill, ClusterID: "cluster-a"}
	result := DataProtectionTaskResult{Success: true, Reference: "velero://cluster-a/restore-drill/test", Checks: []RuntimeCheck{
		{Key: "data-protection/bsl", Status: "PASS"},
		{Key: "data-protection/restore_drill", Status: "PASS"},
	}}
	if err := ValidateDataProtectionSuccessfulResult(run, result); err == nil {
		t.Fatal("restore drill success without progress/cleanup evidence was accepted")
	}
	result.Checks = append(result.Checks,
		RuntimeCheck{Key: "data-protection/restore-progress", Status: "PASS"},
		RuntimeCheck{Key: "data-protection/restore-drill-cleanup", Status: "PASS"},
	)
	if err := ValidateDataProtectionSuccessfulResult(run, result); err != nil {
		t.Fatalf("complete restore drill evidence rejected: %v", err)
	}
}

func TestDataProtectionEvidenceDigestIgnoresRetryTimingTelemetry(t *testing.T) {
	run := DataProtectionRun{ResourceMeta: ResourceMeta{ID: "dpr-deterministic"}, Kind: DataProtectionBackup, ProjectID: "prj-1", ClusterID: "cluster-1", PolicyID: "policy-1", InventoryDigest: testDigest(9101), PolicyDigest: testDigest(9102), VeleroName: "backup-deterministic"}
	base := DataProtectionTaskResult{Success: true, Reference: "velero://cluster-1/backup/backup-deterministic", Checks: []RuntimeCheck{{Key: "data-protection/bsl", Status: "PASS", Detail: "ok", DurationMillis: 15}, {Key: "data-protection/backup", Status: "PASS", Detail: "done", DurationMillis: 37}}, RPOSeconds: 12, RTOSeconds: 42}
	retry := base
	retry.Checks = append([]RuntimeCheck(nil), base.Checks...)
	retry.Checks[0].DurationMillis = 0
	retry.Checks[1].DurationMillis = 1
	retry.RPOSeconds = 9
	retry.RTOSeconds = 0
	if got, want := DataProtectionEvidenceDigest(run, retry), DataProtectionEvidenceDigest(run, base); got != want {
		t.Fatalf("retry timing telemetry changed evidence identity: got=%s want=%s", got, want)
	}
}
