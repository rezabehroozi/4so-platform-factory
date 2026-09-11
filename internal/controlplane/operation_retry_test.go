package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func retryFixture(t *testing.T) (*MemoryStore, context.Context, Project, ManagedCluster, RecoveryCheckpoint, *time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return fmt.Sprintf("%s_%03d", prefix, seq) })
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "retry-org", DisplayName: "Retry Org"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	importToken, agentToken := testDigest(9101), testDigest(9102)
	imp, err := store.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "cluster-a", DisplayName: "Cluster A", TokenDigest: importToken, ExpiresAt: now.Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "operator")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, importToken, agentToken, "uid-retry-a", "0.0.50")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, agentToken, cluster.ExternalUID, ClusterInventory{ObservedAt: now, Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "1.31.0", Digest: testDigest(9103)})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := store.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "backup/retry-a", EvidenceDigest: testDigest(9104), CompletedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(2 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	return store, ctx, project, cluster, cp, &now
}

func queueGenericOperation(t *testing.T, store *MemoryStore, ctx context.Context, op Operation) Operation {
	t.Helper()
	var err error
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationPlanning, "", "operator")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationQueued, "", "operator")
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestOperationStepReplayRejectsSemanticConflict(t *testing.T) {
	store, ctx, project, _, _, now := retryFixture(t)
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "step-idempotency", TargetRef: "target/demo", DesiredRevision: testDigest(9199), Risk: "low", Class: OperationClassMutating}, "step-idempotency", "operator", "req-step-idempotency")
	if err != nil {
		t.Fatal(err)
	}
	op = queueGenericOperation(t, store, ctx, op)
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-step", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-step", claim.FenceToken, "worker-step")
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.AppendOperationStep(ctx, OperationStep{OperationID: op.ID, StepKey: "apply", State: OperationRunning, FenceToken: claim.FenceToken}, "worker-step")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.AppendOperationStep(ctx, OperationStep{OperationID: op.ID, StepKey: "apply", State: OperationRunning, FenceToken: claim.FenceToken}, "worker-step")
	if err != nil || replay.ID != first.ID {
		t.Fatalf("compatible replay=%+v first=%+v err=%v", replay, first, err)
	}
	if _, err = store.AppendOperationStep(ctx, OperationStep{OperationID: op.ID, StepKey: "apply", State: OperationFailed, FenceToken: claim.FenceToken, LastError: "different outcome"}, "worker-step"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting step replay was accepted: %v", err)
	}
}

func TestBoundedRetryAndPerAttemptStepHistory(t *testing.T) {
	store, ctx, project, cluster, cp, now := retryFixture(t)
	op, replay, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "cluster.wipe", TargetRef: "cluster:" + cluster.ID, DesiredRevision: testDigest(9200), Risk: "critical", Class: OperationClassDestructive, RecoveryCheckpointID: cp.ID}, "wipe-1", "operator", "req-1")
	if err != nil || replay {
		t.Fatalf("create=%+v replay=%v err=%v", op, replay, err)
	}
	if op.RetryPolicy.MaxAttempts != 2 || op.Class != OperationClassDestructive || op.RecoveryEvidenceDigest != cp.EvidenceDigest {
		t.Fatalf("policy/binding=%+v", op)
	}
	op = queueGenericOperation(t, store, ctx, op)
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-a", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-a", claim.FenceToken, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if op.Attempt != 1 || op.State != OperationRunning {
		t.Fatalf("start1=%+v", op)
	}
	if _, err = store.AppendOperationStep(ctx, OperationStep{OperationID: op.ID, StepKey: "wipe-target", State: OperationRunning, FenceToken: claim.FenceToken}, "worker-a"); err != nil {
		t.Fatal(err)
	}
	op, err = store.ReportOperationFailure(ctx, op.ID, op.Revision, "worker-a", claim.FenceToken, OperationFailureReport{Class: OperationFailureTransientNetwork, Code: "ECONNRESET", Message: "connection reset"}, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != OperationRetryWait || op.NextAttemptAt == nil || !op.NextAttemptAt.Equal(now.Add(10*time.Second)) {
		t.Fatalf("retry1=%+v", op)
	}
	if _, err = store.ClaimOperation(ctx, op.ID, "worker-b", time.Minute, now.Add(9*time.Second)); !errors.Is(err, ErrNotClaimable) {
		t.Fatalf("early claim err=%v", err)
	}
	*now = now.Add(11 * time.Second)
	claim, err = store.ClaimOperation(ctx, op.ID, "worker-b", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-b", claim.FenceToken, "worker-b")
	if err != nil {
		t.Fatal(err)
	}
	if op.Attempt != 2 {
		t.Fatalf("attempt2=%+v", op)
	}
	if _, err = store.AppendOperationStep(ctx, OperationStep{OperationID: op.ID, StepKey: "wipe-target", State: OperationRunning, FenceToken: claim.FenceToken}, "worker-b"); err != nil {
		t.Fatal(err)
	}
	steps, _ := store.ListOperationSteps(ctx, op.ID)
	if len(steps) != 2 || steps[0].Attempt == steps[1].Attempt {
		t.Fatalf("step history=%+v", steps)
	}
	op, err = store.ReportOperationFailure(ctx, op.ID, op.Revision, "worker-b", claim.FenceToken, OperationFailureReport{Class: OperationFailureTransientNetwork, Code: "ETIMEDOUT", Message: "timeout"}, "worker-b")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != OperationFailed || !op.RetryExhausted || op.Attempt != 2 {
		t.Fatalf("exhausted=%+v", op)
	}
	if _, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationQueued, "", "operator"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("budget bypass err=%v", err)
	}
}

func TestDestructiveRecoveryRevalidatedBeforeMutation(t *testing.T) {
	store, ctx, project, cluster, cp, now := retryFixture(t)
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "cluster.remove", TargetRef: "cluster:" + cluster.ID, DesiredRevision: testDigest(9300), Risk: "critical", Class: OperationClassDestructive, RecoveryCheckpointID: cp.ID}, "destroy-1", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	op = queueGenericOperation(t, store, ctx, op)
	// Change live inventory after the recovery checkpoint/operation were bound.
	imp := store.clusterImports[cluster.ImportID]
	_, _, err = upsertMutationReadyInventoryForTest(t, store, ctx, cluster.ID, imp.AgentTokenDigest, cluster.ExternalUID, ClusterInventory{ObservedAt: now.Add(time.Minute), Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "1.31.1", Digest: testDigest(9301)})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, op.ID, "worker", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	if _, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker", claim.FenceToken, "worker"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("stale recovery err=%v", err)
	}
}

func TestGenericSafeCancellationDrainsAtBoundary(t *testing.T) {
	store, ctx, project, _, _, now := retryFixture(t)
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "config.apply", TargetRef: "project:" + project.ID, DesiredRevision: testDigest(9400), Risk: "medium", Class: OperationClassMutating}, "apply-1", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	op = queueGenericOperation(t, store, ctx, op)
	claim, err := store.ClaimOperation(ctx, op.ID, "worker", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker", claim.FenceToken, "worker")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.RequestOperationCancellation(ctx, op.ID, op.Revision, "operator", "maintenance aborted")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != OperationCancelRequested || op.LeaseOwner != "worker" {
		t.Fatalf("cancel requested=%+v", op)
	}
	op, err = store.AcknowledgeOperationCancellation(ctx, op.ID, op.Revision, "worker", claim.FenceToken, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != OperationCancelled || op.LeaseOwner != "" {
		t.Fatalf("cancelled=%+v", op)
	}
}

func TestLegacyOperationSnapshotRestoresWithRetryDefaults(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now().UTC()
	snap := Snapshot{Operations: []Operation{{ResourceMeta: ResourceMeta{ID: "op_legacy", Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_legacy", Kind: "legacy", TargetRef: "target", DesiredRevision: "rev", State: OperationFailed, Risk: "medium", IdempotencyKey: "legacy-key", RequestDigest: testDigest(9500), ActorID: "operator"}}, Steps: []OperationStep{{ResourceMeta: ResourceMeta{ID: "stp_legacy", Revision: 1, CreatedAt: now, UpdatedAt: now}, OperationID: "op_legacy", StepKey: "apply", State: OperationFailed, FenceToken: 1}}}
	if err := store.Restore(snap); err != nil {
		t.Fatal(err)
	}
	op, err := store.GetOperation(context.Background(), "op_legacy")
	if err != nil {
		t.Fatal(err)
	}
	if op.Class != OperationClassMutating || op.RetryPolicy.MaxAttempts != 3 {
		t.Fatalf("legacy defaults=%+v", op)
	}
	steps, err := store.ListOperationSteps(context.Background(), "op_legacy")
	if err != nil || len(steps) != 1 || steps[0].Attempt != 1 {
		t.Fatalf("legacy steps=%+v err=%v", steps, err)
	}
}

func TestExpiredOperationLeaseRejectsWorkerMutationsBeforeReclaim(t *testing.T) {
	store, ctx, project, _, _, now := retryFixture(t)
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "config.apply", TargetRef: "project:" + project.ID, DesiredRevision: testDigest(9450), Risk: "medium", Class: OperationClassMutating}, "expired-lease-1", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	op = queueGenericOperation(t, store, ctx, op)
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-expired", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-expired", claim.FenceToken, "worker-expired")
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Minute)
	if _, err = store.BeginOperationVerification(ctx, op.ID, op.Revision, "worker-expired", claim.FenceToken, "worker-expired"); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expired verification accepted: %v", err)
	}
	if _, err = store.ReportOperationFailure(ctx, op.ID, op.Revision, "worker-expired", claim.FenceToken, OperationFailureReport{Class: OperationFailurePermanent, Message: "late failure"}, "worker-expired"); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expired failure report accepted: %v", err)
	}
	if _, err = store.AppendOperationStep(ctx, OperationStep{OperationID: op.ID, StepKey: "late-step", State: OperationRunning, FenceToken: claim.FenceToken}, "worker-expired"); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expired operation step accepted: %v", err)
	}
	op, err = store.RequestOperationCancellation(ctx, op.ID, op.Revision, "operator", "lease expired")
	if err != nil || op.State != OperationCancelRequested {
		t.Fatalf("cancel request op=%+v err=%v", op, err)
	}
	if _, err = store.AcknowledgeOperationCancellation(ctx, op.ID, op.Revision, "worker-expired", claim.FenceToken, "worker-expired"); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expired cancellation ack accepted: %v", err)
	}
}

func TestExpiredOperationLeaseRejectsCompletion(t *testing.T) {
	store, ctx, project, _, _, now := retryFixture(t)
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "config.verify", TargetRef: "project:" + project.ID, DesiredRevision: testDigest(9460), Risk: "medium", Class: OperationClassMutating}, "expired-lease-complete", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	op = queueGenericOperation(t, store, ctx, op)
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-expired", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-expired", claim.FenceToken, "worker-expired")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.BeginOperationVerification(ctx, op.ID, op.Revision, "worker-expired", claim.FenceToken, "worker-expired")
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Minute)
	if _, err = store.CompleteOperation(ctx, op.ID, op.Revision, "worker-expired", claim.FenceToken, "worker-expired"); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expired completion accepted: %v", err)
	}
}

func TestRetryWaitRejectedClaimIsSideEffectFree(t *testing.T) {
	store, ctx, project, cluster, _, now := retryFixture(t)
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "cluster.reconcile", TargetRef: "cluster:" + cluster.ID, DesiredRevision: testDigest(9300), Risk: "high", Class: OperationClassMutating}, "retry-side-effect-free", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	op = queueGenericOperation(t, store, ctx, op)
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-a", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-a", claim.FenceToken, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.ReportOperationFailure(ctx, op.ID, op.Revision, "worker-a", claim.FenceToken, OperationFailureReport{Class: OperationFailureTransientNetwork, Code: "retry", Message: "retry"}, "worker-a")
	if err != nil || op.State != OperationRetryWait || op.NextAttemptAt == nil {
		t.Fatalf("retry state=%+v err=%v", op, err)
	}
	*now = op.NextAttemptAt.Add(time.Second)
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ClaimOperation(ctx, op.ID, "   ", time.Minute, *now); !errors.Is(err, ErrValidation) {
		t.Fatalf("blank worker err=%v", err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeRaw, _ := json.Marshal(before)
	afterRaw, _ := json.Marshal(after)
	if !bytes.Equal(beforeRaw, afterRaw) {
		t.Fatalf("rejected claim mutated authority\nbefore=%s\nafter=%s", beforeRaw, afterRaw)
	}
}

func TestOperationLeaseWorkerIdentityIsCanonical(t *testing.T) {
	s := deterministicStore()
	_, prj := bootstrap(t, s)
	op, _, _ := s.CreateOperation(context.Background(), OperationRequest{ProjectID: prj.ID, Kind: "test", TargetRef: "target", DesiredRevision: "rev", Risk: "high"}, "worker-normalization", "actor", "r")
	op, _ = s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationPlanning, "", "actor")
	op, _ = s.TransitionOperation(context.Background(), op.ID, op.Revision, OperationQueued, "", "actor")
	at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	claim, err := s.ClaimOperation(context.Background(), op.ID, "  worker-a  ", time.Minute, at)
	if err != nil {
		t.Fatal(err)
	}
	if claim.LeaseOwner != "worker-a" {
		t.Fatalf("claim owner=%q", claim.LeaseOwner)
	}
	renewed, err := s.RenewOperationLease(context.Background(), op.ID, " worker-a ", claim.FenceToken, time.Minute, at.Add(10*time.Second))
	if err != nil || renewed.LeaseOwner != "worker-a" {
		t.Fatalf("renew=%+v err=%v", renewed, err)
	}
	if err = s.ReleaseOperationLease(context.Background(), op.ID, "\tworker-a\n", claim.FenceToken); err != nil {
		t.Fatal(err)
	}
}
