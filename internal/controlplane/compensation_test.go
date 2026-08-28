package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func compensationFixture(t *testing.T) (*MemoryStore, context.Context, Project, *time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 8, 7, 0, 0, 0, time.UTC)
	seq := 0
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return fmt.Sprintf("%s_%03d", prefix, seq) })
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "comp-org", DisplayName: "Comp Org"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	return store, ctx, project, &now
}

func compensationDigest(ch byte) string {
	return "sha256:" + string(make([]byte, 0)) + fmt.Sprintf("%064c", ch)
}

func sealCompensationStepEvidence(t *testing.T, store *MemoryStore, ctx context.Context, op Operation, step OperationCompensationStep, worker string, fence int64, suffix string) string {
	t.Helper()
	_, evidence, err := store.AppendOperationStepTrace(ctx, OperationStepTraceInput{
		OperationID: op.ID, Phase: OperationStepPhaseCompensation, StepKey: step.StepKey, TraceKey: fmt.Sprintf("%s-%d-%s", step.StepKey, step.Attempt, suffix),
		Level: OperationStepLogInfo, EventType: "compensation.result", Message: "compensation step completed", EvidenceKind: "compensation-result", MediaType: "application/json", Payload: []byte(fmt.Sprintf(`{"step":%q,"attempt":%d,"result":"ok"}`, step.StepKey, step.Attempt)),
	}, worker, fence, worker)
	if err != nil {
		t.Fatal(err)
	}
	return evidence.Digest
}

func testCompPlan() []CompensationPlanStep {
	return []CompensationPlanStep{
		{StepKey: "create-namespace", ForwardOrder: 1, Strategy: CompensationAutomaticRollback, Action: "delete namespace", InputDigest: testDigest(9801), MaxAttempts: 2},
		{StepKey: "apply-controller", ForwardOrder: 2, Strategy: CompensationRestorePreviousRevision, Action: "restore controller revision", InputDigest: testDigest(9802), MaxAttempts: 2},
		{StepKey: "publish-route", ForwardOrder: 3, Strategy: CompensationAutomaticRollback, Action: "remove route", InputDigest: testDigest(9803), MaxAttempts: 2},
	}
}

func startCompensatedOperation(t *testing.T, store *MemoryStore, ctx context.Context, project Project, now time.Time, plan []CompensationPlanStep) (Operation, ClaimResult) {
	t.Helper()
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "platform.compose", TargetRef: "cluster:test", DesiredRevision: testDigest(9810), Risk: "high", Class: OperationClassMutating}, "comp-1", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationPlanning, "", "operator")
	if err != nil {
		t.Fatal(err)
	}
	op, steps, err := store.SetOperationCompensationPlan(ctx, op.ID, op.Revision, plan, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != len(plan) || op.CompensationPlanDigest == "" {
		t.Fatalf("plan=%+v steps=%+v", op, steps)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationQueued, "", "operator")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-a", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-a", claim.FenceToken, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	return op, claim
}

func TestGenericCompensationRunsReverseOrderRetriesAndSurvivesSnapshot(t *testing.T) {
	store, ctx, project, now := compensationFixture(t)
	op, claim := startCompensatedOperation(t, store, ctx, project, *now, testCompPlan())
	for _, key := range []string{"create-namespace", "apply-controller", "publish-route"} {
		_, updated, err := store.RecordOperationForwardStepCompleted(ctx, op.ID, key, op.Revision, "worker-a", claim.FenceToken, "worker-a")
		if err != nil {
			t.Fatal(err)
		}
		op = updated
	}
	op, err := store.ReportOperationFailure(ctx, op.ID, op.Revision, "worker-a", claim.FenceToken, OperationFailureReport{Class: OperationFailurePermanent, Code: "BROKEN", Message: "third phase failed"}, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != OperationFailed {
		t.Fatalf("failed=%+v", op)
	}
	op, err = store.BeginOperationCompensation(ctx, op.ID, op.Revision, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != OperationRollingBack {
		t.Fatalf("begin=%+v", op)
	}
	claim, err = store.ClaimOperation(ctx, op.ID, "rollback-a", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	step, op, err := store.ClaimNextOperationCompensationStep(ctx, op.ID, "rollback-a", claim.FenceToken, "rollback-a")
	if err != nil {
		t.Fatal(err)
	}
	if step.StepKey != "publish-route" {
		t.Fatalf("first compensation=%+v", step)
	}
	evidenceDigest := sealCompensationStepEvidence(t, store, ctx, op, step, "rollback-a", claim.FenceToken, "first")
	step, op, err = store.CompleteOperationCompensationStep(ctx, op.ID, step.StepKey, "rollback-a", claim.FenceToken, evidenceDigest, "rollback-a")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != OperationRollingBack || step.State != CompensationStepSucceeded {
		t.Fatalf("step3 op=%+v step=%+v", op, step)
	}
	// Persist and restore at a compensation boundary. Completed reverse work must not repeat.
	if err = store.ReleaseOperationLease(ctx, op.ID, "rollback-a", claim.FenceToken); err != nil {
		t.Fatal(err)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reopened := NewMemoryStoreWith(func() time.Time { return *now }, nil)
	if err = reopened.Restore(snap); err != nil {
		t.Fatal(err)
	}
	stored, _ := reopened.GetOperation(ctx, op.ID)
	claim, err = reopened.ClaimOperation(ctx, op.ID, "rollback-b", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	step, stored, err = reopened.ClaimNextOperationCompensationStep(ctx, op.ID, "rollback-b", claim.FenceToken, "rollback-b")
	if err != nil {
		t.Fatal(err)
	}
	if step.StepKey != "apply-controller" {
		t.Fatalf("after restart wanted step2 got %+v", step)
	}
	step, stored, err = reopened.ReportOperationCompensationStepFailure(ctx, op.ID, step.StepKey, "rollback-b", claim.FenceToken, CompensationStepFailure{Message: "provider timeout", Retryable: true}, "rollback-b")
	if err != nil {
		t.Fatal(err)
	}
	if step.State != CompensationStepPending || stored.State != OperationRollingBack {
		t.Fatalf("retryable=%+v op=%+v", step, stored)
	}
	step, stored, err = reopened.ClaimNextOperationCompensationStep(ctx, op.ID, "rollback-b", claim.FenceToken, "rollback-b")
	if err != nil {
		t.Fatal(err)
	}
	if step.StepKey != "apply-controller" || step.Attempt != 2 {
		t.Fatalf("retry step=%+v", step)
	}
	evidenceDigest = sealCompensationStepEvidence(t, reopened, ctx, stored, step, "rollback-b", claim.FenceToken, "retry")
	_, stored, err = reopened.CompleteOperationCompensationStep(ctx, op.ID, step.StepKey, "rollback-b", claim.FenceToken, evidenceDigest, "rollback-b")
	if err != nil {
		t.Fatal(err)
	}
	step, stored, err = reopened.ClaimNextOperationCompensationStep(ctx, op.ID, "rollback-b", claim.FenceToken, "rollback-b")
	if err != nil {
		t.Fatal(err)
	}
	if step.StepKey != "create-namespace" {
		t.Fatalf("last compensation=%+v", step)
	}
	evidenceDigest = sealCompensationStepEvidence(t, reopened, ctx, stored, step, "rollback-b", claim.FenceToken, "final")
	_, stored, err = reopened.CompleteOperationCompensationStep(ctx, op.ID, step.StepKey, "rollback-b", claim.FenceToken, evidenceDigest, "rollback-b")
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != OperationRolledBack || stored.CompensationFinishedAt == nil {
		t.Fatalf("final=%+v", stored)
	}
	steps, err := reopened.ListOperationCompensationSteps(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 3 || steps[0].State != CompensationStepSucceeded || steps[1].Attempt != 2 || steps[2].State != CompensationStepSucceeded {
		t.Fatalf("history=%+v", steps)
	}
}

func TestCompensationManualStrategyStopsAtNeedsOperator(t *testing.T) {
	store, ctx, project, now := compensationFixture(t)
	plan := []CompensationPlanStep{{StepKey: "provider-cutover", ForwardOrder: 1, Strategy: CompensationManualRecovery, Action: "run provider recovery procedure", InputDigest: testDigest(9831), MaxAttempts: 1}}
	op, claim := startCompensatedOperation(t, store, ctx, project, *now, plan)
	_, op, err := store.RecordOperationForwardStepCompleted(ctx, op.ID, "provider-cutover", op.Revision, "worker-a", claim.FenceToken, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	// Safe cancel cannot discard already-mutated work.
	op, err = store.RequestOperationCancellation(ctx, op.ID, op.Revision, "operator", "abort")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AcknowledgeOperationCancellation(ctx, op.ID, op.Revision, "worker-a", claim.FenceToken, "worker-a"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("ack bypass err=%v", err)
	}
	op, err = store.BeginOperationCompensation(ctx, op.ID, op.Revision, "operator")
	if err != nil {
		t.Fatal(err)
	}
	claim, err = store.ClaimOperation(ctx, op.ID, "rollback", time.Minute, *now)
	if err != nil {
		t.Fatal(err)
	}
	step, updated, err := store.ClaimNextOperationCompensationStep(ctx, op.ID, "rollback", claim.FenceToken, "rollback")
	if !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("manual err=%v step=%+v op=%+v", err, step, updated)
	}
	if updated.State != OperationNeedsOperator || step.State != CompensationStepManualRequired || updated.CompensationFailureStep != "provider-cutover" {
		t.Fatalf("manual=%+v step=%+v", updated, step)
	}
}

func TestDirectRollbackTransitionCannotBypassCompensationAuthority(t *testing.T) {
	store, ctx, project, _ := compensationFixture(t)
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "test.rollback", TargetRef: "cluster:test", DesiredRevision: testDigest(9991), Risk: "high", Class: OperationClassMutating}, "req-direct-rollback", "operator", "req-direct-rollback")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationPlanning, "", "operator")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationQueued, "", "operator")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationRunning, "", "worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationRollingBack, "forward failed", "worker"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("expected direct rollback transition to be blocked, got %v", err)
	}
}
