package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testAIRun(t *testing.T, store *MemoryStore) (Project, Operation, AIRun) {
	t.Helper()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "ai-run-org", DisplayName: "AI Run"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "ai-run-project", DisplayName: "AI Run Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "inspect", TargetRef: "target/x", DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "low", Class: OperationClassReadOnly}, "op-key", "operator", "req")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	output := json.RawMessage(`{"classification":"environment"}`)
	outputDigest, err := AIRunOutputDigest(output)
	if err != nil {
		t.Fatal(err)
	}
	return project, op, AIRun{ProjectID: project.ID, Purpose: "operator-diagnosis", Provider: "openai-responses", Model: "test", PromptID: "operator.failure-diagnosis.v1", PromptDigest: digest, ContextDigest: digest, OutputDigest: outputDigest, Output: output, LinkedResourceType: "operation", LinkedResourceID: op.ID, IdempotencyKey: "ai-key", RequestDigest: digest, AdvisoryOnly: true}
}

func TestAIExecutionFinalizeIsAdvisorySecretSafeAndIdempotent(t *testing.T) {
	store := NewMemoryStore()
	project, _, input := testAIRun(t, store)
	ctx := context.Background()
	claimInput := AIExecutionClaim{ProjectID: project.ID, Purpose: input.Purpose, IdempotencyKey: input.IdempotencyKey, RequestDigest: input.RequestDigest}
	if _, acquired, err := store.ClaimAIExecution(ctx, claimInput, "operator"); err != nil || !acquired {
		t.Fatalf("claim acquired=%v err=%v", acquired, err)
	}
	created, replay, claim, err := store.FinalizeAIExecution(ctx, input, "operator")
	if err != nil || replay || !created.AdvisoryOnly || claim.AIRunID != created.ID {
		t.Fatalf("created=%+v replay=%v claim=%+v err=%v", created, replay, claim, err)
	}
	got, replay, replayClaim, err := store.FinalizeAIExecution(ctx, input, "operator")
	if err != nil || !replay || got.ID != created.ID || replayClaim.AIRunID != created.ID {
		t.Fatalf("replay=%+v replay=%v claim=%+v err=%v", got, replay, replayClaim, err)
	}
	input.RequestDigest = "sha256:" + strings.Repeat("c", 64)
	if _, _, _, err = store.FinalizeAIExecution(ctx, input, "operator"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestAIRunRejectsSecretOutputAndCrossProjectLink(t *testing.T) {
	store := NewMemoryStore()
	_, op, input := testAIRun(t, store)
	ctx := context.Background()
	input.Output = json.RawMessage(`{"summary":"Authorization: Bearer abcdefghijklmnopqrstuvwxyz"}`)
	if _, _, _, err := store.FinalizeAIExecution(ctx, input, "operator"); !errors.Is(err, ErrValidation) {
		t.Fatalf("secret output accepted: %v", err)
	}
	org2, _ := store.CreateOrganization(ctx, Organization{Name: "other-ai-org", DisplayName: "Other"}, "admin")
	project2, _ := store.CreateProject(ctx, Project{OrganizationID: org2.ID, Name: "other-ai-project", DisplayName: "Other"}, "admin")
	input.ProjectID = project2.ID
	input.Output = json.RawMessage(`{"summary":"safe"}`)
	input.OutputDigest, _ = AIRunOutputDigest(input.Output)
	input.LinkedResourceID = op.ID
	input.IdempotencyKey = "cross-link"
	if _, acquired, err := store.ClaimAIExecution(ctx, AIExecutionClaim{ProjectID: project2.ID, Purpose: input.Purpose, IdempotencyKey: input.IdempotencyKey, RequestDigest: input.RequestDigest}, "operator"); err != nil || !acquired {
		t.Fatalf("cross-project claim acquired=%v err=%v", acquired, err)
	}
	if _, _, _, err := store.FinalizeAIExecution(ctx, input, "operator"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project link accepted: %v", err)
	}
}

func TestAIRunOutputDigestIsCanonicalAndTamperEvident(t *testing.T) {
	a := json.RawMessage(`{"b":2,"a":1}`)
	b := json.RawMessage(` { "a" : 1, "b" : 2 } `)
	da, err := AIRunOutputDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := AIRunOutputDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("canonical digest drift: %s != %s", da, db)
	}

	store := NewMemoryStore()
	_, _, input := testAIRun(t, store)
	input.OutputDigest = "sha256:" + strings.Repeat("f", 64)
	if err := ValidateAIRun(&input); !errors.Is(err, ErrValidation) {
		t.Fatalf("mismatched output digest accepted: %v", err)
	}
}

func TestAIExecutionClaimPreventsRedispatchAndSurvivesSnapshot(t *testing.T) {
	store := NewMemoryStore()
	project, _, input := testAIRun(t, store)
	ctx := context.Background()
	claimInput := AIExecutionClaim{ProjectID: project.ID, Purpose: input.Purpose, IdempotencyKey: input.IdempotencyKey, RequestDigest: input.RequestDigest}
	claim, acquired, err := store.ClaimAIExecution(ctx, claimInput, "operator")
	if err != nil || !acquired || claim.State != AIExecutionDispatched {
		t.Fatalf("claim=%+v acquired=%v err=%v", claim, acquired, err)
	}
	second, acquired, err := store.ClaimAIExecution(ctx, claimInput, "operator")
	if err != nil || acquired || second.ID != claim.ID || second.State != AIExecutionDispatched {
		t.Fatalf("second=%+v acquired=%v err=%v", second, acquired, err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewMemoryStore()
	if err := restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	third, acquired, err := restored.ClaimAIExecution(ctx, claimInput, "operator")
	if err != nil || acquired || third.ID != claim.ID || third.State != AIExecutionDispatched {
		t.Fatalf("restored=%+v acquired=%v err=%v", third, acquired, err)
	}
}

func TestAIExecutionFinalizeReconcilesLegacyRunWithoutRedispatch(t *testing.T) {
	store := NewMemoryStore()
	project, _, input := testAIRun(t, store)
	ctx := context.Background()
	claimInput := AIExecutionClaim{ProjectID: project.ID, Purpose: input.Purpose, IdempotencyKey: input.IdempotencyKey, RequestDigest: input.RequestDigest}
	if _, acquired, err := store.ClaimAIExecution(ctx, claimInput, "operator"); err != nil || !acquired {
		t.Fatalf("claim acquired=%v err=%v", acquired, err)
	}
	now := nowUTC(store.now)
	legacy := input
	legacy.ResourceMeta = ResourceMeta{ID: "air-legacy", Revision: 1, CreatedAt: now, UpdatedAt: now}
	legacy.RequestedBy = "operator"
	legacy.AdvisoryOnly = true
	store.mu.Lock()
	store.aiRuns[legacy.ID] = cloneAIRun(legacy)
	store.mu.Unlock()

	run, replay, claim, err := store.FinalizeAIExecution(ctx, input, "operator")
	if err != nil || !replay || run.ID != legacy.ID || claim.State != AIExecutionCompleted || claim.AIRunID != legacy.ID {
		t.Fatalf("legacy reconcile run=%+v replay=%v claim=%+v err=%v", run, replay, claim, err)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewMemoryStore()
	if err := restored.Restore(snap); err != nil {
		t.Fatal(err)
	}
}

func TestAIExecutionFinalizePersistsRunAndTerminalClaimTogether(t *testing.T) {
	store := NewMemoryStore()
	project, _, input := testAIRun(t, store)
	ctx := context.Background()
	claimInput := AIExecutionClaim{ProjectID: project.ID, Purpose: input.Purpose, IdempotencyKey: input.IdempotencyKey, RequestDigest: input.RequestDigest}
	if _, acquired, err := store.ClaimAIExecution(ctx, claimInput, "operator"); err != nil || !acquired {
		t.Fatalf("claim acquired=%v err=%v", acquired, err)
	}
	run, replay, claim, err := store.FinalizeAIExecution(ctx, input, "operator")
	if err != nil || replay || run.ID == "" || claim.State != AIExecutionCompleted || claim.AIRunID != run.ID {
		t.Fatalf("run=%+v replay=%v claim=%+v err=%v", run, replay, claim, err)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.AIRuns) != 1 || len(snap.AIExecutionClaims) != 1 || snap.AIExecutionClaims[0].State != AIExecutionCompleted || snap.AIExecutionClaims[0].AIRunID != snap.AIRuns[0].ID {
		t.Fatalf("atomic terminal state not persisted together: runs=%+v claims=%+v", snap.AIRuns, snap.AIExecutionClaims)
	}
	replayedRun, replay, replayedClaim, err := store.FinalizeAIExecution(ctx, input, "operator")
	if err != nil || !replay || replayedRun.ID != run.ID || replayedClaim.AIRunID != run.ID || replayedClaim.State != AIExecutionCompleted {
		t.Fatalf("replay run=%+v replay=%v claim=%+v err=%v", replayedRun, replay, replayedClaim, err)
	}
}
