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

func TestAIRunPersistenceIsAdvisorySecretSafeAndIdempotent(t *testing.T) {
	store := NewMemoryStore()
	_, _, input := testAIRun(t, store)
	ctx := context.Background()
	created, replay, err := store.CreateAIRun(ctx, input, "operator")
	if err != nil || replay || !created.AdvisoryOnly {
		t.Fatalf("created=%+v replay=%v err=%v", created, replay, err)
	}
	got, replay, err := store.CreateAIRun(ctx, input, "operator")
	if err != nil || !replay || got.ID != created.ID {
		t.Fatalf("replay=%+v replay=%v err=%v", got, replay, err)
	}
	input.RequestDigest = "sha256:" + strings.Repeat("c", 64)
	if _, _, err = store.CreateAIRun(ctx, input, "operator"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestAIRunRejectsSecretOutputAndCrossProjectLink(t *testing.T) {
	store := NewMemoryStore()
	_, op, input := testAIRun(t, store)
	ctx := context.Background()
	input.Output = json.RawMessage(`{"summary":"Authorization: Bearer abcdefghijklmnopqrstuvwxyz"}`)
	if _, _, err := store.CreateAIRun(ctx, input, "operator"); !errors.Is(err, ErrValidation) {
		t.Fatalf("secret output accepted: %v", err)
	}
	org2, _ := store.CreateOrganization(ctx, Organization{Name: "other-ai-org", DisplayName: "Other"}, "admin")
	project2, _ := store.CreateProject(ctx, Project{OrganizationID: org2.ID, Name: "other-ai-project", DisplayName: "Other"}, "admin")
	input.ProjectID = project2.ID
	input.Output = json.RawMessage(`{"summary":"safe"}`)
	input.OutputDigest, _ = AIRunOutputDigest(input.Output)
	input.LinkedResourceID = op.ID
	input.IdempotencyKey = "cross-link"
	if _, _, err := store.CreateAIRun(ctx, input, "operator"); !errors.Is(err, ErrNotFound) {
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
	if _, _, err := store.CreateAIRun(context.Background(), input, "operator"); !errors.Is(err, ErrValidation) {
		t.Fatalf("mismatched output digest accepted: %v", err)
	}
}
