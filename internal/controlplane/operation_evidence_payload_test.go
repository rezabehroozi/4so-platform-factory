package controlplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOperationEvidencePayloadRequiresActiveLeaseFenceAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	org, err := store.CreateOrganization(ctx, Organization{Name: "evidence-payload", DisplayName: "Evidence Payload"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "support.bundle.generate", TargetRef: "support-bundle:test", DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "low", Class: OperationClassReadOnly}, "evidence-payload", "admin", "req")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationPlanning, "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationQueued, "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, op.ID, "worker", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker", claim.FenceToken, "worker")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("sealed diagnostic payload")
	meta, err := store.AppendOperationEvidencePayload(ctx, EvidenceMetadata{OperationID: op.ID, Kind: "support-bundle", MediaType: "application/zip"}, payload, "worker", claim.FenceToken, "worker")
	if err != nil || !meta.HasPayload || !meta.Sealed {
		t.Fatalf("meta=%+v err=%v", meta, err)
	}
	replay, err := store.AppendOperationEvidencePayload(ctx, EvidenceMetadata{OperationID: op.ID, Kind: "support-bundle", MediaType: "application/zip"}, payload, "worker", claim.FenceToken, "worker")
	if err != nil || replay.ID != meta.ID {
		t.Fatalf("replay=%+v meta=%+v err=%v", replay, meta, err)
	}

	now = now.Add(2 * time.Minute)
	if _, err = store.AppendOperationEvidencePayload(ctx, EvidenceMetadata{OperationID: op.ID, Kind: "late", MediaType: "text/plain"}, []byte("late"), "worker", claim.FenceToken, "worker"); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expired lease wrote evidence: %v", err)
	}
}


func TestExclusiveOperationAwaitingApprovalSerializesSameTarget(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "exclusive-operation", DisplayName: "Exclusive Operation"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	request := OperationRequest{
		ProjectID: project.ID,
		Kind: "application.deploy",
		TargetRef: "environment-binding:cluster-1:binding-1",
		DesiredRevision: "sha256:" + strings.Repeat("a", 64),
		Risk: "medium",
		Class: OperationClassMutating,
	}
	payload := []byte(`{"authority":"APPLICATION_DEPLOYMENT_REQUEST_V1"}`)

	type outcome struct {
		op Operation
		replay bool
		blocker *Operation
		err error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, key := range []string{"exclusive-a", "exclusive-b"} {
		wg.Add(1)
		go func(idempotencyKey string) {
			defer wg.Done()
			<-start
			op, replay, blocker, err := store.CreateExclusiveOperationAwaitingApprovalWithPayload(ctx, request, idempotencyKey, "operator", idempotencyKey, "application/json", payload)
			results <- outcome{op: op, replay: replay, blocker: blocker, err: err}
		}(key)
	}
	close(start)
	wg.Wait()
	close(results)

	created, blocked := 0, 0
	var createdOp Operation
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.blocker != nil {
			blocked++
			continue
		}
		if result.replay {
			t.Fatalf("distinct idempotency keys must not be reported as replays: %+v", result)
		}
		created++
		createdOp = result.op
	}
	if created != 1 || blocked != 1 || createdOp.State != OperationAwaitingApproval {
		t.Fatalf("exclusive target admission drift: created=%d blocked=%d op=%+v", created, blocked, createdOp)
	}

	replay, replayed, blocker, err := store.CreateExclusiveOperationAwaitingApprovalWithPayload(ctx, request, createdOp.IdempotencyKey, "operator", "replay", "application/json", payload)
	if err != nil || !replayed || blocker != nil || replay.ID != createdOp.ID {
		t.Fatalf("same-key replay drift: op=%+v replay=%t blocker=%+v err=%v", replay, replayed, blocker, err)
	}
}

func TestCompleteOperationWithEvidencePayloadIsAtomicAndReplaySafe(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, nil)
	org, err := store.CreateOrganization(ctx, Organization{Name: "terminal-evidence", DisplayName: "Terminal Evidence"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: project.ID, Kind: "application.deploy", TargetRef: "environment-binding:c:b", DesiredRevision: "sha256:" + strings.Repeat("b", 64), Risk: "medium", Class: OperationClassMutating}, "terminal-evidence", "admin", "req")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationPlanning, "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, OperationQueued, "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, op.ID, "agent:c", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "agent:c", claim.FenceToken, "agent:c")
	if err != nil {
		t.Fatal(err)
	}
	runningRevision := op.Revision
	payload := []byte(`{"authority":"APPLICATION_DEPLOYMENT_EVIDENCE_V1","converged":true}`)
	meta := EvidenceMetadata{OperationID: op.ID, Kind: "application-deployment", MediaType: "application/json"}

	completed, sealed, err := store.CompleteOperationWithEvidencePayload(ctx, op.ID, runningRevision, meta, payload, "agent:c", claim.FenceToken, "agent:c")
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != OperationSucceeded || completed.Revision != runningRevision+2 || completed.LeaseOwner != "" || !sealed.HasPayload || !sealed.Sealed {
		t.Fatalf("atomic terminal completion drift: op=%+v evidence=%+v", completed, sealed)
	}

	now = now.Add(10 * time.Minute)
	replayed, replayEvidence, err := store.CompleteOperationWithEvidencePayload(ctx, op.ID, runningRevision, meta, payload, "agent:c", claim.FenceToken, "agent:c")
	if err != nil {
		t.Fatalf("exact terminal result replay failed after lease release: %v", err)
	}
	if replayed.ID != completed.ID || replayed.Revision != completed.Revision || replayEvidence.ID != sealed.ID {
		t.Fatalf("terminal replay created divergent authority: op=%+v evidence=%+v", replayed, replayEvidence)
	}
	evidence, err := store.ListEvidence(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 {
		t.Fatalf("terminal replay duplicated evidence: %+v", evidence)
	}
}
