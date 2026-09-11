package controlplane

import (
	"context"
	"errors"
	"strings"
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
