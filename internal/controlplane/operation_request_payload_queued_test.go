package controlplane

import (
	"context"
	"errors"
	"testing"
)

func TestCreateOperationQueuedWithPayloadIsReadOnlyDurableAndIdempotent(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "queued-payload", DisplayName: "Queued Payload"}, "owner")
	if err != nil { t.Fatal(err) }
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	if err != nil { t.Fatal(err) }

	request := OperationRequest{
		ProjectID: project.ID, Kind: "read.dry-run", TargetRef: "cluster:target",
		DesiredRevision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Risk: "low", Class: OperationClassReadOnly,
	}
	payload := []byte(`{"authority":"READ_ONLY_DRY_RUN_V1"}`)
	op, replay, err := store.CreateOperationQueuedWithPayload(ctx, request, "queued-1", "reader", "req-1", "application/json", payload)
	if err != nil || replay {
		t.Fatalf("create queued payload op=%+v replay=%v err=%v", op, replay, err)
	}
	if op.State != OperationQueued || op.Class != OperationClassReadOnly || op.Revision != 3 {
		t.Fatalf("read-only queued operation authority drift: %+v", op)
	}
	sealed, err := store.GetOperationRequestPayload(ctx, op.ID)
	if err != nil { t.Fatal(err) }
	if sealed.PayloadDigest != OperationRequestPayloadDigest(payload) || sealed.MediaType != "application/json" || string(sealed.Payload) != string(payload) {
		t.Fatalf("sealed queued request payload drift: %+v", sealed)
	}

	again, replay, err := store.CreateOperationQueuedWithPayload(ctx, request, "queued-1", "reader", "req-2", "application/json", payload)
	if err != nil || !replay || again.ID != op.ID || again.State != OperationQueued {
		t.Fatalf("queued payload replay drift op=%+v replay=%v err=%v", again, replay, err)
	}
	if _, _, err = store.CreateOperationQueuedWithPayload(ctx, request, "queued-1", "reader", "req-3", "application/json", []byte(`{"authority":"DIFFERENT"}`)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different queued payload reused idempotency key: %v", err)
	}
}

func TestCreateOperationQueuedWithPayloadRejectsMutationClasses(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "queued-payload-fence", DisplayName: "Queued Payload Fence"}, "owner")
	if err != nil { t.Fatal(err) }
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "apps", DisplayName: "Apps"}, "owner")
	if err != nil { t.Fatal(err) }

	for _, class := range []OperationClass{OperationClassMutating, OperationClassDestructive} {
		_, _, err := store.CreateOperationQueuedWithPayload(ctx, OperationRequest{
			ProjectID: project.ID, Kind: "unsafe", TargetRef: "cluster:target",
			DesiredRevision: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Risk: "high", Class: class,
		}, "unsafe-"+string(class), "reader", "req", "application/json", []byte(`{"dryRun":false}`))
		if err == nil {
			t.Fatalf("queued payload authority admitted %s operation", class)
		}
	}
}
