package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestNotificationFileStoreRestartAndDeadLetterRetry(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	org, err := store.CreateOrganization(ctx, Organization{Name: "notify-org", DisplayName: "Notify Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "notify-project", DisplayName: "Notify Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := store.CreateNotificationDestination(ctx, NotificationDestination{OrganizationID: org.ID, Name: "console", Kind: NotificationDestinationConsole}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateNotificationRoute(ctx, NotificationRoute{OrganizationID: org.ID, ProjectID: project.ID, Name: "all-critical", Enabled: true, EventPatterns: []string{"operation.*"}, MinimumSeverity: NotificationCritical, DestinationIDs: []string{destination.ID}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	event, deliveries, duplicate, err := store.RouteNotificationEvent(ctx, NotificationEvent{OrganizationID: org.ID, ProjectID: project.ID, SourceEventID: "source-restart", AggregateType: "operation", AggregateID: "op1", EventType: "operation.failed", Severity: NotificationCritical, Title: "Operation failed", Payload: []byte(`{"state":"FAILED"}`), OccurredAt: time.Now().UTC()}, "router")
	if err != nil || duplicate || len(deliveries) != 1 {
		t.Fatalf("event=%+v deliveries=%+v duplicate=%v err=%v", event, deliveries, duplicate, err)
	}
	claimed, err := store.ClaimNotificationDeliveries(ctx, "worker", 10, time.Minute, time.Now().UTC().Add(time.Second))
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	dead, attempt, err := store.ReportNotificationDelivery(ctx, claimed[0].ID, "worker", time.Now().UTC().Add(2*time.Second), NotificationDeliveryResult{Success: false, Retryable: false, StatusCode: 400, Error: "bad request"})
	if err != nil || dead.State != NotificationDeliveryDeadLetter || attempt.Attempt != 1 {
		t.Fatalf("dead=%+v attempt=%+v err=%v", dead, attempt, err)
	}

	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	gotEvent, err := reopened.GetNotificationEvent(ctx, event.ID)
	if err != nil || gotEvent.SourceEventID != "source-restart" {
		t.Fatalf("event after restart=%+v err=%v", gotEvent, err)
	}
	gotDelivery, err := reopened.GetNotificationDelivery(ctx, dead.ID)
	if err != nil || gotDelivery.State != NotificationDeliveryDeadLetter {
		t.Fatalf("delivery after restart=%+v err=%v", gotDelivery, err)
	}
	attempts, err := reopened.ListNotificationDeliveryAttempts(ctx, dead.ID)
	if err != nil || len(attempts) != 1 || attempts[0].StatusCode != 400 {
		t.Fatalf("attempts=%+v err=%v", attempts, err)
	}
	requeued, err := reopened.RetryNotificationDelivery(ctx, dead.ID, gotDelivery.Revision, "operator")
	if err != nil || requeued.State != NotificationDeliveryPending || requeued.Attempt != 0 {
		t.Fatalf("requeued=%+v err=%v", requeued, err)
	}

	reopened2, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened2.GetNotificationDelivery(ctx, dead.ID)
	if err != nil || persisted.State != NotificationDeliveryPending || persisted.Attempt != 0 {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
	claimedAgain, err := reopened2.ClaimNotificationDeliveries(ctx, "worker-2", 10, time.Minute, time.Now().UTC().Add(3*time.Second))
	if err != nil || len(claimedAgain) != 1 {
		t.Fatalf("claimedAgain=%+v err=%v", claimedAgain, err)
	}
	succeeded, successAttempt, err := reopened2.ReportNotificationDelivery(ctx, claimedAgain[0].ID, "worker-2", time.Now().UTC().Add(4*time.Second), NotificationDeliveryResult{Success: true, StatusCode: 204})
	if err != nil || succeeded.State != NotificationDeliverySucceeded || successAttempt.StatusCode != 204 {
		t.Fatalf("succeeded=%+v attempt=%+v err=%v", succeeded, successAttempt, err)
	}
	history, err := reopened2.ListNotificationDeliveryAttempts(ctx, dead.ID)
	if err != nil || len(history) != 2 || history[0].StatusCode != 400 || history[1].StatusCode != 204 {
		t.Fatalf("attempt history must be deterministic chronological order for equal retry-cycle attempt numbers: %+v err=%v", history, err)
	}
	_, routedAgain, duplicate, err := reopened2.RouteNotificationEvent(ctx, NotificationEvent{OrganizationID: org.ID, ProjectID: project.ID, SourceEventID: "source-restart", AggregateType: "operation", AggregateID: "op1", EventType: "operation.failed", Severity: NotificationCritical, Title: "Operation failed", Payload: []byte(`{}`)}, "router")
	if err != nil || !duplicate || len(routedAgain) != 1 || routedAgain[0].ID != dead.ID {
		t.Fatalf("duplicate=%v deliveries=%+v err=%v", duplicate, routedAgain, err)
	}
}

func TestNotificationDestinationRejectsArbitraryProcessSecretEnvironment(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "notify-secret-boundary", DisplayName: "Notify Secret Boundary"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateNotificationDestination(ctx, NotificationDestination{OrganizationID: org.ID, Name: "exfiltration-attempt", Kind: NotificationDestinationWebhook, Endpoint: "https://example.invalid/hook", AuthorizationEnv: "PLATFORM_FACTORY_SESSION_SECRET"}, "admin")
	if err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("arbitrary process secret environment was accepted: %v", err)
	}
	prefix := NotificationSecretEnvPrefixForOrganization(org.ID)
	if !NotificationSecretEnvAllowedForOrganization(org.ID, prefix+"NOC") {
		t.Fatal("organization-bound notification secret namespace was rejected")
	}
	if NotificationSecretEnvAllowedForOrganization(org.ID, "PLATFORM_FACTORY_POSTGRES_DSN") {
		t.Fatal("control-plane environment unexpectedly allowed as notification secret")
	}
	other, err := store.CreateOrganization(ctx, Organization{Name: "notify-secret-other", DisplayName: "Notify Secret Other"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if NotificationSecretEnvAllowedForOrganization(other.ID, prefix+"NOC") {
		t.Fatal("another organization unexpectedly accepted this organization's notification secret")
	}
}

func TestNotificationDeliveryLeaseCannotBeReclaimedBeforeExpiryBySameWorker(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return clock }, nil)
	org, err := store.CreateOrganization(ctx, Organization{Name: "lease-org", DisplayName: "Lease Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "lease-project", DisplayName: "Lease Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	dest, err := store.CreateNotificationDestination(ctx, NotificationDestination{OrganizationID: org.ID, Name: "console", Kind: NotificationDestinationConsole}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateNotificationRoute(ctx, NotificationRoute{OrganizationID: org.ID, ProjectID: project.ID, Name: "lease-route", Enabled: true, EventPatterns: []string{"operation.failed"}, MinimumSeverity: NotificationInfo, DestinationIDs: []string{dest.ID}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, deliveries, _, err := store.RouteNotificationEvent(ctx, NotificationEvent{OrganizationID: org.ID, ProjectID: project.ID, SourceEventID: "lease-source", AggregateType: "operation", AggregateID: "op-lease", EventType: "operation.failed", Severity: NotificationCritical, Title: "failed", OccurredAt: clock}, "router")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("deliveries=%+v err=%v", deliveries, err)
	}
	first, err := store.ClaimNotificationDeliveries(ctx, "same-worker", 1, time.Minute, clock)
	if err != nil || len(first) != 1 {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := store.ClaimNotificationDeliveries(ctx, "same-worker", 1, time.Minute, clock.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("same worker reclaimed unexpired fenced delivery: %+v", second)
	}
	third, err := store.ClaimNotificationDeliveries(ctx, "other-worker", 1, time.Minute, clock.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 0 {
		t.Fatalf("other worker reclaimed unexpired fenced delivery: %+v", third)
	}
}

func TestNotificationHealthScanLeaseElectsOneWorkerAndFailsOver(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	claimed, err := store.ClaimNotificationHealthScanLease(ctx, "worker-a", time.Minute, now)
	if err != nil || !claimed {
		t.Fatalf("worker-a claim=%v err=%v", claimed, err)
	}
	claimed, err = store.ClaimNotificationHealthScanLease(ctx, "worker-b", time.Minute, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("worker-b acquired health scan lease before expiry")
	}
	claimed, err = store.ClaimNotificationHealthScanLease(ctx, "worker-b", time.Minute, now.Add(61*time.Second))
	if err != nil || !claimed {
		t.Fatalf("worker-b failover claim=%v err=%v", claimed, err)
	}
}

func TestNotificationDeliveryEqualTimestampOrderingIsDeterministicAndMatchesPostgres(t *testing.T) {
	ctx := context.Background()
	stamp := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return stamp }, nil)

	event := NotificationEvent{
		ResourceMeta:   ResourceMeta{ID: "nte_equal", Revision: 1, CreatedAt: stamp, UpdatedAt: stamp},
		OrganizationID: "org_equal",
		ProjectID:      "prj_equal",
		OccurredAt:     stamp,
	}
	store.notificationEvents[event.ID] = event
	for _, id := range []string{"ndl_001", "ndl_003", "ndl_002"} {
		store.notificationDeliveries[id] = NotificationDelivery{
			ResourceMeta:  ResourceMeta{ID: id, Revision: 1, CreatedAt: stamp, UpdatedAt: stamp},
			EventID:       event.ID,
			State:         NotificationDeliveryPending,
			NextAttemptAt: stamp,
		}
	}

	// PostgreSQL orders operator-facing delivery collections by
	// created_at DESC,id DESC. Equal timestamps are common because routing one
	// event creates all deliveries from the same clock sample. Repeated reads
	// must therefore return the same bounded subset independent of Go map order.
	for i := 0; i < 256; i++ {
		got, err := store.ListNotificationDeliveries(ctx, event.OrganizationID, event.ProjectID, "", 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].ID != "ndl_003" || got[1].ID != "ndl_002" {
			t.Fatalf("iteration %d unstable/non-canonical delivery page: %+v", i, got)
		}
	}
}

func TestNotificationDeliveryClaimEqualTimestampOrderingMatchesPostgres(t *testing.T) {
	ctx := context.Background()
	stamp := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	// PostgreSQL claims with ORDER BY next_attempt_at,created_at,id. When all
	// timestamps tie, the lowest ID must be claimed first so worker behavior is
	// deterministic across Memory/File/PostgreSQL authorities and restarts.
	for i := 0; i < 128; i++ {
		store := NewMemoryStoreWith(func() time.Time { return stamp }, nil)
		for _, id := range []string{"ndl_003", "ndl_001", "ndl_002"} {
			store.notificationDeliveries[id] = NotificationDelivery{
				ResourceMeta:  ResourceMeta{ID: id, Revision: 1, CreatedAt: stamp, UpdatedAt: stamp},
				State:         NotificationDeliveryPending,
				NextAttemptAt: stamp,
				MaxAttempts:   5,
			}
		}
		claimed, err := store.ClaimNotificationDeliveries(ctx, "worker", 1, time.Minute, stamp)
		if err != nil {
			t.Fatal(err)
		}
		if len(claimed) != 1 || claimed[0].ID != "ndl_001" {
			t.Fatalf("iteration %d non-canonical claim order: %+v", i, claimed)
		}
	}
}
