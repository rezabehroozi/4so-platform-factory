package notification

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestWebhookDeliveryRetryHMACAndHistory(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	seq := 0
	store := controlplane.NewMemoryStoreWith(func() time.Time { return clock }, func(prefix string) string {
		seq++
		return prefix + "_" + strings.Repeat("x", 4) + string(rune('a'+seq))
	})
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "ops", DisplayName: "Ops"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Prod"}, "admin")
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	secret := "hmac-test-secret"
	prefix := controlplane.NotificationSecretEnvPrefixForOrganization(org.ID)
	authEnv := prefix + "TEST_AUTH"
	hmacEnv := prefix + "TEST_HMAC"
	if err := os.Setenv(authEnv, "Bearer test-token"); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(hmacEnv, secret); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv(authEnv)
	defer os.Unsetenv(hmacEnv)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("authorization=%q", got)
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got := r.Header.Get("X-Platform-Signature"); got != wantSig {
			t.Errorf("signature=%q want=%q", got, wantSig)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("temporary"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	destination, err := store.CreateNotificationDestination(ctx, controlplane.NotificationDestination{OrganizationID: org.ID, Name: "noc-webhook", Kind: controlplane.NotificationDestinationWebhook, Endpoint: server.URL, AllowHTTP: true, AuthorizationEnv: authEnv, HMACSecretEnv: hmacEnv, TimeoutSeconds: 3}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateNotificationRoute(ctx, controlplane.NotificationRoute{OrganizationID: org.ID, ProjectID: project.ID, Name: "critical-ops", Enabled: true, EventPatterns: []string{"operation.failed"}, MinimumSeverity: controlplane.NotificationWarning, DestinationIDs: []string{destination.ID}}, "admin")
	if err != nil {
		t.Fatal(err)
	}

	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: "TEST", TargetRef: "cluster-a", DesiredRevision: "r1", Risk: "high"}, "idem-1", "operator", "req-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []controlplane.OperationState{controlplane.OperationPlanning, controlplane.OperationQueued} {
		op, err = store.TransitionOperation(ctx, op.ID, op.Revision, state, "", "operator")
		if err != nil {
			t.Fatalf("transition %s: %v", state, err)
		}
	}
	claim, err := store.ClaimOperation(ctx, op.ID, "notification-test-worker", time.Minute, clock)
	if err != nil {
		t.Fatal(err)
	}
	op, _ = store.GetOperation(ctx, op.ID)
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "notification-test-worker", claim.FenceToken, "notification-test-worker")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.ReportOperationFailure(ctx, op.ID, op.Revision, "notification-test-worker", claim.FenceToken, controlplane.OperationFailureReport{Class: controlplane.OperationFailurePermanent, Code: "TEST_FAILURE", Message: "boom"}, "notification-test-worker")
	if err != nil || op.State != controlplane.OperationFailed {
		t.Fatalf("report failure op=%+v err=%v", op, err)
	}

	worker := New(store, nil)
	worker.HTTPClient = server.Client()
	worker.Now = func() time.Time { return clock }
	worker.HealthScan = 24 * time.Hour
	if err := worker.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls after first iteration=%d", calls.Load())
	}
	deliveries, err := store.ListNotificationDeliveries(ctx, org.ID, project.ID, "", 20)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("deliveries=%v err=%v", deliveries, err)
	}
	if deliveries[0].State != controlplane.NotificationDeliveryRetryWait || deliveries[0].Attempt != 1 {
		t.Fatalf("first delivery=%+v", deliveries[0])
	}
	attempts, _ := store.ListNotificationDeliveryAttempts(ctx, deliveries[0].ID)
	if len(attempts) != 1 || !attempts[0].Retryable || attempts[0].StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("attempts=%+v", attempts)
	}

	clock = clock.Add(16 * time.Second)
	if err := worker.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls after retry=%d", calls.Load())
	}
	final, err := store.GetNotificationDelivery(ctx, deliveries[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != controlplane.NotificationDeliverySucceeded || final.Attempt != 2 || final.DeliveredAt == nil {
		t.Fatalf("final=%+v", final)
	}
	attempts, _ = store.ListNotificationDeliveryAttempts(ctx, final.ID)
	if len(attempts) != 2 || !attempts[1].Success {
		t.Fatalf("attempts=%+v", attempts)
	}
	events, _ := store.ListNotificationEvents(ctx, org.ID, project.ID, 20)
	if len(events) != 1 || events[0].EventType != "operation.failed" || events[0].Severity != controlplane.NotificationCritical {
		t.Fatalf("events=%+v", events)
	}
}

func TestFailureReportedOnlyNotifiesWhenOperationIsTerminalFailed(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "notify-failure", DisplayName: "Notify Failure"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "notify-project", DisplayName: "Notify Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	failedPayload := []byte(`{"organizationId":"` + org.ID + `","projectId":"` + project.ID + `","state":"FAILED","lastError":"terminal"}`)
	event, actionable, err := classifyOutboxEvent(ctx, store, controlplane.OutboxEvent{ResourceMeta: controlplane.ResourceMeta{ID: "evt-terminal", CreatedAt: now}, AggregateType: "operation", AggregateID: "op-terminal", EventType: "operation.failure_reported", Payload: failedPayload}, now)
	if err != nil || !actionable {
		t.Fatalf("terminal failure classification actionable=%v event=%+v err=%v", actionable, event, err)
	}
	if event.EventType != "operation.failed" || event.Severity != controlplane.NotificationCritical || event.Summary != "terminal" {
		t.Fatalf("terminal failure event=%+v", event)
	}
	retryPayload := []byte(`{"organizationId":"` + org.ID + `","projectId":"` + project.ID + `","state":"RETRY_WAIT","lastError":"transient"}`)
	event, actionable, err = classifyOutboxEvent(ctx, store, controlplane.OutboxEvent{ResourceMeta: controlplane.ResourceMeta{ID: "evt-retry", CreatedAt: now}, AggregateType: "operation", AggregateID: "op-retry", EventType: "operation.failure_reported", Payload: retryPayload}, now)
	if err != nil {
		t.Fatal(err)
	}
	if actionable {
		t.Fatalf("retry-wait failure unexpectedly emitted terminal notification: %+v", event)
	}
	for _, producerEvent := range []string{"operation.owner_failed", "operation.completed"} {
		event, actionable, err = classifyOutboxEvent(ctx, store, controlplane.OutboxEvent{ResourceMeta: controlplane.ResourceMeta{ID: "evt-" + producerEvent, CreatedAt: now}, AggregateType: "operation", AggregateID: "op-domain", EventType: producerEvent, Payload: failedPayload}, now)
		if err != nil || !actionable || event.EventType != "operation.failed" || event.Severity != controlplane.NotificationCritical {
			t.Fatalf("producer %s did not normalize terminal operation failure: actionable=%v event=%+v err=%v", producerEvent, actionable, event, err)
		}
	}
}

func TestWebhookPermanentFailureDeadLetters(t *testing.T) {
	ctx := context.Background()
	clock := time.Now().UTC()
	store := controlplane.NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "ops2", DisplayName: "Ops2"}, "admin")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "p2", DisplayName: "P2"}, "admin")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }))
	defer server.Close()
	dest, err := store.CreateNotificationDestination(ctx, controlplane.NotificationDestination{OrganizationID: org.ID, Name: "bad", Kind: controlplane.NotificationDestinationWebhook, Endpoint: server.URL, AllowHTTP: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateNotificationRoute(ctx, controlplane.NotificationRoute{OrganizationID: org.ID, ProjectID: project.ID, Name: "route", Enabled: true, EventPatterns: []string{"certification.failed"}, MinimumSeverity: controlplane.NotificationInfo, DestinationIDs: []string{dest.ID}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = store.RouteNotificationEvent(ctx, controlplane.NotificationEvent{OrganizationID: org.ID, ProjectID: project.ID, SourceEventID: "source-x", AggregateType: "runtimeCertification", AggregateID: "rtc-x", EventType: "certification.failed", Severity: controlplane.NotificationCritical, Title: "failed", Payload: []byte(`{}`), OccurredAt: clock}, "test")
	if err != nil {
		t.Fatal(err)
	}
	clock = time.Now().UTC().Add(time.Second)
	worker := New(store, nil)
	worker.HTTPClient = server.Client()
	worker.Now = func() time.Time { return clock }
	worker.lastHealth = clock
	if err = worker.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	deliveries, _ := store.ListNotificationDeliveries(ctx, org.ID, project.ID, "", 10)
	if len(deliveries) != 1 || deliveries[0].State != controlplane.NotificationDeliveryDeadLetter {
		t.Fatalf("deliveries=%+v", deliveries)
	}
}

func TestDefaultWebhookClientBlocksLoopbackAndLinkLocalTargets(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.1"} {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !webhookAddressBlocked(addr) {
			t.Fatalf("unsafe webhook target %s was allowed", raw)
		}
	}
	for _, raw := range []string{"10.10.0.12", "192.168.1.20", "8.8.8.8", "fd00::10"} {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatal(err)
		}
		if webhookAddressBlocked(addr) {
			t.Fatalf("legitimate private/public webhook target %s was blocked", raw)
		}
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = newWebhookHTTPClient().Do(request)
	if err == nil || !strings.Contains(err.Error(), "local or link-local") {
		t.Fatalf("loopback webhook request was not blocked: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("blocked webhook reached local target %d times", calls.Load())
	}
}

type healthSnapshotRejectStore struct{ controlplane.Store }

func (healthSnapshotRejectStore) Snapshot(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{}, io.ErrUnexpectedEOF
}

func TestHealthScannerDoesNotLoadCanonicalSnapshot(t *testing.T) {
	store := healthSnapshotRejectStore{Store: controlplane.NewMemoryStore()}
	worker := New(store, nil)
	if err := worker.scanHealth(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("health scan unexpectedly depended on canonical snapshot: %v", err)
	}
}

func TestNotificationWorkersUseReplicaUniqueLeaseIdentity(t *testing.T) {
	store := controlplane.NewMemoryStore()
	a := New(store, nil)
	b := New(store, nil)
	if a.workerID == "" || b.workerID == "" {
		t.Fatal("worker identity must not be empty")
	}
	if a.workerID == b.workerID {
		t.Fatalf("HA replicas share worker identity %q", a.workerID)
	}
	if !strings.HasPrefix(a.workerID, "notification-dispatcher:") {
		t.Fatalf("unexpected worker identity %q", a.workerID)
	}
}

func TestDeliveryLeaseCoversMaximumWebhookTimeout(t *testing.T) {
	if deliveryClaimTTL <= 60*time.Second {
		t.Fatalf("delivery lease %s must exceed maximum webhook timeout", deliveryClaimTTL)
	}
	if deliveryClaimBatch <= 1 {
		t.Fatalf("delivery batch %d does not preserve parallel throughput", deliveryClaimBatch)
	}
}

func TestOutboxPublishUsesCurrentTimeForLeaseFence(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	store := controlplane.NewMemoryStoreWith(func() time.Time { return base }, nil)
	if _, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "lease-fence", DisplayName: "Lease Fence"}, "admin"); err != nil {
		t.Fatal(err)
	}
	worker := New(store, nil)
	worker.Now = func() time.Time { return base.Add(outboxClaimTTL + time.Second) }
	worker.lastHealth = base
	err := worker.processOutbox(ctx, base)
	if !errors.Is(err, controlplane.ErrStaleFence) {
		t.Fatalf("expired outbox lease was published with stale claim time: %v", err)
	}
}

type incrementalHealthTestStore struct {
	controlplane.Store
	candidateCalls int
	listAllCalls   int
	cluster        controlplane.ManagedCluster
	project        controlplane.Project
	inventory      controlplane.ClusterInventory
	changedAt      time.Time
}

func (s *incrementalHealthTestStore) ListNotificationHealthCandidates(_ context.Context, after time.Time, afterID string, limit int) ([]controlplane.NotificationHealthCandidate, bool, error) {
	s.candidateCalls++
	if limit != healthCandidatePage {
		return nil, false, errors.New("unexpected candidate page size")
	}
	if s.candidateCalls == 1 {
		return []controlplane.NotificationHealthCandidate{{ClusterID: s.cluster.ID, ChangedAt: s.changedAt}}, true, nil
	}
	if after.Before(s.changedAt) || afterID != s.cluster.ID {
		return nil, false, errors.New("incremental cursor did not advance deterministically")
	}
	return nil, false, nil
}

func (s *incrementalHealthTestStore) ListManagedClusters(context.Context, string) ([]controlplane.ManagedCluster, error) {
	s.listAllCalls++
	return nil, errors.New("fleet-wide cluster list must not be used by incremental health scan")
}
func (s *incrementalHealthTestStore) GetManagedCluster(context.Context, string) (controlplane.ManagedCluster, error) {
	return s.cluster, nil
}
func (s *incrementalHealthTestStore) GetProject(context.Context, string) (controlplane.Project, error) {
	return s.project, nil
}
func (s *incrementalHealthTestStore) GetLatestClusterInventory(context.Context, string) (controlplane.ClusterInventory, error) {
	return s.inventory, nil
}
func (s *incrementalHealthTestStore) ListAgentCertificates(context.Context, string) ([]controlplane.AgentCertificate, error) {
	return nil, nil
}
func (s *incrementalHealthTestStore) RouteNotificationEvent(context.Context, controlplane.NotificationEvent, string) (controlplane.NotificationEvent, []controlplane.NotificationDelivery, bool, error) {
	return controlplane.NotificationEvent{}, nil, false, nil
}

func TestHealthScannerUsesIncrementalCandidatePages(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	lastSeen := now
	base := controlplane.NewMemoryStore()
	store := &incrementalHealthTestStore{
		Store:     base,
		cluster:   controlplane.ManagedCluster{ResourceMeta: controlplane.ResourceMeta{ID: "clu-incremental", UpdatedAt: now.Add(-time.Minute)}, ProjectID: "prj-incremental", ConnectionState: "CONNECTED", KubernetesVersion: "v1.35.0", LastSeenAt: &lastSeen},
		project:   controlplane.Project{ResourceMeta: controlplane.ResourceMeta{ID: "prj-incremental"}, OrganizationID: "org-incremental"},
		inventory: controlplane.ClusterInventory{ResourceMeta: controlplane.ResourceMeta{ID: "inv-incremental", UpdatedAt: now.Add(-time.Minute)}, ClusterID: "clu-incremental", ObservedAt: now, KubernetesVersion: "v1.35.0", Digest: "sha256:" + strings.Repeat("a", 64)},
		changedAt: now.Add(-time.Minute),
	}
	worker := New(store, nil)
	worker.Now = func() time.Time { return now }
	worker.HealthScan = time.Minute
	if err := worker.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !worker.lastHealth.IsZero() {
		t.Fatalf("more candidate pages should keep health scan immediately due: %v", worker.lastHealth)
	}
	if err := worker.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if store.candidateCalls != 2 || store.listAllCalls != 0 {
		t.Fatalf("incremental scan calls candidates=%d fleetLists=%d", store.candidateCalls, store.listAllCalls)
	}
	if worker.lastFullHealth.IsZero() || worker.healthFullScan {
		t.Fatalf("cold-start full sweep did not finish incrementally: lastFull=%v full=%v", worker.lastFullHealth, worker.healthFullScan)
	}
}
