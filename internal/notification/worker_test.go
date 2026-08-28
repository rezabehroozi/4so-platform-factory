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
	for _, state := range []controlplane.OperationState{controlplane.OperationPlanning, controlplane.OperationQueued, controlplane.OperationRunning, controlplane.OperationFailed} {
		op, err = store.TransitionOperation(ctx, op.ID, op.Revision, state, "boom", "operator")
		if err != nil {
			t.Fatalf("transition %s: %v", state, err)
		}
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
