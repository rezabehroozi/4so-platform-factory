package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/fleethealth"
)

const (
	defaultPollInterval = 2 * time.Second
	defaultHealthScan   = time.Minute
	healthFullScanEvery = 24 * time.Hour
	healthCandidatePage = 128
	outboxClaimTTL      = 30 * time.Second
	deliveryClaimTTL    = 90 * time.Second
	deliveryClaimBatch  = 8
)

type Worker struct {
	Store          controlplane.Store
	Logger         *slog.Logger
	HTTPClient     *http.Client
	Now            func() time.Time
	PollInterval   time.Duration
	HealthScan     time.Duration
	workerID       string
	lastHealth     time.Time
	healthCursorAt time.Time
	healthCursorID string
	healthFullScan bool
	lastFullHealth time.Time
}

func New(store controlplane.Store, logger *slog.Logger) *Worker {
	return &Worker{Store: store, Logger: logger, HTTPClient: newWebhookHTTPClient(), Now: time.Now, PollInterval: defaultPollInterval, HealthScan: defaultHealthScan, workerID: newWorkerID()}
}

func newWorkerID() string {
	host, _ := os.Hostname()
	host = strings.TrimSpace(host)
	if host == "" {
		host = "unknown-host"
	}
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Sprintf("notification-dispatcher:%s:%d", host, os.Getpid())
	}
	return fmt.Sprintf("notification-dispatcher:%s:%d:%s", host, os.Getpid(), hex.EncodeToString(suffix[:]))
}

type healthScanLeaseStore interface {
	ClaimNotificationHealthScanLease(context.Context, string, time.Duration, time.Time) (bool, error)
}

type healthCandidateStore interface {
	ListNotificationHealthCandidates(context.Context, time.Time, string, int) ([]controlplane.NotificationHealthCandidate, bool, error)
}

func newWebhookHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Notification delivery is server-side authority. Resolve and dial the exact
	// validated address so a tenant-controlled hostname cannot rebind to local or
	// link-local infrastructure between validation and connection establishment.
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid webhook target %q: %w", address, err)
		}
		addresses, err := resolveWebhookHost(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, addr := range addresses {
			if webhookAddressBlocked(addr) {
				return nil, fmt.Errorf("webhook target resolves to a local or link-local address: %s", addr)
			}
		}
		var lastErr error
		for _, addr := range addresses {
			if network == "tcp4" && !addr.Is4() {
				continue
			}
			if network == "tcp6" && addr.Is4() {
				continue
			}
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("webhook target has no address compatible with %s", network)
		}
		return nil, lastErr
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("webhook redirects are disabled")
		},
	}
}

func resolveWebhookHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	values, err := net.DefaultResolver.LookupNetIP(ctx, "ip", strings.TrimSpace(host))
	if err != nil {
		return nil, fmt.Errorf("resolve webhook target %q: %w", host, err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("webhook target %q resolved to no addresses", host)
	}
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		out = append(out, value.Unmap())
	}
	return out, nil
}

func webhookAddressBlocked(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		v := addr.As4()
		return v[0] == 0
	}
	return false
}

func (w *Worker) Run(ctx context.Context) {
	if w == nil || w.Store == nil {
		return
	}
	if w.Logger == nil {
		w.Logger = slog.Default()
	}
	if w.HTTPClient == nil {
		w.HTTPClient = newWebhookHTTPClient()
	}
	if w.Now == nil {
		w.Now = time.Now
	}
	if w.PollInterval <= 0 {
		w.PollInterval = defaultPollInterval
	}
	if w.HealthScan <= 0 {
		w.HealthScan = defaultHealthScan
	}
	_ = w.ProcessOnce(ctx)
	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.ProcessOnce(ctx); err != nil && ctx.Err() == nil {
				w.Logger.Warn("notification dispatcher iteration failed", "error", err)
			}
		}
	}
}

func (w *Worker) ProcessOnce(ctx context.Context) error {
	now := w.Now().UTC()
	if err := w.processOutbox(ctx, now); err != nil {
		return err
	}
	if w.lastHealth.IsZero() || now.Sub(w.lastHealth) >= w.HealthScan {
		shouldScan := true
		if leaseStore, ok := w.Store.(healthScanLeaseStore); ok {
			leaseTTL := 2 * w.HealthScan
			if leaseTTL < 2*time.Minute {
				leaseTTL = 2 * time.Minute
			}
			var leaseErr error
			shouldScan, leaseErr = leaseStore.ClaimNotificationHealthScanLease(ctx, w.workerID, leaseTTL, now)
			if leaseErr != nil {
				return leaseErr
			}
		}
		more := false
		if shouldScan {
			var scanErr error
			if _, ok := w.Store.(healthCandidateStore); ok {
				more, scanErr = w.scanHealthIncremental(ctx, now)
			} else {
				scanErr = w.scanHealth(ctx, now)
			}
			if scanErr != nil {
				return scanErr
			}
		}
		// A worker with more incremental pages keeps the scan due so the next
		// dispatcher poll drains another bounded page under the HA lease.
		// Followers still wait for the normal interval instead of hammering the
		// lease row.
		if shouldScan && more {
			w.lastHealth = time.Time{}
		} else {
			w.lastHealth = now
		}
	}
	return w.processDeliveries(ctx, now)
}

func (w *Worker) processOutbox(ctx context.Context, now time.Time) error {
	events, err := w.Store.ClaimOutbox(ctx, w.workerID, 64, outboxClaimTTL, now)
	if err != nil {
		return err
	}
	for _, source := range events {
		event, actionable, classifyErr := classifyOutboxEvent(ctx, w.Store, source, now)
		if classifyErr != nil {
			return classifyErr
		}
		if actionable {
			if _, _, _, err = w.Store.RouteNotificationEvent(ctx, event, "notification-dispatcher"); err != nil {
				return fmt.Errorf("route outbox event %s: %w", source.ID, err)
			}
		}
		// Fence publication against the lease at completion time, not the
		// timestamp captured before the batch was claimed. Classification/routing
		// can take long enough for the lease to expire; a stale worker must not
		// publish after it no longer owns the event.
		if err = w.Store.MarkOutboxPublished(ctx, source.ID, w.workerID, w.Now().UTC()); err != nil {
			return fmt.Errorf("publish outbox event %s: %w", source.ID, err)
		}
	}
	return nil
}

func genericPayload(payload []byte) map[string]any {
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return map[string]any{}
	}
	return m
}
func stringValue(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func eventScope(ctx context.Context, store controlplane.Store, payload map[string]any) (organizationID, projectID string, err error) {
	organizationID = stringValue(payload, "organizationId")
	projectID = stringValue(payload, "projectId")
	if projectID != "" {
		project, e := store.GetProject(ctx, projectID)
		if e != nil {
			return "", "", e
		}
		if organizationID != "" && organizationID != project.OrganizationID {
			return "", "", fmt.Errorf("event organization/project scope mismatch")
		}
		organizationID = project.OrganizationID
	}
	return organizationID, projectID, nil
}

func classifyOutboxEvent(ctx context.Context, store controlplane.Store, source controlplane.OutboxEvent, now time.Time) (controlplane.NotificationEvent, bool, error) {
	payload := genericPayload(source.Payload)
	orgID, projectID, err := eventScope(ctx, store, payload)
	if err != nil {
		return controlplane.NotificationEvent{}, false, err
	}
	state := strings.ToUpper(stringValue(payload, "state"))
	typeName := strings.ToLower(strings.TrimSpace(source.EventType))
	eventType, title, summary := "", "", ""
	severity := controlplane.NotificationInfo
	switch {
	case strings.EqualFold(strings.TrimSpace(source.AggregateType), "operation") && state == "FAILED":
		// Operation failure notifications are state-authoritative rather than tied
		// to one producer event name. Generic retry, owner-destructive and
		// maintenance authorities emit different outbox event types but share the
		// same durable operation FAILED state.
		eventType, severity, title = "operation.failed", controlplane.NotificationCritical, "Operation failed"
		summary = stringValue(payload, "lastError")
	case typeName == "baseline_deployment.plan_stale":
		eventType, severity, title = "plan.stale", controlplane.NotificationWarning, "Approved plan became stale"
		summary = "Cluster inventory changed after planning; a new plan and approval are required."
	case typeName == "runtime_certification.failed":
		eventType, severity, title = "certification.failed", controlplane.NotificationCritical, "Runtime certification failed"
		summary = stringValue(payload, "lastError")
	case typeName == "runtime_certification.blocked":
		eventType, severity, title = "certification.blocked", controlplane.NotificationWarning, "Runtime certification is blocked"
		summary = stringValue(payload, "lastError")
	case typeName == "runtime_certification.succeeded":
		eventType, severity, title = "certification.succeeded", controlplane.NotificationInfo, "Runtime certification succeeded"
	case strings.HasPrefix(typeName, "upgrade_campaign.") && (state == "HALTED" || state == "FAILED"):
		eventType, severity, title = "upgrade.blocked", controlplane.NotificationCritical, "Upgrade campaign requires operator action"
		summary = stringValue(payload, "summary")
	case strings.HasSuffix(typeName, ".failed"):
		eventType, severity, title = typeName, controlplane.NotificationCritical, "Runtime workflow failed"
		summary = stringValue(payload, "lastError")
	default:
		return controlplane.NotificationEvent{}, false, nil
	}
	if orgID == "" {
		// Actionable notifications are tenant-scoped. Events without resolvable
		// organization context remain in audit/outbox but are not routed.
		return controlplane.NotificationEvent{}, false, nil
	}
	if summary == "" {
		summary = typeName
	}
	return controlplane.NotificationEvent{
		OrganizationID: orgID, ProjectID: projectID, SourceEventID: source.ID,
		AggregateType: source.AggregateType, AggregateID: source.AggregateID,
		EventType: eventType, Severity: severity, Title: title, Summary: summary,
		Payload: append([]byte(nil), source.Payload...), OccurredAt: source.CreatedAt,
	}, true, nil
}

func (w *Worker) routeClusterHealth(ctx context.Context, cluster controlplane.ManagedCluster, now time.Time) error {
	project, err := w.Store.GetProject(ctx, cluster.ProjectID)
	if err != nil {
		if errors.Is(err, controlplane.ErrNotFound) {
			return nil
		}
		return err
	}
	var inventory controlplane.ClusterInventory
	inventory, err = w.Store.GetLatestClusterInventory(ctx, cluster.ID)
	if err != nil && !errors.Is(err, controlplane.ErrNotFound) {
		return err
	}
	certificates, err := w.Store.ListAgentCertificates(ctx, cluster.ID)
	if err != nil {
		return err
	}
	health := fleethealth.Evaluate(cluster, inventory, certificates, now)
	raw, _ := json.Marshal(health)
	day := now.Format("2006-01-02")
	if health.Health != "HEALTHY" {
		severity := controlplane.NotificationWarning
		if health.Health == "CRITICAL" || health.Health == "STALE" {
			severity = controlplane.NotificationCritical
		}
		event := controlplane.NotificationEvent{OrganizationID: project.OrganizationID, ProjectID: project.ID, SourceEventID: "derived:fleet-health:" + cluster.ID + ":" + health.Health + ":" + day, AggregateType: "managedCluster", AggregateID: cluster.ID, EventType: "fleet.health.degraded", Severity: severity, Title: "Cluster health requires attention", Summary: strings.Join(health.Warnings, "; "), Payload: raw, OccurredAt: now}
		if _, _, _, err = w.Store.RouteNotificationEvent(ctx, event, "notification-health-scanner"); err != nil {
			return err
		}
	}
	for _, cert := range health.Certificates {
		if cert.State != "EXPIRED" && cert.State != "EXPIRING" {
			continue
		}
		severity := controlplane.NotificationWarning
		eventType := "certificate.expiring"
		title := "Certificate is approaching expiry"
		if cert.State == "EXPIRED" {
			severity = controlplane.NotificationCritical
			eventType = "certificate.expired"
			title = "Certificate has expired"
		}
		payload, _ := json.Marshal(cert)
		event := controlplane.NotificationEvent{OrganizationID: project.OrganizationID, ProjectID: project.ID, SourceEventID: "derived:certificate:" + cluster.ID + ":" + cert.Fingerprint + ":" + cert.State + ":" + day, AggregateType: "managedCluster", AggregateID: cluster.ID, EventType: eventType, Severity: severity, Title: title, Summary: fmt.Sprintf("%s certificate state=%s daysLeft=%d", cert.Name, cert.State, cert.DaysLeft), Payload: payload, OccurredAt: now}
		if _, _, _, err = w.Store.RouteNotificationEvent(ctx, event, "notification-health-scanner"); err != nil {
			return err
		}
	}
	switch health.KubernetesSupport.Status {
	case "EOL", "EOL_SOON":
		severity := controlplane.NotificationWarning
		eventType := "kubernetes.eol_soon"
		title := "Kubernetes release is approaching end-of-life"
		if health.KubernetesSupport.Status == "EOL" {
			severity = controlplane.NotificationCritical
			eventType = "kubernetes.eol"
			title = "Kubernetes release is end-of-life"
		}
		payload, _ := json.Marshal(health.KubernetesSupport)
		event := controlplane.NotificationEvent{OrganizationID: project.OrganizationID, ProjectID: project.ID, SourceEventID: "derived:kubernetes-eol:" + cluster.ID + ":" + health.KubernetesSupport.Status + ":" + day, AggregateType: "managedCluster", AggregateID: cluster.ID, EventType: eventType, Severity: severity, Title: title, Summary: fmt.Sprintf("Kubernetes %s support status is %s", health.KubernetesSupport.Minor, health.KubernetesSupport.Status), Payload: payload, OccurredAt: now}
		if _, _, _, err = w.Store.RouteNotificationEvent(ctx, event, "notification-health-scanner"); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) scanHealthIncremental(ctx context.Context, now time.Time) (bool, error) {
	store := w.Store.(healthCandidateStore)
	if w.lastFullHealth.IsZero() || now.Sub(w.lastFullHealth) >= healthFullScanEvery {
		if !w.healthFullScan {
			w.healthFullScan = true
			w.healthCursorAt = time.Time{}
			w.healthCursorID = ""
		}
	}
	candidates, more, err := store.ListNotificationHealthCandidates(ctx, w.healthCursorAt, w.healthCursorID, healthCandidatePage)
	if err != nil {
		return false, err
	}
	for _, candidate := range candidates {
		cluster, getErr := w.Store.GetManagedCluster(ctx, candidate.ClusterID)
		if getErr != nil {
			if errors.Is(getErr, controlplane.ErrNotFound) {
				continue
			}
			return false, getErr
		}
		if err = w.routeClusterHealth(ctx, cluster, now); err != nil {
			return false, err
		}
		w.healthCursorAt = candidate.ChangedAt.UTC()
		w.healthCursorID = candidate.ClusterID
	}
	if more {
		return true, nil
	}
	// Keep the cursor on the last candidate that was actually observed. Do not
	// advance it to wall-clock now: a cluster may commit between the final
	// bounded query and this assignment with an UpdatedAt earlier than now.
	// Advancing to now would skip that change forever. Re-reading the last
	// (changedAt,id) boundary is harmless because the pager is strictly >.
	if w.healthFullScan {
		w.lastFullHealth = now.UTC()
		w.healthFullScan = false
	}
	return false, nil
}

func (w *Worker) scanHealth(ctx context.Context, now time.Time) error {
	clusters, err := w.Store.ListManagedClusters(ctx, "")
	if err != nil {
		return err
	}
	for _, cluster := range clusters {
		if err = w.routeClusterHealth(ctx, cluster, now); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) processDeliveries(ctx context.Context, now time.Time) error {
	deliveries, err := w.Store.ClaimNotificationDeliveries(ctx, w.workerID, deliveryClaimBatch, deliveryClaimTTL, now)
	if err != nil {
		return err
	}
	if len(deliveries) == 0 {
		return nil
	}
	errCh := make(chan error, len(deliveries))
	for _, delivery := range deliveries {
		delivery := delivery
		go func() {
			result := w.deliver(ctx, delivery)
			if _, _, reportErr := w.Store.ReportNotificationDelivery(ctx, delivery.ID, w.workerID, w.Now().UTC(), result); reportErr != nil {
				errCh <- fmt.Errorf("report notification delivery %s: %w", delivery.ID, reportErr)
				return
			}
			errCh <- nil
		}()
	}
	var errs []error
	for range deliveries {
		if deliveryErr := <-errCh; deliveryErr != nil {
			errs = append(errs, deliveryErr)
		}
	}
	return errors.Join(errs...)
}

func (w *Worker) deliver(ctx context.Context, delivery controlplane.NotificationDelivery) controlplane.NotificationDeliveryResult {
	started := w.Now()
	destination, err := w.Store.GetNotificationDestination(ctx, delivery.DestinationID)
	if err != nil {
		return resultError(started, w.Now(), false, 0, "destination lookup: "+err.Error())
	}
	if destination.State != controlplane.NotificationDestinationActive {
		return resultError(started, w.Now(), false, 0, "destination is disabled")
	}
	event, err := w.Store.GetNotificationEvent(ctx, delivery.EventID)
	if err != nil {
		return resultError(started, w.Now(), false, 0, "event lookup: "+err.Error())
	}
	if destination.Kind == controlplane.NotificationDestinationConsole {
		return controlplane.NotificationDeliveryResult{Success: true, DurationMillis: elapsedMillis(started, w.Now())}
	}
	body, err := json.Marshal(map[string]any{"schemaVersion": "1", "deliveryId": delivery.ID, "event": event})
	if err != nil {
		return resultError(started, w.Now(), false, 0, err.Error())
	}
	timeout := time.Duration(destination.TimeoutSeconds) * time.Second
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, destination.Endpoint, bytes.NewReader(body))
	if err != nil {
		return resultError(started, w.Now(), false, 0, err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "4so-platform-factory-notification/1")
	req.Header.Set("X-Platform-Delivery-ID", delivery.ID)
	req.Header.Set("X-Platform-Event-ID", event.ID)
	req.Header.Set("X-Platform-Event-Type", event.EventType)
	if destination.AuthorizationEnv != "" {
		if !controlplane.NotificationSecretEnvAllowedForOrganization(destination.OrganizationID, destination.AuthorizationEnv) {
			return resultError(started, w.Now(), false, 0, "authorization environment variable is outside the destination organization notification secret namespace")
		}
		value, ok := os.LookupEnv(destination.AuthorizationEnv)
		if !ok || strings.TrimSpace(value) == "" {
			return resultError(started, w.Now(), false, 0, "authorization environment variable is not configured")
		}
		req.Header.Set("Authorization", value)
	}
	if destination.HMACSecretEnv != "" {
		if !controlplane.NotificationSecretEnvAllowedForOrganization(destination.OrganizationID, destination.HMACSecretEnv) {
			return resultError(started, w.Now(), false, 0, "HMAC environment variable is outside the destination organization notification secret namespace")
		}
		secret, ok := os.LookupEnv(destination.HMACSecretEnv)
		if !ok || secret == "" {
			return resultError(started, w.Now(), false, 0, "HMAC secret environment variable is not configured")
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		req.Header.Set("X-Platform-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.HTTPClient.Do(req)
	if err != nil {
		return resultError(started, w.Now(), true, 0, err.Error())
	}
	defer resp.Body.Close()
	limited, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if readErr != nil {
		return resultError(started, w.Now(), true, resp.StatusCode, readErr.Error())
	}
	sum := sha256.Sum256(limited)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	duration := elapsedMillis(started, w.Now())
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return controlplane.NotificationDeliveryResult{Success: true, StatusCode: resp.StatusCode, ResponseDigest: digest, DurationMillis: duration}
	}
	retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooEarly || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return controlplane.NotificationDeliveryResult{Success: false, Retryable: retryable, StatusCode: resp.StatusCode, Error: fmt.Sprintf("webhook returned HTTP %d", resp.StatusCode), ResponseDigest: digest, DurationMillis: duration}
}

func elapsedMillis(start, end time.Time) int64 {
	d := end.Sub(start)
	if d < 0 {
		return 0
	}
	return d.Milliseconds()
}
func resultError(start, end time.Time, retryable bool, status int, message string) controlplane.NotificationDeliveryResult {
	return controlplane.NotificationDeliveryResult{Success: false, Retryable: retryable, StatusCode: status, Error: message, DurationMillis: elapsedMillis(start, end)}
}

// SortEventTypes is exported for deterministic API/console metadata and tests.
func SortEventTypes(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
