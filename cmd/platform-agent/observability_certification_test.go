package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestObservabilityCertificationAdapters(t *testing.T) {
	var mu sync.Mutex
	logPushed := false
	alertLabels := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-observability-token" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/query":
			if r.URL.Query().Get("query") != "vector(1)" {
				http.Error(w, "unexpected query", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": []any{map[string]any{"metric": map[string]string{}, "value": []any{1, "1"}}}}})
		case r.URL.Path == "/loki/api/v1/push":
			mu.Lock()
			logPushed = true
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/loki/api/v1/query_range":
			mu.Lock()
			pushed := logPushed
			mu.Unlock()
			result := []any{}
			if pushed && strings.Contains(r.URL.Query().Get("query"), `run_id="rtc-test"`) && strings.Contains(r.URL.Query().Get("query"), `execution_id="rtc-test"`) {
				result = append(result, map[string]any{"stream": map[string]string{"run_id": "rtc-test", "execution_id": "rtc-test"}, "values": [][]string{{"1", "4so-platform-factory runtime-certification observability probe rtc-test"}}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": result}})
		case r.URL.Path == "/api/v2/alerts" && r.Method == http.MethodPost:
			var alerts []struct {
				Labels map[string]string `json:"labels"`
			}
			if err := json.NewDecoder(r.Body).Decode(&alerts); err != nil || len(alerts) != 1 {
				http.Error(w, "invalid alerts", http.StatusBadRequest)
				return
			}
			mu.Lock()
			alertLabels = alerts[0].Labels
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/api/v2/alerts" && r.Method == http.MethodGet:
			mu.Lock()
			labels := map[string]string{}
			for k, v := range alertLabels {
				labels[k] = v
			}
			mu.Unlock()
			items := []any{}
			if labels["run_id"] == "rtc-test" {
				items = append(items, map[string]any{"labels": labels})
			}
			_ = json.NewEncoder(w).Encode(items)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-observability-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{ObservabilityMetricsURL: srv.URL, ObservabilityLogsURL: srv.URL, ObservabilityAlertsURL: srv.URL, ObservabilityBearerTokenFile: tokenFile, ObservabilityAllowHTTP: true}
	client, err := buildObservabilityHTTPClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{cfg: cfg, observability: client}
	checks, ok, msg := a.verifyObservabilityRuntime(context.Background(), controlplane.RuntimeCertificationTask{RunID: "rtc-test"})
	if !ok || msg != "" {
		t.Fatalf("observability checks failed: ok=%v msg=%q checks=%+v", ok, msg, checks)
	}
	if len(checks) != 5 {
		t.Fatalf("expected five executable observability checks, got %d: %+v", len(checks), checks)
	}
	for _, c := range checks {
		if c.Status != "PASS" {
			t.Fatalf("check did not pass: %+v", c)
		}
	}
}

func TestObservabilityRetryRejectsStalePriorAttemptEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/query":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"result": []any{map[string]any{"metric": map[string]string{}, "value": []any{1, "1"}}}}})
		case r.URL.Path == "/loki/api/v1/push":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/loki/api/v1/query_range":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"result": []any{map[string]any{"stream": map[string]string{"run_id": "rtc-retry", "execution_id": "rtc-retry"}, "values": [][]string{{"1", "4so-platform-factory runtime-certification observability probe rtc-retry"}}}}}})
		case r.URL.Path == "/api/v2/alerts" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/api/v2/alerts" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"labels": map[string]string{"alertname": "FourSOPlatformFactoryRuntimeCertification", "run_id": "rtc-retry", "execution_id": "rtc-retry"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := config{ObservabilityMetricsURL: srv.URL, ObservabilityLogsURL: srv.URL, ObservabilityAlertsURL: srv.URL, ObservabilityAllowHTTP: true}
	client, err := buildObservabilityHTTPClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{cfg: cfg, observability: client}
	checks, ok, _ := a.verifyObservabilityRuntime(context.Background(), controlplane.RuntimeCertificationTask{RunID: "rtc-retry", TaskAttempt: 2})
	if ok {
		t.Fatalf("stale prior-attempt observability evidence was accepted: %+v", checks)
	}
	for _, c := range checks {
		if (c.Key == "target-runtime/logs-query" || c.Key == "target-runtime/alert-query") && c.Status == "PASS" {
			t.Fatalf("stale prior-attempt evidence passed %s: %+v", c.Key, checks)
		}
	}
}

func TestObservabilityHTTPRequiresExplicitPlainHTTP(t *testing.T) {
	_, err := buildObservabilityHTTPClient(config{ObservabilityMetricsURL: "http://127.0.0.1:9090"})
	if err == nil || !strings.Contains(err.Error(), "ALLOW_HTTP") {
		t.Fatalf("expected explicit HTTP opt-in error, got %v", err)
	}
}

func TestObservabilityCapabilityRequiresAllAdapters(t *testing.T) {
	a := &agent{cfg: config{ObservabilityMetricsURL: "https://metrics.example.test", ObservabilityLogsURL: "https://logs.example.test"}, observability: &http.Client{}}
	if a.observabilityAdapterConfigured() {
		t.Fatal("partial adapter configuration must not advertise observability certification capability")
	}
}

func TestObservabilityAdapterAutoDiscoveryFromKubernetesServices(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/services" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		body := `{"items":[
			{"metadata":{"name":"vmselect-platform","namespace":"monitoring","labels":{"app.kubernetes.io/name":"victoria-metrics-k8s-stack","app.kubernetes.io/component":"vmselect"}},"spec":{"ports":[{"name":"http","port":8481}]}},
			{"metadata":{"name":"loki-gateway","namespace":"logging","labels":{"app.kubernetes.io/name":"loki"}},"spec":{"ports":[{"name":"http","port":80}]}},
			{"metadata":{"name":"vmalertmanager-platform","namespace":"monitoring","labels":{"app.kubernetes.io/name":"vmalertmanager"}},"spec":{"ports":[{"name":"http","port":9093}]}}
		]}`
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = filepath.Join(t.TempDir(), "token")
	defer func() { serviceAccountTokenPath = previous }()
	if err := os.WriteFile(serviceAccountTokenPath, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &agent{kube: client}
	if err := a.ensureObservabilityAdapterDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.observabilityAdapterConfigured() || !a.observabilityAutoDiscovered {
		t.Fatalf("auto discovery did not configure adapter: %+v", a.cfg)
	}
	if a.cfg.ObservabilityMetricsURL != "http://vmselect-platform.monitoring.svc:8481" || a.cfg.ObservabilityLogsURL != "http://loki-gateway.logging.svc:80" || a.cfg.ObservabilityAlertsURL != "http://vmalertmanager-platform.monitoring.svc:9093" {
		t.Fatalf("unexpected discovered endpoints: %+v", a.cfg)
	}
}
