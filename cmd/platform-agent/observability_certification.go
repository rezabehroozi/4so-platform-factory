package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func buildObservabilityHTTPClient(cfg config) (*http.Client, error) {
	urls := []string{cfg.ObservabilityMetricsURL, cfg.ObservabilityLogsURL, cfg.ObservabilityAlertsURL}
	configured := false
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		configured = true
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, fmt.Errorf("observability adapter endpoint must be an absolute http(s) URL")
		}
		if u.Scheme == "http" && !cfg.ObservabilityAllowHTTP {
			return nil, fmt.Errorf("plain HTTP observability endpoint requires PLATFORM_OBSERVABILITY_ALLOW_HTTP=true")
		}
		if u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("observability adapter endpoint cannot contain userinfo or fragment")
		}
	}
	if !configured {
		return nil, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ObservabilityCAFile != "" {
		raw, err := os.ReadFile(cfg.ObservabilityCAFile)
		if err != nil {
			return nil, fmt.Errorf("read observability CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("observability CA file contains no certificate")
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}

func (a *agent) observabilityAdapterConfigured() bool {
	return a.observability != nil && a.cfg.ObservabilityMetricsURL != "" && a.cfg.ObservabilityLogsURL != "" && a.cfg.ObservabilityAlertsURL != ""
}

func (a *agent) observabilityBearerToken() (string, error) {
	if a.cfg.ObservabilityBearerTokenFile == "" {
		return "", nil
	}
	raw, err := os.ReadFile(a.cfg.ObservabilityBearerTokenFile)
	if err != nil {
		return "", fmt.Errorf("read observability bearer token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("observability bearer token file is empty")
	}
	return token, nil
}

func (a *agent) observabilityRequest(ctx context.Context, method, endpoint string, body any) (*http.Response, []byte, error) {
	if a.observability == nil {
		return nil, nil, fmt.Errorf("observability HTTP adapter is not configured")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	token, err := a.observabilityBearerToken()
	if err != nil {
		return nil, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := a.observability.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return res, nil, err
	}
	return res, raw, nil
}

func (a *agent) verifyMetricsQuery(ctx context.Context) controlplane.RuntimeCheck {
	started := time.Now()
	u, _ := url.Parse(a.cfg.ObservabilityMetricsURL + "/api/v1/query")
	q := u.Query()
	q.Set("query", "vector(1)")
	u.RawQuery = q.Encode()
	res, raw, err := a.observabilityRequest(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return check("target-runtime/metrics-query", started, false, err.Error())
	}
	if res.StatusCode/100 != 2 {
		return check("target-runtime/metrics-query", started, false, "metrics API returned HTTP "+strconv.Itoa(res.StatusCode))
	}
	var payload struct {
		Status string `json:"status"`
		Data   struct {
			Result []json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if err = json.Unmarshal(raw, &payload); err != nil || payload.Status != "success" || len(payload.Data.Result) == 0 {
		return check("target-runtime/metrics-query", started, false, "metrics query did not return a successful non-empty vector result")
	}
	return check("target-runtime/metrics-query", started, true, "Prometheus-compatible query API returned a non-empty vector result")
}

func (a *agent) verifyLogsPath(ctx context.Context, task controlplane.RuntimeCertificationTask) []controlplane.RuntimeCheck {
	checks := []controlplane.RuntimeCheck{}
	executionID := runtimeCertificationExecutionID(task)
	probeLine := "4so-platform-factory runtime-certification observability probe " + executionID
	now := time.Now().UTC()
	started := time.Now()
	push := map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"job": "4so-platform-factory-certification", "run_id": task.RunID, "execution_id": executionID}, "values": [][]string{{strconv.FormatInt(now.UnixNano(), 10), probeLine}}}}}
	res, _, err := a.observabilityRequest(ctx, http.MethodPost, a.cfg.ObservabilityLogsURL+"/loki/api/v1/push", push)
	pushOK := err == nil && res.StatusCode/100 == 2
	detail := "Loki-compatible push API accepted a certification probe log"
	if err != nil {
		detail = err.Error()
	} else if !pushOK {
		detail = "logs push API returned HTTP " + strconv.Itoa(res.StatusCode)
	}
	checks = append(checks, check("target-runtime/logs-push", started, pushOK, detail))
	if !pushOK {
		checks = append(checks, controlplane.RuntimeCheck{Key: "target-runtime/logs-query", Status: "FAIL", Detail: "logs query skipped because probe push failed"})
		return checks
	}

	started = time.Now()
	u, _ := url.Parse(a.cfg.ObservabilityLogsURL + "/loki/api/v1/query_range")
	q := u.Query()
	q.Set("query", `{job="4so-platform-factory-certification",run_id="`+task.RunID+`",execution_id="`+executionID+`"}`)
	q.Set("start", strconv.FormatInt(now.Add(-30*time.Second).UnixNano(), 10))
	q.Set("end", strconv.FormatInt(now.Add(30*time.Second).UnixNano(), 10))
	q.Set("limit", "10")
	u.RawQuery = q.Encode()
	var queryOK bool
	for attempt := 0; attempt < 8; attempt++ {
		res, raw, reqErr := a.observabilityRequest(ctx, http.MethodGet, u.String(), nil)
		if reqErr == nil && res.StatusCode/100 == 2 {
			var payload struct {
				Status string `json:"status"`
				Data   struct {
					Result []struct {
						Stream map[string]string `json:"stream"`
						Values [][]string        `json:"values"`
					} `json:"result"`
				} `json:"data"`
			}
			if json.Unmarshal(raw, &payload) == nil && payload.Status == "success" {
				for _, stream := range payload.Data.Result {
					if stream.Stream["run_id"] != task.RunID || stream.Stream["execution_id"] != executionID {
						continue
					}
					for _, value := range stream.Values {
						if len(value) >= 2 && value[1] == probeLine {
							queryOK = true
							break
						}
					}
					if queryOK {
						break
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			attempt = 8
		case <-time.After(125 * time.Millisecond):
		}
	}
	checks = append(checks, check("target-runtime/logs-query", started, queryOK, "Loki-compatible query_range returned the certification probe stream"))
	return checks
}

func (a *agent) verifyAlertPath(ctx context.Context, task controlplane.RuntimeCertificationTask) []controlplane.RuntimeCheck {
	checks := []controlplane.RuntimeCheck{}
	now := time.Now().UTC()
	executionID := runtimeCertificationExecutionID(task)
	alertName := "FourSOPlatformFactoryRuntimeCertification"
	alert := []map[string]any{{
		"labels":      map[string]string{"alertname": alertName, "run_id": task.RunID, "execution_id": executionID, "severity": "info"},
		"annotations": map[string]string{"summary": "4SO Platform Factory observability certification probe"},
		"startsAt":    now.Format(time.RFC3339Nano), "endsAt": now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		"generatorURL": "https://platform.4so.io/runtime-certification/" + task.RunID,
	}}
	started := time.Now()
	res, _, err := a.observabilityRequest(ctx, http.MethodPost, a.cfg.ObservabilityAlertsURL+"/api/v2/alerts", alert)
	fireOK := err == nil && res.StatusCode/100 == 2
	detail := "Alertmanager-compatible API accepted a certification probe alert"
	if err != nil {
		detail = err.Error()
	} else if !fireOK {
		detail = "alert fire API returned HTTP " + strconv.Itoa(res.StatusCode)
	}
	checks = append(checks, check("target-runtime/alert-fire", started, fireOK, detail))
	if !fireOK {
		checks = append(checks, controlplane.RuntimeCheck{Key: "target-runtime/alert-query", Status: "FAIL", Detail: "alert query skipped because alert fire failed"})
		return checks
	}

	started = time.Now()
	u, _ := url.Parse(a.cfg.ObservabilityAlertsURL + "/api/v2/alerts")
	q := u.Query()
	q.Add("filter", `run_id="`+task.RunID+`"`)
	q.Add("filter", `execution_id="`+executionID+`"`)
	u.RawQuery = q.Encode()
	queryOK := false
	for attempt := 0; attempt < 8; attempt++ {
		res, raw, reqErr := a.observabilityRequest(ctx, http.MethodGet, u.String(), nil)
		if reqErr == nil && res.StatusCode/100 == 2 {
			var alerts []struct {
				Labels map[string]string `json:"labels"`
			}
			if json.Unmarshal(raw, &alerts) == nil {
				for _, item := range alerts {
					if item.Labels["run_id"] == task.RunID && item.Labels["execution_id"] == executionID && item.Labels["alertname"] == alertName {
						queryOK = true
						break
					}
				}
			}
		}
		if queryOK {
			break
		}
		select {
		case <-ctx.Done():
			attempt = 8
		case <-time.After(125 * time.Millisecond):
		}
	}
	checks = append(checks, check("target-runtime/alert-query", started, queryOK, "Alertmanager-compatible API returned the fired certification alert"))
	return checks
}

func (a *agent) verifyObservabilityRuntime(ctx context.Context, task controlplane.RuntimeCertificationTask) ([]controlplane.RuntimeCheck, bool, string) {
	if !a.observabilityAdapterConfigured() {
		checks := []controlplane.RuntimeCheck{
			{Key: "target-runtime/metrics-query", Status: "BLOCKED", Detail: "metrics adapter endpoint is not configured on the cluster agent"},
			{Key: "target-runtime/logs-query", Status: "BLOCKED", Detail: "logs adapter endpoint is not configured on the cluster agent"},
			{Key: "target-runtime/alert-fire", Status: "BLOCKED", Detail: "alerts adapter endpoint is not configured on the cluster agent"},
		}
		return checks, false, "observability runtime adapters are not configured"
	}
	checks := []controlplane.RuntimeCheck{a.verifyMetricsQuery(ctx)}
	checks = append(checks, a.verifyLogsPath(ctx, task)...)
	checks = append(checks, a.verifyAlertPath(ctx, task)...)
	for _, item := range checks {
		if item.Status != "PASS" {
			return checks, false, "one or more observability runtime adapter checks failed"
		}
	}
	return checks, true, ""
}

type kubeServiceList struct {
	Items []struct {
		Metadata struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			Ports []struct {
				Name string `json:"name"`
				Port int    `json:"port"`
			} `json:"ports"`
		} `json:"spec"`
	} `json:"items"`
}

func serviceEndpoint(name, namespace string, port int) string {
	if name == "" || namespace == "" || port <= 0 {
		return ""
	}
	return "http://" + name + "." + namespace + ".svc:" + strconv.Itoa(port)
}

func preferredServicePort(ports []struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}) int {
	for _, preferred := range []string{"http", "http-web", "web", "http-metrics"} {
		for _, item := range ports {
			if item.Name == preferred && item.Port > 0 {
				return item.Port
			}
		}
	}
	for _, item := range ports {
		if item.Port > 0 {
			return item.Port
		}
	}
	return 0
}

func observabilityServiceScore(kind, name string, labels map[string]string) int {
	identity := strings.ToLower(name + " " + labels["app.kubernetes.io/name"] + " " + labels["app"] + " " + labels["app.kubernetes.io/component"])
	score := 0
	switch kind {
	case "metrics":
		if strings.Contains(identity, "vmselect") {
			score = 100
		} else if strings.Contains(identity, "victoria-metrics") || strings.Contains(identity, "victoriametrics") {
			score = 80
		}
	case "logs":
		if strings.Contains(identity, "loki-gateway") {
			score = 100
		} else if strings.Contains(identity, "loki") && strings.Contains(identity, "gateway") {
			score = 95
		} else if strings.Contains(identity, "loki") {
			score = 70
		}
	case "alerts":
		if strings.Contains(identity, "vmalertmanager") {
			score = 100
		} else if strings.Contains(identity, "alertmanager") {
			score = 90
		}
	}
	return score
}

func (a *agent) ensureObservabilityAdapterDiscovery(ctx context.Context) error {
	if a.observabilityAdapterConfigured() {
		return nil
	}
	var services kubeServiceList
	if err := a.kubeJSON(ctx, http.MethodGet, "/api/v1/services", nil, &services); err != nil {
		return err
	}
	type candidate struct {
		score int
		url   string
	}
	selected := map[string]candidate{}
	for _, item := range services.Items {
		port := preferredServicePort(item.Spec.Ports)
		endpoint := serviceEndpoint(item.Metadata.Name, item.Metadata.Namespace, port)
		if endpoint == "" {
			continue
		}
		for _, kind := range []string{"metrics", "logs", "alerts"} {
			score := observabilityServiceScore(kind, item.Metadata.Name, item.Metadata.Labels)
			if score > selected[kind].score {
				selected[kind] = candidate{score: score, url: endpoint}
			}
		}
	}
	if a.cfg.ObservabilityMetricsURL == "" && selected["metrics"].score > 0 {
		a.cfg.ObservabilityMetricsURL = selected["metrics"].url
	}
	if a.cfg.ObservabilityLogsURL == "" && selected["logs"].score > 0 {
		a.cfg.ObservabilityLogsURL = selected["logs"].url
	}
	if a.cfg.ObservabilityAlertsURL == "" && selected["alerts"].score > 0 {
		a.cfg.ObservabilityAlertsURL = selected["alerts"].url
	}
	if a.cfg.ObservabilityMetricsURL == "" || a.cfg.ObservabilityLogsURL == "" || a.cfg.ObservabilityAlertsURL == "" {
		return nil
	}
	effective := a.cfg
	effective.ObservabilityAllowHTTP = true // cluster-local *.svc endpoints are discovered from the authenticated Kubernetes API.
	client, err := buildObservabilityHTTPClient(effective)
	if err != nil {
		return err
	}
	a.observability = client
	a.observabilityAutoDiscovered = true
	return nil
}
