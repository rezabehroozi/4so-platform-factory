package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunWorkloadLogQueryResolvesInventoryWorkloadToBoundedPods(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()
	var lokiQuery string
	kube := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status := http.StatusOK
		body := `{}`
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/apis/apps/v1/namespaces/app/deployments/web":
			body = `{"spec":{"selector":{"matchLabels":{"app":"web"}}}}`
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/app/pods":
			if got := r.URL.Query().Get("labelSelector"); got != "app=web" {
				t.Fatalf("label selector=%q", got)
			}
			if got := r.URL.Query().Get("limit"); got != "100" {
				t.Fatalf("pod limit=%q", got)
			}
			body = `{"items":[{"metadata":{"name":"web-a"}},{"metadata":{"name":"web-b"}}]}`
		default:
			t.Fatalf("unexpected kube request %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	observability := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != "/loki/api/v1/query_range" {
			t.Fatalf("unexpected observability request %s %s", r.Method, r.URL.Path)
		}
		lokiQuery = r.URL.Query().Get("query")
		if r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("direction") != "backward" {
			t.Fatalf("unexpected Loki bounds: %s", r.URL.RawQuery)
		}
		body := `{"status":"success","data":{"result":[` +
			`{"stream":{"namespace":"app","pod":"web-a","container":"app"},"values":[["1000000000","old"],["2000000000","new"]]},` +
			`{"stream":{"namespace":"app","pod":"rogue","container":"app"},"values":[["3000000000","must-not-leak"]]}` +
			`]}}`
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	a := &agent{clusterID: "clu-1", kube: kube, observability: observability, cfg: config{ObservabilityLogsURL: "http://logs.test", ObservabilityAllowHTTP: true}}
	task := agentWorkloadLogTask{
		OperationID: "op-1", OperationRevision: 3, TaskFenceToken: 8, LeaseExpiresAt: time.Now().Add(time.Minute), InventoryDigest: "sha256:" + strings.Repeat("a", 64),
		Request: agentWorkloadLogRequest{ProjectID: "prj-1", ClusterID: "clu-1", Namespace: "app", WorkloadKind: "Deployment", WorkloadName: "web", Container: "app", Mode: "TAIL", SinceSeconds: 300, Limit: 2},
	}
	result := a.runWorkloadLogQuery(context.Background(), task)
	if !result.Success || result.Error != "" || len(result.Lines) != 2 {
		t.Fatalf("result=%+v", result)
	}
	if result.Lines[0].Line != "old" || result.Lines[1].Line != "new" {
		t.Fatalf("unexpected lines=%+v", result.Lines)
	}
	decoded, _ := url.QueryUnescape(lokiQuery)
	if !strings.Contains(decoded, `namespace="app"`) || !strings.Contains(decoded, `pod=~"^(?:web-a|web-b)$"`) || !strings.Contains(decoded, `container="app"`) || strings.Contains(decoded, "rogue") {
		t.Fatalf("unexpected bounded LogQL=%q", decoded)
	}
}

func TestRunWorkloadLogQueryRejectsExpiredOrOutOfBoundsTaskBeforeIO(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { called = true; return nil, nil })}
	a := &agent{clusterID: "clu-1", kube: client, observability: client, cfg: config{ObservabilityLogsURL: "http://logs.test", ObservabilityAllowHTTP: true}}
	result := a.runWorkloadLogQuery(context.Background(), agentWorkloadLogTask{OperationID: "op-1", OperationRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(-time.Second), Request: agentWorkloadLogRequest{ClusterID: "clu-1", Namespace: "app", WorkloadName: "web", Limit: 500, SinceSeconds: 300}})
	if result.Success || result.Error == "" || called {
		t.Fatalf("expired task result=%+v called=%v", result, called)
	}
	called = false
	result = a.runWorkloadLogQuery(context.Background(), agentWorkloadLogTask{OperationID: "op-1", OperationRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Minute), Request: agentWorkloadLogRequest{ClusterID: "clu-1", Namespace: "app", WorkloadName: "web", Limit: 501, SinceSeconds: 300}})
	if result.Success || result.Error == "" || called {
		t.Fatalf("unbounded task result=%+v called=%v", result, called)
	}
}
