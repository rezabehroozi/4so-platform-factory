package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func withTestServiceAccountToken(t *testing.T) {
	t.Helper()
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(serviceAccountTokenPath, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serviceAccountTokenPath = previous })
}

func TestRuntimeCertificationEphemeralObjectRefusesForeignConcurrentCreateAndReplacementCleanup(t *testing.T) {
	withTestServiceAccountToken(t)
	path := "/api/v1/namespaces/cert/pods/probe"
	collection := "/api/v1/namespaces/cert/pods"
	gets := 0
	patches := 0
	deletes := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response := func(code int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == path:
			gets++
			if gets == 1 {
				return response(http.StatusNotFound, `{}`)
			}
			return response(http.StatusOK, `{"metadata":{"name":"probe","namespace":"cert","uid":"uid-foreign","resourceVersion":"3","labels":{"platform.4so.io/runtime-certification":"rtc_foreign","platform.4so.io/runtime-cleanup-token":"cleanup-foreign"}},"spec":{"restartPolicy":"Never"}}`)
		case r.Method == http.MethodPost && r.URL.Path == collection:
			return response(http.StatusConflict, `{}`)
		case r.Method == http.MethodPatch:
			patches++
			return response(http.StatusOK, `{}`)
		case r.Method == http.MethodDelete:
			deletes++
			return response(http.StatusOK, `{}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			return response(http.StatusInternalServerError, `{}`)
		}
	})}
	a := &agent{kube: client}
	desired := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "probe", "namespace": "cert", "labels": map[string]any{"platform.4so.io/runtime-certification": "rtc_expected"}}, "spec": map[string]any{"restartPolicy": "Never"}}
	if _, err := a.ensureRuntimeCertificationEphemeralObject(context.Background(), path, desired, "rtc_expected", "cleanup-expected"); err == nil || !strings.Contains(err.Error(), "refusing to adopt") {
		t.Fatalf("foreign concurrent object accepted: %v", err)
	}
	if patches != 0 || deletes != 0 {
		t.Fatalf("foreign object mutated patches=%d deletes=%d", patches, deletes)
	}

	// A stale cleanup reference must never delete a same-name replacement.
	gets = 1 // next GET returns foreign UID above
	err := a.cleanupRuntimeCertificationEphemeralObject(context.Background(), runtimeCertificationCleanupRef{Path: path, Owner: "rtc_foreign", CleanupToken: "cleanup-foreign", UID: "uid-old"}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "replaced before cleanup") {
		t.Fatalf("replacement cleanup not fenced: %v", err)
	}
	if deletes != 0 {
		t.Fatalf("replacement object deleted: %d", deletes)
	}
}

func TestRuntimeVerificationCleanupRefusesForeignAndReplacementJobs(t *testing.T) {
	withTestServiceAccountToken(t)
	verificationID := "rtv_owner_fence"
	jobPath := "/apis/batch/v1/namespaces/4so-platform-baseline/jobs/probe"
	current := map[string]any{"metadata": map[string]any{"uid": "uid-foreign", "resourceVersion": "2", "labels": map[string]any{"platform.4so.io/runtime-verification": "other"}}}
	deletes := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && r.URL.Path == jobPath {
			raw, _ := json.Marshal(current)
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
		}
		if r.Method == http.MethodDelete {
			deletes++
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		}
		t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		return nil, nil
	})}
	a := &agent{kube: client}
	task := controlplane.RuntimeVerificationTask{VerificationID: verificationID}
	if err := a.deleteRuntimeVerificationJob(context.Background(), jobPath, task, "", time.Second); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("foreign job accepted: %v", err)
	}
	current = map[string]any{"metadata": map[string]any{"uid": "uid-new", "resourceVersion": "3", "labels": map[string]any{"platform.4so.io/runtime-verification": verificationID}}}
	if err := a.deleteRuntimeVerificationJob(context.Background(), jobPath, task, "uid-old", time.Second); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("replacement job accepted: %v", err)
	}
	if deletes != 0 {
		t.Fatalf("foreign/replacement job was deleted: %d", deletes)
	}
}

func TestTenantSuspendRefusesSameNameReplacementPodBeforeDelete(t *testing.T) {
	withTestServiceAccountToken(t)
	namespace := "tenant-replacement-test"
	deletes := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response := func(code int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+namespace+"/pods":
			return response(http.StatusOK, `{"items":[{"metadata":{"name":"web-0","uid":"uid-old","resourceVersion":"1","ownerReferences":[{"uid":"controller","controller":true}]}}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+namespace+"/pods/web-0":
			return response(http.StatusOK, `{"metadata":{"name":"web-0","uid":"uid-new","resourceVersion":"2","ownerReferences":[{"uid":"controller","controller":true}]}}`)
		case r.Method == http.MethodDelete:
			deletes++
			return response(http.StatusOK, `{}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			return response(http.StatusInternalServerError, `{}`)
		}
	})}
	a := &agent{kube: client}
	_, err := a.suspendTenantPods(context.Background(), controlplane.TenantTask{Namespace: namespace})
	if err == nil || !strings.Contains(err.Error(), "replaced before suspend") {
		t.Fatalf("replacement pod not fenced: %v", err)
	}
	if deletes != 0 {
		t.Fatalf("replacement pod was deleted: %d", deletes)
	}
}

func TestKubeObjectDesiredFieldComparisonUsesJSONNumericSemantics(t *testing.T) {
	current := map[string]any{"spec": map[string]any{"ports": []any{map[string]any{"port": float64(18080)}}}}
	desired := map[string]any{"spec": map[string]any{"ports": []any{map[string]any{"port": 18080}}}}
	if !kubeObjectContainsDesiredFields(current, desired) {
		t.Fatal("JSON numeric values with equivalent semantics compared unequal")
	}
}
