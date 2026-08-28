package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func jsonResponse(status int, value any) *http.Response {
	var body io.ReadCloser = io.NopCloser(strings.NewReader(""))
	if value != nil {
		raw, _ := json.Marshal(value)
		body = io.NopCloser(strings.NewReader(string(raw)))
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: body, Header: make(http.Header)}
}

func TestStorageBackupCertificationAdapterExecutesPVCsnapshotBackupRestore(t *testing.T) {
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = filepath.Join(t.TempDir(), "token")
	defer func() { serviceAccountTokenPath = previous }()
	if err := os.WriteFile(serviceAccountTokenPath, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	objects := map[string]map[string]any{}
	deletedProbe := false
	probeDeletionPending := false
	probeDeletionObservations := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		p := r.URL.Path
		switch {
		case r.Method == http.MethodGet && p == "/apis/storage.k8s.io/v1/storageclasses":
			return jsonResponse(http.StatusOK, map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"name": "fast", "annotations": map[string]any{"storageclass.kubernetes.io/is-default-class": "true"}}, "provisioner": "csi.example.io", "volumeBindingMode": "WaitForFirstConsumer"}}}), nil
		case r.Method == http.MethodGet && p == "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses":
			return jsonResponse(http.StatusOK, map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"name": "snap-default", "annotations": map[string]any{"snapshot.storage.kubernetes.io/is-default-class": "true"}}, "driver": "csi.example.io"}}}), nil
		case r.Method == http.MethodGet && p == "/apis/velero.io/v1":
			return jsonResponse(http.StatusOK, map[string]any{"resources": []any{map[string]any{"name": "backups"}, map[string]any{"name": "restores"}}}), nil
		case r.Method == http.MethodGet && p == "/apis/velero.io/v1/backupstoragelocations":
			return jsonResponse(http.StatusOK, map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"name": "default", "namespace": "velero"}, "status": map[string]any{"phase": "Available"}}}}), nil
		case r.Method == http.MethodPost:
			var obj map[string]any
			_ = json.NewDecoder(r.Body).Decode(&obj)
			meta, _ := obj["metadata"].(map[string]any)
			name := objectString(obj, "metadata", "name")
			objectPath := strings.TrimRight(p, "/") + "/" + name
			if _, exists := objects[objectPath]; exists {
				return jsonResponse(http.StatusConflict, map[string]any{"kind": "Status"}), nil
			}
			meta["uid"] = "uid-" + name
			meta["resourceVersion"] = "1"
			if strings.Contains(objectPath, "/persistentvolumeclaims/") {
				obj["status"] = map[string]any{"phase": "Bound"}
			}
			if strings.Contains(objectPath, "/pods/") {
				obj["status"] = map[string]any{"phase": "Succeeded"}
			}
			if strings.Contains(objectPath, "/volumesnapshots/") {
				obj["status"] = map[string]any{"readyToUse": true}
			}
			if strings.Contains(objectPath, "/backups/") {
				obj["status"] = map[string]any{"phase": "Completed"}
			}
			if strings.Contains(objectPath, "/restores/") {
				if probeDeletionPending {
					t.Fatalf("Velero restore started before deleted probe absence was observed")
				}
				obj["status"] = map[string]any{"phase": "Completed"}
				if deletedProbe {
					probePath := "/api/v1/namespaces/cert-ns/configmaps/4so-cert-backup-probe-test"
					objects[probePath] = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "4so-cert-backup-probe-test", "namespace": "cert-ns", "uid": "uid-restored-probe", "resourceVersion": "9", "labels": map[string]any{"platform.4so.io/runtime-certification": "rtc_test", "platform.4so.io/backup-probe": "true", "platform.4so.io/runtime-cleanup-token": "cleanup-test"}}, "data": map[string]any{"marker": "4so-runtime-certification-rtc_test"}}
				}
			}
			objects[objectPath] = obj
			return jsonResponse(http.StatusCreated, obj), nil
		case r.Method == http.MethodPatch:
			var obj map[string]any
			_ = json.NewDecoder(r.Body).Decode(&obj)
			if strings.Contains(p, "/persistentvolumeclaims/") {
				obj["status"] = map[string]any{"phase": "Bound"}
			}
			if strings.Contains(p, "/pods/") {
				obj["status"] = map[string]any{"phase": "Succeeded"}
			}
			if strings.Contains(p, "/volumesnapshots/") {
				obj["status"] = map[string]any{"readyToUse": true}
			}
			if strings.Contains(p, "/backups/") {
				obj["status"] = map[string]any{"phase": "Completed"}
			}
			if strings.Contains(p, "/restores/") {
				if probeDeletionPending {
					t.Fatalf("Velero restore started before deleted probe absence was observed")
				}
				obj["status"] = map[string]any{"phase": "Completed"}
				// Simulate Velero restoring the deliberately deleted probe ConfigMap.
				if deletedProbe {
					for key, existing := range objects {
						if strings.Contains(key, "/configmaps/") {
							_ = existing
						}
					}
					probePath := "/api/v1/namespaces/cert-ns/configmaps/4so-cert-backup-probe-test"
					objects[probePath] = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "4so-cert-backup-probe-test", "namespace": "cert-ns", "uid": "uid-restored-probe", "resourceVersion": "9", "labels": map[string]any{"platform.4so.io/runtime-certification": "rtc_test", "platform.4so.io/backup-probe": "true", "platform.4so.io/runtime-cleanup-token": "cleanup-test"}}, "data": map[string]any{"marker": "4so-runtime-certification-rtc_test"}}
				}
			}
			objects[p] = obj
			return jsonResponse(http.StatusOK, obj), nil
		case r.Method == http.MethodGet:
			if probeDeletionPending && strings.Contains(p, "/configmaps/4so-cert-backup-probe-test") {
				probeDeletionObservations++
				if probeDeletionObservations >= 2 {
					delete(objects, p)
					probeDeletionPending = false
				}
			}
			if obj, ok := objects[p]; ok {
				return jsonResponse(http.StatusOK, obj), nil
			}
			return jsonResponse(http.StatusNotFound, map[string]any{"kind": "Status"}), nil
		case r.Method == http.MethodDelete:
			if strings.Contains(p, "/configmaps/4so-cert-backup-probe-test") {
				deletedProbe = true
				probeDeletionPending = true
				return jsonResponse(http.StatusOK, map[string]any{"status": "Success"}), nil
			}
			delete(objects, p)
			return jsonResponse(http.StatusOK, map[string]any{"status": "Success"}), nil
		default:
			return jsonResponse(http.StatusNotFound, nil), nil
		}
	})}
	a := &agent{cfg: config{BackupNamespace: "velero", RuntimeProbeImage: "registry.local/platform-probe@sha256:" + strings.Repeat("a", 64)}, kube: client}
	task := controlplane.RuntimeCertificationTask{RunID: "rtc_test", Namespace: "cert-ns", CleanupToken: "cleanup-test"}
	checks, ok, blocked, msg := a.verifyStorageBackupRuntime(context.Background(), task)
	if !ok || blocked || msg != "" {
		t.Fatalf("storage backup checks failed ok=%v blocked=%v msg=%q checks=%+v", ok, blocked, msg, checks)
	}
	if len(checks) != 7 {
		t.Fatalf("expected 7 executable checks, got %d: %+v", len(checks), checks)
	}
	for _, c := range checks {
		if c.Status != "PASS" {
			t.Fatalf("check failed: %+v", c)
		}
	}
	if probeDeletionObservations < 2 {
		t.Fatalf("restore did not wait for authoritative probe deletion: observations=%d", probeDeletionObservations)
	}
}

func TestStorageBackupCapabilityRequiresExecutableProviderSurface(t *testing.T) {
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = filepath.Join(t.TempDir(), "token")
	defer func() { serviceAccountTokenPath = previous }()
	_ = os.WriteFile(serviceAccountTokenPath, []byte("service-account"), 0o600)
	a := &agent{kube: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/apis/storage.k8s.io/v1/storageclasses" {
			return jsonResponse(http.StatusOK, map[string]any{"items": []any{}}), nil
		}
		return jsonResponse(http.StatusNotFound, nil), nil
	})}}
	if caps, ok := a.storageBackupCapabilities(context.Background()); ok || len(caps) != 0 {
		t.Fatalf("unexpected capabilities: %v ok=%v", caps, ok)
	}
}

func TestRuntimeCertificationRetryUsesAttemptScopedEphemeralNames(t *testing.T) {
	first := controlplane.RuntimeCertificationTask{RunID: "rtc_retry_scope", TaskAttempt: 1}
	retry := controlplane.RuntimeCertificationTask{RunID: "rtc_retry_scope", TaskAttempt: 2}
	if runtimeCertificationExecutionID(first) != first.RunID {
		t.Fatalf("first attempt unexpectedly changed execution id: %s", runtimeCertificationExecutionID(first))
	}
	if runtimeCertificationExecutionID(retry) == retry.RunID {
		t.Fatal("retry reused the first attempt runtime certification resource identity")
	}
	if certName("4so-cert-backup", runtimeCertificationExecutionID(first)) == certName("4so-cert-backup", runtimeCertificationExecutionID(retry)) {
		t.Fatal("retry would collide with a terminating Velero Backup from the previous attempt")
	}
}
