package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func cleanupDiscoveryResponse(r *http.Request) (*http.Response, bool) {
	if r.Method != http.MethodGet {
		return nil, false
	}
	switch r.URL.Path {
	case "/apis/storage.k8s.io/v1/storageclasses":
		return jsonResponse(http.StatusOK, map[string]any{"items": []any{
			map[string]any{
				"metadata": map[string]any{
					"name":        "fast",
					"annotations": map[string]any{"storageclass.kubernetes.io/is-default-class": "true"},
				},
				"provisioner":       "csi.example.io",
				"volumeBindingMode": "WaitForFirstConsumer",
			},
		}}), true
	case "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses":
		return jsonResponse(http.StatusOK, map[string]any{"items": []any{
			map[string]any{
				"metadata": map[string]any{
					"name":        "snap-default",
					"annotations": map[string]any{"snapshot.storage.kubernetes.io/is-default-class": "true"},
				},
				"driver": "csi.example.io",
			},
		}}), true
	case "/apis/velero.io/v1":
		return jsonResponse(http.StatusOK, map[string]any{"resources": []any{
			map[string]any{"name": "backups"},
			map[string]any{"name": "restores"},
		}}), true
	case "/apis/velero.io/v1/backupstoragelocations":
		return jsonResponse(http.StatusOK, map[string]any{"items": []any{
			map[string]any{
				"metadata": map[string]any{"name": "default", "namespace": "velero"},
				"status":   map[string]any{"phase": "Available"},
			},
		}}), true
	default:
		return nil, false
	}
}

func TestRuntimeCertificationRetryCleansPriorAttemptByDurableCleanupToken(t *testing.T) {
	withTestServiceAccountToken(t)
	generation := controlplane.RuntimeCertificationCleanupGeneration{
		TaskAttempt: 2,
		Phase:       controlplane.RuntimeCertificationPhaseVerify,
		Token:       "cleanup-old",
	}
	task := controlplane.RuntimeCertificationTask{
		RunID:                   "rtc_cleanup_retry",
		Namespace:               "cert-ns",
		TaskAttempt:             3,
		CleanupToken:            "cleanup-current",
		PriorCleanupGenerations: []controlplane.RuntimeCertificationCleanupGeneration{generation},
	}
	adapter := storageBackupAdapter{
		StorageClass:    "fast",
		SnapshotClass:   "snap-default",
		VeleroNamespace: "velero",
	}
	expected := priorRuntimeCertificationCleanupRefs(task, generation, adapter)

	var mu sync.Mutex
	objects := map[string]map[string]any{}
	for i, ref := range expected {
		objects[ref.Path] = map[string]any{
			"metadata": map[string]any{
				"uid":             "uid-" + string(rune('a'+i)),
				"resourceVersion": "1",
				"labels": map[string]any{
					"platform.4so.io/runtime-certification": ref.Owner,
					"platform.4so.io/runtime-cleanup-token": generation.Token,
				},
			},
		}
	}
	deleted := map[string]bool{}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if response, ok := cleanupDiscoveryResponse(r); ok {
			return response, nil
		}
		switch r.Method {
		case http.MethodGet:
			if deleted[r.URL.Path] {
				return jsonResponse(http.StatusNotFound, map[string]any{"kind": "Status"}), nil
			}
			if obj, ok := objects[r.URL.Path]; ok {
				return jsonResponse(http.StatusOK, obj), nil
			}
			return jsonResponse(http.StatusNotFound, map[string]any{"kind": "Status"}), nil
		case http.MethodDelete:
			obj, ok := objects[r.URL.Path]
			if !ok {
				t.Fatalf("unexpected cleanup delete %s", r.URL.Path)
			}
			var options map[string]any
			if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
				t.Fatalf("decode delete options for %s: %v", r.URL.Path, err)
			}
			pre, _ := options["preconditions"].(map[string]any)
			meta, _ := obj["metadata"].(map[string]any)
			if strings.TrimSpace(fmt.Sprint(pre["uid"])) != strings.TrimSpace(fmt.Sprint(meta["uid"])) ||
				strings.TrimSpace(fmt.Sprint(pre["resourceVersion"])) != strings.TrimSpace(fmt.Sprint(meta["resourceVersion"])) {
				t.Fatalf("delete for %s was not fenced to current UID/resourceVersion: %+v", r.URL.Path, pre)
			}
			deleted[r.URL.Path] = true
			return jsonResponse(http.StatusOK, map[string]any{"status": "Success"}), nil
		default:
			return jsonResponse(http.StatusNotFound, map[string]any{"kind": "Status"}), nil
		}
	})}
	a := &agent{cfg: config{BackupNamespace: "velero"}, kube: client}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.cleanupPriorRuntimeCertificationAttempts(ctx, task); err != nil {
		t.Fatalf("prior attempt cleanup failed: %v", err)
	}
	if len(deleted) != len(expected) {
		t.Fatalf("prior cleanup deleted %d/%d exact resources", len(deleted), len(expected))
	}
}

func TestRuntimeCertificationRetryRefusesForeignPriorCleanupToken(t *testing.T) {
	withTestServiceAccountToken(t)
	generation := controlplane.RuntimeCertificationCleanupGeneration{
		TaskAttempt: 2,
		Phase:       controlplane.RuntimeCertificationPhaseVerify,
		Token:       "cleanup-old",
	}
	task := controlplane.RuntimeCertificationTask{
		RunID:                   "rtc_cleanup_foreign",
		Namespace:               "cert-ns",
		TaskAttempt:             3,
		CleanupToken:            "cleanup-current",
		PriorCleanupGenerations: []controlplane.RuntimeCertificationCleanupGeneration{generation},
	}
	executionID := runtimeCertificationExecutionIDForAttempt(task.RunID, generation.TaskAttempt)
	firstPath := "/api/v1/namespaces/" + certificationNamespace("4so-cert-net-a", executionID)
	deletes := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if response, ok := cleanupDiscoveryResponse(r); ok {
			return response, nil
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == firstPath:
			return jsonResponse(http.StatusOK, map[string]any{
				"metadata": map[string]any{
					"uid":             "uid-foreign",
					"resourceVersion": "2",
					"labels": map[string]any{
						"platform.4so.io/runtime-certification": task.RunID,
						"platform.4so.io/runtime-cleanup-token": "other-token",
					},
				},
			}), nil
		case r.Method == http.MethodDelete:
			deletes++
			return jsonResponse(http.StatusOK, map[string]any{"status": "Success"}), nil
		default:
			return jsonResponse(http.StatusNotFound, map[string]any{"kind": "Status"}), nil
		}
	})}
	a := &agent{cfg: config{BackupNamespace: "velero"}, kube: client}
	err := a.cleanupPriorRuntimeCertificationAttempts(context.Background(), task)
	if err == nil || !strings.Contains(err.Error(), "foreign ownership") {
		t.Fatalf("foreign prior cleanup token was not rejected: %v", err)
	}
	if deletes != 0 {
		t.Fatalf("foreign prior attempt object was deleted: %d", deletes)
	}
}
