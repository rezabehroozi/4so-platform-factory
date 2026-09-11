package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestDataProtectionAgentBackupAndRestoreDrillCleanup(t *testing.T) {
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = filepath.Join(t.TempDir(), "token")
	defer func() { serviceAccountTokenPath = previous }()
	if err := os.WriteFile(serviceAccountTokenPath, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	objects := map[string]map[string]any{}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		p := r.URL.Path
		switch {
		case r.Method == http.MethodGet && p == "/apis/velero.io/v1":
			return jsonResponse(http.StatusOK, map[string]any{"resources": []any{map[string]any{"name": "backups"}, map[string]any{"name": "restores"}, map[string]any{"name": "backupstoragelocations"}}}), nil
		case r.Method == http.MethodGet && p == "/apis/velero.io/v1/namespaces/velero/backupstoragelocations":
			return jsonResponse(http.StatusOK, map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"name": "primary", "namespace": "velero"}, "spec": map[string]any{"credential": map[string]any{"name": "cloud-credentials"}}, "status": map[string]any{"phase": "Available"}}}}), nil
		case r.Method == http.MethodGet && p == "/apis/velero.io/v1/namespaces/velero/backupstoragelocations/primary":
			return jsonResponse(http.StatusOK, map[string]any{"metadata": map[string]any{"name": "primary", "namespace": "velero"}, "spec": map[string]any{"credential": map[string]any{"name": "cloud-credentials"}}, "status": map[string]any{"phase": "Available"}}), nil
		case r.Method == http.MethodPost && (strings.HasSuffix(p, "/backups") || strings.HasSuffix(p, "/restores")):
			var obj map[string]any
			_ = json.NewDecoder(r.Body).Decode(&obj)
			name := objectString(obj, "metadata", "name")
			itemPath := strings.TrimRight(p, "/") + "/" + name
			if _, exists := objects[itemPath]; exists {
				return jsonResponse(http.StatusConflict, map[string]any{"kind": "Status"}), nil
			}
			meta := obj["metadata"].(map[string]any)
			meta["uid"] = "uid-" + name
			meta["resourceVersion"] = "1"
			obj["status"] = map[string]any{"phase": "Completed", "errors": 0, "warnings": 0, "progress": map[string]any{"totalItems": 3, "itemsRestored": 3}}
			objects[itemPath] = obj
			if strings.HasSuffix(p, "/restores") {
				spec, _ := obj["spec"].(map[string]any)
				mapping, _ := spec["namespaceMapping"].(map[string]any)
				for _, target := range mapping {
					ns := target.(string)
					objects["/api/v1/namespaces/"+ns] = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns, "uid": "uid-" + ns, "resourceVersion": "7"}}
				}
			}
			return jsonResponse(http.StatusCreated, obj), nil
		case r.Method == http.MethodDelete && strings.HasPrefix(p, "/api/v1/namespaces/"):
			if _, ok := objects[p]; !ok {
				return jsonResponse(http.StatusNotFound, map[string]any{"kind": "Status"}), nil
			}
			delete(objects, p)
			return jsonResponse(http.StatusOK, map[string]any{"kind": "Status", "status": "Success"}), nil
		case r.Method == http.MethodGet:
			if obj, ok := objects[p]; ok {
				return jsonResponse(http.StatusOK, obj), nil
			}
			return jsonResponse(http.StatusNotFound, map[string]any{"kind": "Status"}), nil
		default:
			return jsonResponse(http.StatusNotFound, map[string]any{"kind": "Status", "path": p}), nil
		}
	})}
	a := &agent{kube: client, clusterID: "cluster-dp"}
	if !a.dataProtectionCapabilityAvailable(context.Background()) {
		t.Fatal("data protection capability was not auto-discovered")
	}
	base := controlplane.DataProtectionTask{RunID: "dpr_backup", RunRevision: 2, Kind: controlplane.DataProtectionBackup, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Minute), ProjectID: "prj", ClusterID: "cluster-dp", PolicyID: "bkp", InventoryDigest: "sha256:" + strings.Repeat("1", 64), PolicyDigest: "sha256:" + strings.Repeat("2", 64), Provider: "velero", BackupStorageLocation: "primary", CredentialRef: "k8s-secret://velero/cloud-credentials", Retention: "168h", IncludedNamespaces: []string{"payments"}, VeleroName: "backup-one"}
	result := a.runDataProtectionTask(context.Background(), base)
	if !result.Success || !strings.HasPrefix(result.EvidenceDigest, "sha256:") || len(result.Checks) != 2 {
		t.Fatalf("backup result=%+v", result)
	}
	if _, ok := objects["/apis/velero.io/v1/namespaces/velero/backups/backup-one"]; !ok {
		t.Fatal("backup object was not created")
	}
	// Retry is resume-safe: the same owned object is observed instead of adopted/recreated.
	retry := a.runDataProtectionTask(context.Background(), base)
	if !retry.Success || retry.EvidenceDigest != result.EvidenceDigest {
		t.Fatalf("retry=%+v first=%+v", retry, result)
	}

	drill := base
	drill.RunID = "dpr_drill"
	drill.Kind = controlplane.DataProtectionRestoreDrill
	drill.BackupRunID = "dpr_backup"
	drill.SourceBackupName = "backup-one"
	drill.TargetNamespace = "restore-drill-1"
	drill.VeleroName = "restore-drill-one"
	drill.TaskFenceToken = 2
	drillResult := a.runDataProtectionTask(context.Background(), drill)
	if !drillResult.Success || !strings.Contains(drillResult.Reference, "restore-drill") {
		t.Fatalf("drill result=%+v", drillResult)
	}
	keys := map[string]bool{}
	for _, c := range drillResult.Checks {
		keys[c.Key] = c.Status == "PASS"
	}
	if !keys["data-protection/restore-progress"] || !keys["data-protection/restore-drill-cleanup"] {
		t.Fatalf("drill evidence checks=%+v", drillResult.Checks)
	}
	if _, ok := objects["/api/v1/namespaces/restore-drill-1"]; ok {
		t.Fatal("restore drill namespace was not cleaned up")
	}
}

func TestDataProtectionAgentRejectsCredentialReferenceMismatch(t *testing.T) {
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = filepath.Join(t.TempDir(), "token")
	defer func() { serviceAccountTokenPath = previous }()
	_ = os.WriteFile(serviceAccountTokenPath, []byte("x"), 0o600)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{"spec": map[string]any{"credential": map[string]any{"name": "other"}}, "status": map[string]any{"phase": "Available"}}), nil
	})}
	a := &agent{kube: client, clusterID: "c"}
	task := controlplane.DataProtectionTask{BackupStorageLocation: "primary", CredentialRef: "k8s-secret://velero/cloud"}
	if err := a.verifyDataProtectionBSL(context.Background(), task); err == nil {
		t.Fatal("credential reference mismatch was accepted")
	}
}
