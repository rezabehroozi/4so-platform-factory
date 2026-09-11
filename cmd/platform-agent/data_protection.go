package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const dataProtectionVeleroNamespace = "velero"

func (a *agent) dataProtectionCapabilityAvailable(ctx context.Context) bool {
	if !a.kubeDiscoveryAvailable(ctx, "/apis/velero.io/v1") {
		return false
	}
	var list backupStorageLocationList
	if err := a.kubeJSON(ctx, http.MethodGet, "/apis/velero.io/v1/namespaces/"+dataProtectionVeleroNamespace+"/backupstoragelocations", nil, &list); err != nil {
		return false
	}
	for _, item := range list.Items {
		if strings.EqualFold(strings.TrimSpace(item.Status.Phase), "Available") {
			return true
		}
	}
	return false
}

func validateDataProtectionTask(task controlplane.DataProtectionTask) error {
	if strings.TrimSpace(task.RunID) == "" || task.RunRevision < 1 || task.TaskFenceToken < 1 || task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) || strings.TrimSpace(task.ProjectID) == "" || strings.TrimSpace(task.ClusterID) == "" || strings.TrimSpace(task.PolicyID) == "" || strings.TrimSpace(task.PolicyDigest) == "" || strings.TrimSpace(task.InventoryDigest) == "" || task.Provider != "velero" || strings.TrimSpace(task.BackupStorageLocation) == "" || !strings.HasPrefix(task.CredentialRef, "k8s-secret://velero/") || strings.TrimSpace(task.Retention) == "" || len(task.IncludedNamespaces) == 0 || strings.TrimSpace(task.VeleroName) == "" {
		return fmt.Errorf("data protection task identity is incomplete")
	}
	if task.Kind != controlplane.DataProtectionBackup && task.Kind != controlplane.DataProtectionRestore && task.Kind != controlplane.DataProtectionRestoreDrill {
		return fmt.Errorf("unsupported data protection task kind")
	}
	if task.Kind != controlplane.DataProtectionBackup && strings.TrimSpace(task.SourceBackupName) == "" {
		return fmt.Errorf("restore task source backup is missing")
	}
	if task.Kind == controlplane.DataProtectionRestoreDrill && (strings.TrimSpace(task.TargetNamespace) == "" || len(task.IncludedNamespaces) != 1) {
		return fmt.Errorf("restore drill requires one source namespace and isolated target namespace")
	}
	return nil
}

func (a *agent) processDataProtectionTask(ctx context.Context) error {
	task, ok, err := a.nextDataProtectionTask(ctx)
	if err != nil || !ok {
		return err
	}
	result := controlplane.DataProtectionTaskResult{TaskFenceToken: task.TaskFenceToken}
	if err = validateDataProtectionTask(task); err != nil {
		result.Error = err.Error()
		return a.reportDataProtectionTask(ctx, task, result)
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result = a.runDataProtectionTask(execCtx, task)
	result.TaskFenceToken = task.TaskFenceToken
	return a.reportDataProtectionTask(ctx, task, result)
}

func (a *agent) nextDataProtectionTask(ctx context.Context) (controlplane.DataProtectionTask, bool, error) {
	var task controlplane.DataProtectionTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/data-protection-tasks/next", nil)
	if err != nil {
		return task, false, err
	}
	res, err := a.hub.Do(req)
	if err != nil {
		return task, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return task, false, nil
	}
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("data protection task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func (a *agent) reportDataProtectionTask(ctx context.Context, task controlplane.DataProtectionTask, result controlplane.DataProtectionTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/data-protection-tasks/"+url.PathEscape(task.RunID)+"/result", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.RunRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("data protection report API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) verifyDataProtectionBSL(ctx context.Context, task controlplane.DataProtectionTask) error {
	path := "/apis/velero.io/v1/namespaces/" + dataProtectionVeleroNamespace + "/backupstoragelocations/" + url.PathEscape(task.BackupStorageLocation)
	var obj map[string]any
	if err := a.kubeJSON(ctx, http.MethodGet, path, nil, &obj); err != nil {
		return err
	}
	if !strings.EqualFold(objectString(obj, "status", "phase"), "Available") {
		return fmt.Errorf("BackupStorageLocation %s is not Available", task.BackupStorageLocation)
	}
	wantedSecret := strings.TrimPrefix(task.CredentialRef, "k8s-secret://velero/")
	credentialName := objectString(obj, "spec", "credential", "name")
	if wantedSecret == "" || credentialName != wantedSecret {
		return fmt.Errorf("BackupStorageLocation credential reference does not match policy credentialRef")
	}
	return nil
}

func dataProtectionOwnedBy(obj map[string]any, task controlplane.DataProtectionTask) bool {
	metadata, _ := obj["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	return strings.TrimSpace(fmt.Sprint(labels["platform.4so.io/data-protection-run"])) == task.RunID && strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/policy-digest"])) == task.PolicyDigest
}

func (a *agent) createOrResumeDataProtectionObject(ctx context.Context, collection, itemPath string, task controlplane.DataProtectionTask, obj map[string]any) (map[string]any, error) {
	var existing map[string]any
	found, err := a.kubeJSONOptional(ctx, itemPath, &existing)
	if err != nil {
		return nil, err
	}
	if found {
		if !dataProtectionOwnedBy(existing, task) {
			return nil, fmt.Errorf("existing Velero object is not owned by data protection run")
		}
		return existing, nil
	}
	var created map[string]any
	if err := a.kubeJSON(ctx, http.MethodPost, collection, obj, &created); err != nil {
		return nil, err
	}
	if !dataProtectionOwnedBy(created, task) {
		return nil, fmt.Errorf("created Velero object ownership marker mismatch")
	}
	return created, nil
}

func dataProtectionMetadata(task controlplane.DataProtectionTask) map[string]any {
	return map[string]any{"name": task.VeleroName, "namespace": dataProtectionVeleroNamespace, "labels": map[string]any{"platform.4so.io/data-protection-run": task.RunID}, "annotations": map[string]any{"platform.4so.io/policy-digest": task.PolicyDigest, "platform.4so.io/inventory-digest": task.InventoryDigest}}
}

func veleroObjectCompleted(v map[string]any) bool {
	return strings.EqualFold(objectString(v, "status", "phase"), "Completed")
}

func (a *agent) runDataProtectionTask(ctx context.Context, task controlplane.DataProtectionTask) controlplane.DataProtectionTaskResult {
	checks := []controlplane.RuntimeCheck{}
	started := time.Now()
	if err := a.verifyDataProtectionBSL(ctx, task); err != nil {
		checks = append(checks, check("data-protection/bsl", started, false, err.Error()))
		return controlplane.DataProtectionTaskResult{Success: false, Checks: checks, Error: err.Error()}
	}
	checks = append(checks, check("data-protection/bsl", started, true, "BackupStorageLocation is Available and references the policy credentialRef without reading secret material"))
	start := time.Now()
	var reference string
	var extraChecks []controlplane.RuntimeCheck
	var err error
	switch task.Kind {
	case controlplane.DataProtectionBackup:
		reference, err = a.executeDataProtectionBackup(ctx, task)
	case controlplane.DataProtectionRestore:
		reference, extraChecks, err = a.executeDataProtectionRestore(ctx, task, false)
	case controlplane.DataProtectionRestoreDrill:
		reference, extraChecks, err = a.executeDataProtectionRestore(ctx, task, true)
	}
	checks = append(checks, check("data-protection/"+strings.ToLower(string(task.Kind)), start, err == nil, func() string {
		if err != nil {
			return err.Error()
		}
		return "Velero operation completed with run-scoped ownership and verification"
	}()))
	if err != nil {
		return controlplane.DataProtectionTaskResult{Success: false, Checks: checks, Error: err.Error()}
	}
	checks = append(checks, extraChecks...)
	result := controlplane.DataProtectionTaskResult{Success: true, Reference: reference, Checks: checks, RTOSeconds: int64(time.Since(start).Seconds())}
	// RPO is measured externally against backup completion/source selection; V1
	// records zero when no trustworthy observation is available rather than inventing one.
	run := controlplane.DataProtectionRun{ResourceMeta: controlplane.ResourceMeta{ID: task.RunID}, Kind: task.Kind, ProjectID: task.ProjectID, ClusterID: task.ClusterID, PolicyID: task.PolicyID, BackupRunID: task.BackupRunID, PolicyDigest: task.PolicyDigest, InventoryDigest: task.InventoryDigest, VeleroName: task.VeleroName, SourceBackupName: task.SourceBackupName, TargetNamespace: task.TargetNamespace}
	result.EvidenceDigest = controlplane.DataProtectionEvidenceDigest(run, result)
	return result
}

func (a *agent) executeDataProtectionBackup(ctx context.Context, task controlplane.DataProtectionTask) (string, error) {
	collection := "/apis/velero.io/v1/namespaces/" + dataProtectionVeleroNamespace + "/backups"
	path := collection + "/" + url.PathEscape(task.VeleroName)
	obj := map[string]any{"apiVersion": "velero.io/v1", "kind": "Backup", "metadata": dataProtectionMetadata(task), "spec": map[string]any{"includedNamespaces": task.IncludedNamespaces, "storageLocation": task.BackupStorageLocation, "ttl": task.Retention, "snapshotVolumes": true}}
	if _, err := a.createOrResumeDataProtectionObject(ctx, collection, path, task, obj); err != nil {
		return "", err
	}
	completed, err := a.waitKubeObject(ctx, path, 5*time.Minute, veleroObjectCompleted)
	if err != nil {
		return "", err
	}
	if !dataProtectionOwnedBy(completed, task) {
		return "", fmt.Errorf("completed backup ownership marker mismatch")
	}
	return "velero://" + task.ClusterID + "/backup/" + task.VeleroName, nil
}

func numericStatusValue(obj map[string]any, path ...string) (int64, bool) {
	var current any = obj
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return 0, false
		}
		current, ok = m[key]
		if !ok {
			return 0, false
		}
	}
	switch v := current.(type) {
	case float64:
		return int64(v), v == float64(int64(v))
	case float32:
		return int64(v), v == float32(int64(v))
	case int:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		i, err := v.Int64()
		return i, err == nil
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}

func validateVeleroRestoreProgress(completed map[string]any) (string, error) {
	errorsCount, ok := numericStatusValue(completed, "status", "errors")
	if !ok {
		return "", fmt.Errorf("completed restore did not report an errors count")
	}
	warningsCount, ok := numericStatusValue(completed, "status", "warnings")
	if !ok {
		return "", fmt.Errorf("completed restore did not report a warnings count")
	}
	total, ok := numericStatusValue(completed, "status", "progress", "totalItems")
	if !ok || total <= 0 {
		return "", fmt.Errorf("completed restore did not report a positive totalItems progress value")
	}
	restored, ok := numericStatusValue(completed, "status", "progress", "itemsRestored")
	if !ok || restored != total {
		return "", fmt.Errorf("completed restore progress is incomplete: restored=%d total=%d", restored, total)
	}
	if errorsCount != 0 || warningsCount != 0 {
		return "", fmt.Errorf("completed restore reported warnings/errors: warnings=%d errors=%d", warningsCount, errorsCount)
	}
	return fmt.Sprintf("Velero restore progress complete: restored=%d total=%d warnings=0 errors=0", restored, total), nil
}
func (a *agent) executeDataProtectionRestore(ctx context.Context, task controlplane.DataProtectionTask, drill bool) (string, []controlplane.RuntimeCheck, error) {
	collection := "/apis/velero.io/v1/namespaces/" + dataProtectionVeleroNamespace + "/restores"
	path := collection + "/" + url.PathEscape(task.VeleroName)
	if drill {
		// A fresh drill may only target a namespace proven absent. On retry, an
		// already-owned Restore object proves that the namespace belongs to this
		// same run and may be resumed/cleaned up safely.
		var existingRestore map[string]any
		restoreExists, err := a.kubeJSONOptional(ctx, path, &existingRestore)
		if err != nil {
			return "", nil, err
		}
		if restoreExists && !dataProtectionOwnedBy(existingRestore, task) {
			return "", nil, fmt.Errorf("existing restore drill object is not owned by data protection run")
		}
		if !restoreExists {
			var existingNamespace map[string]any
			found, err := a.kubeJSONOptional(ctx, "/api/v1/namespaces/"+url.PathEscape(task.TargetNamespace), &existingNamespace)
			if err != nil {
				return "", nil, err
			}
			if found {
				return "", nil, fmt.Errorf("restore drill target namespace already exists; refusing adoption")
			}
		}
	}
	spec := map[string]any{"backupName": task.SourceBackupName, "includedNamespaces": task.IncludedNamespaces}
	if drill {
		spec["namespaceMapping"] = map[string]any{task.IncludedNamespaces[0]: task.TargetNamespace}
	}
	obj := map[string]any{"apiVersion": "velero.io/v1", "kind": "Restore", "metadata": dataProtectionMetadata(task), "spec": spec}
	if _, err := a.createOrResumeDataProtectionObject(ctx, collection, path, task, obj); err != nil {
		return "", nil, err
	}
	completed, err := a.waitKubeObject(ctx, path, 5*time.Minute, veleroObjectCompleted)
	if err != nil {
		return "", nil, err
	}
	if !dataProtectionOwnedBy(completed, task) {
		return "", nil, fmt.Errorf("completed restore ownership marker mismatch")
	}
	progressDetail, err := validateVeleroRestoreProgress(completed)
	if err != nil {
		return "", nil, err
	}
	extraChecks := []controlplane.RuntimeCheck{{Key: "data-protection/restore-progress", Status: "PASS", Detail: progressDetail}}
	if !drill {
		return "velero://" + task.ClusterID + "/restore/" + task.VeleroName, extraChecks, nil
	}
	nsPath := "/api/v1/namespaces/" + url.PathEscape(task.TargetNamespace)
	var ns map[string]any
	found, err := a.kubeJSONOptional(ctx, nsPath, &ns)
	if err != nil {
		return "", nil, err
	}
	if !found {
		return "", nil, fmt.Errorf("restore drill target namespace was not observed")
	}
	uid, err := kubeObjectUID(ns)
	if err != nil {
		return "", nil, err
	}
	rv, err := kubeObjectResourceVersion(ns)
	if err != nil {
		return "", nil, err
	}
	if err = a.deleteKubeObjectWithUIDAndResourceVersionAndWait(ctx, nsPath, uid, rv, 90*time.Second); err != nil {
		return "", nil, fmt.Errorf("restore drill cleanup: %w", err)
	}
	extraChecks = append(extraChecks, controlplane.RuntimeCheck{Key: "data-protection/restore-drill-cleanup", Status: "PASS", Detail: "isolated restore namespace was deleted with UID/resourceVersion preconditions and confirmed absent"})
	return "velero://" + task.ClusterID + "/restore-drill/" + task.VeleroName, extraChecks, nil
}
