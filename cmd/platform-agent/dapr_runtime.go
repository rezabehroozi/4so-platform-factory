package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	daprruntime "platform.4so.io/factory/internal/dapr"
)

const (
	daprExecutorJobAuthority   = "DAPR_TARGET_EXECUTOR_JOB_AUTHORITY_V1"
	daprExecutorJobLabel       = "platform.4so.io/dapr-runtime-executor"
	daprExecutorServiceAccount = "4so-dapr-executor"
	daprReceiptName            = "4so-dapr-runtime-observed"
	daprReceiptNamespace       = "dapr-system"
	daprReceiptAuthority       = "DAPR_TARGET_OBSERVED_RECEIPT_V1"
)

type daprAgentTask struct {
	OperationID       string                       `json:"operationId"`
	OperationRevision int64                        `json:"operationRevision"`
	TaskFenceToken    int64                        `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                    `json:"leaseExpiresAt"`
	Request           daprruntime.LifecycleRequest `json:"request"`
	RuntimeLock       daprruntime.RuntimeLock       `json:"runtimeLock"`
}

type daprAgentResult struct {
	TaskFenceToken     int64  `json:"taskFenceToken"`
	Success            bool   `json:"success"`
	RecoveryRequired   bool   `json:"recoveryRequired,omitempty"`
	Installed          bool   `json:"installed"`
	ObservedLockDigest string `json:"observedLockDigest,omitempty"`
	Version            string `json:"version,omitempty"`
	UpstreamCommit     string `json:"upstreamCommit,omitempty"`
	Phase              string `json:"phase,omitempty"`
	Error              string `json:"error,omitempty"`
}

type daprRecoveryTask struct {
	OperationID       string                       `json:"operationId"`
	OperationRevision int64                        `json:"operationRevision"`
	TaskFenceToken    int64                        `json:"taskFenceToken"`
	Request           daprruntime.LifecycleRequest `json:"request"`
}

type daprRecoveryResult struct {
	ConfirmedSuccess   bool   `json:"confirmedSuccess"`
	Installed          bool   `json:"installed"`
	ObservedLockDigest string `json:"observedLockDigest,omitempty"`
	Version            string `json:"version,omitempty"`
	UpstreamCommit     string `json:"upstreamCommit,omitempty"`
	Phase              string `json:"phase,omitempty"`
	Error              string `json:"error,omitempty"`
}

type daprObservedReceipt struct {
	Authority         string `json:"authority"`
	Installed         bool   `json:"installed"`
	RuntimeLockDigest string `json:"runtimeLockDigest,omitempty"`
	OperationID       string `json:"operationId"`
	FenceToken        int64  `json:"fenceToken"`
	Version           string `json:"version,omitempty"`
	UpstreamCommit    string `json:"upstreamCommit,omitempty"`
	ObservedAt        string `json:"observedAt"`
	Phase             string `json:"phase"`
}

func daprObjectName(prefix, operationID string, fence int64) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(operationID)))
	return prefix + hex.EncodeToString(sum[:6]) + "-" + strconv.FormatInt(fence, 10)
}

func daprExecutorJobName(task daprAgentTask) string {
	return daprObjectName("dapr-exec-", task.OperationID, task.TaskFenceToken)
}

func daprExecutorJobPath(namespace string, task daprAgentTask) string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(namespace) + "/jobs/" + url.PathEscape(daprExecutorJobName(task))
}

func validateDaprAgentTask(task daprAgentTask, clusterID string) error {
	if strings.TrimSpace(task.OperationID) == "" || task.OperationRevision <= 0 || task.TaskFenceToken <= 0 ||
		task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("Dapr lifecycle task identity/fence is invalid")
	}
	req, err := daprruntime.CanonicalLifecycleRequest(task.Request)
	if err != nil {
		return err
	}
	if req.ClusterID != strings.TrimSpace(clusterID) {
		return fmt.Errorf("Dapr lifecycle task cluster does not match this agent")
	}
	if err = daprruntime.ValidateRuntimeLock(task.RuntimeLock); err != nil {
		return fmt.Errorf("Dapr runtime lock is not execution eligible: %w", err)
	}
	digest, err := daprruntime.RuntimeLockDigest(task.RuntimeLock)
	if err != nil {
		return err
	}
	if digest != req.RuntimeLockDigest {
		return fmt.Errorf("Dapr task runtime lock digest does not match sealed lifecycle request")
	}
	if task.RuntimeLock.Version != req.RuntimeVersion || strings.ToLower(strings.TrimSpace(task.RuntimeLock.UpstreamCommit)) != req.UpstreamCommit {
		return fmt.Errorf("Dapr task runtime identity does not match sealed lifecycle request")
	}
	if strings.TrimSpace(task.RuntimeLock.ExecutorImageReference) == "" || !strings.Contains(task.RuntimeLock.ExecutorImageReference, "@sha256:") {
		return fmt.Errorf("Dapr executor image is not exact-digest pinned")
	}
	return nil
}

func daprExecutorJob(task daprAgentTask, namespace string) (map[string]any, error) {
	lockRaw, err := json.Marshal(task.RuntimeLock)
	if err != nil {
		return nil, err
	}
	action := strings.ToLower(string(task.Request.Action))
	annotations := map[string]any{
		"platform.4so.io/authority":           daprExecutorJobAuthority,
		"platform.4so.io/operation-id":        task.OperationID,
		"platform.4so.io/task-fence-token":    strconv.FormatInt(task.TaskFenceToken, 10),
		"platform.4so.io/runtime-lock-digest": task.Request.RuntimeLockDigest,
		"platform.4so.io/lifecycle-action":    string(task.Request.Action),
	}
	labels := map[string]any{daprExecutorJobLabel: "true", "platform.4so.io/managed": "true"}
	return map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{"name": daprExecutorJobName(task), "namespace": namespace, "labels": labels, "annotations": annotations},
		"spec": map[string]any{
			"backoffLimit": 0, "ttlSecondsAfterFinished": 86400,
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels, "annotations": annotations},
				"spec": map[string]any{
					"serviceAccountName": daprExecutorServiceAccount, "restartPolicy": "Never",
					"securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
					"containers": []any{map[string]any{
						"name": "executor", "image": task.RuntimeLock.ExecutorImageReference, "imagePullPolicy": "IfNotPresent",
						"args": []any{"lifecycle", "--action", action},
						"env": []any{
							map[string]any{"name": "FOURSO_DAPR_RUNTIME_LOCK_JSON", "value": string(lockRaw)},
							map[string]any{"name": "FOURSO_DAPR_RUNTIME_LOCK_DIGEST", "value": task.Request.RuntimeLockDigest},
							map[string]any{"name": "FOURSO_DAPR_OPERATION_ID", "value": task.OperationID},
							map[string]any{"name": "FOURSO_DAPR_TASK_FENCE_TOKEN", "value": strconv.FormatInt(task.TaskFenceToken, 10)},
							map[string]any{"name": "FOURSO_DAPR_EXPECTED_OBSERVED_LOCK_DIGEST", "value": task.Request.ExpectedObservedLockDigest},
						},
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
							"capabilities": map[string]any{"drop": []any{"ALL"}},
						},
						"volumeMounts": []any{
							map[string]any{"name": "tmp", "mountPath": "/tmp"},
							map[string]any{"name": "helm-cache", "mountPath": "/home/nonroot/.cache/helm"},
							map[string]any{"name": "helm-config", "mountPath": "/home/nonroot/.config/helm"},
						},
					}},
					"volumes": []any{
						map[string]any{"name": "tmp", "emptyDir": map[string]any{}},
						map[string]any{"name": "helm-cache", "emptyDir": map[string]any{}},
						map[string]any{"name": "helm-config", "emptyDir": map[string]any{}},
					},
				},
			},
		},
	}, nil
}

func daprExecutorJobOwnership(job map[string]any, task daprAgentTask, namespace string) error {
	if job["apiVersion"] != "batch/v1" || job["kind"] != "Job" {
		return fmt.Errorf("Dapr executor object identity is invalid")
	}
	meta, _ := job["metadata"].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(meta["name"])) != daprExecutorJobName(task) ||
		strings.TrimSpace(fmt.Sprint(meta["namespace"])) != strings.TrimSpace(namespace) {
		return fmt.Errorf("Dapr executor Job metadata does not match task fence")
	}
	annotations, _ := meta["annotations"].(map[string]any)
	want := map[string]string{
		"platform.4so.io/authority":           daprExecutorJobAuthority,
		"platform.4so.io/operation-id":        task.OperationID,
		"platform.4so.io/task-fence-token":    strconv.FormatInt(task.TaskFenceToken, 10),
		"platform.4so.io/runtime-lock-digest": task.Request.RuntimeLockDigest,
		"platform.4so.io/lifecycle-action":    string(task.Request.Action),
	}
	for key, value := range want {
		if strings.TrimSpace(fmt.Sprint(annotations[key])) != value {
			return fmt.Errorf("Dapr executor Job ownership mismatch for %s", key)
		}
	}
	spec, _ := job["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	pod, _ := template["spec"].(map[string]any)
	containers, _ := pod["containers"].([]any)
	if len(containers) != 1 {
		return fmt.Errorf("Dapr executor Job container identity is invalid")
	}
	if strings.TrimSpace(fmt.Sprint(pod["serviceAccountName"])) != daprExecutorServiceAccount {
		return fmt.Errorf("Dapr executor service account is not the dedicated runtime principal")
	}
	container, _ := containers[0].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(container["image"])) != task.RuntimeLock.ExecutorImageReference {
		return fmt.Errorf("Dapr executor image does not match exact runtime lock")
	}
	return nil
}

func daprJobTerminal(job map[string]any) (done, failed bool, phase string) {
	status, _ := job["status"].(map[string]any)
	conditions, _ := status["conditions"].([]any)
	for _, raw := range conditions {
		condition, _ := raw.(map[string]any)
		if strings.TrimSpace(fmt.Sprint(condition["status"])) != "True" {
			continue
		}
		switch strings.TrimSpace(fmt.Sprint(condition["type"])) {
		case "Complete":
			return true, false, "ExecutorComplete"
		case "Failed":
			return true, true, "ExecutorFailed"
		}
	}
	return false, false, "ExecutorRunning"
}

func (a *agent) nextDaprLifecycleTask(ctx context.Context) (daprAgentTask, bool, error) {
	var task daprAgentTask
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/dapr-tasks/next"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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
		return task, false, fmt.Errorf("Dapr task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func (a *agent) dispatchDaprExecutor(ctx context.Context, task daprAgentTask) daprAgentResult {
	result := daprAgentResult{TaskFenceToken: task.TaskFenceToken}
	if strings.TrimSpace(a.cfg.ServiceAccount) == "" {
		result.Error = "Dapr executor requires import-scoped agent service account"
		return result
	}
	path := daprExecutorJobPath(a.cfg.Namespace, task)
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		result.RecoveryRequired = true
		result.Error = "Dapr executor pre-mutation readback failed: " + err.Error()
		return result
	}
	if found {
		if err = daprExecutorJobOwnership(current, task, a.cfg.Namespace); err != nil {
			result.RecoveryRequired = true
			result.Error = err.Error()
			return result
		}
	} else {
		job, buildErr := daprExecutorJob(task, a.cfg.Namespace)
		if buildErr != nil {
			result.Error = buildErr.Error()
			return result
		}
		collection := "/apis/batch/v1/namespaces/" + url.PathEscape(a.cfg.Namespace) + "/jobs"
		_, conflict, createErr := a.createKubeObject(ctx, collection, job)
		if createErr != nil {
			current, found, err = a.getKubeObject(ctx, path)
			if err != nil || !found {
				result.RecoveryRequired = true
				result.Error = "Dapr executor Job mutation outcome is unknown: " + createErr.Error()
				return result
			}
			if ownErr := daprExecutorJobOwnership(current, task, a.cfg.Namespace); ownErr != nil {
				result.RecoveryRequired = true
				result.Error = ownErr.Error()
				return result
			}
		}
		if conflict {
			current, found, err = a.getKubeObject(ctx, path)
			if err != nil || !found {
				result.RecoveryRequired = true
				result.Error = "Dapr executor Job conflict lacks authoritative readback"
				return result
			}
			if ownErr := daprExecutorJobOwnership(current, task, a.cfg.Namespace); ownErr != nil {
				result.RecoveryRequired = true
				result.Error = ownErr.Error()
				return result
			}
		}
	}
	deadline := task.LeaseExpiresAt.Add(-10 * time.Second)
	for time.Now().UTC().Before(deadline) {
		current, found, err = a.getKubeObject(ctx, path)
		if err != nil {
			result.RecoveryRequired = true
			result.Error = "Dapr executor Job readback failed: " + err.Error()
			return result
		}
		if !found {
			result.RecoveryRequired = true
			result.Error = "Dapr executor Job disappeared after dispatch"
			return result
		}
		if err = daprExecutorJobOwnership(current, task, a.cfg.Namespace); err != nil {
			result.RecoveryRequired = true
			result.Error = err.Error()
			return result
		}
		done, failed, phase := daprJobTerminal(current)
		result.Phase = phase
		if done {
			if failed {
				result.RecoveryRequired = true
				result.Error = "Dapr executor Job failed after mutation dispatch; authoritative recovery readback is required"
				return result
			}
			return a.readDaprReceipt(ctx, task)
		}
		select {
		case <-ctx.Done():
			result.RecoveryRequired = true
			result.Error = "Dapr executor interrupted after mutation dispatch"
			return result
		case <-time.After(3 * time.Second):
		}
	}
	result.RecoveryRequired = true
	result.Error = "Dapr executor lease deadline reached before authoritative terminal readback"
	return result
}

func (a *agent) readDaprReceipt(ctx context.Context, task daprAgentTask) daprAgentResult {
	result := daprAgentResult{TaskFenceToken: task.TaskFenceToken, Phase: "ReceiptReadback"}
	path := "/api/v1/namespaces/" + url.PathEscape(daprReceiptNamespace) + "/configmaps/" + url.PathEscape(daprReceiptName)
	obj, found, err := a.getKubeObject(ctx, path)
	if err != nil || !found {
		result.RecoveryRequired = true
		result.Error = "Dapr observed receipt is unavailable after executor completion"
		if err != nil {
			result.Error += ": " + err.Error()
		}
		return result
	}
	data, _ := obj["data"].(map[string]any)
	stateRaw := strings.TrimSpace(fmt.Sprint(data["state.json"]))
	if stateRaw == "" {
		result.RecoveryRequired = true
		result.Error = "Dapr observed receipt state is missing"
		return result
	}
	var receipt daprObservedReceipt
	decoder := json.NewDecoder(strings.NewReader(stateRaw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&receipt); err != nil {
		result.RecoveryRequired = true
		result.Error = "Dapr observed receipt is invalid: " + err.Error()
		return result
	}
	if receipt.Authority != daprReceiptAuthority || receipt.OperationID != task.OperationID || receipt.FenceToken != task.TaskFenceToken {
		result.RecoveryRequired = true
		result.Error = "Dapr observed receipt authority/operation/fence mismatch"
		return result
	}
	wantInstalled := task.Request.Action != daprruntime.ActionRemove
	if receipt.Installed != wantInstalled || strings.TrimSpace(receipt.Phase) == "" {
		result.RecoveryRequired = true
		result.Error = "Dapr observed receipt installed state does not match lifecycle action"
		return result
	}
	result.Installed = receipt.Installed
	result.ObservedLockDigest = strings.TrimSpace(receipt.RuntimeLockDigest)
	result.Version = strings.TrimSpace(receipt.Version)
	result.UpstreamCommit = strings.TrimSpace(receipt.UpstreamCommit)
	result.Phase = strings.TrimSpace(receipt.Phase)
	if wantInstalled && (result.ObservedLockDigest != task.Request.RuntimeLockDigest ||
		result.Version != task.Request.RuntimeVersion || result.UpstreamCommit != task.Request.UpstreamCommit) {
		result.RecoveryRequired = true
		result.Error = "Dapr observed receipt does not match exact admitted runtime lock"
		return result
	}
	result.Success = true
	return result
}

func (a *agent) reportDaprLifecycleTask(ctx context.Context, task daprAgentTask, result daprAgentResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/dapr-tasks/" + url.PathEscape(task.OperationID) + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("%q", strconv.FormatInt(task.OperationRevision, 10)))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("Dapr task result API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) nextDaprRecoveryTask(ctx context.Context) (daprRecoveryTask, bool, error) {
	var task daprRecoveryTask
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/dapr-recovery/next"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil { return task, false, err }
	res, err := a.hub.Do(req)
	if err != nil { return task, false, err }
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent { return task, false, nil }
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("Dapr recovery task API %s: %s", res.Status, string(body))
	}
	decoder := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&task); err != nil { return task, false, err }
	if strings.TrimSpace(task.OperationID) == "" || task.OperationRevision <= 0 || task.TaskFenceToken <= 0 {
		return task, false, fmt.Errorf("Dapr recovery task identity is invalid")
	}
	reqValue, err := daprruntime.CanonicalLifecycleRequest(task.Request)
	if err != nil { return task, false, err }
	task.Request = reqValue
	if task.Request.ClusterID != a.clusterID {
		return task, false, fmt.Errorf("Dapr recovery task cluster does not match this agent")
	}
	return task, true, nil
}

func (a *agent) readDaprRecoveryReceipt(ctx context.Context, task daprRecoveryTask) daprRecoveryResult {
	lifecycleTask := daprAgentTask{
		OperationID: task.OperationID,
		OperationRevision: task.OperationRevision,
		TaskFenceToken: task.TaskFenceToken,
		Request: task.Request,
	}
	readback := a.readDaprReceipt(ctx, lifecycleTask)
	return daprRecoveryResult{
		ConfirmedSuccess: readback.Success && !readback.RecoveryRequired,
		Installed: readback.Installed,
		ObservedLockDigest: readback.ObservedLockDigest,
		Version: readback.Version,
		UpstreamCommit: readback.UpstreamCommit,
		Phase: readback.Phase,
		Error: readback.Error,
	}
}

func (a *agent) reportDaprRecoveryTask(ctx context.Context, task daprRecoveryTask, result daprRecoveryResult) error {
	raw, err := json.Marshal(result)
	if err != nil { return err }
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/dapr-recovery/" + url.PathEscape(task.OperationID) + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("%q", strconv.FormatInt(task.OperationRevision, 10)))
	res, err := a.hub.Do(req)
	if err != nil { return err }
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("Dapr recovery result API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) processDaprRecoveryTask(ctx context.Context) error {
	task, ok, err := a.nextDaprRecoveryTask(ctx)
	if err != nil || !ok { return err }
	result := a.readDaprRecoveryReceipt(ctx, task)
	return a.reportDaprRecoveryTask(ctx, task, result)
}

func (a *agent) processDaprLifecycleTask(ctx context.Context) error {
	task, ok, err := a.nextDaprLifecycleTask(ctx)
	if err != nil || !ok {
		return err
	}
	if err = validateDaprAgentTask(task, a.clusterID); err != nil {
		return a.reportDaprLifecycleTask(ctx, task, daprAgentResult{
			TaskFenceToken: task.TaskFenceToken, RecoveryRequired: true, Error: err.Error(),
		})
	}
	result := a.dispatchDaprExecutor(ctx, task)
	return a.reportDaprLifecycleTask(ctx, task, result)
}
