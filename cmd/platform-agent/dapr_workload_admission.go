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

	daprruntime "platform.4so.io/factory/internal/dapr"
)

const daprWorkloadAdmissionJobAuthority = "DAPR_WORKLOAD_ADMISSION_EXECUTOR_JOB_V1"

type agentDaprWorkloadAdmissionTask struct {
	OperationID       string                               `json:"operationId"`
	OperationRevision int64                                `json:"operationRevision"`
	TaskFenceToken    int64                                `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                            `json:"leaseExpiresAt"`
	Request           daprruntime.WorkloadAdmissionRequest `json:"request"`
	ExecutorAuthority daprruntime.ExecutorAuthority         `json:"executorAuthority"`
	RuntimeLock       *daprruntime.RuntimeLock              `json:"runtimeLock,omitempty"`
}

type agentDaprWorkloadAdmissionResult struct {
	Success        bool                                   `json:"success"`
	TaskFenceToken int64                                  `json:"taskFenceToken"`
	Error          string                                 `json:"error,omitempty"`
	Evidence       *daprruntime.WorkloadAdmissionEvidence `json:"evidence,omitempty"`
	EvidenceDigest string                                 `json:"evidenceDigest,omitempty"`
}

type daprWorkloadAdmissionExecutorResult struct {
	Authority      string                                  `json:"authority"`
	OperationID    string                                  `json:"operationId"`
	Evidence       daprruntime.WorkloadAdmissionEvidence   `json:"evidence"`
	EvidenceDigest string                                  `json:"evidenceDigest"`
}

func (a *agent) processDaprWorkloadAdmissionTask(ctx context.Context) error {
	task, ok, err := a.nextDaprWorkloadAdmissionTask(ctx)
	if err != nil || !ok {
		return err
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result := a.runDaprWorkloadAdmission(execCtx, task)
	result.TaskFenceToken = task.TaskFenceToken
	return a.reportDaprWorkloadAdmissionTask(ctx, task, result)
}

func (a *agent) nextDaprWorkloadAdmissionTask(ctx context.Context) (agentDaprWorkloadAdmissionTask, bool, error) {
	var task agentDaprWorkloadAdmissionTask
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/dapr-workload-admission-tasks/next"
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
		return task, false, fmt.Errorf("Dapr workload admission task API %s: %s", res.Status, string(raw))
	}
	decoder := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&task); err != nil {
		return task, false, err
	}
	request, valid, validateErr := a.nextDaprWorkloadAdmissionTaskValidation(task)
	if validateErr != nil || !valid {
		if validateErr != nil {
			return task, false, validateErr
		}
		return task, false, fmt.Errorf("Dapr workload admission task is invalid")
	}
	task.Request = request
	return task, true, nil
}

func daprWorkloadAdmissionJobName(task agentDaprWorkloadAdmissionTask) string {
	return daprObjectName("dapr-admit-", task.OperationID, task.TaskFenceToken)
}

func daprWorkloadAdmissionJobPath(namespace string, task agentDaprWorkloadAdmissionTask) string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(namespace) + "/jobs/" + url.PathEscape(daprWorkloadAdmissionJobName(task))
}

func daprWorkloadAdmissionJob(task agentDaprWorkloadAdmissionTask, namespace string) (map[string]any, error) {
	requestRaw, requestDigest, err := daprruntime.MarshalWorkloadAdmissionRequest(task.Request)
	if err != nil {
		return nil, err
	}
	annotations := map[string]any{
		"platform.4so.io/authority": daprWorkloadAdmissionJobAuthority,
		"platform.4so.io/cluster-id": task.Request.ClusterID,
		"platform.4so.io/operation-id": task.OperationID,
		"platform.4so.io/task-fence-token": strconv.FormatInt(task.TaskFenceToken, 10),
		"platform.4so.io/workload-admission-digest": requestDigest,
		"platform.4so.io/executor-evidence-digest": task.Request.ExecutorEvidenceDigest,
	}
	labels := map[string]any{
		"platform.4so.io/dapr-workload-admission": "true",
		"platform.4so.io/managed": "true",
	}
	return map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{
			"name": daprWorkloadAdmissionJobName(task), "namespace": namespace,
			"labels": labels, "annotations": annotations,
		},
		"spec": map[string]any{
			"backoffLimit": 0, "ttlSecondsAfterFinished": 3600,
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels, "annotations": annotations},
				"spec": map[string]any{
					"serviceAccountName": daprExecutorServiceAccount,
					"restartPolicy": "Never",
					"securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
					"containers": []any{map[string]any{
						"name": "executor",
						"image": task.Request.ExecutorImageReference,
						"imagePullPolicy": "IfNotPresent",
						"args": []any{"workload-admission"},
						"env": []any{
							map[string]any{"name": "FOURSO_DAPR_WORKLOAD_OPERATION_ID", "value": task.OperationID},
							map[string]any{"name": "FOURSO_DAPR_WORKLOAD_ADMISSION_JSON", "value": string(requestRaw)},
							map[string]any{"name": "FOURSO_DAPR_WORKLOAD_ADMISSION_DIGEST", "value": requestDigest},
						},
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
							"capabilities": map[string]any{"drop": []any{"ALL"}},
						},
					}},
				},
			},
		},
	}, nil
}

func daprWorkloadAdmissionJobOwnership(job map[string]any, task agentDaprWorkloadAdmissionTask, namespace string) error {
	if job["apiVersion"] != "batch/v1" || job["kind"] != "Job" {
		return fmt.Errorf("Dapr workload admission executor object identity is invalid")
	}
	meta, _ := job["metadata"].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(meta["name"])) != daprWorkloadAdmissionJobName(task) ||
		strings.TrimSpace(fmt.Sprint(meta["namespace"])) != strings.TrimSpace(namespace) {
		return fmt.Errorf("Dapr workload admission Job metadata does not match task fence")
	}
	annotations, _ := meta["annotations"].(map[string]any)
	_, requestDigest, err := daprruntime.MarshalWorkloadAdmissionRequest(task.Request)
	if err != nil {
		return err
	}
	want := map[string]string{
		"platform.4so.io/authority": daprWorkloadAdmissionJobAuthority,
		"platform.4so.io/cluster-id": task.Request.ClusterID,
		"platform.4so.io/operation-id": task.OperationID,
		"platform.4so.io/task-fence-token": strconv.FormatInt(task.TaskFenceToken, 10),
		"platform.4so.io/workload-admission-digest": requestDigest,
		"platform.4so.io/executor-evidence-digest": task.Request.ExecutorEvidenceDigest,
	}
	for key, value := range want {
		if strings.TrimSpace(fmt.Sprint(annotations[key])) != value {
			return fmt.Errorf("Dapr workload admission Job ownership mismatch for %s", key)
		}
	}
	spec, _ := job["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(podSpec["serviceAccountName"])) != daprExecutorServiceAccount {
		return fmt.Errorf("Dapr workload admission Job service account mismatch")
	}
	containers, _ := podSpec["containers"].([]any)
	if len(containers) != 1 {
		return fmt.Errorf("Dapr workload admission Job container identity invalid")
	}
	container, _ := containers[0].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(container["image"])) != task.Request.ExecutorImageReference {
		return fmt.Errorf("Dapr workload admission executor image mismatch")
	}
	return nil
}

func (a *agent) readDaprWorkloadAdmissionExecutorResult(ctx context.Context, task agentDaprWorkloadAdmissionTask) (agentDaprWorkloadAdmissionResult, error) {
	var pods struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				ContainerStatuses []struct {
					Name  string `json:"name"`
					State struct {
						Terminated *struct {
							ExitCode int    `json:"exitCode"`
							Message  string `json:"message"`
						} `json:"terminated,omitempty"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	path := "/api/v1/namespaces/" + url.PathEscape(a.cfg.Namespace) + "/pods?labelSelector=" +
		url.QueryEscape("job-name="+daprWorkloadAdmissionJobName(task)) + "&limit=2"
	if err := a.kubeJSON(ctx, http.MethodGet, path, nil, &pods); err != nil {
		return agentDaprWorkloadAdmissionResult{}, err
	}
	if len(pods.Items) != 1 {
		return agentDaprWorkloadAdmissionResult{}, fmt.Errorf("Dapr workload admission executor pod identity is ambiguous")
	}
	for _, status := range pods.Items[0].Status.ContainerStatuses {
		if status.Name != "executor" || status.State.Terminated == nil {
			continue
		}
		if status.State.Terminated.ExitCode != 0 {
			return agentDaprWorkloadAdmissionResult{}, fmt.Errorf("Dapr workload admission executor exited with code %d", status.State.Terminated.ExitCode)
		}
		message := strings.TrimSpace(status.State.Terminated.Message)
		if message == "" || len(message) > 4096 {
			return agentDaprWorkloadAdmissionResult{}, fmt.Errorf("Dapr workload admission executor termination evidence is unavailable")
		}
		var sealed daprWorkloadAdmissionExecutorResult
		decoder := json.NewDecoder(strings.NewReader(message))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&sealed); err != nil {
			return agentDaprWorkloadAdmissionResult{}, fmt.Errorf("decode Dapr workload admission executor result: %w", err)
		}
		if sealed.Authority != daprruntime.WorkloadAdmissionEvidenceAuthority || sealed.OperationID != task.OperationID {
			return agentDaprWorkloadAdmissionResult{}, fmt.Errorf("Dapr workload admission executor result authority mismatch")
		}
		if err := daprruntime.ValidateWorkloadAdmissionEvidence(sealed.Evidence, task.Request, task.OperationID); err != nil {
			return agentDaprWorkloadAdmissionResult{}, err
		}
		digest, err := daprruntime.WorkloadAdmissionEvidenceDigest(sealed.Evidence, task.Request, task.OperationID)
		if err != nil || digest != strings.ToLower(strings.TrimSpace(sealed.EvidenceDigest)) {
			return agentDaprWorkloadAdmissionResult{}, fmt.Errorf("Dapr workload admission executor evidence digest mismatch")
		}
		return agentDaprWorkloadAdmissionResult{
			Success: true, TaskFenceToken: task.TaskFenceToken,
			Evidence: &sealed.Evidence, EvidenceDigest: digest,
		}, nil
	}
	return agentDaprWorkloadAdmissionResult{}, fmt.Errorf("Dapr workload admission executor has no terminal result")
}

func (a *agent) runDaprWorkloadAdmission(ctx context.Context, task agentDaprWorkloadAdmissionTask) agentDaprWorkloadAdmissionResult {
	result := agentDaprWorkloadAdmissionResult{TaskFenceToken: task.TaskFenceToken}
	if strings.TrimSpace(a.cfg.ServiceAccount) == "" {
		result.Error = "Dapr workload admission executor requires import-scoped agent service account"
		return result
	}
	request, ok, err := a.nextDaprWorkloadAdmissionTaskValidation(task)
	if err != nil || !ok {
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Error = "Dapr workload admission task is invalid"
		}
		return result
	}
	task.Request = request
	path := daprWorkloadAdmissionJobPath(a.cfg.Namespace, task)
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		result.Error = "Dapr workload admission pre-dispatch readback failed: " + err.Error()
		return result
	}
	if found {
		if err = daprWorkloadAdmissionJobOwnership(current, task, a.cfg.Namespace); err != nil {
			result.Error = err.Error()
			return result
		}
	} else {
		job, buildErr := daprWorkloadAdmissionJob(task, a.cfg.Namespace)
		if buildErr != nil {
			result.Error = buildErr.Error()
			return result
		}
		collection := "/apis/batch/v1/namespaces/" + url.PathEscape(a.cfg.Namespace) + "/jobs"
		_, conflict, createErr := a.createKubeObject(ctx, collection, job)
		if createErr != nil && !conflict {
			result.Error = "Dapr workload admission executor dispatch failed: " + createErr.Error()
			return result
		}
		current, found, err = a.getKubeObject(ctx, path)
		if err != nil || !found {
			result.Error = "Dapr workload admission executor dispatch lacks authoritative readback"
			return result
		}
		if err = daprWorkloadAdmissionJobOwnership(current, task, a.cfg.Namespace); err != nil {
			result.Error = err.Error()
			return result
		}
	}
	deadline := task.LeaseExpiresAt.Add(-5 * time.Second)
	for time.Now().UTC().Before(deadline) {
		current, found, err = a.getKubeObject(ctx, path)
		if err != nil || !found {
			result.Error = "Dapr workload admission executor Job readback failed"
			if err != nil {
				result.Error += ": " + err.Error()
			}
			return result
		}
		if err = daprWorkloadAdmissionJobOwnership(current, task, a.cfg.Namespace); err != nil {
			result.Error = err.Error()
			return result
		}
		done, failed, _ := daprJobTerminal(current)
		if done {
			if failed {
				result.Error = "Dapr workload admission executor Job failed"
				return result
			}
			final, readErr := a.readDaprWorkloadAdmissionExecutorResult(ctx, task)
			if readErr != nil {
				result.Error = readErr.Error()
				return result
			}
			return final
		}
		select {
		case <-ctx.Done():
			result.Error = "Dapr workload admission executor interrupted"
			return result
		case <-time.After(2 * time.Second):
		}
	}
	result.Error = "Dapr workload admission executor lease deadline reached"
	return result
}

func (a *agent) nextDaprWorkloadAdmissionTaskValidation(task agentDaprWorkloadAdmissionTask) (daprruntime.WorkloadAdmissionRequest, bool, error) {
	if task.OperationID == "" || task.OperationRevision <= 0 || task.TaskFenceToken <= 0 ||
		!task.LeaseExpiresAt.After(time.Now().UTC()) || task.Request.ClusterID != a.clusterID {
		return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("Dapr workload admission task identity/lease is invalid")
	}
	request, err := daprruntime.CanonicalWorkloadAdmissionRequest(task.Request)
	if err != nil {
		return daprruntime.WorkloadAdmissionRequest{}, false, err
	}
	if err = daprruntime.ValidateExecutorAuthority(task.ExecutorAuthority); err != nil {
		return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("Dapr workload executor authority invalid: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(task.ExecutorAuthority.EvidenceDigest), request.ExecutorEvidenceDigest) ||
		strings.TrimSpace(task.ExecutorAuthority.ImageReference) != request.ExecutorImageReference {
		return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("Dapr workload executor authority does not match sealed request")
	}
	switch request.RuntimeMode {
	case "USE_NATIVE":
		if task.RuntimeLock != nil {
			return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("native Dapr workload admission must not receive product runtime lock")
		}
	case "PRODUCT_MANAGED":
		if task.RuntimeLock == nil {
			return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("product-managed Dapr workload admission requires runtime lock")
		}
		if err = daprruntime.ValidateRuntimeLock(*task.RuntimeLock); err != nil {
			return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("Dapr workload admission runtime lock invalid: %w", err)
		}
		lockDigest, digestErr := daprruntime.RuntimeLockDigest(*task.RuntimeLock)
		if digestErr != nil || lockDigest != request.RuntimeLockDigest {
			return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("Dapr workload admission runtime lock mismatch")
		}
		runtimeExecutor, executorErr := daprruntime.ExecutorAuthorityFromRuntimeLock(*task.RuntimeLock)
		if executorErr != nil || !daprruntime.ExecutorAuthoritiesEqual(runtimeExecutor, task.ExecutorAuthority) {
			return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("Dapr workload executor authority diverges from product runtime lock")
		}
	default:
		return daprruntime.WorkloadAdmissionRequest{}, false, fmt.Errorf("Dapr workload runtime mode invalid")
	}
	return request, true, nil
}

func (a *agent) reportDaprWorkloadAdmissionTask(ctx context.Context, task agentDaprWorkloadAdmissionTask, result agentDaprWorkloadAdmissionResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/dapr-workload-admission-tasks/" + url.PathEscape(task.OperationID) + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("%q", task.OperationRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("Dapr workload admission result API %s: %s", res.Status, string(body))
	}
	return nil
}
