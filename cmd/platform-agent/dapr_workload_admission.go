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
	"sort"
	"strings"
	"time"

	daprruntime "platform.4so.io/factory/internal/dapr"
)

type agentDaprWorkloadAdmissionTask struct {
	OperationID       string                               `json:"operationId"`
	OperationRevision int64                                `json:"operationRevision"`
	TaskFenceToken    int64                                `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                            `json:"leaseExpiresAt"`
	Request           daprruntime.WorkloadAdmissionRequest `json:"request"`
}

type agentDaprWorkloadAdmissionResult struct {
	Success        bool                                   `json:"success"`
	TaskFenceToken int64                                  `json:"taskFenceToken"`
	Error          string                                 `json:"error,omitempty"`
	Evidence       *daprruntime.WorkloadAdmissionEvidence `json:"evidence,omitempty"`
	EvidenceDigest string                                 `json:"evidenceDigest,omitempty"`
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
	if task.OperationID == "" || task.OperationRevision <= 0 || task.TaskFenceToken <= 0 ||
		!task.LeaseExpiresAt.After(time.Now().UTC()) || task.Request.ClusterID != a.clusterID {
		return task, false, fmt.Errorf("Dapr workload admission task identity/lease is invalid")
	}
	if _, err = daprruntime.CanonicalWorkloadAdmissionRequest(task.Request); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func daprAdmissionObjectName(operationID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(operationID)))
	return "4so-dapr-admission-" + hex.EncodeToString(sum[:6])
}

func daprAdmissionDeployment(task agentDaprWorkloadAdmissionTask) map[string]any {
	labels := map[string]any{
		"platform.4so.io/dapr-admission": daprAdmissionObjectName(task.OperationID),
	}
	annotations := map[string]any{}
	for _, item := range task.Request.Plan.Annotations {
		annotations[item.Key] = item.Value
	}
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": map[string]any{
			"name": daprAdmissionObjectName(task.OperationID),
			"namespace": task.Request.Plan.Namespace,
			"labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/admission-only": "true"},
		},
		"spec": map[string]any{
			"replicas": 1,
			"selector": map[string]any{"matchLabels": labels},
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels, "annotations": annotations},
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"containers": []any{
						map[string]any{
							"name": "app",
							"image": task.Request.WorkloadImage,
							"imagePullPolicy": "IfNotPresent",
							"securityContext": map[string]any{
								"allowPrivilegeEscalation": false,
								"readOnlyRootFilesystem": true,
								"runAsNonRoot": true,
								"capabilities": map[string]any{"drop": []any{"ALL"}},
							},
						},
					},
				},
			},
		},
	}
}

func nestedMap(value map[string]any, keys ...string) map[string]any {
	current := value
	for _, key := range keys {
		next, _ := current[key].(map[string]any)
		if next == nil {
			return nil
		}
		current = next
	}
	return current
}

func boolField(value map[string]any, key string) bool {
	v, ok := value[key].(bool)
	return ok && v
}

func daprAdmissionEvidence(task agentDaprWorkloadAdmissionTask, response map[string]any, status int) (daprruntime.WorkloadAdmissionEvidence, error) {
	templateMeta := nestedMap(response, "spec", "template", "metadata")
	templateSpec := nestedMap(response, "spec", "template", "spec")
	if templateMeta == nil || templateSpec == nil {
		return daprruntime.WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_DEPLOYMENT_SHAPE_INVALID")
	}
	actualAnnotations, _ := templateMeta["annotations"].(map[string]any)
	annotationsVerified := len(actualAnnotations) >= len(task.Request.Plan.Annotations)
	for _, wanted := range task.Request.Plan.Annotations {
		if strings.TrimSpace(fmt.Sprint(actualAnnotations[wanted.Key])) != wanted.Value {
			annotationsVerified = false
			break
		}
	}
	containers, _ := templateSpec["containers"].([]any)
	appPreserved := false
	var sidecar map[string]any
	for _, raw := range containers {
		container, _ := raw.(map[string]any)
		name := strings.TrimSpace(fmt.Sprint(container["name"]))
		switch name {
		case "app":
			if strings.TrimSpace(fmt.Sprint(container["image"])) == task.Request.WorkloadImage {
				appPreserved = true
			}
		case "daprd":
			if sidecar != nil {
				return daprruntime.WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_DUPLICATE_SIDECAR")
			}
			sidecar = container
		}
	}
	if sidecar == nil {
		return daprruntime.WorkloadAdmissionEvidence{}, fmt.Errorf("DAPR_DRY_RUN_SIDECAR_NOT_INJECTED")
	}
	security, _ := sidecar["securityContext"].(map[string]any)
	capabilities, _ := security["capabilities"].(map[string]any)
	rawDrops, _ := capabilities["drop"].([]any)
	drops := make([]string, 0, len(rawDrops))
	for _, raw := range rawDrops {
		value := strings.ToUpper(strings.TrimSpace(fmt.Sprint(raw)))
		if value != "" {
			drops = append(drops, value)
		}
	}
	sort.Strings(drops)
	dropAll := false
	for _, value := range drops {
		if value == "ALL" {
			dropAll = true
			break
		}
	}
	sidecarImage := strings.TrimSpace(fmt.Sprint(sidecar["image"]))
	expectedMatched := false
	if task.Request.RuntimeMode == "PRODUCT_MANAGED" {
		expectedMatched = sidecarImage == task.Request.ExpectedSidecarImage
	}
	evidence := daprruntime.WorkloadAdmissionEvidence{
		Authority: daprruntime.WorkloadAdmissionEvidenceAuthority,
		OperationID: task.OperationID,
		ProjectID: task.Request.ProjectID,
		ClusterID: task.Request.ClusterID,
		TraitDigest: task.Request.TraitDigest,
		InventoryDigest: task.Request.InventoryDigest,
		RuntimeMode: task.Request.RuntimeMode,
		RuntimeLockDigest: task.Request.RuntimeLockDigest,
		PlanDigest: task.Request.PlanDigest,
		Namespace: task.Request.Plan.Namespace,
		AppID: task.Request.Plan.AppID,
		DryRunHTTPStatus: status,
		InjectedSidecarObserved: true,
		SidecarContainerName: "daprd",
		SidecarImageReference: sidecarImage,
		ExpectedSidecarImageMatched: expectedMatched,
		RunAsNonRoot: boolField(security, "runAsNonRoot"),
		ReadOnlyRootFilesystem: boolField(security, "readOnlyRootFilesystem"),
		AllowPrivilegeEscalation: boolField(security, "allowPrivilegeEscalation"),
		DroppedCapabilities: drops,
		DropAllCapabilities: dropAll,
		AppContainerPreserved: appPreserved,
		AnnotationsVerified: annotationsVerified,
		ServerSideDryRun: true,
		StrictFieldValidation: true,
		SidecarPullObserved: false,
		PhysicalCertificationInferred: false,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := daprruntime.ValidateWorkloadAdmissionEvidence(evidence, task.Request, task.OperationID); err != nil {
		return daprruntime.WorkloadAdmissionEvidence{}, err
	}
	return evidence, nil
}

func (a *agent) runDaprWorkloadAdmission(ctx context.Context, task agentDaprWorkloadAdmissionTask) agentDaprWorkloadAdmissionResult {
	result := agentDaprWorkloadAdmissionResult{}
	if task.OperationID == "" || task.OperationRevision <= 0 || task.TaskFenceToken <= 0 ||
		!task.LeaseExpiresAt.After(time.Now().UTC()) || task.Request.ClusterID != a.clusterID {
		result.Error = "Dapr workload admission task identity/lease is invalid"
		return result
	}
	request, err := daprruntime.CanonicalWorkloadAdmissionRequest(task.Request)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	task.Request = request
	body, err := json.Marshal(daprAdmissionDeployment(task))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	path := "/apis/apps/v1/namespaces/" + url.PathEscape(request.Plan.Namespace) + "/deployments?dryRun=All&fieldValidation=Strict"
	req, err := a.kubeRequest(ctx, http.MethodPost, path, bytes.NewReader(body), "application/json")
	if err != nil {
		result.Error = err.Error()
		return result
	}
	res, err := a.kube.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer res.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if readErr != nil {
		result.Error = readErr.Error()
		return result
	}
	if res.StatusCode/100 != 2 {
		result.Error = fmt.Sprintf("Dapr workload server-side dry-run returned HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
		return result
	}
	var response map[string]any
	if err = json.Unmarshal(raw, &response); err != nil {
		result.Error = "Dapr workload dry-run response is invalid JSON"
		return result
	}
	evidence, err := daprAdmissionEvidence(task, response, res.StatusCode)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	digest, err := daprruntime.WorkloadAdmissionEvidenceDigest(evidence, request, task.OperationID)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Success = true
	result.Evidence = &evidence
	result.EvidenceDigest = digest
	return result
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
