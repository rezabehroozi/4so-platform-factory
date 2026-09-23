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

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/virtualcluster"
)

const (
	virtualClusterExecutorJobLabel = "platform.4so.io/virtual-cluster-runtime"
	virtualClusterExecutorAuthority = "VIRTUAL_CLUSTER_EXECUTOR_JOB_AUTHORITY_V1"
)

type virtualClusterTaskEnvelope struct {
	Task          controlplane.VirtualClusterTask
	RuntimeSource virtualcluster.RuntimeSource
}

func virtualClusterRuntimeName(prefix, id string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(id)))
	return prefix + hex.EncodeToString(sum[:8])
}

func virtualClusterReleaseName(id string) string {
	return virtualClusterRuntimeName("vcl-", id)
}

func virtualClusterExecutorJobName(task controlplane.VirtualClusterTask) string {
	return virtualClusterRuntimeName("vcl-exec-", task.VirtualClusterID) + "-" + strconv.FormatInt(task.TaskFenceToken, 10)
}

func virtualClusterExecutorJobPath(namespace, name string) string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(namespace) + "/jobs/" + url.PathEscape(name)
}

func validateVirtualClusterTask(task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource, clusterID string) error {
	if strings.TrimSpace(task.VirtualClusterID) == "" || task.ClusterRevision <= 0 || task.TaskFenceToken <= 0 ||
		task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("virtual cluster task identity/fence is invalid")
	}
	if strings.TrimSpace(task.HostClusterID) == "" || strings.TrimSpace(task.HostClusterID) != strings.TrimSpace(clusterID) {
		return fmt.Errorf("virtual cluster task host cluster does not match this agent")
	}
	if strings.TrimSpace(task.HostNamespace) == "" || strings.TrimSpace(task.WorkspaceID) == "" ||
		strings.TrimSpace(task.WorkspaceBindingID) == "" || task.WorkspaceBindingRevision <= 0 {
		return fmt.Errorf("virtual cluster workspace binding authority is incomplete")
	}
	if !controlplane.VirtualClusterKnownTaskAction(task.Action) {
		return fmt.Errorf("unsupported virtual cluster task action %q", task.Action)
	}
	if controlplane.VirtualClusterMutationTaskAction(task.Action) {
		if strings.TrimSpace(string(task.LifecycleAction)) != task.Action {
			return fmt.Errorf("virtual cluster lifecycle task action fence mismatch")
		}
	}
	if task.Action == "LIFECYCLE_INSPECT" {
		if _, err := controlplane.NormalizeVirtualClusterLifecycleAction(task.LifecycleAction); err != nil {
			return fmt.Errorf("virtual cluster lifecycle inspect action is invalid: %w", err)
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(task.DesiredDigest), "sha256:") || len(strings.TrimSpace(task.DesiredDigest)) != 71 {
		return fmt.Errorf("virtual cluster desired digest is invalid")
	}
	if err := controlplane.ValidateVirtualClusterRuntimeSourceDigest(task.RuntimeSourceDigest); err != nil {
		return err
	}
	if err := virtualcluster.ValidateRuntimeExecutionSource(source); err != nil {
		return fmt.Errorf("virtual cluster runtime source is not execution eligible: %w", err)
	}
	digest, err := virtualcluster.RuntimeSourceDigest(source)
	if err != nil {
		return err
	}
	if digest != strings.TrimSpace(task.RuntimeSourceDigest) {
		return fmt.Errorf("virtual cluster runtime source digest does not match task fence")
	}
	return nil
}

func virtualClusterOwnershipKey(id string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(id)))
	return hex.EncodeToString(sum[:8])
}

func virtualClusterExecutorMutationAction(task controlplane.VirtualClusterTask) string {
	switch task.Action {
	case "INSPECT":
		return "APPLY"
	case "LIFECYCLE_INSPECT":
		return strings.ToUpper(strings.TrimSpace(string(task.LifecycleAction)))
	default:
		return strings.ToUpper(strings.TrimSpace(task.Action))
	}
}

func virtualClusterExecutorArgs(task controlplane.VirtualClusterTask) ([]any, error) {
	switch virtualClusterExecutorMutationAction(task) {
	case "APPLY":
		ownershipKey := virtualClusterOwnershipKey(task.VirtualClusterID)
		return []any{
			"upgrade", "--install", virtualClusterReleaseName(task.VirtualClusterID), "/runtime/vcluster.tgz",
			"--namespace", task.HostNamespace, "--values", "/runtime/execution-values.yaml",
			"--post-renderer", "/usr/local/bin/4so-vcluster-post-renderer",
			"--set-string", "controlPlane.statefulSet.labels.platform\\.4so\\.io/virtual-cluster-key=" + ownershipKey,
			"--set-string", "controlPlane.statefulSet.annotations.platform\\.4so\\.io/virtual-cluster-id=" + task.VirtualClusterID,
			"--set-string", "controlPlane.statefulSet.annotations.platform\\.4so\\.io/desired-digest=" + task.DesiredDigest,
			"--atomic", "--wait", "--timeout", "10m",
		}, nil
	case "DELETE":
		return []any{"uninstall", virtualClusterReleaseName(task.VirtualClusterID), "--namespace", task.HostNamespace, "--wait", "--timeout", "10m"}, nil
	default:
		return nil, fmt.Errorf("virtual cluster executor action %q is unsupported", virtualClusterExecutorMutationAction(task))
	}
}

func virtualClusterExecutorJob(task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource, agentNamespace, serviceAccount string) (map[string]any, error) {
	mirrorMap, err := virtualcluster.RuntimeImageMirrorMap(source)
	if err != nil {
		return nil, err
	}
	mirrorRaw, err := json.Marshal(mirrorMap)
	if err != nil {
		return nil, err
	}
	executorArgs, err := virtualClusterExecutorArgs(task)
	if err != nil {
		return nil, err
	}
	annotations := map[string]any{
		"platform.4so.io/authority":                  virtualClusterExecutorAuthority,
		"platform.4so.io/virtual-cluster-id":         task.VirtualClusterID,
		"platform.4so.io/desired-digest":             task.DesiredDigest,
		"platform.4so.io/runtime-source-digest":      task.RuntimeSourceDigest,
		"platform.4so.io/task-fence-token":           strconv.FormatInt(task.TaskFenceToken, 10),
		"platform.4so.io/workspace-binding-id":       task.WorkspaceBindingID,
		"platform.4so.io/workspace-binding-revision": strconv.FormatInt(task.WorkspaceBindingRevision, 10),
		"platform.4so.io/host-namespace":             task.HostNamespace,
		"platform.4so.io/task-action":                virtualClusterExecutorMutationAction(task),
	}
	labels := map[string]any{virtualClusterExecutorJobLabel: "true", "platform.4so.io/managed": "true"}
	return map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{
			"name": virtualClusterExecutorJobName(task), "namespace": agentNamespace,
			"labels": labels, "annotations": annotations,
		},
		"spec": map[string]any{
			"backoffLimit": 0, "ttlSecondsAfterFinished": 86400,
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels, "annotations": annotations},
				"spec": map[string]any{
					"serviceAccountName": serviceAccount, "restartPolicy": "Never",
					"securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
					"containers": []any{map[string]any{
						"name": "executor", "image": source.ExecutorImageReference, "imagePullPolicy": "IfNotPresent",
						"args": executorArgs,
						"env": []any{
							map[string]any{"name": "FOURSO_VIRTUAL_CLUSTER_IMAGE_MAP_JSON", "value": string(mirrorRaw)},
							map[string]any{"name": "FOURSO_VIRTUAL_CLUSTER_ID", "value": task.VirtualClusterID},
							map[string]any{"name": "FOURSO_VIRTUAL_CLUSTER_DESIRED_DIGEST", "value": task.DesiredDigest},
							map[string]any{"name": "FOURSO_VIRTUAL_CLUSTER_RUNTIME_SOURCE_DIGEST", "value": task.RuntimeSourceDigest},
							map[string]any{"name": "FOURSO_VIRTUAL_CLUSTER_PROFILE", "value": string(task.Profile)},
							map[string]any{"name": "FOURSO_VIRTUAL_CLUSTER_KUBERNETES_VERSION", "value": task.KubernetesVersion},
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

func virtualClusterExecutorJobOwnership(job map[string]any, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource, agentNamespace string) error {
	if job["apiVersion"] != "batch/v1" || job["kind"] != "Job" {
		return fmt.Errorf("virtual cluster executor object identity is invalid")
	}
	metadata, _ := job["metadata"].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(metadata["name"])) != virtualClusterExecutorJobName(task) ||
		strings.TrimSpace(fmt.Sprint(metadata["namespace"])) != strings.TrimSpace(agentNamespace) {
		return fmt.Errorf("virtual cluster executor Job metadata does not match task fence")
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	want := map[string]string{
		"platform.4so.io/authority":                  virtualClusterExecutorAuthority,
		"platform.4so.io/virtual-cluster-id":         task.VirtualClusterID,
		"platform.4so.io/desired-digest":             task.DesiredDigest,
		"platform.4so.io/runtime-source-digest":      task.RuntimeSourceDigest,
		"platform.4so.io/task-fence-token":           strconv.FormatInt(task.TaskFenceToken, 10),
		"platform.4so.io/workspace-binding-id":       task.WorkspaceBindingID,
		"platform.4so.io/workspace-binding-revision": strconv.FormatInt(task.WorkspaceBindingRevision, 10),
		"platform.4so.io/host-namespace":             task.HostNamespace,
		"platform.4so.io/task-action":                virtualClusterExecutorMutationAction(task),
	}
	for key, value := range want {
		if strings.TrimSpace(fmt.Sprint(annotations[key])) != value {
			return fmt.Errorf("virtual cluster executor Job ownership mismatch for %s", key)
		}
	}
	spec, _ := job["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	containers, _ := podSpec["containers"].([]any)
	if len(containers) != 1 {
		return fmt.Errorf("virtual cluster executor Job container identity is invalid")
	}
	container, _ := containers[0].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(container["image"])) != source.ExecutorImageReference {
		return fmt.Errorf("virtual cluster executor Job image does not match exact runtime source")
	}
	return nil
}

func virtualClusterRuntimeStatefulSetListPath(task controlplane.VirtualClusterTask) string {
	selector := "platform.4so.io/virtual-cluster-key=" + virtualClusterOwnershipKey(task.VirtualClusterID)
	return "/apis/apps/v1/namespaces/" + url.PathEscape(task.HostNamespace) + "/statefulsets?labelSelector=" + url.QueryEscape(selector)
}

func virtualClusterWorkloadImages(object map[string]any) []string {
	spec, _ := object["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	var out []string
	for _, field := range []string{"initContainers", "containers"} {
		rows, _ := podSpec[field].([]any)
		for _, raw := range rows {
			container, _ := raw.(map[string]any)
			image := strings.TrimSpace(fmt.Sprint(container["image"]))
			if image != "" {
				out = append(out, image)
			}
		}
	}
	return out
}

func (a *agent) readVirtualClusterRuntimeWorkload(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) (map[string]any, bool, error) {
	var list map[string]any
	if err := a.kubeJSON(ctx, http.MethodGet, virtualClusterRuntimeStatefulSetListPath(task), nil, &list); err != nil {
		return nil, false, fmt.Errorf("read virtual cluster StatefulSet: %w", err)
	}
	items, _ := list["items"].([]any)
	if len(items) == 0 {
		return nil, false, nil
	}
	if len(items) != 1 {
		return nil, false, fmt.Errorf("virtual cluster authoritative StatefulSet count is %d, expected at most 1", len(items))
	}
	statefulSet, _ := items[0].(map[string]any)
	metadata, _ := statefulSet["metadata"].(map[string]any)
	name := strings.TrimSpace(fmt.Sprint(metadata["name"]))
	if name == "" {
		return nil, false, fmt.Errorf("virtual cluster StatefulSet name is empty")
	}
	if namespace := strings.TrimSpace(fmt.Sprint(metadata["namespace"])); namespace != "" && namespace != task.HostNamespace {
		return nil, false, fmt.Errorf("virtual cluster StatefulSet namespace is outside task authority")
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/virtual-cluster-id"])) != task.VirtualClusterID ||
		strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/desired-digest"])) != task.DesiredDigest {
		return nil, false, fmt.Errorf("virtual cluster StatefulSet ownership/digest annotation mismatch")
	}
	allowed := map[string]bool{}
	for _, ref := range source.MirrorImageReferences {
		allowed[ref] = true
	}
	images := virtualClusterWorkloadImages(statefulSet)
	if len(images) == 0 {
		return nil, false, fmt.Errorf("virtual cluster StatefulSet has no container image")
	}
	for _, image := range images {
		if !allowed[image] {
			return nil, false, fmt.Errorf("virtual cluster StatefulSet image is outside exact mirror authority: %s", image)
		}
	}
	return statefulSet, true, nil
}

func virtualClusterStatefulSetReplicas(statefulSet map[string]any) int64 {
	spec, _ := statefulSet["spec"].(map[string]any)
	if raw, ok := kubeJSONNumber(spec["replicas"]); ok && raw >= 0 {
		return int64(raw)
	}
	return 1
}

func virtualClusterStatefulSetReady(statefulSet map[string]any) bool {
	metadata, _ := statefulSet["metadata"].(map[string]any)
	status, _ := statefulSet["status"].(map[string]any)
	replicas := virtualClusterStatefulSetReplicas(statefulSet)
	readyReplicas, _ := kubeJSONNumber(status["readyReplicas"])
	updatedReplicas, _ := kubeJSONNumber(status["updatedReplicas"])
	generation, _ := kubeJSONNumber(metadata["generation"])
	observedGeneration, _ := kubeJSONNumber(status["observedGeneration"])
	return int64(readyReplicas) >= replicas && int64(updatedReplicas) >= replicas && observedGeneration >= generation
}

func virtualClusterStatefulSetAnnotations(statefulSet map[string]any) map[string]any {
	metadata, _ := statefulSet["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	if annotations == nil {
		annotations = map[string]any{}
	}
	return annotations
}

func virtualClusterStatefulSetPath(task controlplane.VirtualClusterTask, statefulSet map[string]any) (string, error) {
	metadata, _ := statefulSet["metadata"].(map[string]any)
	name := strings.TrimSpace(fmt.Sprint(metadata["name"]))
	if name == "" {
		return "", fmt.Errorf("virtual cluster StatefulSet name is empty")
	}
	return "/apis/apps/v1/namespaces/" + url.PathEscape(task.HostNamespace) + "/statefulsets/" + url.PathEscape(name), nil
}

func (a *agent) inspectVirtualClusterRuntimeWorkload(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) (bool, string, error) {
	statefulSet, found, err := a.readVirtualClusterRuntimeWorkload(ctx, task, source)
	if err != nil {
		return false, "", err
	}
	if !found {
		return false, "", fmt.Errorf("virtual cluster authoritative StatefulSet is absent")
	}
	if !virtualClusterStatefulSetReady(statefulSet) {
		return false, "WorkloadReconciling", nil
	}
	return true, "Ready", nil
}

func virtualClusterExecutorJobState(job map[string]any) (ready bool, failed bool, phase string) {
	status, _ := job["status"].(map[string]any)
	conditions, _ := status["conditions"].([]any)
	for _, raw := range conditions {
		condition, _ := raw.(map[string]any)
		if strings.TrimSpace(fmt.Sprint(condition["status"])) != "True" {
			continue
		}
		switch strings.TrimSpace(fmt.Sprint(condition["type"])) {
		case "Complete":
			return true, false, "Ready"
		case "Failed":
			return false, true, "ExecutorFailed"
		}
	}
	if active, ok := status["active"].(float64); ok && active > 0 {
		return false, false, "ExecutorRunning"
	}
	return false, false, "ExecutorPending"
}

func (a *agent) nextVirtualClusterTask(ctx context.Context) (virtualClusterTaskEnvelope, bool, error) {
	var envelope virtualClusterTaskEnvelope
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/virtual-cluster-tasks/next"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil { return envelope, false, err }
	res, err := a.hub.Do(req)
	if err != nil { return envelope, false, err }
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent { return envelope, false, nil }
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return envelope, false, fmt.Errorf("virtual cluster task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&envelope); err != nil { return envelope, false, err }
	return envelope, true, nil
}

func (a *agent) inspectVirtualClusterExecutorJob(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) controlplane.VirtualClusterTaskResult {
	result := controlplane.VirtualClusterTaskResult{TaskFenceToken: task.TaskFenceToken, Action: task.Action}
	path := virtualClusterExecutorJobPath(a.cfg.Namespace, virtualClusterExecutorJobName(task))
	job, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		result.RecoveryRequired = true
		result.Error = "virtual cluster executor authoritative readback failed: " + err.Error()
		return result
	}
	if !found {
		result.RecoveryRequired = true
		result.Error = "virtual cluster executor Job is absent after mutation dispatch"
		return result
	}
	if err = virtualClusterExecutorJobOwnership(job, task, source, a.cfg.Namespace); err != nil {
		result.RecoveryRequired = true
		result.Error = err.Error()
		return result
	}
	ready, failed, phase := virtualClusterExecutorJobState(job)
	result.Phase = phase
	if failed {
		result.RecoveryRequired = true
		result.Error = "virtual cluster executor Job failed after mutation dispatch"
		return result
	}
	if !ready {
		result.Success = true
		result.ObservedDigest = task.DesiredDigest
		return result
	}
	workloadReady, workloadPhase, workloadErr := a.inspectVirtualClusterRuntimeWorkload(ctx, task, source)
	if workloadErr != nil {
		result.RecoveryRequired = true
		result.Phase = "WorkloadReadbackFailed"
		result.Error = "virtual cluster runtime authoritative readback failed: " + workloadErr.Error()
		return result
	}
	result.Success = true
	result.Ready = workloadReady
	result.ObservedDigest = task.DesiredDigest
	result.Phase = workloadPhase
	return result
}

func (a *agent) applyVirtualClusterExecutorJob(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) controlplane.VirtualClusterTaskResult {
	result := controlplane.VirtualClusterTaskResult{TaskFenceToken: task.TaskFenceToken, Action: task.Action}
	path := virtualClusterExecutorJobPath(a.cfg.Namespace, virtualClusterExecutorJobName(task))
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		result.RecoveryRequired = true
		result.Error = "virtual cluster executor pre-mutation readback failed: " + err.Error()
		return result
	}
	if found {
		if err = virtualClusterExecutorJobOwnership(current, task, source, a.cfg.Namespace); err != nil {
			result.RecoveryRequired = true
			result.Error = err.Error()
			return result
		}
		return a.inspectVirtualClusterExecutorJob(ctx, task, source)
	}
	if strings.TrimSpace(a.cfg.ServiceAccount) == "" {
		result.Error = "virtual cluster executor requires an import-scoped agent service account"
		return result
	}
	collection := "/apis/batch/v1/namespaces/" + url.PathEscape(a.cfg.Namespace) + "/jobs"
	jobObject, jobErr := virtualClusterExecutorJob(task, source, a.cfg.Namespace, a.cfg.ServiceAccount)
	if jobErr != nil {
		result.RecoveryRequired = true
		result.Error = "virtual cluster executor Job construction failed: " + jobErr.Error()
		return result
	}
	_, conflict, createErr := a.createKubeObject(ctx, collection, jobObject)
	if createErr != nil {
		current, found, readErr := a.getKubeObject(ctx, path)
		if readErr != nil || !found {
			result.RecoveryRequired = kubeMutationOutcomeUnknown(createErr) || readErr != nil
			result.Error = "virtual cluster executor Job creation failed without authoritative convergence proof: " + createErr.Error()
			if readErr != nil { result.Error += "; readback: " + readErr.Error() }
			return result
		}
		if err = virtualClusterExecutorJobOwnership(current, task, source, a.cfg.Namespace); err != nil {
			result.RecoveryRequired = true
			result.Error = err.Error()
			return result
		}
	}
	if conflict {
		current, found, err = a.getKubeObject(ctx, path)
		if err != nil || !found {
			result.RecoveryRequired = true
			result.Error = "virtual cluster executor Job conflict could not be resolved by authoritative readback"
			return result
		}
		if err = virtualClusterExecutorJobOwnership(current, task, source, a.cfg.Namespace); err != nil {
			result.RecoveryRequired = true
			result.Error = err.Error()
			return result
		}
	}
	return a.inspectVirtualClusterExecutorJob(ctx, task, source)
}

func virtualClusterLifecycleResult(task controlplane.VirtualClusterTask) controlplane.VirtualClusterTaskResult {
	return controlplane.VirtualClusterTaskResult{TaskFenceToken: task.TaskFenceToken, Action: task.Action, LifecycleAction: task.LifecycleAction}
}

func (a *agent) patchVirtualClusterStatefulSet(ctx context.Context, task controlplane.VirtualClusterTask, statefulSet map[string]any, patch []map[string]any) error {
	path, err := virtualClusterStatefulSetPath(task, statefulSet)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	req, err := a.kubeRequest(ctx, http.MethodPatch, path, bytes.NewReader(raw), "application/json-patch+json")
	if err != nil {
		return err
	}
	res, err := a.kube.Do(req)
	if err != nil {
		return &kubeMutationOutcomeUnknownError{operation: "patch virtual cluster StatefulSet", err: err}
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("fenced virtual cluster StatefulSet patch %s: %s", res.Status, string(body))
	}
	return nil
}

func virtualClusterStatefulSetFencePatch(statefulSet map[string]any, task controlplane.VirtualClusterTask) ([]map[string]any, error) {
	rv, err := kubeObjectResourceVersion(statefulSet)
	if err != nil {
		return nil, err
	}
	return []map[string]any{
		{"op": "test", "path": "/metadata/resourceVersion", "value": rv},
		{"op": "test", "path": "/metadata/annotations/platform.4so.io~1virtual-cluster-id", "value": task.VirtualClusterID},
		{"op": "test", "path": "/metadata/annotations/platform.4so.io~1desired-digest", "value": task.DesiredDigest},
	}, nil
}

func (a *agent) inspectVirtualClusterSuspended(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) controlplane.VirtualClusterTaskResult {
	result := virtualClusterLifecycleResult(task)
	statefulSet, found, err := a.readVirtualClusterRuntimeWorkload(ctx, task, source)
	if err != nil || !found {
		result.RecoveryRequired = true
		if err != nil { result.Error = err.Error() } else { result.Error = "virtual cluster StatefulSet is absent while suspend is pending" }
		return result
	}
	annotations := virtualClusterStatefulSetAnnotations(statefulSet)
	if strings.TrimSpace(fmt.Sprint(annotations["loft.sh/paused"])) == "true" && virtualClusterStatefulSetReplicas(statefulSet) == 0 {
		result.Success, result.Ready, result.ObservedDigest, result.Phase = true, true, task.DesiredDigest, "Suspended"
		return result
	}
	result.Success, result.ObservedDigest, result.Phase = true, task.DesiredDigest, "SuspendReconciling"
	return result
}

func (a *agent) suspendVirtualCluster(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) controlplane.VirtualClusterTaskResult {
	result := virtualClusterLifecycleResult(task)
	statefulSet, found, err := a.readVirtualClusterRuntimeWorkload(ctx, task, source)
	if err != nil || !found {
		result.RecoveryRequired = true
		if err != nil { result.Error = err.Error() } else { result.Error = "virtual cluster StatefulSet is absent before suspend" }
		return result
	}
	annotations := virtualClusterStatefulSetAnnotations(statefulSet)
	if paused := strings.TrimSpace(fmt.Sprint(annotations["loft.sh/paused"])); paused != "" {
		if paused == "true" && virtualClusterStatefulSetReplicas(statefulSet) == 0 {
			result.Success, result.Ready, result.ObservedDigest, result.Phase = true, true, task.DesiredDigest, "Suspended"
			return result
		}
		result.RecoveryRequired = true
		result.Error = "virtual cluster pause annotations are present but not converged under 4SO authority"
		return result
	}
	replicas := virtualClusterStatefulSetReplicas(statefulSet)
	if replicas <= 0 {
		result.RecoveryRequired = true
		result.Error = "virtual cluster StatefulSet has zero replicas without 4SO pause authority"
		return result
	}
	patch, err := virtualClusterStatefulSetFencePatch(statefulSet, task)
	if err != nil {
		result.RecoveryRequired = true; result.Error = err.Error(); return result
	}
	patch = append(patch,
		map[string]any{"op": "add", "path": "/metadata/annotations/loft.sh~1paused", "value": "true"},
		map[string]any{"op": "add", "path": "/metadata/annotations/loft.sh~1paused-replicas", "value": strconv.FormatInt(replicas, 10)},
		map[string]any{"op": "add", "path": "/metadata/annotations/loft.sh~1paused-date", "value": time.Now().UTC().Format(time.RFC3339Nano)},
		map[string]any{"op": "add", "path": "/spec/replicas", "value": 0},
	)
	if err = a.patchVirtualClusterStatefulSet(ctx, task, statefulSet, patch); err != nil {
		result.RecoveryRequired = true; result.Error = err.Error(); return result
	}
	return a.inspectVirtualClusterSuspended(ctx, task, source)
}

func (a *agent) inspectVirtualClusterResumed(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) controlplane.VirtualClusterTaskResult {
	result := virtualClusterLifecycleResult(task)
	statefulSet, found, err := a.readVirtualClusterRuntimeWorkload(ctx, task, source)
	if err != nil || !found {
		result.RecoveryRequired = true
		if err != nil { result.Error = err.Error() } else { result.Error = "virtual cluster StatefulSet is absent while resume is pending" }
		return result
	}
	annotations := virtualClusterStatefulSetAnnotations(statefulSet)
	if strings.TrimSpace(fmt.Sprint(annotations["loft.sh/paused"])) != "" || strings.TrimSpace(fmt.Sprint(annotations["loft.sh/paused-replicas"])) != "" {
		result.Success, result.ObservedDigest, result.Phase = true, task.DesiredDigest, "ResumeReconciling"
		return result
	}
	result.Success, result.Ready, result.ObservedDigest = true, virtualClusterStatefulSetReady(statefulSet), task.DesiredDigest
	if result.Ready { result.Phase = "Ready" } else { result.Phase = "ResumeReconciling" }
	return result
}

func (a *agent) resumeVirtualCluster(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) controlplane.VirtualClusterTaskResult {
	result := virtualClusterLifecycleResult(task)
	statefulSet, found, err := a.readVirtualClusterRuntimeWorkload(ctx, task, source)
	if err != nil || !found {
		result.RecoveryRequired = true
		if err != nil { result.Error = err.Error() } else { result.Error = "virtual cluster StatefulSet is absent before resume" }
		return result
	}
	annotations := virtualClusterStatefulSetAnnotations(statefulSet)
	if strings.TrimSpace(fmt.Sprint(annotations["loft.sh/paused"])) != "true" {
		result.RecoveryRequired = true
		result.Error = "virtual cluster is not paused by the expected lifecycle contract"
		return result
	}
	pausedReplicas := strings.TrimSpace(fmt.Sprint(annotations["loft.sh/paused-replicas"]))
	replicas, err := strconv.ParseInt(pausedReplicas, 10, 32)
	if err != nil || replicas <= 0 || strings.TrimSpace(fmt.Sprint(annotations["loft.sh/paused-date"])) == "" {
		result.RecoveryRequired = true
		result.Error = "virtual cluster pause replica/date journal is invalid"
		return result
	}
	patch, err := virtualClusterStatefulSetFencePatch(statefulSet, task)
	if err != nil {
		result.RecoveryRequired = true; result.Error = err.Error(); return result
	}
	patch = append(patch,
		map[string]any{"op": "test", "path": "/metadata/annotations/loft.sh~1paused", "value": "true"},
		map[string]any{"op": "test", "path": "/metadata/annotations/loft.sh~1paused-replicas", "value": pausedReplicas},
		map[string]any{"op": "remove", "path": "/metadata/annotations/loft.sh~1paused"},
		map[string]any{"op": "remove", "path": "/metadata/annotations/loft.sh~1paused-replicas"},
		map[string]any{"op": "remove", "path": "/metadata/annotations/loft.sh~1paused-date"},
		map[string]any{"op": "add", "path": "/spec/replicas", "value": replicas},
	)
	if err = a.patchVirtualClusterStatefulSet(ctx, task, statefulSet, patch); err != nil {
		result.RecoveryRequired = true; result.Error = err.Error(); return result
	}
	return a.inspectVirtualClusterResumed(ctx, task, source)
}

func (a *agent) inspectVirtualClusterDeleted(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) controlplane.VirtualClusterTaskResult {
	result := virtualClusterLifecycleResult(task)
	jobPath := virtualClusterExecutorJobPath(a.cfg.Namespace, virtualClusterExecutorJobName(task))
	job, jobFound, err := a.getKubeObject(ctx, jobPath)
	if err != nil || !jobFound {
		result.RecoveryRequired = true
		if err != nil { result.Error = "read delete executor Job: " + err.Error() } else { result.Error = "virtual cluster delete executor Job is absent after dispatch" }
		return result
	}
	if err = virtualClusterExecutorJobOwnership(job, task, source, a.cfg.Namespace); err != nil {
		result.RecoveryRequired = true; result.Error = err.Error(); return result
	}
	complete, failed, phase := virtualClusterExecutorJobState(job)
	if failed {
		result.RecoveryRequired = true; result.Phase = "DeleteExecutorFailed"; result.Error = "virtual cluster delete executor Job failed"; return result
	}
	_, workloadFound, readErr := a.readVirtualClusterRuntimeWorkload(ctx, task, source)
	if readErr != nil {
		result.RecoveryRequired = true; result.Error = "delete authoritative readback failed: " + readErr.Error(); return result
	}
	if !workloadFound && complete {
		result.Success, result.Ready, result.ObservedDigest, result.Phase = true, true, "", "Deleted"
		return result
	}
	result.Success = true
	if !complete { result.Phase = phase } else { result.Phase = "DeleteReconciling" }
	return result
}

func (a *agent) deleteVirtualCluster(ctx context.Context, task controlplane.VirtualClusterTask, source virtualcluster.RuntimeSource) controlplane.VirtualClusterTaskResult {
	result := virtualClusterLifecycleResult(task)
	path := virtualClusterExecutorJobPath(a.cfg.Namespace, virtualClusterExecutorJobName(task))
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		result.RecoveryRequired = true; result.Error = "virtual cluster delete executor pre-mutation readback failed: " + err.Error(); return result
	}
	if found {
		if err = virtualClusterExecutorJobOwnership(current, task, source, a.cfg.Namespace); err != nil {
			result.RecoveryRequired = true; result.Error = err.Error(); return result
		}
		return a.inspectVirtualClusterDeleted(ctx, task, source)
	}
	if strings.TrimSpace(a.cfg.ServiceAccount) == "" {
		result.RecoveryRequired = true; result.Error = "virtual cluster delete executor requires an import-scoped agent service account"; return result
	}
	jobObject, err := virtualClusterExecutorJob(task, source, a.cfg.Namespace, a.cfg.ServiceAccount)
	if err != nil {
		result.RecoveryRequired = true; result.Error = err.Error(); return result
	}
	collection := "/apis/batch/v1/namespaces/" + url.PathEscape(a.cfg.Namespace) + "/jobs"
	_, _, err = a.createKubeObject(ctx, collection, jobObject)
	if err != nil {
		current, found, readErr := a.getKubeObject(ctx, path)
		if readErr != nil || !found {
			result.RecoveryRequired = true
			result.Error = "virtual cluster delete executor creation failed without authoritative readback: " + err.Error()
			if readErr != nil { result.Error += "; readback: " + readErr.Error() }
			return result
		}
		if ownErr := virtualClusterExecutorJobOwnership(current, task, source, a.cfg.Namespace); ownErr != nil {
			result.RecoveryRequired = true; result.Error = ownErr.Error(); return result
		}
	}
	return a.inspectVirtualClusterDeleted(ctx, task, source)
}

func (a *agent) dispatchVirtualClusterTask(ctx context.Context, task controlplane.VirtualClusterTask) (controlplane.VirtualClusterTask, error) {
	body, err := json.Marshal(map[string]any{"taskFenceToken": task.TaskFenceToken, "action": task.Action})
	if err != nil {
		return controlplane.VirtualClusterTask{}, err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/virtual-cluster-tasks/" + task.VirtualClusterID + "/dispatch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return controlplane.VirtualClusterTask{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("%q", strconv.FormatInt(task.ClusterRevision, 10)))
	res, err := a.hub.Do(req)
	if err != nil {
		return controlplane.VirtualClusterTask{}, err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return controlplane.VirtualClusterTask{}, fmt.Errorf("virtual cluster dispatch ACK API %s: %s", res.Status, string(raw))
	}
	var envelope struct {
		Task controlplane.VirtualClusterTask `json:"task"`
	}
	if err = json.NewDecoder(res.Body).Decode(&envelope); err != nil {
		return controlplane.VirtualClusterTask{}, err
	}
	if envelope.Task.VirtualClusterID != task.VirtualClusterID || envelope.Task.TaskFenceToken != task.TaskFenceToken || envelope.Task.Action != task.Action {
		return controlplane.VirtualClusterTask{}, fmt.Errorf("virtual cluster dispatch ACK changed task identity/fence")
	}
	return envelope.Task, nil
}

func (a *agent) executeVirtualClusterTask(ctx context.Context, envelope virtualClusterTaskEnvelope) controlplane.VirtualClusterTaskResult {
	task, source := envelope.Task, envelope.RuntimeSource
	result := controlplane.VirtualClusterTaskResult{TaskFenceToken: task.TaskFenceToken, Action: task.Action}
	if err := validateVirtualClusterTask(task, source, a.clusterID); err != nil {
		result.RecoveryRequired = true
		result.Error = err.Error()
		return result
	}
	switch task.Action {
	case "APPLY":
		return a.applyVirtualClusterExecutorJob(ctx, task, source)
	case "INSPECT":
		return a.inspectVirtualClusterExecutorJob(ctx, task, source)
	case "SUSPEND":
		return a.suspendVirtualCluster(ctx, task, source)
	case "RESUME":
		return a.resumeVirtualCluster(ctx, task, source)
	case "DELETE":
		return a.deleteVirtualCluster(ctx, task, source)
	case "LIFECYCLE_INSPECT":
		switch task.LifecycleAction {
		case virtualcluster.ActionSuspend:
			return a.inspectVirtualClusterSuspended(ctx, task, source)
		case virtualcluster.ActionResume:
			return a.inspectVirtualClusterResumed(ctx, task, source)
		case virtualcluster.ActionDelete:
			return a.inspectVirtualClusterDeleted(ctx, task, source)
		default:
			result.RecoveryRequired = true
			result.Error = "virtual cluster lifecycle inspect action is unsupported"
			return result
		}
	default:
		result.Error = "virtual cluster task action is unsupported"
		return result
	}
}

func (a *agent) reportVirtualClusterTask(ctx context.Context, task controlplane.VirtualClusterTask, result controlplane.VirtualClusterTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil { return err }
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/virtual-cluster-tasks/" + task.VirtualClusterID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.ClusterRevision))
	res, err := a.hub.Do(req)
	if err != nil { return err }
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("virtual cluster result API %s: %s", res.Status, string(body))
	}
	return nil
}

func (a *agent) processVirtualClusterTask(ctx context.Context) error {
	envelope, ok, err := a.nextVirtualClusterTask(ctx)
	if err != nil || !ok { return err }
	if err = validateVirtualClusterTask(envelope.Task, envelope.RuntimeSource, a.clusterID); err != nil {
		if controlplane.VirtualClusterMutationTaskAction(envelope.Task.Action) {
			return err
		}
		result := controlplane.VirtualClusterTaskResult{TaskFenceToken: envelope.Task.TaskFenceToken, Action: envelope.Task.Action, LifecycleAction: envelope.Task.LifecycleAction, RecoveryRequired: true, Error: err.Error()}
		return a.reportVirtualClusterTask(ctx, envelope.Task, result)
	}
	execCtx, cancel, err := taskExecutionContext(ctx, envelope.Task.LeaseExpiresAt)
	if err != nil { return err }
	defer cancel()
	if controlplane.VirtualClusterMutationTaskAction(envelope.Task.Action) {
		dispatched, dispatchErr := a.dispatchVirtualClusterTask(execCtx, envelope.Task)
		if dispatchErr != nil {
			return dispatchErr
		}
		envelope.Task = dispatched
	}
	return a.reportVirtualClusterTask(ctx, envelope.Task, a.executeVirtualClusterTask(execCtx, envelope))
}
