package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

type agentApplicationDeploymentTask struct {
	OperationID       string                                    `json:"operationId"`
	OperationRevision int64                                     `json:"operationRevision"`
	TaskFenceToken    int64                                     `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                                 `json:"leaseExpiresAt"`
	Request           controlplane.ApplicationDeploymentRequest `json:"request"`
}

type agentApplicationDeploymentResult struct {
	Success          bool                                        `json:"success"`
	RecoveryRequired bool                                        `json:"recoveryRequired,omitempty"`
	TaskFenceToken   int64                                       `json:"taskFenceToken"`
	Error            string                                      `json:"error,omitempty"`
	Evidence         *controlplane.ApplicationDeploymentEvidence `json:"evidence,omitempty"`
	EvidenceDigest   string                                      `json:"evidenceDigest,omitempty"`
}

func (a *agent) nextApplicationDeploymentTask(ctx context.Context) (agentApplicationDeploymentTask, bool, error) {
	var task agentApplicationDeploymentTask
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/application-deployment-tasks/next"
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
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return task, false, fmt.Errorf("application deployment task API %s: %s", res.Status, string(body))
	}
	decoder := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func (a *agent) reportApplicationDeploymentTask(ctx context.Context, task agentApplicationDeploymentTask, result agentApplicationDeploymentResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/application-deployment-tasks/" + url.PathEscape(task.OperationID) + "/result"
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
		return fmt.Errorf("application deployment result API %s: %s", res.Status, string(body))
	}
	return nil
}

func applicationDeploymentMetadata(object map[string]any) (map[string]any, map[string]any, map[string]any) {
	metadata, _ := object["metadata"].(map[string]any)
	if metadata == nil {
		return nil, nil, nil
	}
	labels, _ := metadata["labels"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	return metadata, labels, annotations
}

func applicationDeploymentOwnedByBinding(object map[string]any, plan controlplane.ApplicationDeploymentPlan) bool {
	metadata, labels, _ := applicationDeploymentMetadata(object)
	if metadata == nil || labels == nil {
		return false
	}
	return strings.TrimSpace(fmt.Sprint(metadata["name"])) == plan.WorkloadName &&
		strings.TrimSpace(fmt.Sprint(metadata["namespace"])) == plan.Namespace &&
		strings.TrimSpace(fmt.Sprint(labels["app.kubernetes.io/managed-by"])) == "4so-platform-factory" &&
		strings.TrimSpace(fmt.Sprint(labels["platform.4so.io/environment-binding"])) == plan.EnvironmentBindingID
}

func applicationDeploymentAuthorityDigestsMatch(object map[string]any, plan controlplane.ApplicationDeploymentPlan) bool {
	_, _, annotations := applicationDeploymentMetadata(object)
	if annotations == nil {
		return false
	}
	return strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/application-release-digest"])) == plan.ReleaseDigest &&
		strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/environment-binding-digest"])) == plan.EnvironmentBindingDigest &&
		strings.TrimSpace(fmt.Sprint(annotations["platform.4so.io/runtime-spec-digest"])) == plan.RuntimeSpecDigest
}

func applicationDeploymentResourcePath(plan controlplane.ApplicationDeploymentPlan, resource map[string]any) (collection, path string, err error) {
	kind := strings.TrimSpace(fmt.Sprint(resource["kind"]))
	name := plan.WorkloadName
	namespace := url.PathEscape(plan.Namespace)
	switch kind {
	case "Deployment":
		collection = "/apis/apps/v1/namespaces/" + namespace + "/deployments"
		path = collection + "/" + url.PathEscape(name)
	case "Service":
		collection = "/api/v1/namespaces/" + namespace + "/services"
		path = collection + "/" + url.PathEscape(name)
	default:
		return "", "", fmt.Errorf("unsupported application deployment resource kind %q", kind)
	}
	return collection, path, nil
}

func (a *agent) applyApplicationDeploymentResource(ctx context.Context, request controlplane.ApplicationDeploymentRequest, resource map[string]any) (bool, error) {
	collection, path, err := applicationDeploymentResourcePath(request.Plan, resource)
	if err != nil {
		return false, err
	}
	current, found, err := a.getKubeObject(ctx, path)
	if err != nil {
		return false, err
	}
	if found && !applicationDeploymentOwnedByBinding(current, request.Plan) {
		return false, fmt.Errorf("application deployment resource collision at %s", path)
	}
	if !found {
		_, conflict, createErr := a.createKubeObject(ctx, collection, resource)
		if createErr != nil {
			if kubeMutationOutcomeUnknown(createErr) {
				return true, createErr
			}
			return false, createErr
		}
		if conflict {
			current, found, err = a.getKubeObject(ctx, path)
			if err != nil || !found {
				return false, fmt.Errorf("application deployment create conflict lacks readback at %s", path)
			}
			if !applicationDeploymentOwnedByBinding(current, request.Plan) {
				return false, fmt.Errorf("application deployment create conflict is owned by another authority at %s", path)
			}
		}
	} else {
		if err = a.serverSideApplyConditional(ctx, path, resource, current); err != nil {
			if kubeMutationOutcomeUnknown(err) {
				return true, err
			}
			return false, err
		}
	}
	current, found, err = a.getKubeObject(ctx, path)
	if err != nil || !found {
		if err == nil {
			err = fmt.Errorf("resource disappeared after mutation")
		}
		return false, fmt.Errorf("application deployment post-mutation readback %s: %w", path, err)
	}
	if !applicationDeploymentOwnedByBinding(current, request.Plan) {
		return false, fmt.Errorf("application deployment ownership drift after mutation at %s", path)
	}
	return false, nil
}

func numericInt(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case float32:
		return int(v)
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	default:
		return 0
	}
}

func numericInt64(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case float32:
		return int64(v)
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}

func deploymentAppContainer(object map[string]any) (map[string]any, error) {
	spec, _ := object["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	templateSpec, _ := template["spec"].(map[string]any)
	containers, _ := templateSpec["containers"].([]any)
	if len(containers) != 1 {
		return nil, fmt.Errorf("application Deployment readback must contain one app container")
	}
	container, _ := containers[0].(map[string]any)
	if container == nil {
		return nil, fmt.Errorf("application Deployment container readback is invalid")
	}
	return container, nil
}

func containerResourceValue(container map[string]any, section, name string) string {
	resources, _ := container["resources"].(map[string]any)
	values, _ := resources[section].(map[string]any)
	return strings.TrimSpace(fmt.Sprint(values[name]))
}

func deploymentReadback(object map[string]any, request controlplane.ApplicationDeploymentRequest) (controlplane.ApplicationDeploymentReadback, bool, error) {
	plan := request.Plan
	if !applicationDeploymentOwnedByBinding(object, plan) {
		return controlplane.ApplicationDeploymentReadback{}, false, fmt.Errorf("application Deployment ownership readback mismatch")
	}
	metadata, _, _ := applicationDeploymentMetadata(object)
	spec, _ := object["spec"].(map[string]any)
	status, _ := object["status"].(map[string]any)
	container, err := deploymentAppContainer(object)
	if err != nil {
		return controlplane.ApplicationDeploymentReadback{}, false, err
	}
	generation := numericInt64(metadata["generation"])
	observedGeneration := numericInt64(status["observedGeneration"])
	desired := numericInt(spec["replicas"])
	ready := numericInt(status["readyReplicas"])
	readback := controlplane.ApplicationDeploymentReadback{
		DeploymentName: plan.WorkloadName,
		DeploymentUID: strings.TrimSpace(fmt.Sprint(metadata["uid"])),
		Generation: generation,
		ObservedGeneration: observedGeneration,
		DesiredReplicas: desired,
		ReadyReplicas: ready,
		WorkloadImage: strings.TrimSpace(fmt.Sprint(container["image"])),
		CPURequest: containerResourceValue(container, "requests", "cpu"),
		CPULimit: containerResourceValue(container, "limits", "cpu"),
		MemoryRequest: containerResourceValue(container, "requests", "memory"),
		MemoryLimit: containerResourceValue(container, "limits", "memory"),
		AuthorityLabelsMatch: true,
		AuthorityDigestsMatch: applicationDeploymentAuthorityDigestsMatch(object, plan),
	}
	converged := readback.DeploymentUID != "" && generation > 0 && observedGeneration >= generation &&
		desired == plan.RuntimeSpec.Replicas && ready == plan.RuntimeSpec.Replicas &&
		readback.WorkloadImage == plan.WorkloadImageReference &&
		readback.CPURequest == plan.RuntimeSpec.CPURequest && readback.CPULimit == plan.RuntimeSpec.CPULimit &&
		readback.MemoryRequest == plan.RuntimeSpec.MemoryRequest && readback.MemoryLimit == plan.RuntimeSpec.MemoryLimit &&
		readback.AuthorityDigestsMatch
	return readback, converged, nil
}

func serviceReadback(object map[string]any, request controlplane.ApplicationDeploymentRequest, readback *controlplane.ApplicationDeploymentReadback) error {
	plan := request.Plan
	if !applicationDeploymentOwnedByBinding(object, plan) || !applicationDeploymentAuthorityDigestsMatch(object, plan) {
		return fmt.Errorf("application Service authority readback mismatch")
	}
	metadata, _, _ := applicationDeploymentMetadata(object)
	spec, _ := object["spec"].(map[string]any)
	ports, _ := spec["ports"].([]any)
	if len(ports) != 1 {
		return fmt.Errorf("application Service readback must contain exactly one port")
	}
	port, _ := ports[0].(map[string]any)
	servicePort := numericInt(port["port"])
	targetPort := numericInt(port["targetPort"])
	if targetPort == 0 {
		targetPort = numericInt(fmt.Sprint(port["targetPort"]))
	}
	clusterIP := strings.TrimSpace(fmt.Sprint(spec["clusterIP"]))
	if servicePort != plan.RuntimeSpec.ServicePort || targetPort != plan.RuntimeSpec.ContainerPort || clusterIP == "" || clusterIP == "None" {
		return fmt.Errorf("application Service port/clusterIP readback mismatch")
	}
	readback.ServiceObserved = true
	readback.ServiceName = strings.TrimSpace(fmt.Sprint(metadata["name"]))
	readback.ServiceClusterIP = clusterIP
	readback.ServicePort = servicePort
	readback.ServiceTargetPort = targetPort
	return nil
}

func (a *agent) observeApplicationDeployment(ctx context.Context, task agentApplicationDeploymentTask) (controlplane.ApplicationDeploymentEvidence, error) {
	plan := task.Request.Plan
	deploymentPath := "/apis/apps/v1/namespaces/" + url.PathEscape(plan.Namespace) + "/deployments/" + url.PathEscape(plan.WorkloadName)
	servicePath := "/api/v1/namespaces/" + url.PathEscape(plan.Namespace) + "/services/" + url.PathEscape(plan.WorkloadName)
	deadline := task.LeaseExpiresAt.Add(-5 * time.Second)
	if max := time.Now().UTC().Add(150 * time.Second); deadline.After(max) {
		deadline = max
	}
	var readback controlplane.ApplicationDeploymentReadback
	for time.Now().UTC().Before(deadline) {
		deployment, found, err := a.getKubeObject(ctx, deploymentPath)
		if err != nil {
			return controlplane.ApplicationDeploymentEvidence{}, err
		}
		if found {
			value, converged, readErr := deploymentReadback(deployment, task.Request)
			if readErr != nil {
				return controlplane.ApplicationDeploymentEvidence{}, readErr
			}
			readback = value
			if converged {
				if plan.RuntimeSpec.ServicePort > 0 {
					service, serviceFound, serviceErr := a.getKubeObject(ctx, servicePath)
					if serviceErr != nil {
						return controlplane.ApplicationDeploymentEvidence{}, serviceErr
					}
					if serviceFound {
						if serviceErr = serviceReadback(service, task.Request, &readback); serviceErr != nil {
							return controlplane.ApplicationDeploymentEvidence{}, serviceErr
						}
						break
					}
				} else {
					service, serviceFound, serviceErr := a.getKubeObject(ctx, servicePath)
					if serviceErr != nil {
						return controlplane.ApplicationDeploymentEvidence{}, serviceErr
					}
					if serviceFound {
						if applicationDeploymentOwnedByBinding(service, plan) {
							return controlplane.ApplicationDeploymentEvidence{}, fmt.Errorf("owned Service remains but service removal lifecycle is not implemented")
						}
						return controlplane.ApplicationDeploymentEvidence{}, fmt.Errorf("foreign Service collides with deployment-only workload name")
					}
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return controlplane.ApplicationDeploymentEvidence{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if readback.DeploymentUID == "" || readback.ReadyReplicas != plan.RuntimeSpec.Replicas ||
		(plan.RuntimeSpec.ServicePort > 0 && !readback.ServiceObserved) {
		return controlplane.ApplicationDeploymentEvidence{}, fmt.Errorf("application Deployment did not converge before task lease deadline")
	}
	evidence := controlplane.ApplicationDeploymentEvidence{
		Authority: controlplane.ApplicationDeploymentEvidenceAuthority,
		OperationID: task.OperationID,
		ProjectID: plan.ProjectID,
		ClusterID: plan.ClusterID,
		Namespace: plan.Namespace,
		EnvironmentBindingID: plan.EnvironmentBindingID,
		EnvironmentBindingRevision: plan.EnvironmentBindingRevision,
		ReleaseDigest: plan.ReleaseDigest,
		InventoryDigest: task.Request.InventoryDigest,
		RenderedDigest: plan.RenderedDigest,
		Readback: readback,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		RuntimeMutationObserved: true,
		PhysicalCertificationInferred: false,
	}
	if err := controlplane.ValidateApplicationDeploymentEvidence(evidence, task.Request, task.OperationID); err != nil {
		return controlplane.ApplicationDeploymentEvidence{}, err
	}
	return evidence, nil
}

func (a *agent) runApplicationDeployment(ctx context.Context, task agentApplicationDeploymentTask) agentApplicationDeploymentResult {
	result := agentApplicationDeploymentResult{TaskFenceToken: task.TaskFenceToken}
	if task.OperationID == "" || task.OperationRevision <= 0 || task.TaskFenceToken <= 0 ||
		!task.LeaseExpiresAt.After(time.Now().UTC()) || task.Request.Plan.ClusterID != a.clusterID {
		result.Error = "application deployment task identity/lease is invalid"
		return result
	}
	raw, _, err := controlplane.MarshalApplicationDeploymentRequest(task.Request)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	request, err := controlplane.ParseApplicationDeploymentRequest(raw, "")
	if err != nil {
		result.Error = err.Error()
		return result
	}
	task.Request = request
	for _, resource := range request.Plan.RenderedResources {
		unknown, applyErr := a.applyApplicationDeploymentResource(ctx, request, resource)
		if applyErr != nil {
			result.RecoveryRequired = unknown
			result.Error = applyErr.Error()
			return result
		}
	}
	evidence, err := a.observeApplicationDeployment(ctx, task)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	digest, err := controlplane.ApplicationDeploymentEvidenceDigest(evidence, request, task.OperationID)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Success = true
	result.Evidence = &evidence
	result.EvidenceDigest = digest
	return result
}

func (a *agent) processApplicationDeploymentTask(ctx context.Context) error {
	task, ok, err := a.nextApplicationDeploymentTask(ctx)
	if err != nil || !ok {
		return err
	}
	result := a.runApplicationDeployment(ctx, task)
	return a.reportApplicationDeploymentTask(ctx, task, result)
}
