package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/targetmodel"
)

const hostMaintenanceNamespace = "4so-platform-node-maintenance"

func (a *agent) nodeHostMaintenanceExecutorReady(ctx context.Context, distribution string) bool {
	if distribution != targetmodel.DistributionRKE2 || !strings.Contains(a.cfg.AgentImage, "@sha256:") {
		return false
	}
	checks := []struct {
		group, version, resource, verb string
	}{
		{group: "batch", version: "v1", resource: "jobs", verb: "create"},
		{group: "batch", version: "v1", resource: "jobs", verb: "get"},
		{group: "", version: "v1", resource: "pods", verb: "list"},
	}
	for _, check := range checks {
		allowed, err := a.selfSubjectAccessAllowed(ctx, check.group, check.version, check.resource, check.verb, hostMaintenanceNamespace)
		if err != nil || !allowed {
			return false
		}
	}
	return true
}

func maintenanceJobName(runID, nodeUID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(runID) + "\x00" + strings.TrimSpace(nodeUID)))
	return "4so-os-patch-" + hex.EncodeToString(sum[:])[:20]
}

func buildOSPatchJob(task controlplane.ClusterMaintenanceTask, node, nodeUID, image string) map[string]any {
	timeout := task.HostActionTimeoutSeconds
	if timeout < 60 {
		timeout = 3600
	}
	name := maintenanceJobName(task.RunID, nodeUID)
	labels := map[string]any{
		"app.kubernetes.io/managed-by":       "4so-platform-factory",
		"platform.4so.io/cluster-id":         task.ClusterID,
		"platform.4so.io/maintenance-run-id": task.RunID,
		"platform.4so.io/node-uid-hash":      name[len("4so-os-patch-"):],
		"platform.4so.io/action":             "os-patch",
	}
	annotations := map[string]any{
		"platform.4so.io/executor-authority": hostMaintenanceAuthority,
		"platform.4so.io/inventory-digest":   task.InventoryDigest,
		"platform.4so.io/node-uid":           nodeUID,
		"platform.4so.io/node-name":          node,
	}
	return map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata":   map[string]any{"name": name, "namespace": hostMaintenanceNamespace, "labels": labels, "annotations": annotations},
		"spec": map[string]any{
			"backoffLimit":            0,
			"activeDeadlineSeconds":   timeout,
			"ttlSecondsAfterFinished": 3600,
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels, "annotations": annotations},
				"spec": map[string]any{
					"restartPolicy": "Never",
					"nodeName":      node,
					"hostPID":       true,
					"containers": []any{map[string]any{
						"name":            "host-maintenance",
						"image":           image,
						"imagePullPolicy": "IfNotPresent",
						"command":         []any{"/platform-agent", "host-maintenance", "os-patch", "--host-root", "/host"},
						"securityContext": map[string]any{"privileged": true, "allowPrivilegeEscalation": true, "runAsUser": 0},
						"volumeMounts":    []any{map[string]any{"name": "host-root", "mountPath": "/host", "mountPropagation": "HostToContainer"}},
					}},
					"volumes": []any{map[string]any{"name": "host-root", "hostPath": map[string]any{"path": "/", "type": "Directory"}}},
				},
			},
		},
	}
}

type osPatchJobStatus struct {
	Metadata struct {
		Name        string            `json:"name"`
		UID         string            `json:"uid"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				NodeName   string `json:"nodeName"`
				Containers []struct {
					Name            string   `json:"name"`
					Image           string   `json:"image"`
					Command         []string `json:"command"`
					SecurityContext struct {
						Privileged *bool `json:"privileged"`
					} `json:"securityContext"`
				} `json:"containers"`
				Volumes []struct {
					Name     string `json:"name"`
					HostPath *struct {
						Path string `json:"path"`
					} `json:"hostPath"`
				} `json:"volumes"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		Succeeded  int                                              `json:"succeeded"`
		Failed     int                                              `json:"failed"`
		Conditions []struct{ Type, Status, Reason, Message string } `json:"conditions"`
	} `json:"status"`
}

type maintenanceJobPodList struct {
	Items []struct {
		Status struct {
			ContainerStatuses []struct {
				Name  string `json:"name"`
				State struct {
					Terminated *struct {
						ExitCode int    `json:"exitCode"`
						Message  string `json:"message"`
						Reason   string `json:"reason"`
					} `json:"terminated,omitempty"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

func validateExistingPatchJob(job osPatchJobStatus, task controlplane.ClusterMaintenanceTask, node, nodeUID, image string) error {
	if strings.TrimSpace(job.Metadata.UID) == "" || job.Metadata.Annotations["platform.4so.io/executor-authority"] != hostMaintenanceAuthority || job.Metadata.Annotations["platform.4so.io/inventory-digest"] != task.InventoryDigest || job.Metadata.Annotations["platform.4so.io/node-uid"] != nodeUID || job.Metadata.Annotations["platform.4so.io/node-name"] != node {
		return fmt.Errorf("existing OS patch Job identity does not match approved maintenance task")
	}
	if job.Spec.Template.Spec.NodeName != node {
		return fmt.Errorf("existing OS patch Job is not pinned to approved node")
	}
	var executorFound, hostRootFound bool
	for _, container := range job.Spec.Template.Spec.Containers {
		if container.Name != "host-maintenance" {
			continue
		}
		executorFound = true
		if container.Image != image || !strings.Contains(container.Image, "@sha256:") {
			return fmt.Errorf("existing OS patch Job executor image does not match digest-pinned agent image")
		}
		expectedCommand := []string{"/platform-agent", "host-maintenance", "os-patch", "--host-root", "/host"}
		if len(container.Command) != len(expectedCommand) {
			return fmt.Errorf("existing OS patch Job executor command does not match approved contract")
		}
		for i := range expectedCommand {
			if container.Command[i] != expectedCommand[i] {
				return fmt.Errorf("existing OS patch Job executor command does not match approved contract")
			}
		}
		if container.SecurityContext.Privileged == nil || !*container.SecurityContext.Privileged {
			return fmt.Errorf("existing OS patch Job executor is not privileged")
		}
	}
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.Name == "host-root" && volume.HostPath != nil && volume.HostPath.Path == "/" {
			hostRootFound = true
		}
	}
	if !executorFound || !hostRootFound {
		return fmt.Errorf("existing OS patch Job executor contract is incomplete")
	}
	return nil
}

func parseHostMaintenanceTermination(message string) (hostMaintenanceResult, error) {
	var out hostMaintenanceResult
	if strings.TrimSpace(message) == "" {
		return out, fmt.Errorf("host maintenance termination evidence is empty")
	}
	if err := json.Unmarshal([]byte(message), &out); err != nil {
		return out, fmt.Errorf("decode host maintenance termination evidence: %w", err)
	}
	if out.Authority != hostMaintenanceAuthority || out.Action != "os-patch" || strings.TrimSpace(out.PackageManager) == "" || strings.TrimSpace(out.FinishedAt) == "" {
		return out, fmt.Errorf("host maintenance termination evidence failed authority validation")
	}
	return out, nil
}

func (a *agent) patchJobTerminationEvidence(ctx context.Context, jobName, jobUID string) (hostMaintenanceResult, string, error) {
	var pods maintenanceJobPodList
	path := "/api/v1/namespaces/" + hostMaintenanceNamespace + "/pods?labelSelector=" + url.QueryEscape("job-name="+jobName)
	if err := a.kubeJSON(ctx, http.MethodGet, path, nil, &pods); err != nil {
		return hostMaintenanceResult{}, "", err
	}
	for _, pod := range pods.Items {
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Name != "host-maintenance" || cs.State.Terminated == nil || cs.State.Terminated.ExitCode != 0 {
				continue
			}
			parsed, err := parseHostMaintenanceTermination(cs.State.Terminated.Message)
			if err != nil {
				return hostMaintenanceResult{}, "", err
			}
			digest := sha256.Sum256([]byte(cs.State.Terminated.Message))
			evidence := fmt.Sprintf("Job/%s@%s:sha256:%s", jobName, jobUID, hex.EncodeToString(digest[:]))
			return parsed, evidence, nil
		}
	}
	return hostMaintenanceResult{}, "", fmt.Errorf("successful OS patch Job has no validated termination evidence")
}

func (a *agent) executeOSPatchJob(ctx context.Context, task controlplane.ClusterMaintenanceTask, node, nodeUID string) (hostMaintenanceResult, string, error) {
	if !strings.Contains(a.cfg.AgentImage, "@sha256:") {
		return hostMaintenanceResult{}, "", fmt.Errorf("OS patch executor image must be digest-pinned")
	}
	name := maintenanceJobName(task.RunID, nodeUID)
	path := "/apis/batch/v1/namespaces/" + hostMaintenanceNamespace + "/jobs/" + url.PathEscape(name)
	var job osPatchJobStatus
	found, err := a.kubeJSONOptional(ctx, path, &job)
	if err != nil {
		return hostMaintenanceResult{}, "", err
	}
	if found {
		if err := validateExistingPatchJob(job, task, node, nodeUID, a.cfg.AgentImage); err != nil {
			return hostMaintenanceResult{}, "", err
		}
	} else {
		body := buildOSPatchJob(task, node, nodeUID, a.cfg.AgentImage)
		if err := a.kubeJSON(ctx, http.MethodPost, "/apis/batch/v1/namespaces/"+hostMaintenanceNamespace+"/jobs", body, &job); err != nil {
			return hostMaintenanceResult{}, "", err
		}
		if err := validateExistingPatchJob(job, task, node, nodeUID, a.cfg.AgentImage); err != nil {
			return hostMaintenanceResult{}, "", err
		}
	}
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	for {
		if job.Status.Succeeded > 0 {
			return a.patchJobTerminationEvidence(ctx, name, job.Metadata.UID)
		}
		if job.Status.Failed > 0 {
			return hostMaintenanceResult{}, "", fmt.Errorf("OS patch Job %s failed", name)
		}
		select {
		case <-ctx.Done():
			return hostMaintenanceResult{}, "", ctx.Err()
		case <-poll.C:
			if err := a.kubeJSON(ctx, http.MethodGet, path, nil, &job); err != nil {
				return hostMaintenanceResult{}, "", err
			}
			if err := validateExistingPatchJob(job, task, node, nodeUID, a.cfg.AgentImage); err != nil {
				return hostMaintenanceResult{}, "", err
			}
		}
	}
}
