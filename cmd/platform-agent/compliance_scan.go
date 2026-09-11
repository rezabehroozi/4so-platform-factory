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

	"platform.4so.io/factory/internal/compliance"
	"platform.4so.io/factory/internal/controlplane"
)

const maxComplianceObjectsPerScan = 10000

type complianceKubeList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []map[string]any `json:"items"`
}

type complianceCollection struct {
	path string
	kind string
}

var complianceCollections = []complianceCollection{
	{path: "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", kind: "ClusterRoleBinding"},
	{path: "/apis/rbac.authorization.k8s.io/v1/rolebindings", kind: "RoleBinding"},
	{path: "/apis/apps/v1/deployments", kind: "Deployment"},
	{path: "/apis/apps/v1/statefulsets", kind: "StatefulSet"},
	{path: "/apis/apps/v1/daemonsets", kind: "DaemonSet"},
	{path: "/apis/apps/v1/replicasets", kind: "ReplicaSet"},
	{path: "/apis/batch/v1/jobs", kind: "Job"},
	{path: "/apis/batch/v1/cronjobs", kind: "CronJob"},
	{path: "/api/v1/pods", kind: "Pod"},
}

func validateComplianceScanTask(task controlplane.ComplianceScanTask) error {
	if strings.TrimSpace(task.RunID) == "" || task.RunRevision < 1 || strings.TrimSpace(task.ProjectID) == "" || strings.TrimSpace(task.ClusterID) == "" {
		return fmt.Errorf("compliance scan task identity is incomplete")
	}
	if task.BaselineAuthority != compliance.BaselineAuthority {
		return fmt.Errorf("unsupported compliance baseline authority %q", task.BaselineAuthority)
	}
	if !strings.HasPrefix(task.InventoryDigest, "sha256:") || len(task.InventoryDigest) != 71 {
		return fmt.Errorf("compliance scan inventory digest is invalid")
	}
	if task.Attempt < 1 || task.FenceToken < 1 || task.LeaseExpiresAt.IsZero() || !task.LeaseExpiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("compliance scan task lease/fence is invalid")
	}
	return nil
}

func (a *agent) processComplianceScanTask(ctx context.Context) error {
	task, ok, err := a.nextComplianceScanTask(ctx)
	if err != nil || !ok {
		return err
	}
	result := controlplane.ComplianceScanTaskResult{TaskFenceToken: task.FenceToken}
	if err = validateComplianceScanTask(task); err != nil {
		result.Error = err.Error()
		return a.reportComplianceScanTask(ctx, task, result)
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	objects, err := a.collectComplianceObjects(execCtx)
	if err != nil {
		result.Error = err.Error()
		return a.reportComplianceScanTask(ctx, task, result)
	}
	evaluated := compliance.Evaluate(objects)
	if evaluated.Authority != task.BaselineAuthority {
		result.Error = "local compliance evaluator authority mismatch"
		return a.reportComplianceScanTask(ctx, task, result)
	}
	result.Findings = evaluated.Findings
	return a.reportComplianceScanTask(ctx, task, result)
}

func (a *agent) nextComplianceScanTask(ctx context.Context) (controlplane.ComplianceScanTask, bool, error) {
	var task controlplane.ComplianceScanTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+url.PathEscape(a.clusterID)+"/compliance-scan-tasks/next", nil)
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
		return task, false, fmt.Errorf("compliance scan task API %s: %s", res.Status, strings.TrimSpace(string(raw)))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func (a *agent) reportComplianceScanTask(ctx context.Context, task controlplane.ComplianceScanTask, result controlplane.ComplianceScanTaskResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + url.PathEscape(a.clusterID) + "/compliance-scan-tasks/" + url.PathEscape(task.RunID) + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
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
		return fmt.Errorf("compliance scan report API %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (a *agent) collectComplianceObjects(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0, 256)
	for _, collection := range complianceCollections {
		items, err := a.collectComplianceCollection(ctx, collection)
		if err != nil {
			return nil, fmt.Errorf("collect %s: %w", collection.kind, err)
		}
		if len(out)+len(items) > maxComplianceObjectsPerScan {
			return nil, fmt.Errorf("compliance scan exceeds bounded object limit %d", maxComplianceObjectsPerScan)
		}
		out = append(out, items...)
	}
	return out, nil
}

func (a *agent) collectComplianceCollection(ctx context.Context, collection complianceCollection) ([]map[string]any, error) {
	const pageLimit = 500
	out := []map[string]any{}
	continuation := ""
	for {
		path := collection.path + "?limit=500"
		if continuation != "" {
			path += "&continue=" + url.QueryEscape(continuation)
		}
		var page complianceKubeList
		if err := a.kubeJSON(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		if len(page.Items) > pageLimit {
			return nil, fmt.Errorf("Kubernetes API returned oversized page")
		}
		for _, item := range page.Items {
			clean, err := sanitizeComplianceObject(collection.kind, item)
			if err != nil {
				return nil, err
			}
			out = append(out, clean)
			if len(out) > maxComplianceObjectsPerScan {
				return nil, fmt.Errorf("collection exceeds bounded object limit")
			}
		}
		continuation = strings.TrimSpace(page.Metadata.Continue)
		if continuation == "" {
			break
		}
	}
	return out, nil
}

func sanitizeComplianceObject(kind string, obj map[string]any) (map[string]any, error) {
	meta, _ := obj["metadata"].(map[string]any)
	name := strings.TrimSpace(fmt.Sprint(meta["name"]))
	namespace := strings.TrimSpace(fmt.Sprint(meta["namespace"]))
	if name == "" {
		return nil, fmt.Errorf("%s object has no metadata.name", kind)
	}
	clean := map[string]any{
		"kind": kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
	}
	if kind == "ClusterRoleBinding" || kind == "RoleBinding" {
		roleRef, _ := obj["roleRef"].(map[string]any)
		clean["roleRef"] = map[string]any{
			"kind": strings.TrimSpace(fmt.Sprint(roleRef["kind"])),
			"name": strings.TrimSpace(fmt.Sprint(roleRef["name"])),
		}
		return clean, nil
	}
	spec, _ := obj["spec"].(map[string]any)
	podSpec := compliancePodSpec(kind, spec)
	if podSpec == nil {
		return nil, fmt.Errorf("%s object has no supported pod spec", kind)
	}
	cleanPod := sanitizeCompliancePodSpec(podSpec)
	switch kind {
	case "Pod":
		clean["spec"] = cleanPod
	case "CronJob":
		clean["spec"] = map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": cleanPod}}}}
	default:
		clean["spec"] = map[string]any{"template": map[string]any{"spec": cleanPod}}
	}
	return clean, nil
}

func compliancePodSpec(kind string, spec map[string]any) map[string]any {
	switch kind {
	case "Pod":
		return spec
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet":
		template, _ := spec["template"].(map[string]any)
		pod, _ := template["spec"].(map[string]any)
		return pod
	case "CronJob":
		jobTemplate, _ := spec["jobTemplate"].(map[string]any)
		jobSpec, _ := jobTemplate["spec"].(map[string]any)
		template, _ := jobSpec["template"].(map[string]any)
		pod, _ := template["spec"].(map[string]any)
		return pod
	default:
		return nil
	}
}

func sanitizeCompliancePodSpec(spec map[string]any) map[string]any {
	out := map[string]any{}
	for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if v, ok := spec[field].(bool); ok {
			out[field] = v
		}
	}
	for _, key := range []string{"initContainers", "containers", "ephemeralContainers"} {
		items, _ := spec[key].([]any)
		if len(items) == 0 {
			continue
		}
		cleanItems := make([]any, 0, len(items))
		for _, raw := range items {
			container, _ := raw.(map[string]any)
			cleanContainer := map[string]any{
				"name":  strings.TrimSpace(fmt.Sprint(container["name"])),
				"image": strings.TrimSpace(fmt.Sprint(container["image"])),
			}
			if sec, ok := container["securityContext"].(map[string]any); ok {
				if privileged, ok := sec["privileged"].(bool); ok {
					cleanContainer["securityContext"] = map[string]any{"privileged": privileged}
				}
			}
			cleanItems = append(cleanItems, cleanContainer)
		}
		out[key] = cleanItems
	}
	return out
}
