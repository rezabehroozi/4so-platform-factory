package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type agentWorkloadLogRequest struct {
	ProjectID    string `json:"projectId"`
	ClusterID    string `json:"clusterId"`
	Namespace    string `json:"namespace"`
	WorkloadKind string `json:"workloadKind"`
	WorkloadName string `json:"workloadName"`
	Container    string `json:"container,omitempty"`
	Mode         string `json:"mode"`
	SinceSeconds int    `json:"sinceSeconds"`
	Limit        int    `json:"limit"`
}
type agentWorkloadLogTask struct {
	OperationID       string                  `json:"operationId"`
	OperationRevision int64                   `json:"operationRevision"`
	TaskFenceToken    int64                   `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time               `json:"leaseExpiresAt"`
	InventoryDigest   string                  `json:"inventoryDigest"`
	Request           agentWorkloadLogRequest `json:"request"`
}
type agentWorkloadLogLine struct {
	Timestamp time.Time `json:"timestamp"`
	Pod       string    `json:"pod"`
	Container string    `json:"container,omitempty"`
	Line      string    `json:"line"`
}
type agentWorkloadLogResult struct {
	Success        bool                   `json:"success"`
	TaskFenceToken int64                  `json:"taskFenceToken"`
	Error          string                 `json:"error,omitempty"`
	Lines          []agentWorkloadLogLine `json:"lines,omitempty"`
}

func (a *agent) processWorkloadLogTask(ctx context.Context) error {
	task, ok, err := a.nextWorkloadLogTask(ctx)
	if err != nil || !ok {
		return err
	}
	execCtx, cancel, err := taskExecutionContext(ctx, task.LeaseExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	result := a.runWorkloadLogQuery(execCtx, task)
	result.TaskFenceToken = task.TaskFenceToken
	return a.reportWorkloadLogTask(ctx, task, result)
}
func (a *agent) nextWorkloadLogTask(ctx context.Context) (agentWorkloadLogTask, bool, error) {
	var task agentWorkloadLogTask
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Hub+"/agent/v1/clusters/"+a.clusterID+"/workload-log-tasks/next", nil)
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
		return task, false, fmt.Errorf("workload log task API %s: %s", res.Status, string(raw))
	}
	if err = json.NewDecoder(res.Body).Decode(&task); err != nil {
		return task, false, err
	}
	return task, true, nil
}

func workloadControllerPath(kind, namespace, name string) (string, error) {
	ns, pathName := url.PathEscape(namespace), url.PathEscape(name)
	switch strings.ToLower(kind) {
	case "deployment":
		return "/apis/apps/v1/namespaces/" + ns + "/deployments/" + pathName, nil
	case "statefulset":
		return "/apis/apps/v1/namespaces/" + ns + "/statefulsets/" + pathName, nil
	case "daemonset":
		return "/apis/apps/v1/namespaces/" + ns + "/daemonsets/" + pathName, nil
	case "replicaset":
		return "/apis/apps/v1/namespaces/" + ns + "/replicasets/" + pathName, nil
	case "job":
		return "/apis/batch/v1/namespaces/" + ns + "/jobs/" + pathName, nil
	case "pod":
		return "/api/v1/namespaces/" + ns + "/pods/" + pathName, nil
	default:
		return "", fmt.Errorf("workload kind %s is not supported for target logs", kind)
	}
}
func selectorString(labels map[string]any) (string, error) {
	if len(labels) == 0 {
		return "", fmt.Errorf("workload controller selector has no matchLabels")
	}
	keys := make([]string, 0, len(labels))
	for k, v := range labels {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(fmt.Sprint(v)) == "" {
			return "", fmt.Errorf("workload selector contains an empty label")
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+fmt.Sprint(labels[k]))
	}
	return strings.Join(parts, ","), nil
}
func (a *agent) resolveWorkloadPods(ctx context.Context, req agentWorkloadLogRequest) ([]string, error) {
	path, err := workloadControllerPath(req.WorkloadKind, req.Namespace, req.WorkloadName)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(req.WorkloadKind, "Pod") {
		var pod map[string]any
		exists, err := a.kubeJSONOptional(ctx, path, &pod)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("target pod no longer exists")
		}
		return []string{req.WorkloadName}, nil
	}
	var obj map[string]any
	exists, err := a.kubeJSONOptional(ctx, path, &obj)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("target workload no longer exists")
	}
	spec, _ := obj["spec"].(map[string]any)
	selector, _ := spec["selector"].(map[string]any)
	labels, _ := selector["matchLabels"].(map[string]any)
	labelSelector, err := selectorString(labels)
	if err != nil {
		return nil, err
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	podPath := "/api/v1/namespaces/" + url.PathEscape(req.Namespace) + "/pods?labelSelector=" + url.QueryEscape(labelSelector) + "&limit=100"
	if err = a.kubeJSON(ctx, http.MethodGet, podPath, nil, &pods); err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("target workload has no matching pods")
	}
	if len(pods.Items) > 50 {
		return nil, fmt.Errorf("target workload pod set exceeds bounded limit 50")
	}
	out := make([]string, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if strings.TrimSpace(pod.Metadata.Name) != "" {
			out = append(out, pod.Metadata.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (a *agent) runWorkloadLogQuery(ctx context.Context, task agentWorkloadLogTask) agentWorkloadLogResult {
	result := agentWorkloadLogResult{}
	if task.OperationID == "" || task.OperationRevision < 1 || task.TaskFenceToken <= 0 || !task.LeaseExpiresAt.After(time.Now().UTC()) {
		result.Error = "workload log task identity or lease is invalid"
		return result
	}
	req := task.Request
	if req.ClusterID != a.clusterID || req.Namespace == "" || req.WorkloadName == "" || req.Limit < 1 || req.Limit > 500 || req.SinceSeconds < 60 || req.SinceSeconds > 3600 {
		result.Error = "workload log task target is outside admitted bounds"
		return result
	}
	if a.observability == nil || a.cfg.ObservabilityLogsURL == "" {
		result.Error = "Loki-compatible observability logs adapter is not configured"
		return result
	}
	pods, err := a.resolveWorkloadPods(ctx, req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	podSet := map[string]bool{}
	regexParts := make([]string, 0, len(pods))
	for _, pod := range pods {
		podSet[pod] = true
		regexParts = append(regexParts, regexp.QuoteMeta(pod))
	}
	selector := "{namespace=" + strconv.Quote(req.Namespace) + ",pod=~" + strconv.Quote("^(?:"+strings.Join(regexParts, "|")+")$")
	if req.Container != "" {
		selector += ",container=" + strconv.Quote(req.Container)
	}
	selector += "}"
	now := time.Now().UTC()
	u, _ := url.Parse(a.cfg.ObservabilityLogsURL + "/loki/api/v1/query_range")
	q := u.Query()
	q.Set("query", selector)
	q.Set("start", strconv.FormatInt(now.Add(-time.Duration(req.SinceSeconds)*time.Second).UnixNano(), 10))
	q.Set("end", strconv.FormatInt(now.UnixNano(), 10))
	q.Set("limit", strconv.Itoa(req.Limit))
	q.Set("direction", "backward")
	u.RawQuery = q.Encode()
	res, raw, err := a.observabilityRequest(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if res.StatusCode/100 != 2 {
		result.Error = "logs query API returned HTTP " + strconv.Itoa(res.StatusCode)
		return result
	}
	var payload struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err = json.Unmarshal(raw, &payload); err != nil || payload.Status != "success" {
		result.Error = "logs query returned an invalid Loki response"
		return result
	}
	lines := make([]agentWorkloadLogLine, 0, req.Limit)
	for _, stream := range payload.Data.Result {
		pod := strings.TrimSpace(stream.Stream["pod"])
		if stream.Stream["namespace"] != req.Namespace || !podSet[pod] {
			continue
		}
		container := strings.TrimSpace(stream.Stream["container"])
		if req.Container != "" && container != req.Container {
			continue
		}
		for _, value := range stream.Values {
			if len(value) < 2 || len(lines) >= req.Limit {
				continue
			}
			ns, parseErr := strconv.ParseInt(value[0], 10, 64)
			if parseErr != nil {
				continue
			}
			line := value[1]
			if len(line) > 16*1024 {
				line = line[:16*1024]
			}
			lines = append(lines, agentWorkloadLogLine{Timestamp: time.Unix(0, ns).UTC(), Pod: pod, Container: container, Line: line})
		}
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].Timestamp.Before(lines[j].Timestamp) })
	result.Success = true
	result.Lines = lines
	return result
}
func (a *agent) reportWorkloadLogTask(ctx context.Context, task agentWorkloadLogTask, result agentWorkloadLogResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := a.cfg.Hub + "/agent/v1/clusters/" + a.clusterID + "/workload-log-tasks/" + task.OperationID + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", task.OperationRevision))
	res, err := a.hub.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("workload log result API %s: %s", res.Status, string(body))
	}
	return nil
}
