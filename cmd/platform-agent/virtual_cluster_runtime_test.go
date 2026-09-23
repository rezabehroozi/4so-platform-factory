package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/virtualcluster"
)

func virtualClusterRuntimeSourceFixture(t *testing.T) virtualcluster.RuntimeSource {
	t.Helper()
	source, err := virtualcluster.ResolveRuntimeSource(virtualcluster.RuntimeSourceResolution{
		Version: virtualcluster.RuntimeSelectedVersion,
		ChartRepository: virtualcluster.RuntimeChartRepository,
		ChartName: virtualcluster.RuntimeChartName,
		ChartSHA256: "sha256:" + strings.Repeat("a", 64),
		ValuesSHA256: "sha256:" + strings.Repeat("b", 64),
		RenderManifestSHA256: "sha256:" + strings.Repeat("c", 64),
		ImageReferences: []string{"ghcr.io/loft-sh/vcluster-oss@sha256:" + strings.Repeat("d", 64)},
		ChartArtifactPath: "runtime/virtualcluster/chart/vcluster-0.37.1.tgz",
		ExecutorImageReference: "zot.internal/platform/virtual-cluster-runtime@sha256:" + strings.Repeat("e", 64),
		MirrorReady: true,
		MirrorImageReferences: []string{"zot.internal/mirror/vcluster-oss@sha256:" + strings.Repeat("d", 64)},
	})
	if err != nil { t.Fatal(err) }
	return source
}

func virtualClusterTaskFixture(t *testing.T, source virtualcluster.RuntimeSource, action string) controlplane.VirtualClusterTask {
	t.Helper()
	digest, err := virtualcluster.RuntimeSourceDigest(source)
	if err != nil { t.Fatal(err) }
	return controlplane.VirtualClusterTask{
		VirtualClusterID: "vcl_test_001", ClusterRevision: 3, TaskFenceToken: 7,
		LeaseExpiresAt: time.Now().Add(time.Minute), Action: action,
		ProjectID: "prj_1", WorkspaceID: "wsp_1", WorkspaceBindingID: "wsb_1", WorkspaceBindingRevision: 2,
		HostClusterID: "clu_1", HostNamespace: "team-a", Name: "dev",
		Profile: virtualcluster.ProfileDeveloper, DeveloperMode: true, KubernetesVersion: "v1.34.2",
		CPUMilli: 2000, MemoryMiB: 4096, StorageGiB: 20, MaxNamespaces: 3, SleepAfterMinutes: 60,
		DesiredDigest: "sha256:" + strings.Repeat("f", 64), RuntimeSourceDigest: digest,
	}
}

func virtualClusterAgentForKubeTest(t *testing.T, transport roundTripFunc) *agent {
	t.Helper()
	tokenFile := t.TempDir() + "/token"
	if err := os.WriteFile(tokenFile, []byte("service-account-token"), 0o600); err != nil { t.Fatal(err) }
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	t.Cleanup(func() { serviceAccountTokenPath = previous })
	return &agent{
		cfg: config{Namespace: "4so-platform-agent", ServiceAccount: "4so-platform-agent-test"},
		clusterID: "clu_1", kube: &http.Client{Transport: transport},
	}
}

func TestVirtualClusterTaskProcessorIsInSingleWriterLane(t *testing.T) {
	a := &agent{}
	for _, p := range a.taskProcessors() {
		if p.name == "virtual cluster" { return }
	}
	t.Fatal("virtual cluster processor is not part of the single-writer agent task lane")
}

func TestVirtualClusterExecutorJobIsFencedAndExact(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "APPLY")
	job, err := virtualClusterExecutorJob(task, source, "4so-platform-agent", "agent-sa")
	if err != nil { t.Fatal(err) }
	if err := virtualClusterExecutorJobOwnership(job, task, source, "4so-platform-agent"); err != nil { t.Fatal(err) }
	spec := job["spec"].(map[string]any)
	template := spec["template"].(map[string]any)
	podSpec := template["spec"].(map[string]any)
	container := podSpec["containers"].([]any)[0].(map[string]any)
	if container["image"] != source.ExecutorImageReference { t.Fatalf("executor image=%v", container["image"]) }
	args := container["args"].([]any)
	parts := make([]string, len(args))
	for i := range args { parts[i] = args[i].(string) }
	command := strings.Join(parts, " ")
	for _, want := range []string{"upgrade --install", "/runtime/vcluster.tgz", "--namespace team-a", "--values /runtime/execution-values.yaml", "--post-renderer /usr/local/bin/4so-vcluster-post-renderer", "virtual-cluster-key=", "desired-digest=sha256:", "--atomic", "--wait"} {
		if !strings.Contains(command, want) { t.Fatalf("executor command missing %q: %s", want, command) }
	}
	if strings.Contains(command, "charts.loft.sh") || strings.Contains(command, "http://") || strings.Contains(command, "https://") {
		t.Fatalf("executor command depends on external network: %s", command)
	}
	env := container["env"].([]any)
	foundMap := false
	for _, raw := range env {
		row := raw.(map[string]any)
		if row["name"] == "FOURSO_VIRTUAL_CLUSTER_IMAGE_MAP_JSON" {
			value := fmt.Sprint(row["value"])
			if !strings.Contains(value, "zot.internal/mirror/vcluster-oss@sha256:") {
				t.Fatalf("exact mirror map missing from executor env: %s", value)
			}
			foundMap = true
		}
	}
	if !foundMap { t.Fatal("executor image mirror map env missing") }
}

func TestVirtualClusterApplyCreatesJobThenReportsReconciling(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "APPLY")
	jobPath := virtualClusterExecutorJobPath("4so-platform-agent", virtualClusterExecutorJobName(task))
	gets, posts := 0, 0
	a := virtualClusterAgentForKubeTest(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == jobPath:
			gets++
			if gets == 1 {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
			}
			job, jobErr := virtualClusterExecutorJob(task, source, "4so-platform-agent", "4so-platform-agent-test")
			if jobErr != nil { t.Fatal(jobErr) }
			job["status"] = map[string]any{"active": float64(1)}
			raw, _ := json.Marshal(job)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
		case r.Method == http.MethodPost && r.URL.Path == "/apis/batch/v1/namespaces/4so-platform-agent/jobs":
			posts++
			raw, _ := io.ReadAll(r.Body)
			if !bytes.Contains(raw, []byte(source.ExecutorImageReference)) { t.Fatalf("created Job does not bind exact executor image: %s", raw) }
			return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Body: io.NopCloser(bytes.NewReader([]byte("{}"))), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected Kubernetes request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	}))
	result := a.executeVirtualClusterTask(context.Background(), virtualClusterTaskEnvelope{Task: task, RuntimeSource: source})
	if !result.Success || result.Ready || result.RecoveryRequired || result.ObservedDigest != task.DesiredDigest || result.Phase != "ExecutorRunning" {
		t.Fatalf("result=%#v", result)
	}
	if posts != 1 || gets != 2 { t.Fatalf("posts=%d gets=%d", posts, gets) }
}

func TestVirtualClusterInspectOnlyPromotesCompletedOwnedJob(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "INSPECT")
	job, jobErr := virtualClusterExecutorJob(task, source, "4so-platform-agent", "4so-platform-agent-test")
	if jobErr != nil { t.Fatal(jobErr) }
	job["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}}
	raw, _ := json.Marshal(job)
	a := virtualClusterAgentForKubeTest(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/statefulsets") {
			sts := map[string]any{
				"items": []any{map[string]any{
					"metadata": map[string]any{
						"generation": float64(3),
						"annotations": map[string]any{
							"platform.4so.io/virtual-cluster-id": task.VirtualClusterID,
							"platform.4so.io/desired-digest": task.DesiredDigest,
						},
					},
					"spec": map[string]any{
						"replicas": float64(1),
						"template": map[string]any{"spec": map[string]any{"containers": []any{
							map[string]any{"name": "vcluster", "image": source.MirrorImageReferences[0]},
						}}},
					},
					"status": map[string]any{"readyReplicas": float64(1), "updatedReplicas": float64(1), "observedGeneration": float64(3)},
				}},
			}
			stsRaw, _ := json.Marshal(sts)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(stsRaw)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
	}))
	result := a.executeVirtualClusterTask(context.Background(), virtualClusterTaskEnvelope{Task: task, RuntimeSource: source})
	if !result.Success || !result.Ready || result.RecoveryRequired || result.ObservedDigest != task.DesiredDigest || result.Phase != "Ready" {
		t.Fatalf("result=%#v", result)
	}
}

func TestVirtualClusterExecutorOwnershipMismatchFailsRecoveryClosed(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "INSPECT")
	job, jobErr := virtualClusterExecutorJob(task, source, "4so-platform-agent", "4so-platform-agent-test")
	if jobErr != nil { t.Fatal(jobErr) }
	meta := job["metadata"].(map[string]any)
	meta["annotations"].(map[string]any)["platform.4so.io/desired-digest"] = "sha256:" + strings.Repeat("0", 64)
	raw, _ := json.Marshal(job)
	a := virtualClusterAgentForKubeTest(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
	}))
	result := a.executeVirtualClusterTask(context.Background(), virtualClusterTaskEnvelope{Task: task, RuntimeSource: source})
	if result.Success || !result.RecoveryRequired || !strings.Contains(result.Error, "ownership mismatch") {
		t.Fatalf("result=%#v", result)
	}
}

func TestVirtualClusterSourceDigestMismatchDoesNotTouchKubernetes(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "APPLY")
	task.RuntimeSourceDigest = "sha256:" + strings.Repeat("0", 64)
	calls := 0
	a := virtualClusterAgentForKubeTest(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unexpected call")
	}))
	result := a.executeVirtualClusterTask(context.Background(), virtualClusterTaskEnvelope{Task: task, RuntimeSource: source})
	if result.Success || !result.RecoveryRequired || calls != 0 { t.Fatalf("result=%#v calls=%d", result, calls) }
}


func TestVirtualClusterCompletedExecutorRequiresExactWorkloadReadback(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "INSPECT")
	job, err := virtualClusterExecutorJob(task, source, "4so-platform-agent", "4so-platform-agent-test")
	if err != nil { t.Fatal(err) }
	job["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}}
	jobRaw, _ := json.Marshal(job)
	a := virtualClusterAgentForKubeTest(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/statefulsets") {
			sts := map[string]any{"items": []any{map[string]any{
				"metadata": map[string]any{
					"generation": float64(1),
					"annotations": map[string]any{
						"platform.4so.io/virtual-cluster-id": task.VirtualClusterID,
						"platform.4so.io/desired-digest": task.DesiredDigest,
					},
				},
				"spec": map[string]any{"replicas": float64(1), "template": map[string]any{"spec": map[string]any{"containers": []any{
					map[string]any{"name": "vcluster", "image": "ghcr.io/loft-sh/vcluster-oss:0.37.1"},
				}}}},
				"status": map[string]any{"readyReplicas": float64(1), "updatedReplicas": float64(1), "observedGeneration": float64(1)},
			}}}
			raw, _ := json.Marshal(sts)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(jobRaw)), Header: make(http.Header)}, nil
	}))
	result := a.executeVirtualClusterTask(context.Background(), virtualClusterTaskEnvelope{Task: task, RuntimeSource: source})
	if result.Success || !result.RecoveryRequired || result.ObservedDigest != "" || !strings.Contains(result.Error, "outside exact mirror authority") {
		t.Fatalf("mutable/unmirrored workload was promoted ready: %#v", result)
	}
}


func TestVirtualClusterDeleteExecutorUsesPinnedHelmUninstall(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "DELETE")
	task.LifecycleAction = virtualcluster.ActionDelete
	job, err := virtualClusterExecutorJob(task, source, "4so-platform-agent", "agent-sa")
	if err != nil { t.Fatal(err) }
	container := job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	args := container["args"].([]any)
	parts := make([]string, len(args))
	for i := range args { parts[i] = fmt.Sprint(args[i]) }
	command := strings.Join(parts, " ")
	if !strings.Contains(command, "uninstall "+virtualClusterReleaseName(task.VirtualClusterID)+" --namespace "+task.HostNamespace+" --wait --timeout 10m") {
		t.Fatalf("delete executor command=%s", command)
	}
	if strings.Contains(command, "upgrade") || strings.Contains(command, "--install") {
		t.Fatalf("delete executor reused install mutation: %s", command)
	}
}

func TestVirtualClusterLifecycleMutationValidationRequiresActionFence(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "SUSPEND")
	if err := validateVirtualClusterTask(task, source, "clu_1"); err == nil {
		t.Fatal("lifecycle task without lifecycleAction fence was accepted")
	}
	task.LifecycleAction = virtualcluster.ActionSuspend
	if err := validateVirtualClusterTask(task, source, "clu_1"); err != nil {
		t.Fatalf("valid suspend task rejected: %v", err)
	}
}


func TestVirtualClusterDeleteAlreadyAbsentConvergesWithoutCreatingJob(t *testing.T) {
	source := virtualClusterRuntimeSourceFixture(t)
	task := virtualClusterTaskFixture(t, source, "DELETE")
	task.LifecycleAction = virtualcluster.ActionDelete
	calls := 0
	a := virtualClusterAgentForKubeTest(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/statefulsets") {
			t.Fatalf("delete-absent touched mutation endpoint: %s %s", r.Method, r.URL.Path)
		}
		raw, _ := json.Marshal(map[string]any{"items": []any{}})
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
	}))
	result := a.deleteVirtualCluster(context.Background(), task, source)
	if !result.Success || !result.Ready || result.Phase != "Deleted" || result.ObservedDigest != "" || calls != 1 {
		t.Fatalf("delete absent result=%#v calls=%d", result, calls)
	}
}
