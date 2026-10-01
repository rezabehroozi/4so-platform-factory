package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func applicationDeploymentAgentTask(t *testing.T) agentApplicationDeploymentTask {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	release, err := controlplane.NormalizeApplicationRelease(controlplane.ApplicationRelease{
		ProjectID: "prj-1", Name: "payments", Version: "1.0.0",
		WorkloadTypeDigest: digest("a"), WorkspaceProfileDigest: digest("b"),
		WorkloadImageReference: "zot.internal.example/apps/payments@" + digest("c"),
		SourceDigest: digest("d"),
	})
	if err != nil { t.Fatal(err) }
	release.ResourceMeta = controlplane.ResourceMeta{ID: "arl-1", Revision: 1}
	workspaceBinding, err := controlplane.NormalizeWorkspaceBinding(controlplane.WorkspaceBinding{
		ResourceMeta: controlplane.ResourceMeta{ID: "wsb-1", Revision: 4},
		WorkspaceID: "ws-1", ProjectID: "prj-1", ClusterID: "clu_1", Namespace: "payments",
		State: controlplane.WorkspaceBindingActive,
	})
	if err != nil { t.Fatal(err) }
	binding, err := controlplane.NormalizeEnvironmentBinding(controlplane.EnvironmentBinding{
		ResourceMeta: controlplane.ResourceMeta{ID: "aeb-1", Revision: 3},
		ProjectID: "prj-1", ReleaseID: release.ID, ReleaseDigest: release.Digest,
		WorkspaceID: workspaceBinding.WorkspaceID, WorkspaceBindingID: workspaceBinding.ID,
		WorkspaceBindingRevision: workspaceBinding.Revision, ClusterID: workspaceBinding.ClusterID,
		Namespace: workspaceBinding.Namespace, Environment: "production",
		CapabilityResolutionDigest: digest("e"),
	})
	if err != nil { t.Fatal(err) }
	binding.ResourceMeta = controlplane.ResourceMeta{ID: "aeb-1", Revision: 3}
	plan, err := controlplane.ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, controlplane.ApplicationRuntimeSpec{
		Replicas: 2, ContainerPort: 8080, ServicePort: 80,
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "512Mi",
	})
	if err != nil { t.Fatal(err) }
	return agentApplicationDeploymentTask{
		OperationID: "op-app-deploy", OperationRevision: 8, TaskFenceToken: 12,
		LeaseExpiresAt: time.Now().UTC().Add(3 * time.Minute),
		Request: controlplane.ApplicationDeploymentRequest{
			Authority: controlplane.ApplicationDeploymentRequestAuthority,
			InventoryDigest: digest("f"), Plan: plan,
		},
	}
}

func cloneApplicationResource(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil { t.Fatal(err) }
	var out map[string]any
	if err = json.Unmarshal(raw, &out); err != nil { t.Fatal(err) }
	return out
}

func TestApplicationDeploymentProcessorIsInSingleWriterLane(t *testing.T) {
	a := &agent{}
	for _, p := range a.taskProcessors() {
		if p.name == "application deployment" { return }
	}
	t.Fatal("application deployment processor is not part of the single-writer agent task lane")
}

func TestApplicationDeploymentReadbackBindsExactArtifactAndAuthority(t *testing.T) {
	task := applicationDeploymentAgentTask(t)
	deployment := cloneApplicationResource(t, task.Request.Plan.RenderedResources[0])
	meta := deployment["metadata"].(map[string]any)
	meta["uid"] = "uid-payments"
	meta["generation"] = float64(5)
	deployment["status"] = map[string]any{"observedGeneration": float64(5), "readyReplicas": float64(2)}
	readback, converged, err := deploymentReadback(deployment, task.Request)
	if err != nil || !converged {
		t.Fatalf("valid application Deployment readback rejected: converged=%v err=%v readback=%#v", converged, err, readback)
	}
	if readback.WorkloadImage != task.Request.Plan.WorkloadImageReference || !readback.AuthorityDigestsMatch {
		t.Fatalf("application Deployment exact authority lost: %#v", readback)
	}

	service := cloneApplicationResource(t, task.Request.Plan.RenderedResources[1])
	service["spec"].(map[string]any)["clusterIP"] = "10.96.0.24"
	if err = serviceReadback(service, task.Request, &readback); err != nil {
		t.Fatalf("valid application Service readback rejected: %v", err)
	}
	if !readback.ServiceObserved || readback.ServicePort != 80 || readback.ServiceTargetPort != 8080 {
		t.Fatalf("application Service evidence drift: %#v", readback)
	}

	foreign := cloneApplicationResource(t, task.Request.Plan.RenderedResources[0])
	foreign["metadata"].(map[string]any)["labels"].(map[string]any)["platform.4so.io/environment-binding"] = "aeb-foreign"
	if applicationDeploymentOwnedByBinding(foreign, task.Request.Plan) {
		t.Fatal("foreign environment binding ownership was accepted")
	}
}

func TestApplicationDeploymentUnknownMutationOutcomeRequiresRecovery(t *testing.T) {
	task := applicationDeploymentAgentTask(t)
	a := virtualClusterAgentForKubeTest(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.Method {
		case http.MethodGet:
			return jsonResponse(http.StatusNotFound, nil), nil
		case http.MethodPost:
			return nil, errors.New("connection reset after request write")
		default:
			return jsonResponse(http.StatusMethodNotAllowed, nil), nil
		}
	}))
	a.clusterID = task.Request.Plan.ClusterID
	unknown, err := a.applyApplicationDeploymentResource(context.Background(), task.Request, task.Request.Plan.RenderedResources[0])
	if err == nil || !unknown || !kubeMutationOutcomeUnknown(err) {
		t.Fatalf("ambiguous application Deployment mutation was replay-safe: unknown=%v err=%v", unknown, err)
	}
}
