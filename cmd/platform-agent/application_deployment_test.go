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
	recoveryIndex, deploymentIndex := -1, -1
	for index, p := range a.taskProcessors() {
		switch p.name {
		case "application deployment recovery readback":
			recoveryIndex = index
		case "application deployment":
			deploymentIndex = index
		}
	}
	if recoveryIndex < 0 || deploymentIndex < 0 {
		t.Fatalf("application deployment processors missing: recovery=%d deployment=%d", recoveryIndex, deploymentIndex)
	}
	if recoveryIndex >= deploymentIndex {
		t.Fatalf("application deployment recovery must run before new deployment claims: recovery=%d deployment=%d", recoveryIndex, deploymentIndex)
	}
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

func TestApplicationDeploymentRecoveryReadbackIsMutationFreeAndExact(t *testing.T) {
	base := applicationDeploymentAgentTask(t)
	task := agentApplicationDeploymentRecoveryTask{
		OperationID: base.OperationID,
		OperationRevision: base.OperationRevision + 2,
		TaskFenceToken: base.TaskFenceToken,
		Request: base.Request,
	}
	deployment := cloneApplicationResource(t, task.Request.Plan.RenderedResources[0])
	deploymentMeta := deployment["metadata"].(map[string]any)
	deploymentMeta["uid"] = "uid-recovered-deployment"
	deploymentMeta["generation"] = float64(7)
	deployment["status"] = map[string]any{"observedGeneration": float64(7), "readyReplicas": float64(2)}
	service := cloneApplicationResource(t, task.Request.Plan.RenderedResources[1])
	service["spec"].(map[string]any)["clusterIP"] = "10.96.0.88"
	deploymentPath := "/apis/apps/v1/namespaces/payments/deployments/" + task.Request.Plan.WorkloadName
	servicePath := "/api/v1/namespaces/payments/services/" + task.Request.Plan.WorkloadName
	mutations := 0
	a := virtualClusterAgentForKubeTest(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			mutations++
			return jsonResponse(http.StatusMethodNotAllowed, nil), nil
		}
		switch r.URL.Path {
		case deploymentPath:
			return jsonResponse(http.StatusOK, deployment), nil
		case servicePath:
			return jsonResponse(http.StatusOK, service), nil
		default:
			return jsonResponse(http.StatusNotFound, nil), nil
		}
	}))
	a.clusterID = task.Request.Plan.ClusterID
	evidence, confirmed, err := a.readApplicationDeploymentRecoveryEvidence(context.Background(), task)
	if err != nil || !confirmed {
		t.Fatalf("exact recovery readback was not confirmed: confirmed=%v err=%v evidence=%#v", confirmed, err, evidence)
	}
	if mutations != 0 {
		t.Fatalf("application deployment recovery performed %d target mutations", mutations)
	}
	if evidence.OperationID != task.OperationID || evidence.Readback.WorkloadImage != task.Request.Plan.WorkloadImageReference ||
		!evidence.Readback.AuthorityDigestsMatch || !evidence.Readback.ServiceObserved || evidence.PhysicalCertificationInferred {
		t.Fatalf("application deployment recovery evidence drift: %#v", evidence)
	}
}
