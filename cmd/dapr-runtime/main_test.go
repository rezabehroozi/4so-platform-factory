package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	daprruntime "platform.4so.io/factory/internal/dapr"
	"platform.4so.io/factory/internal/targetmodel"
)

func readyDaprDeployment(name, container, image string) *kubeDeployment {
	replicas := int32(1)
	var deployment kubeDeployment
	deployment.Metadata.Name = name
	deployment.Metadata.Generation = 7
	deployment.Spec.Replicas = &replicas
	deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, struct {
		Name  string `json:"name"`
		Image string `json:"image"`
		Env   []struct {
			Name  string `json:"name"`
			Value string `json:"value,omitempty"`
		} `json:"env,omitempty"`
	}{Name: container, Image: image})
	deployment.Status.ObservedGeneration = 7
	deployment.Status.Replicas = 1
	deployment.Status.UpdatedReplicas = 1
	deployment.Status.AvailableReplicas = 1
	return &deployment
}

func TestVerifyDeploymentReadyExactRejectsImageAndReadinessDrift(t *testing.T) {
	const image = "zot.internal.example/dapr/operator@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	deployment := readyDaprDeployment("dapr-operator", "dapr-operator", image)
	if _, err := verifyDeploymentReadyExact(deployment, "dapr-operator", "dapr-operator", image); err != nil {
		t.Fatalf("valid observed Dapr Deployment rejected: %v", err)
	}

	deployment = readyDaprDeployment("dapr-operator", "dapr-operator", image)
	deployment.Spec.Template.Spec.Containers[0].Image = strings.Replace(image, "aaaa", "bbbb", 1)
	if _, err := verifyDeploymentReadyExact(deployment, "dapr-operator", "dapr-operator", image); err == nil || !strings.Contains(err.Error(), "DAPR_OBSERVED_IMAGE_MISMATCH") {
		t.Fatalf("Dapr observed image substitution accepted: %v", err)
	}

	deployment = readyDaprDeployment("dapr-operator", "dapr-operator", image)
	deployment.Status.ObservedGeneration = 6
	if _, err := verifyDeploymentReadyExact(deployment, "dapr-operator", "dapr-operator", image); err == nil || !strings.Contains(err.Error(), "DAPR_OBSERVED_DEPLOYMENT_NOT_READY") {
		t.Fatalf("stale Dapr Deployment generation accepted: %v", err)
	}

	deployment = readyDaprDeployment("dapr-operator", "dapr-operator", image)
	deployment.Status.AvailableReplicas = 0
	if _, err := verifyDeploymentReadyExact(deployment, "dapr-operator", "dapr-operator", image); err == nil || !strings.Contains(err.Error(), "DAPR_OBSERVED_DEPLOYMENT_NOT_READY") {
		t.Fatalf("unavailable Dapr Deployment accepted: %v", err)
	}
}

func TestVerifyInjectorObservedPolicyPinsSidecarAndHardening(t *testing.T) {
	const sidecar = "zot.internal.example/dapr/sidecar@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	env := map[string]string{
		"SIDECAR_IMAGE": sidecar,
		"SIDECAR_RUN_AS_NON_ROOT": "true",
		"SIDECAR_DROP_ALL_CAPABILITIES": "true",
		"SIDECAR_READ_ONLY_ROOT_FILESYSTEM": "true",
	}
	if err := verifyInjectorObservedPolicy(env, sidecar); err != nil {
		t.Fatalf("valid observed injector policy rejected: %v", err)
	}
	for _, key := range []string{"SIDECAR_IMAGE", "SIDECAR_RUN_AS_NON_ROOT", "SIDECAR_DROP_ALL_CAPABILITIES", "SIDECAR_READ_ONLY_ROOT_FILESYSTEM"} {
		drifted := map[string]string{}
		for k, v := range env {
			drifted[k] = v
		}
		if key == "SIDECAR_IMAGE" {
			drifted[key] = "ghcr.io/dapr/daprd:latest"
		} else {
			drifted[key] = "false"
		}
		if err := verifyInjectorObservedPolicy(drifted, sidecar); err == nil || !strings.Contains(err.Error(), "DAPR_OBSERVED_INJECTOR_POLICY_MISMATCH") {
			t.Fatalf("injector policy drift %s accepted: %v", key, err)
		}
	}
}


func TestReadWorkloadPolicyObservationUsesExactTargetObjects(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	plan, err := targetmodel.ResolveDaprWorkloadRuntimePlan(targetmodel.DaprWorkloadPlanInput{
		Namespace: "payments", AppID: "payments-api", AppPort: 8080, AppProtocol: "http",
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "256Mi",
		ComponentNames: []string{"orders-broker"}, EnableInvocation: true, EnablePubSub: true,
	})
	if err != nil { t.Fatal(err) }
	planDigest, err := daprruntime.WorkloadPlanDigest(plan)
	if err != nil { t.Fatal(err) }
	request, err := daprruntime.CanonicalWorkloadAdmissionRequest(daprruntime.WorkloadAdmissionRequest{
		Authority: daprruntime.WorkloadAdmissionAuthority,
		ProjectID: "prj_test", ClusterID: "clu_test", TraitID: "trait_dapr",
		TraitDigest: digest("1"), InventoryDigest: digest("2"), RuntimeMode: "PRODUCT_MANAGED",
		RuntimeLockDigest: digest("3"),
		ExpectedSidecarImage: "zot.internal.example/dapr/sidecar@" + digest("4"),
		ExecutorEvidenceDigest: digest("5"), ExecutorSourceReleaseDigest: digest("6"),
		ExecutorImageReference: "zot.internal.example/4so/dapr-runtime@" + digest("7"),
		WorkloadImage: "zot.internal.example/apps/payments@" + digest("8"),
		Plan: plan, PlanDigest: planDigest,
	})
	if err != nil { t.Fatal(err) }
	configuration, err := daprruntime.BuildWorkloadConfigurationProjection(request.Plan)
	if err != nil { t.Fatal(err) }
	driftScope := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/apis/dapr.io/v1alpha1/namespaces/payments/configurations/4so-dapr-payments-api":
			_ = json.NewEncoder(w).Encode(configuration)
		case "/apis/dapr.io/v1alpha1/namespaces/payments/components/orders-broker":
			scope := request.Plan.AppID
			if driftScope { scope = "other-app" }
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "dapr.io/v1alpha1", "kind": "Component",
				"metadata": map[string]any{"name": "orders-broker", "namespace": "payments"},
				"scopes": []any{scope},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	kube := &kubeClient{base: server.URL, token: "test-token", http: server.Client()}
	observation, err := readWorkloadPolicyObservation(context.Background(), kube, request)
	if err != nil {
		t.Fatalf("valid Dapr workload policy readback rejected: %v", err)
	}
	if err = daprruntime.ValidateWorkloadPolicyObservation(observation, request); err != nil {
		t.Fatalf("Dapr workload policy observation invalid: %v", err)
	}
	driftScope = true
	if _, err = readWorkloadPolicyObservation(context.Background(), kube, request); err == nil ||
		!strings.Contains(err.Error(), "COMPONENT_SCOPE_MISMATCH") {
		t.Fatalf("cross-app Dapr Component scope was not rejected: %v", err)
	}
}

func TestValidateMutationOwnerRejectsFenceTakeoverWhileMutating(t *testing.T) {
	cfg := lifecycleConfig{Action: daprruntime.ActionUpgrade, OperationID: "op-new", FenceToken: 12}
	owner := &ownerState{Authority: receiptAuthority, OperationID: "op-old", FenceToken: 11, Phase: "Mutating"}
	sameOperation, samePending, err := validateMutationOwner(owner, cfg)
	if sameOperation || samePending || err == nil || !strings.Contains(err.Error(), "MUTATION_ALREADY_OWNED_RECOVERY_REQUIRED") {
		t.Fatalf("Dapr mutation owner takeover was not rejected: sameOperation=%v samePending=%v err=%v", sameOperation, samePending, err)
	}
}

func TestValidateMutationOwnerAllowsOnlyExactPendingResume(t *testing.T) {
	cfg := lifecycleConfig{Action: daprruntime.ActionInstall, OperationID: "op-same", FenceToken: 17}
	owner := &ownerState{Authority: receiptAuthority, OperationID: "op-same", FenceToken: 17, Phase: "Mutating"}
	sameOperation, samePending, err := validateMutationOwner(owner, cfg)
	if err != nil || !sameOperation || !samePending {
		t.Fatalf("exact Dapr fenced resume rejected: sameOperation=%v samePending=%v err=%v", sameOperation, samePending, err)
	}
	owner.Phase = "Installed"
	sameOperation, samePending, err = validateMutationOwner(owner, cfg)
	if err != nil || !sameOperation || samePending {
		t.Fatalf("terminal Dapr owner identity drift: sameOperation=%v samePending=%v err=%v", sameOperation, samePending, err)
	}
}
