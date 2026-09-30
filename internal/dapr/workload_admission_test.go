package daprruntime

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/targetmodel"
)

func workloadAdmissionTestDigest(ch string) string {
	return "sha256:" + strings.Repeat(ch, 64)
}

func workloadAdmissionTestRequest(t *testing.T, mode string) WorkloadAdmissionRequest {
	t.Helper()
	plan, err := targetmodel.ResolveDaprWorkloadRuntimePlan(targetmodel.DaprWorkloadPlanInput{
		Namespace: "payments", AppID: "payments-api", AppPort: 8080, AppProtocol: "http",
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "256Mi",
		ComponentNames: []string{"orders-broker"}, EnableInvocation: true, EnablePubSub: true,
	})
	if err != nil { t.Fatal(err) }
	planDigest, err := WorkloadPlanDigest(plan)
	if err != nil { t.Fatal(err) }
	request := WorkloadAdmissionRequest{
		Authority: WorkloadAdmissionAuthority,
		ProjectID: "prj_test", ClusterID: "clu_test", TraitID: "trait_dapr",
		TraitDigest: workloadAdmissionTestDigest("1"), InventoryDigest: workloadAdmissionTestDigest("2"),
		RuntimeMode: mode,
		ExecutorEvidenceDigest: workloadAdmissionTestDigest("7"),
		ExecutorSourceReleaseDigest: workloadAdmissionTestDigest("8"),
		ExecutorImageReference: "zot.internal.example/4so/dapr-runtime@" + workloadAdmissionTestDigest("3"),
		WorkloadImage: "zot.internal.example/apps/payments@" + workloadAdmissionTestDigest("4"),
		Plan: plan, PlanDigest: planDigest,
	}
	if mode == "PRODUCT_MANAGED" {
		request.RuntimeLockDigest = workloadAdmissionTestDigest("5")
		request.ExpectedSidecarImage = "zot.internal.example/dapr/sidecar@" + workloadAdmissionTestDigest("6")
	}
	request, err = CanonicalWorkloadAdmissionRequest(request)
	if err != nil { t.Fatalf("fixture request invalid: %v", err) }
	return request
}

func workloadAdmissionTestPolicyObservation(t *testing.T, request WorkloadAdmissionRequest) WorkloadPolicyObservation {
	t.Helper()
	configuration, err := BuildWorkloadConfigurationProjection(request.Plan)
	if err != nil { t.Fatal(err) }
	components := map[string]map[string]any{}
	for _, scope := range request.Plan.ComponentScopes {
		components[scope.ComponentName] = map[string]any{
			"apiVersion": "dapr.io/v1alpha1",
			"kind": "Component",
			"metadata": map[string]any{"name": scope.ComponentName, "namespace": request.Plan.Namespace},
			"spec": map[string]any{"type": "pubsub.redis", "version": "v1", "metadata": []any{}},
			"scopes": []any{request.Plan.AppID},
		}
	}
	observation, err := ValidateWorkloadPolicyReadback(request, configuration, components)
	if err != nil { t.Fatal(err) }
	return observation
}

func injectTestDaprSidecar(t *testing.T, pod map[string]any, image string) map[string]any {
	t.Helper()
	meta, ok := pod["metadata"].(map[string]any)
	if !ok { t.Fatal("pod metadata missing") }
	annotations, ok := meta["annotations"].(map[string]any)
	if !ok { t.Fatal("pod annotations missing") }
	podSpec, ok := pod["spec"].(map[string]any)
	if !ok { t.Fatal("pod spec missing") }
	containers, ok := podSpec["containers"].([]any)
	if !ok { t.Fatal("containers missing") }
	podSpec["containers"] = append(containers, map[string]any{
		"name": "daprd", "image": image,
		"resources": map[string]any{
			"requests": map[string]any{
				"cpu": fmt.Sprint(annotations["dapr.io/sidecar-cpu-request"]),
				"memory": fmt.Sprint(annotations["dapr.io/sidecar-memory-request"]),
			},
			"limits": map[string]any{
				"cpu": fmt.Sprint(annotations["dapr.io/sidecar-cpu-limit"]),
				"memory": fmt.Sprint(annotations["dapr.io/sidecar-memory-limit"]),
			},
		},
		"securityContext": map[string]any{
			"runAsNonRoot": true,
			"readOnlyRootFilesystem": true,
			"allowPrivilegeEscalation": false,
			"capabilities": map[string]any{"drop": []any{"ALL"}},
		},
	})
	return pod
}

func TestWorkloadAdmissionRequestIsDigestBoundAndRequiresExactImages(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	raw, digest, err := MarshalWorkloadAdmissionRequest(request)
	if err != nil { t.Fatal(err) }
	parsed, err := ParseWorkloadAdmissionRequest(raw, digest)
	if err != nil { t.Fatal(err) }
	if parsed.ProjectID != request.ProjectID || parsed.PlanDigest != request.PlanDigest ||
		parsed.ExecutorSourceReleaseDigest != request.ExecutorSourceReleaseDigest ||
		parsed.ExecutorImageReference != request.ExecutorImageReference || parsed.ExpectedSidecarImage != request.ExpectedSidecarImage {
		t.Fatalf("Dapr workload admission request drift: %#v", parsed)
	}
	if _, err = ParseWorkloadAdmissionRequest(append(raw, []byte("{}")...), digest); err == nil {
		t.Fatal("trailing JSON entered Dapr workload admission request")
	}

	bad := request
	bad.WorkloadImage = "zot.internal.example/apps/payments:latest"
	if _, err = CanonicalWorkloadAdmissionRequest(bad); err == nil {
		t.Fatal("mutable workload image entered Dapr workload admission")
	}
	bad = request
	bad.ExecutorImageReference = "zot.internal.example/4so/dapr-runtime:latest"
	if _, err = CanonicalWorkloadAdmissionRequest(bad); err == nil {
		t.Fatal("mutable Dapr executor image entered workload admission")
	}
	bad = request
	bad.ExecutorSourceReleaseDigest = ""
	if _, err = CanonicalWorkloadAdmissionRequest(bad); err == nil {
		t.Fatal("Dapr workload admission accepted executor without exact release binding")
	}
}

func TestWorkloadAdmissionDryRunProvesInjectedSidecarSecurityWithoutPullOrPhysicalClaims(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	pod, err := BuildWorkloadAdmissionPod(request, "op_test")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, pod, request.ExpectedSidecarImage)
	evidence, err := WorkloadAdmissionEvidenceFromDryRun(request, "op_test", workloadAdmissionTestPolicyObservation(t, request), response, 201, time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	if err != nil { t.Fatal(err) }
	if !evidence.InjectedSidecarObserved || !evidence.RunAsNonRoot || !evidence.ReadOnlyRootFilesystem ||
		evidence.AllowPrivilegeEscalation || !evidence.DropAllCapabilities || !evidence.ExpectedSidecarImageMatched ||
		!evidence.SidecarResourcesVerified || evidence.SidecarCPURequest != "100m" || evidence.SidecarCPULimit != "500m" ||
		evidence.SidecarMemoryRequest != "128Mi" || evidence.SidecarMemoryLimit != "256Mi" ||
		!evidence.AppContainerPreserved || !evidence.AnnotationsVerified || !evidence.ServerSideDryRun || !evidence.StrictFieldValidation {
		t.Fatalf("Dapr workload dry-run evidence missing security proof: %#v", evidence)
	}
	if evidence.SidecarPullObserved || evidence.PhysicalCertificationInferred ||
		evidence.ExecutorSourceReleaseDigest != request.ExecutorSourceReleaseDigest ||
		!evidence.PolicyObservation.ComponentTypesVerified || evidence.PolicyObservation.PubSubComponentCount != 1 ||
		evidence.PolicyObservation.BindingComponentCount != 0 {
		t.Fatalf("Dapr workload dry-run overclaimed or lost executor release binding: %#v", evidence)
	}
	first, err := WorkloadAdmissionEvidenceDigest(evidence, request, "op_test")
	if err != nil { t.Fatal(err) }
	evidence.DroppedCapabilities = []string{"all"}
	second, err := WorkloadAdmissionEvidenceDigest(evidence, request, "op_test")
	if err != nil { t.Fatal(err) }
	if first != second {
		t.Fatalf("Dapr workload admission evidence digest is not canonical: %s != %s", first, second)
	}
}

func TestWorkloadAdmissionRejectsPolicyProjectionDrift(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	configuration, err := BuildWorkloadConfigurationProjection(request.Plan)
	if err != nil { t.Fatal(err) }
	spec := configuration["spec"].(map[string]any)
	access := spec["accessControl"].(map[string]any)
	access["defaultAction"] = "allow"
	components := map[string]map[string]any{
		"orders-broker": {
			"apiVersion": "dapr.io/v1alpha1",
			"kind": "Component",
			"metadata": map[string]any{"name": "orders-broker", "namespace": request.Plan.Namespace},
			"scopes": []any{request.Plan.AppID},
		},
	}
	if _, err = ValidateWorkloadPolicyReadback(request, configuration, components); err == nil ||
		!strings.Contains(err.Error(), "ACCESS_CONTROL_INVALID") {
		t.Fatalf("Dapr workload Configuration default-allow drift passed policy admission: %v", err)
	}

	configuration, err = BuildWorkloadConfigurationProjection(request.Plan)
	if err != nil { t.Fatal(err) }
	components["orders-broker"]["scopes"] = []any{"other-app"}
	if _, err = ValidateWorkloadPolicyReadback(request, configuration, components); err == nil ||
		!strings.Contains(err.Error(), "COMPONENT_SCOPE_MISMATCH") {
		t.Fatalf("cross-app Dapr Component scope passed policy admission: %v", err)
	}
}

func TestWorkloadAdmissionRejectsForbiddenComponentFamiliesAndSecretAuthority(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	configuration, err := BuildWorkloadConfigurationProjection(request.Plan)
	if err != nil { t.Fatal(err) }
	component := map[string]any{
		"apiVersion": "dapr.io/v1alpha1",
		"kind": "Component",
		"metadata": map[string]any{"name": "orders-broker", "namespace": request.Plan.Namespace},
		"spec": map[string]any{"type": "state.redis", "version": "v1", "metadata": []any{}},
		"scopes": []any{request.Plan.AppID},
	}
	components := map[string]map[string]any{"orders-broker": component}
	if _, err = ValidateWorkloadPolicyReadback(request, configuration, components); err == nil ||
		!strings.Contains(err.Error(), "COMPONENT_TYPE_FORBIDDEN") {
		t.Fatalf("forbidden Dapr state Component entered initial workload profile: %v", err)
	}

	component["spec"] = map[string]any{"type": "pubsub.redis", "version": "v1", "metadata": []any{}}
	component["auth"] = map[string]any{"secretStore": "kubernetes"}
	if _, err = ValidateWorkloadPolicyReadback(request, configuration, components); err == nil ||
		!strings.Contains(err.Error(), "SECRET_AUTHORITY_FORBIDDEN") {
		t.Fatalf("Dapr Component secret authority entered initial workload profile: %v", err)
	}
}

func TestWorkloadAdmissionRequiresComponentFamilyForEnabledAPI(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	configuration, err := BuildWorkloadConfigurationProjection(request.Plan)
	if err != nil { t.Fatal(err) }
	components := map[string]map[string]any{
		"orders-broker": {
			"apiVersion": "dapr.io/v1alpha1",
			"kind": "Component",
			"metadata": map[string]any{"name": "orders-broker", "namespace": request.Plan.Namespace},
			"spec": map[string]any{"type": "bindings.http", "version": "v1", "metadata": []any{}},
			"scopes": []any{request.Plan.AppID},
		},
	}
	if _, err = ValidateWorkloadPolicyReadback(request, configuration, components); err == nil ||
		!strings.Contains(err.Error(), "COMPONENT_TYPE_FORBIDDEN") {
		t.Fatalf("binding Component satisfied publish-only Dapr profile: %v", err)
	}
}

func TestWorkloadAdmissionAcceptsBindingsComponentOnlyWhenBindingsAPIEnabled(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	plan, err := targetmodel.ResolveDaprWorkloadRuntimePlan(targetmodel.DaprWorkloadPlanInput{
		Namespace: "payments", AppID: "payments-api", AppPort: 8080, AppProtocol: "http",
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "256Mi",
		ComponentNames: []string{"billing-binding"}, EnableInvocation: true, EnableBindings: true,
	})
	if err != nil { t.Fatal(err) }
	planDigest, err := WorkloadPlanDigest(plan)
	if err != nil { t.Fatal(err) }
	request.Plan, request.PlanDigest = plan, planDigest
	request, err = CanonicalWorkloadAdmissionRequest(request)
	if err != nil { t.Fatal(err) }
	configuration, err := BuildWorkloadConfigurationProjection(request.Plan)
	if err != nil { t.Fatal(err) }
	components := map[string]map[string]any{
		"billing-binding": {
			"apiVersion": "dapr.io/v1alpha1", "kind": "Component",
			"metadata": map[string]any{"name": "billing-binding", "namespace": request.Plan.Namespace},
			"spec": map[string]any{"type": "bindings.http", "version": "v1", "metadata": []any{}},
			"scopes": []any{request.Plan.AppID},
		},
	}
	observation, err := ValidateWorkloadPolicyReadback(request, configuration, components)
	if err != nil { t.Fatalf("valid Dapr binding Component rejected: %v", err) }
	if !observation.ComponentTypesVerified || observation.BindingComponentCount != 1 || observation.PubSubComponentCount != 0 {
		t.Fatalf("Dapr binding component evidence drift: %#v", observation)
	}
	if err = ValidateWorkloadPolicyObservation(observation, request); err != nil {
		t.Fatalf("valid Dapr binding observation rejected: %v", err)
	}
}

func TestWorkloadPolicyObservationRejectsForgedComponentTypeCounts(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	observation := workloadAdmissionTestPolicyObservation(t, request)
	observation.PubSubComponentCount = 0
	observation.BindingComponentCount = 1
	if err := ValidateWorkloadPolicyObservation(observation, request); err == nil ||
		!strings.Contains(err.Error(), "POLICY_OBSERVATION_INVALID") {
		t.Fatalf("forged Dapr Component family counts entered workload evidence: %v", err)
	}
}

func TestWorkloadAdmissionEvidenceRejectsForeignPolicyObservation(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	pod, err := BuildWorkloadAdmissionPod(request, "op_policy_drift")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, pod, request.ExpectedSidecarImage)
	policy := workloadAdmissionTestPolicyObservation(t, request)
	policy.ConfigurationPolicyDigest = workloadAdmissionTestDigest("9")
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_policy_drift", policy, response, 201, time.Now().UTC()); err == nil ||
		!strings.Contains(err.Error(), "POLICY_OBSERVATION_INVALID") {
		t.Fatalf("foreign Dapr workload policy observation entered admission evidence: %v", err)
	}
}

func TestWorkloadAdmissionRejectsDeploymentDryRunShape(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	response := map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": AdmissionObjectName("op_wrong"), "namespace": request.Plan.Namespace},
		"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{}, "spec": map[string]any{}}},
	}
	if _, err := WorkloadAdmissionEvidenceFromDryRun(request, "op_wrong", workloadAdmissionTestPolicyObservation(t, request), response, 201, time.Now().UTC()); err == nil ||
		!strings.Contains(err.Error(), "POD_SHAPE_INVALID") {
		t.Fatalf("Deployment dry-run was treated as Dapr Pod injection evidence: %v", err)
	}
}

func TestWorkloadAdmissionRejectsInjectorSecurityAndImageSubstitution(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	pod, err := BuildWorkloadAdmissionPod(request, "op_test")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, pod, "zot.internal.example/dapr/sidecar@"+workloadAdmissionTestDigest("9"))
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_test", workloadAdmissionTestPolicyObservation(t, request), response, 201, time.Now().UTC()); err == nil {
		t.Fatal("substituted Dapr sidecar image passed product-managed dry-run evidence")
	}

	pod, err = BuildWorkloadAdmissionPod(request, "op_test")
	if err != nil { t.Fatal(err) }
	response = injectTestDaprSidecar(t, pod, request.ExpectedSidecarImage)
	spec := response["spec"].(map[string]any)
	containers := spec["containers"].([]any)
	sidecar := containers[len(containers)-1].(map[string]any)
	security := sidecar["securityContext"].(map[string]any)
	security["readOnlyRootFilesystem"] = false
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_test", workloadAdmissionTestPolicyObservation(t, request), response, 201, time.Now().UTC()); err == nil {
		t.Fatal("Dapr sidecar without read-only root filesystem passed workload admission")
	}
}

func TestWorkloadAdmissionRejectsInjectedSidecarResourceSizingDrift(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	pod, err := BuildWorkloadAdmissionPod(request, "op_resource_drift")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, pod, request.ExpectedSidecarImage)
	spec := response["spec"].(map[string]any)
	containers := spec["containers"].([]any)
	sidecar := containers[len(containers)-1].(map[string]any)
	resources := sidecar["resources"].(map[string]any)
	requests := resources["requests"].(map[string]any)
	requests["cpu"] = "250m"
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_resource_drift", workloadAdmissionTestPolicyObservation(t, request), response, 201, time.Now().UTC()); err == nil ||
		!strings.Contains(err.Error(), "RESOURCE_SIZING_INVALID") {
		t.Fatalf("Dapr sidecar resource drift passed workload admission: %v", err)
	}
}

func TestWorkloadAdmissionRejectsDuplicateAppContainerIdentity(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	pod, err := BuildWorkloadAdmissionPod(request, "op_duplicate_app")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, pod, request.ExpectedSidecarImage)
	spec := response["spec"].(map[string]any)
	containers := spec["containers"].([]any)
	containers = append(containers, map[string]any{"name": "app", "image": request.WorkloadImage})
	spec["containers"] = containers
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_duplicate_app", workloadAdmissionTestPolicyObservation(t, request), response, 201, time.Now().UTC()); err == nil ||
		!strings.Contains(err.Error(), "DUPLICATE_APP_CONTAINER") {
		t.Fatalf("duplicate app identity entered Dapr admission evidence: %v", err)
	}
}

func TestWorkloadAdmissionRejectsMissingExplicitPrivilegeEscalationField(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	pod, err := BuildWorkloadAdmissionPod(request, "op_missing_security")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, pod, request.ExpectedSidecarImage)
	spec := response["spec"].(map[string]any)
	containers := spec["containers"].([]any)
	sidecar := containers[len(containers)-1].(map[string]any)
	security := sidecar["securityContext"].(map[string]any)
	delete(security, "allowPrivilegeEscalation")
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_missing_security", workloadAdmissionTestPolicyObservation(t, request), response, 201, time.Now().UTC()); err == nil ||
		!strings.Contains(err.Error(), "SECURITY_FIELDS_MISSING") {
		t.Fatalf("missing explicit allowPrivilegeEscalation=false was treated as proof: %v", err)
	}
}

func TestNativeDaprAdmissionObservesSecurityButNeverClaimsProductImageFence(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "USE_NATIVE")
	pod, err := BuildWorkloadAdmissionPod(request, "op_native")
	if err != nil { t.Fatal(err) }
	nativeImage := "registry.native.example/dapr/daprd:v1.18.4"
	response := injectTestDaprSidecar(t, pod, nativeImage)
	evidence, err := WorkloadAdmissionEvidenceFromDryRun(request, "op_native", workloadAdmissionTestPolicyObservation(t, request), response, 200, time.Now().UTC())
	if err != nil { t.Fatal(err) }
	if evidence.ExpectedSidecarImageMatched || evidence.SidecarImageReference != nativeImage {
		t.Fatalf("native Dapr admission was incorrectly product-image fenced: %#v", evidence)
	}
	raw, err := json.Marshal(evidence)
	if err != nil { t.Fatal(err) }
	if strings.Contains(string(raw), "\"sidecarPullObserved\":true") || strings.Contains(string(raw), "\"physicalCertificationInferred\":true") {
		t.Fatalf("native dry-run evidence overclaimed execution: %s", raw)
	}
}
