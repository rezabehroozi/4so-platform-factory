package daprruntime

import (
	"encoding/json"
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

func injectTestDaprSidecar(t *testing.T, deployment map[string]any, image string) map[string]any {
	t.Helper()
	spec, ok := deployment["spec"].(map[string]any)
	if !ok { t.Fatal("deployment spec missing") }
	template, ok := spec["template"].(map[string]any)
	if !ok { t.Fatal("deployment template missing") }
	podSpec, ok := template["spec"].(map[string]any)
	if !ok { t.Fatal("pod spec missing") }
	containers, ok := podSpec["containers"].([]any)
	if !ok { t.Fatal("containers missing") }
	podSpec["containers"] = append(containers, map[string]any{
		"name": "daprd", "image": image,
		"securityContext": map[string]any{
			"runAsNonRoot": true,
			"readOnlyRootFilesystem": true,
			"allowPrivilegeEscalation": false,
			"capabilities": map[string]any{"drop": []any{"ALL"}},
		},
	})
	return deployment
}

func TestWorkloadAdmissionRequestIsDigestBoundAndRequiresExactImages(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	raw, digest, err := MarshalWorkloadAdmissionRequest(request)
	if err != nil { t.Fatal(err) }
	parsed, err := ParseWorkloadAdmissionRequest(raw, digest)
	if err != nil { t.Fatal(err) }
	if parsed.ProjectID != request.ProjectID || parsed.PlanDigest != request.PlanDigest ||
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
}

func TestWorkloadAdmissionDryRunProvesInjectedSidecarSecurityWithoutPullOrPhysicalClaims(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	deployment, err := BuildWorkloadAdmissionDeployment(request, "op_test")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, deployment, request.ExpectedSidecarImage)
	evidence, err := WorkloadAdmissionEvidenceFromDryRun(request, "op_test", response, 201, time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	if err != nil { t.Fatal(err) }
	if !evidence.InjectedSidecarObserved || !evidence.RunAsNonRoot || !evidence.ReadOnlyRootFilesystem ||
		evidence.AllowPrivilegeEscalation || !evidence.DropAllCapabilities || !evidence.ExpectedSidecarImageMatched ||
		!evidence.AppContainerPreserved || !evidence.AnnotationsVerified || !evidence.ServerSideDryRun || !evidence.StrictFieldValidation {
		t.Fatalf("Dapr workload dry-run evidence missing security proof: %#v", evidence)
	}
	if evidence.SidecarPullObserved || evidence.PhysicalCertificationInferred {
		t.Fatalf("Dapr workload dry-run overclaimed runtime/physical evidence: %#v", evidence)
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

func TestWorkloadAdmissionRejectsInjectorSecurityAndImageSubstitution(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	deployment, err := BuildWorkloadAdmissionDeployment(request, "op_test")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, deployment, "zot.internal.example/dapr/sidecar@"+workloadAdmissionTestDigest("9"))
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_test", response, 201, time.Now().UTC()); err == nil {
		t.Fatal("substituted Dapr sidecar image passed product-managed dry-run evidence")
	}

	deployment, err = BuildWorkloadAdmissionDeployment(request, "op_test")
	if err != nil { t.Fatal(err) }
	response = injectTestDaprSidecar(t, deployment, request.ExpectedSidecarImage)
	spec := response["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	containers := spec["containers"].([]any)
	sidecar := containers[len(containers)-1].(map[string]any)
	security := sidecar["securityContext"].(map[string]any)
	security["readOnlyRootFilesystem"] = false
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_test", response, 201, time.Now().UTC()); err == nil {
		t.Fatal("Dapr sidecar without read-only root filesystem passed workload admission")
	}
}

func TestWorkloadAdmissionRejectsMissingExplicitPrivilegeEscalationField(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "PRODUCT_MANAGED")
	deployment, err := BuildWorkloadAdmissionDeployment(request, "op_missing_security")
	if err != nil { t.Fatal(err) }
	response := injectTestDaprSidecar(t, deployment, request.ExpectedSidecarImage)
	spec := response["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	containers := spec["containers"].([]any)
	sidecar := containers[len(containers)-1].(map[string]any)
	security := sidecar["securityContext"].(map[string]any)
	delete(security, "allowPrivilegeEscalation")
	if _, err = WorkloadAdmissionEvidenceFromDryRun(request, "op_missing_security", response, 201, time.Now().UTC()); err == nil ||
		!strings.Contains(err.Error(), "SECURITY_FIELDS_MISSING") {
		t.Fatalf("missing explicit allowPrivilegeEscalation=false was treated as proof: %v", err)
	}
}

func TestNativeDaprAdmissionObservesSecurityButNeverClaimsProductImageFence(t *testing.T) {
	request := workloadAdmissionTestRequest(t, "USE_NATIVE")
	deployment, err := BuildWorkloadAdmissionDeployment(request, "op_native")
	if err != nil { t.Fatal(err) }
	nativeImage := "registry.native.example/dapr/daprd:v1.18.4"
	response := injectTestDaprSidecar(t, deployment, nativeImage)
	evidence, err := WorkloadAdmissionEvidenceFromDryRun(request, "op_native", response, 200, time.Now().UTC())
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
