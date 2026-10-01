package controlplane

import (
	"strings"
	"testing"
	"time"
)

func applicationDeploymentFixture(t *testing.T) (ApplicationRelease, EnvironmentBinding, WorkspaceBinding, ApplicationRuntimeSpec) {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	release, err := NormalizeApplicationRelease(ApplicationRelease{
		ProjectID: "prj-1", Name: "payments.api", Version: "1.2.3",
		WorkloadTypeDigest: digest("a"), TraitDigests: []string{digest("b")},
		ManagedResourceDigests: []string{digest("c")}, WorkspaceProfileDigest: digest("d"),
		WorkloadImageReference: "zot.internal.example/apps/payments@" + digest("e"),
		SourceDigest: digest("f"),
	})
	if err != nil { t.Fatal(err) }
	release.ResourceMeta = ResourceMeta{ID: "arl-1", Revision: 1}
	workspaceBinding := WorkspaceBinding{
		ResourceMeta: ResourceMeta{ID: "wsb-1", Revision: 7},
		WorkspaceID: "ws-1", ProjectID: "prj-1", ClusterID: "clu-1", Namespace: "payments",
		State: WorkspaceBindingActive,
	}
	workspaceBinding, err = NormalizeWorkspaceBinding(workspaceBinding)
	if err != nil { t.Fatal(err) }
	binding, err := NormalizeEnvironmentBinding(EnvironmentBinding{
		ResourceMeta: ResourceMeta{ID: "aeb-1", Revision: 3},
		ProjectID: "prj-1", ReleaseID: release.ID, ReleaseDigest: release.Digest,
		WorkspaceID: workspaceBinding.WorkspaceID, WorkspaceBindingID: workspaceBinding.ID,
		WorkspaceBindingRevision: workspaceBinding.Revision, ClusterID: workspaceBinding.ClusterID,
		Namespace: workspaceBinding.Namespace, Environment: "production",
		CapabilityResolutionDigest: digest("9"),
	})
	if err != nil { t.Fatal(err) }
	binding.ResourceMeta = ResourceMeta{ID: "aeb-1", Revision: 3}
	runtime := ApplicationRuntimeSpec{
		Replicas: 3, ContainerPort: 8080, ServicePort: 443,
		CPURequest: "250m", CPULimit: "1000m", MemoryRequest: "256Mi", MemoryLimit: "1Gi",
	}
	return release, binding, workspaceBinding, runtime
}

func TestApplicationDeploymentPlanBindsDesiredAuthorityToDeterministicRuntime(t *testing.T) {
	release, binding, workspaceBinding, runtime := applicationDeploymentFixture(t)
	first, err := ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, runtime)
	if err != nil { t.Fatal(err) }
	second, err := ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, runtime)
	if err != nil { t.Fatal(err) }
	if first.Authority != ApplicationDeploymentPlanAuthority || first.RenderedDigest == "" ||
		first.RenderedDigest != second.RenderedDigest || first.RuntimeSpecDigest != second.RuntimeSpecDigest ||
		first.WorkloadName != "payments-api" || len(first.RenderedResources) != 2 ||
		first.RuntimeMutationPerformed || first.PhysicalCertificationInferred {
		t.Fatalf("application deployment plan drift: first=%#v second=%#v", first, second)
	}
	deployment := first.RenderedResources[0]
	spec := deployment["spec"].(map[string]any)
	template := spec["template"].(map[string]any)
	podSpec := template["spec"].(map[string]any)
	containers := podSpec["containers"].([]any)
	container := containers[0].(map[string]any)
	if container["image"] != release.WorkloadImageReference || podSpec["automountServiceAccountToken"] != false {
		t.Fatalf("rendered workload lost exact image or no-token default: %#v", deployment)
	}
}

func TestApplicationDeploymentPlanRejectsLegacyAndStaleAuthority(t *testing.T) {
	release, binding, workspaceBinding, runtime := applicationDeploymentFixture(t)

	legacy := release
	legacy.WorkloadImageReference = ""
	legacy, err := NormalizeApplicationRelease(legacy)
	if err != nil { t.Fatal(err) }
	legacy.ResourceMeta = release.ResourceMeta
	legacyBinding := binding
	legacyBinding.ReleaseDigest = legacy.Digest
	legacyBinding, err = NormalizeEnvironmentBinding(legacyBinding)
	if err != nil { t.Fatal(err) }
	legacyBinding.ResourceMeta = binding.ResourceMeta
	if _, err = ResolveApplicationDeploymentPlan(legacy, legacyBinding, workspaceBinding, runtime); err == nil ||
		!strings.Contains(err.Error(), "no exact workload artifact") {
		t.Fatalf("legacy application release entered deployment plan: %v", err)
	}

	staleBinding := workspaceBinding
	staleBinding.Revision++
	if _, err = ResolveApplicationDeploymentPlan(release, binding, staleBinding, runtime); err == nil ||
		!strings.Contains(err.Error(), "WorkspaceBinding authority changed") {
		t.Fatalf("stale WorkspaceBinding entered deployment plan: %v", err)
	}

	foreignRelease := release
	foreignRelease.ProjectID = "prj-2"
	if _, err = ResolveApplicationDeploymentPlan(foreignRelease, binding, workspaceBinding, runtime); err == nil {
		t.Fatal("cross-project release entered deployment plan")
	}
}

func TestApplicationDeploymentPlanRejectsUnsafeRuntimeShape(t *testing.T) {
	release, binding, workspaceBinding, runtime := applicationDeploymentFixture(t)
	bad := runtime
	bad.Replicas = 0
	if _, err := ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, bad); err == nil {
		t.Fatal("zero replicas entered application deployment plan")
	}
	bad = runtime
	bad.CPURequest = "0m"
	if _, err := ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, bad); err == nil {
		t.Fatal("zero CPU request entered application deployment plan")
	}
	bad = runtime
	bad.MemoryLimit = "1Ti"
	if _, err := ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, bad); err == nil {
		t.Fatal("unsupported memory quantity entered application deployment plan")
	}
	bad = runtime
	bad.ServicePort = 70000
	if _, err := ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, bad); err == nil {
		t.Fatal("invalid service port entered application deployment plan")
	}
}

func TestApplicationDeploymentRequestSealsPlanAndInventoryAuthority(t *testing.T) {
	release, binding, workspaceBinding, runtime := applicationDeploymentFixture(t)
	plan, err := ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, runtime)
	if err != nil { t.Fatal(err) }
	request := ApplicationDeploymentRequest{
		Authority: ApplicationDeploymentRequestAuthority,
		InventoryDigest: appDigest('8'),
		Plan: plan,
	}
	raw, digest, err := MarshalApplicationDeploymentRequest(request)
	if err != nil { t.Fatal(err) }
	parsed, err := ParseApplicationDeploymentRequest(raw, digest)
	if err != nil { t.Fatal(err) }
	if parsed.Plan.RenderedDigest != plan.RenderedDigest || parsed.InventoryDigest != request.InventoryDigest {
		t.Fatalf("application deployment request lost authority: %#v", parsed)
	}

	tampered := request
	tampered.Plan.RenderedResources[0]["metadata"].(map[string]any)["namespace"] = "foreign"
	if _, _, err = MarshalApplicationDeploymentRequest(tampered); err == nil {
		t.Fatal("tampered rendered deployment entered sealed application deployment request")
	}
}

func TestApplicationDeploymentEvidenceRequiresObservedConvergenceAndExactArtifact(t *testing.T) {
	release, binding, workspaceBinding, runtime := applicationDeploymentFixture(t)
	plan, err := ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, runtime)
	if err != nil { t.Fatal(err) }
	request := ApplicationDeploymentRequest{
		Authority: ApplicationDeploymentRequestAuthority,
		InventoryDigest: appDigest('8'),
		Plan: plan,
	}
	evidence := ApplicationDeploymentEvidence{
		Authority: ApplicationDeploymentEvidenceAuthority,
		OperationID: "op_app_deploy",
		ProjectID: plan.ProjectID,
		ClusterID: plan.ClusterID,
		Namespace: plan.Namespace,
		EnvironmentBindingID: plan.EnvironmentBindingID,
		EnvironmentBindingRevision: plan.EnvironmentBindingRevision,
		ReleaseDigest: plan.ReleaseDigest,
		InventoryDigest: request.InventoryDigest,
		RenderedDigest: plan.RenderedDigest,
		Readback: ApplicationDeploymentReadback{
			DeploymentName: plan.WorkloadName,
			DeploymentUID: "uid-deploy-1",
			Generation: 4,
			ObservedGeneration: 4,
			DesiredReplicas: runtime.Replicas,
			UpdatedReplicas: runtime.Replicas,
			ReadyReplicas: runtime.Replicas,
			AvailableReplicas: runtime.Replicas,
			WorkloadImage: plan.WorkloadImageReference,
			CPURequest: runtime.CPURequest,
			CPULimit: runtime.CPULimit,
			MemoryRequest: runtime.MemoryRequest,
			MemoryLimit: runtime.MemoryLimit,
			PodTemplateAuthorityMatch: true,
			ReadinessProbeMatch: true,
			AutomountServiceAccountTokenDisabled: true,
			ServiceObserved: true,
			ServiceSelectorMatch: true,
			ServiceName: plan.WorkloadName,
			ServiceClusterIP: "10.96.0.25",
			ServicePort: runtime.ServicePort,
			ServiceTargetPort: runtime.ContainerPort,
			AuthorityLabelsMatch: true,
			AuthorityDigestsMatch: true,
		},
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		RuntimeMutationObserved: true,
		PhysicalCertificationInferred: false,
	}
	digest, err := ApplicationDeploymentEvidenceDigest(evidence, request, evidence.OperationID)
	if err != nil || !applicationPlatformDigestPattern.MatchString(digest) {
		t.Fatalf("valid application deployment evidence rejected: digest=%q err=%v", digest, err)
	}
	bad := evidence
	bad.Readback.WorkloadImage = "zot.internal.example/apps/payments@" + appDigest('0')
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("foreign workload image passed deployment evidence validation")
	}
	bad = evidence
	bad.Readback.ReadyReplicas--
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("under-ready application deployment passed terminal evidence validation")
	}
	bad = evidence
	bad.Readback.UpdatedReplicas--
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("application deployment with old ReplicaSet pods still serving passed terminal evidence validation")
	}
	bad = evidence
	bad.Readback.AvailableReplicas--
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("under-available application deployment passed terminal evidence validation")
	}
	bad = evidence
	bad.Readback.ReadinessProbeMatch = false
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("application deployment without approved readiness contract passed terminal evidence validation")
	}
	bad = evidence
	bad.Readback.PodTemplateAuthorityMatch = false
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("application deployment with pod-template authority drift passed terminal evidence validation")
	}
	bad = evidence
	bad.Readback.AutomountServiceAccountTokenDisabled = false
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("application deployment regained default ServiceAccount token mounting")
	}
	bad = evidence
	bad.Readback.ServiceSelectorMatch = false
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("application Service selector drift passed terminal evidence validation")
	}
	bad = evidence
	bad.PhysicalCertificationInferred = true
	if err = ValidateApplicationDeploymentEvidence(bad, request, evidence.OperationID); err == nil {
		t.Fatal("application deployment evidence overclaimed Physical certification")
	}
}
