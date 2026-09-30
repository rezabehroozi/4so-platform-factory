package targetmodel

import (
	"strings"
	"testing"
)

func TestDaprApplicationRuntimeModelPreserves4SOAuthorityBoundaries(t *testing.T) {
	model := DaprApplicationRuntimeModel()
	if issues := ValidateDaprApplicationRuntimeModel(model); len(issues) != 0 {
		t.Fatalf("Dapr adoption model invalid: %#v", issues)
	}
	if model.Authority != DaprApplicationRuntimeAuthority || model.ReviewedRuntimeVersion != "v1.18.4" {
		t.Fatalf("Dapr review identity drift: %#v", model)
	}
	if model.DefaultEnabled || !model.TargetOnly || model.ManagementPlaneInstall || model.SharedDeploymentEnabled {
		t.Fatalf("Dapr must remain optional target-only sidecar runtime: %#v", model)
	}
	if !model.PostgreSQLSoTPreserved || !model.ProductDurableOpsPreserved || !model.ProductSecretRefsPreserved || model.ImplicitBrokerInstallAllowed {
		t.Fatalf("Dapr must not replace product authorities or install hidden dependencies: %#v", model)
	}
}

func TestDaprInitialProfileExcludesSchedulerPlacementAndDuplicateAuthorities(t *testing.T) {
	model := DaprApplicationRuntimeModel()
	disabled := map[string]bool{}
	for _, service := range model.DisabledTargetServices {
		disabled[service] = true
	}
	for _, service := range []string{"dapr-scheduler", "dapr-placement", "dapr-dashboard"} {
		if !disabled[service] {
			t.Fatalf("unsafe/duplicate Dapr service is not disabled in initial profile: %s", service)
		}
	}
	decisions := map[string]string{}
	for _, decision := range model.FeatureDecisions {
		decisions[decision.Feature] = decision.Decision
	}
	for _, feature := range []string{"service-invocation", "pubsub", "bindings", "resiliency", "observability"} {
		if decisions[feature] != "ALLOW_APPLICATION_RUNTIME" {
			t.Fatalf("safe Dapr feature not admitted for application runtime: %s=%s", feature, decisions[feature])
		}
	}
	for _, feature := range []string{"state-management", "workflows", "jobs", "actors", "distributed-lock", "secrets", "configuration", "cryptography", "conversation"} {
		if decisions[feature] == "ALLOW_APPLICATION_RUNTIME" {
			t.Fatalf("duplicate/complex Dapr feature admitted in initial profile: %s", feature)
		}
	}
}

func TestDaprRuntimeSourcePlanPinsMinimalUpstreamProfile(t *testing.T) {
	plan := DaprRuntimeSourcePlanModel()
	if issues := ValidateDaprRuntimeSourcePlan(plan); len(issues) != 0 {
		t.Fatalf("Dapr source plan invalid: %#v", issues)
	}
	if plan.UpstreamCommit != "6d1c53f430205c0c0f3bc3589ce5a3ec3f6f1647" || plan.UpstreamRef != "v1.18.4" {
		t.Fatalf("Dapr upstream identity drift: %#v", plan)
	}
	overrides := map[string]string{}
	for _, item := range plan.HelmOverrides {
		overrides[item.Path] = item.Value
	}
	for path, want := range map[string]string{
		"global.registry": "ghcr.io/dapr",
		"global.tag": "1.18.4",
		"global.actors.enabled": "false",
		"global.scheduler.enabled": "false",
		"global.mtls.enabled": "true",
		"global.prometheus.enabled": "true",
		"dapr_config.dapr_config_chart_included": "false",
		"dapr_rbac.secretReader.enabled": "false",
		"dapr_sidecar_injector.sidecarDropALLCapabilities": "true",
	} {
		if overrides[path] != want {
			t.Fatalf("required Dapr Helm override %s=%q want %q", path, overrides[path], want)
		}
	}
	roles := map[string]string{}
	for _, image := range plan.RequiredImages {
		roles[image.Role] = image.Repository
	}
	if len(roles) != 4 || roles["sidecar"] != "ghcr.io/dapr/daprd" || roles["operator"] != "ghcr.io/dapr/operator" ||
		roles["injector"] != "ghcr.io/dapr/injector" || roles["sentry"] != "ghcr.io/dapr/sentry" {
		t.Fatalf("Dapr minimal image inventory drift: %#v", roles)
	}
}

func TestDaprRuntimeSourcePlanRejectsUpstreamDefaultsThatReenableDuplicateAuthorities(t *testing.T) {
	plan := DaprRuntimeSourcePlanModel()
	for i := range plan.HelmOverrides {
		if plan.HelmOverrides[i].Path == "global.scheduler.enabled" {
			plan.HelmOverrides[i].Value = "true"
		}
	}
	if issues := ValidateDaprRuntimeSourcePlan(plan); !contains(issues, "dapr-required-helm-override-missing") {
		t.Fatalf("scheduler re-enable was not rejected: %#v", issues)
	}
	plan = DaprRuntimeSourcePlanModel()
	plan.HelmOverrides = append(plan.HelmOverrides, DaprHelmOverride{Path: "global.scheduler.placement.enabled", Value: "true"})
	if issues := ValidateDaprRuntimeSourcePlan(plan); !contains(issues, "dapr-helm-overrides-not-exact") {
		t.Fatalf("unreviewed Dapr Helm override was accepted: %#v", issues)
	}
	plan = DaprRuntimeSourcePlanModel()
	plan.RequiredImages = append(plan.RequiredImages, DaprRuntimeImageRole{Role: "placement", Repository: "ghcr.io/dapr/placement"})
	if issues := ValidateDaprRuntimeSourcePlan(plan); !contains(issues, "dapr-forbidden-images-invalid") {
		t.Fatalf("placement image entered minimal profile: %#v", issues)
	}
}

func TestDaprWorkloadPlanIsScopedSizedAndAPIAllowListed(t *testing.T) {
	plan, err := ResolveDaprWorkloadRuntimePlan(DaprWorkloadPlanInput{
		Namespace: "payments", AppID: "payments-api", AppPort: 8080, AppProtocol: "http",
		CPURequest: "100m", CPULimit: "500m", MemoryRequest: "128Mi", MemoryLimit: "256Mi",
		ComponentNames: []string{"orders-broker", "billing-binding"},
		EnableInvocation: true, EnablePubSub: true, EnableBindings: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Authority != DaprWorkloadRuntimePlanAuthority || plan.ConfigurationName != "4so-dapr-payments-api" ||
		!plan.ConfigurationDerived || plan.ConfigurationBecomesSoT || plan.ServiceInvocationDefault != "DENY" ||
		plan.CrossNamespaceInvocation || plan.SecretMaterialEmbedded || !plan.DeploymentDryRunRequired ||
		plan.SidecarSecurityCompatibilityInferred || plan.PhysicalCertificationInferred {
		t.Fatalf("Dapr workload authority drift: %#v", plan)
	}
	annotations := map[string]string{}
	for _, item := range plan.Annotations { annotations[item.Key] = item.Value }
	for key, want := range map[string]string{
		"dapr.io/enabled": "true", "dapr.io/app-id": "payments-api", "dapr.io/config": "4so-dapr-payments-api",
		"dapr.io/app-port": "8080", "dapr.io/disable-builtin-k8s-secret-store": "true",
		"dapr.io/sidecar-cpu-request": "100m", "dapr.io/sidecar-cpu-limit": "500m",
		"dapr.io/sidecar-memory-request": "128Mi", "dapr.io/sidecar-memory-limit": "256Mi",
	} {
		if annotations[key] != want { t.Fatalf("Dapr annotation %s=%q want %q", key, annotations[key], want) }
	}
	rules := map[string]bool{}
	for _, rule := range plan.AllowedAPIs { rules[rule.Protocol+"/"+rule.Version+"/"+rule.Name] = true }
	for _, key := range []string{
		"http/v1/invoke", "grpc/v1/invoke", "http/v1/publish", "grpc/v1/publish", "http/v1/bindings", "grpc/v1/bindings",
	} {
		if !rules[key] { t.Fatalf("required Dapr API rule missing: %s rules=%#v", key, rules) }
	}
	for _, scope := range plan.ComponentScopes {
		if len(scope.Scopes) != 1 || scope.Scopes[0] != "payments-api" {
			t.Fatalf("Dapr component escaped app scope: %#v", scope)
		}
	}
}

func TestDaprWorkloadPlanRejectsUnsizedDuplicateOrOverlongIdentity(t *testing.T) {
	base := DaprWorkloadPlanInput{
		Namespace: "apps", AppID: "api", CPURequest: "100m", CPULimit: "500m",
		MemoryRequest: "128Mi", MemoryLimit: "256Mi", EnableInvocation: true,
	}
	unsized := base; unsized.MemoryLimit = ""
	if _, err := ResolveDaprWorkloadRuntimePlan(unsized); err == nil || err.Error() != "DAPR_WORKLOAD_RESOURCE_SIZING_INVALID" {
		t.Fatalf("unsized Dapr sidecar accepted: %v", err)
	}
	duplicate := base; duplicate.ComponentNames = []string{"Broker", "broker"}
	if _, err := ResolveDaprWorkloadRuntimePlan(duplicate); err == nil || err.Error() != "DAPR_COMPONENT_SCOPE_INVALID" {
		t.Fatalf("duplicate Dapr component scope accepted: %v", err)
	}
	long := base; long.AppID = strings.Repeat("a", 55)
	if _, err := ResolveDaprWorkloadRuntimePlan(long); err == nil || err.Error() != "DAPR_WORKLOAD_IDENTITY_INVALID" {
		t.Fatalf("overlong Dapr derived configuration identity accepted: %v", err)
	}
	unused := base; unused.ComponentNames = []string{"orders-broker"}
	if _, err := ResolveDaprWorkloadRuntimePlan(unused); err == nil || err.Error() != "DAPR_COMPONENT_PROFILE_UNUSED" {
		t.Fatalf("Dapr Component without pubsub/bindings API profile accepted: %v", err)
	}
	missing := base; missing.EnablePubSub = true
	if _, err := ResolveDaprWorkloadRuntimePlan(missing); err == nil || err.Error() != "DAPR_COMPONENT_SCOPE_REQUIRED" {
		t.Fatalf("Dapr pubsub profile without scoped Component accepted: %v", err)
	}
}

func validDaprSupplyChainLock() DaprRuntimeSupplyChainLock {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	plan := DaprRuntimeSourcePlanModel()
	locks := make([]DaprRuntimeImageLock, 0, len(plan.RequiredImages))
	chars := []string{"a", "b", "c", "d"}
	for i, image := range plan.RequiredImages {
		d := digest(chars[i])
		locks = append(locks, DaprRuntimeImageLock{
			Role: image.Role, SourceRepository: image.Repository, SourceDigest: d,
			MirrorReference: "zot.internal.example/dapr/" + image.Role + "@" + d,
			MirrorDigest: d,
		})
	}
	return DaprRuntimeSupplyChainLock{
		Authority: DaprRuntimeSupplyChainAuthority, SourcePlanAuthority: plan.Authority,
		Version: plan.Version, UpstreamRepository: plan.UpstreamRepository, UpstreamRef: plan.UpstreamRef,
		UpstreamCommit: plan.UpstreamCommit, SourceArchiveDigest: digest("e"), HelmChartDigest: digest("f"),
		HelmPackageDigest: digest("0"), HelmRenderDigest: digest("1"),
		HelmMirrorReference: "zot.internal.example/dapr-charts/dapr@" + digest("4"), HelmMirrorManifestDigest: digest("4"),
		AcquisitionReceiptDigest: digest("2"), MirrorEvidenceDigest: digest("3"),
		ExecutorEvidenceDigest: digest("5"), ExecutorSourceReleaseDigest: digest("7"), ExecutorImageDigest: digest("6"),
		ExecutorImageReference: "zot.internal.example/4so/dapr-runtime@" + digest("6"),
		RegistryAuthority: "zot", RegistryScheme: "https", MirrorRegistry: "zot.internal.example",
		ImageLocks: locks, ZotMirrorVerified: true, OfflineReplayReady: true, Admitted: true,
	}
}

func TestDaprSupplyChainLockRequiresExactFourImageMirrorSet(t *testing.T) {
	lock := validDaprSupplyChainLock()
	if issues := ValidateDaprRuntimeSupplyChainLock(lock); len(issues) != 0 || !DaprRuntimeSupplyChainAdmitted(lock) {
		t.Fatalf("valid Dapr supply-chain lock rejected: %#v", issues)
	}
	lock = validDaprSupplyChainLock()
	lock.ImageLocks = lock.ImageLocks[:3]
	lock.Admitted = false
	if issues := ValidateDaprRuntimeSupplyChainLock(lock); !contains(issues, "dapr-supply-chain-image-set-incomplete") {
		t.Fatalf("incomplete Dapr image set accepted: %#v", issues)
	}
	lock = validDaprSupplyChainLock()
	lock.ImageLocks[0].MirrorDigest = "sha256:" + strings.Repeat("9", 64)
	lock.Admitted = false
	if issues := ValidateDaprRuntimeSupplyChainLock(lock); !contains(issues, "dapr-supply-chain-image-digest-invalid") {
		t.Fatalf("source/mirror digest substitution accepted: %#v", issues)
	}
}

func TestDaprSupplyChainLockRejectsMirrorRegistrySelfInconsistency(t *testing.T) {
	lock := validDaprSupplyChainLock()
	lock.ImageLocks[0].MirrorReference = strings.Replace(lock.ImageLocks[0].MirrorReference, "zot.internal.example", "other.example", 1)
	lock.Admitted = false
	if issues := ValidateDaprRuntimeSupplyChainLock(lock); !contains(issues, "dapr-supply-chain-mirror-reference-invalid") {
		t.Fatalf("Dapr mirror escaped declared zot registry: %#v", issues)
	}
	lock = validDaprSupplyChainLock()
	lock.ImageLocks[0].MirrorReference = lock.ImageLocks[0].MirrorReference + ".tampered"
	lock.Admitted = false
	if issues := ValidateDaprRuntimeSupplyChainLock(lock); !contains(issues, "dapr-supply-chain-mirror-reference-invalid") {
		t.Fatalf("Dapr mirror reference suffix tampering accepted: %#v", issues)
	}
	lock = validDaprSupplyChainLock()
	lock.RegistryScheme = "ftp"
	lock.Admitted = false
	if issues := ValidateDaprRuntimeSupplyChainLock(lock); !contains(issues, "dapr-supply-chain-registry-authority-invalid") {
		t.Fatalf("unsupported Dapr registry scheme accepted: %#v", issues)
	}
	lock = validDaprSupplyChainLock()
	lock.RegistryAuthority = "docker"
	lock.Admitted = false
	if issues := ValidateDaprRuntimeSupplyChainLock(lock); !contains(issues, "dapr-supply-chain-registry-authority-invalid") {
		t.Fatalf("non-zot Dapr registry authority accepted: %#v", issues)
	}
}

func TestDaprSupplyChainLockRejectsForbiddenSchedulerImage(t *testing.T) {
	lock := validDaprSupplyChainLock()
	d := "sha256:" + strings.Repeat("7", 64)
	lock.ImageLocks = append(lock.ImageLocks, DaprRuntimeImageLock{
		Role: "scheduler", SourceRepository: "ghcr.io/dapr/scheduler", SourceDigest: d,
		MirrorReference: "zot.internal.example/dapr/scheduler@" + d, MirrorDigest: d,
	})
	lock.Admitted = false
	if issues := ValidateDaprRuntimeSupplyChainLock(lock); !contains(issues, "dapr-supply-chain-image-identity-invalid") {
		t.Fatalf("scheduler image entered initial Dapr lock: %#v", issues)
	}
}

func TestDaprTargetAdmissionSuppressesDuplicateNativeRuntime(t *testing.T) {
	out := EvaluateDaprTargetAdmission(DaprTargetAdmissionInput{
		DistributionIdentity: "okd", TargetAdmitted: true, TargetMutationReady: true,
		CapabilityDiscoveryComplete: true, DurableLifecycleReady: true,
		ObservedCapabilities: []string{
			DaprApplicationRuntimeCapability,
		},
	})
	if !out.Eligible || out.Mode != "USE_NATIVE" || !out.InstallSuppressed || len(out.Blockers) != 0 {
		t.Fatalf("native Dapr capability must suppress duplicate install without source acquisition: %#v", out)
	}
	if out.PhysicalCertificationInferred {
		t.Fatal("Dapr target assessment must never infer Physical certification")
	}
}

func TestDaprTargetAdmissionFailsClosedUntilInstallProfileIsActuallyReady(t *testing.T) {
	out := EvaluateDaprTargetAdmission(DaprTargetAdmissionInput{
		DistributionIdentity: "rke2", TargetAdmitted: true, TargetMutationReady: true, ExecutorRBACReady: true,
		CapabilityDiscoveryComplete: true, DurableLifecycleReady: true,
	})
	if out.Eligible || out.Mode != "INSTALL_REQUIRED" || out.InstallSuppressed {
		t.Fatalf("unadmitted Dapr install was treated as eligible: %#v", out)
	}
	want := map[string]bool{
		"DAPR_EXACT_SOURCE_AUTHORITY_PENDING": true,
	}
	for _, blocker := range out.Blockers {
		delete(want, blocker)
	}
	if len(want) != 0 {
		t.Fatalf("Dapr admission blockers incomplete: missing=%v out=%#v", want, out)
	}
}

func TestDaprDisconnectedInstallRequiresProductMirrorAndDefersTargetPullProofToExecution(t *testing.T) {
	base := DaprTargetAdmissionInput{
		DistributionIdentity: "okd", TargetAdmitted: true, TargetMutationReady: true, ExecutorRBACReady: true,
		CapabilityDiscoveryComplete: true, DurableLifecycleReady: true, Disconnected: true,
		ObservedCapabilities: []string{"application-runtime.dapr-mirror-pull-ready"},
		ExactSourceAdmitted: true,
	}
	blocked := EvaluateDaprTargetAdmission(base)
	if blocked.Eligible || !contains(blocked.Blockers, "DAPR_DISCONNECTED_MIRROR_PENDING") ||
		!blocked.TargetMirrorPullEvidenceRequired || !blocked.WorkloadSidecarAdmissionIndependent {
		t.Fatalf("disconnected Dapr install bypassed product mirror admission or lost execution-evidence contract: %#v", blocked)
	}
	for _, blocker := range blocked.Blockers {
		if strings.Contains(blocker, "MIRROR_PULL_CAPABILITY") {
			t.Fatalf("self-asserted target capability was treated as mirror-pull evidence: %#v", blocked)
		}
	}
	base.DisconnectedProductMirrorAdmitted = true
	admitted := EvaluateDaprTargetAdmission(base)
	if !admitted.Eligible || !admitted.TargetMirrorPullEvidenceRequired {
		t.Fatalf("disconnected install did not defer target pull proof to executor readback: %#v", admitted)
	}
	base.ObservedCapabilities = append(base.ObservedCapabilities, DaprApplicationRuntimeCapability)
	native := EvaluateDaprTargetAdmission(base)
	if !native.Eligible || native.Mode != "USE_NATIVE" || native.TargetMirrorPullEvidenceRequired {
		t.Fatalf("already-native Dapr capability incorrectly entered product mirror execution proof: %#v", native)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want { return true }
	}
	return false
}

func TestDaprInitialProfileIsFailClosedForCrossNamespaceAndAPIAccess(t *testing.T) {
	model := DaprApplicationRuntimeModel()
	if !model.MTLSRequired || !model.APIAllowListRequired || !model.ServiceInvocationDefaultDeny || !model.NamespaceAndAppScopesRequired {
		t.Fatalf("Dapr security baseline weakened: %#v", model)
	}
	if model.CrossNamespaceInvocationDefault {
		t.Fatal("cross-namespace Dapr invocation must be opt-in, not default")
	}
}
