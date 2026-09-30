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
		"global.actors.enabled": "false",
		"global.scheduler.enabled": "false",
		"global.mtls.enabled": "true",
		"dapr_config.dapr_config_chart_included": "false",
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
	plan.RequiredImages = append(plan.RequiredImages, DaprRuntimeImageRole{Role: "placement", Repository: "ghcr.io/dapr/placement"})
	if issues := ValidateDaprRuntimeSourcePlan(plan); !contains(issues, "dapr-forbidden-images-invalid") {
		t.Fatalf("placement image entered minimal profile: %#v", issues)
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
			DaprSidecarSecurityCapability,
			DaprComponentScopeCapability,
			DaprResourceSizingCapability,
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
		DistributionIdentity: "rke2", TargetAdmitted: true, TargetMutationReady: true,
		CapabilityDiscoveryComplete: true, DurableLifecycleReady: true,
	})
	if out.Eligible || out.Mode != "INSTALL_REQUIRED" || out.InstallSuppressed {
		t.Fatalf("unadmitted Dapr install was treated as eligible: %#v", out)
	}
	want := map[string]bool{
		"DAPR_EXACT_SOURCE_AUTHORITY_PENDING": true,
		"DAPR_SIDECAR_SECURITY_COMPATIBILITY_PENDING": true,
		"DAPR_COMPONENT_SCOPE_ENFORCEMENT_PENDING": true,
		"DAPR_RESOURCE_SIZING_PENDING": true,
	}
	for _, blocker := range out.Blockers {
		delete(want, blocker)
	}
	if len(want) != 0 {
		t.Fatalf("Dapr admission blockers incomplete: missing=%v out=%#v", want, out)
	}
}

func TestDaprDisconnectedInstallRequiresMirrorButNativeRuntimeDoesNot(t *testing.T) {
	base := DaprTargetAdmissionInput{
		DistributionIdentity: "okd", TargetAdmitted: true, TargetMutationReady: true,
		CapabilityDiscoveryComplete: true, DurableLifecycleReady: true, Disconnected: true,
		ObservedCapabilities: []string{DaprSidecarSecurityCapability, DaprComponentScopeCapability, DaprResourceSizingCapability},
		ExactSourceAdmitted: true,
	}
	blocked := EvaluateDaprTargetAdmission(base)
	if blocked.Eligible || !contains(blocked.Blockers, "DAPR_DISCONNECTED_MIRROR_PENDING") {
		t.Fatalf("disconnected Dapr install bypassed mirror admission: %#v", blocked)
	}
	base.ObservedCapabilities = append(base.ObservedCapabilities, DaprApplicationRuntimeCapability)
	native := EvaluateDaprTargetAdmission(base)
	if !native.Eligible || native.Mode != "USE_NATIVE" {
		t.Fatalf("already-native Dapr capability incorrectly required product mirror: %#v", native)
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
