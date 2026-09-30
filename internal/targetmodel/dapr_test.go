package targetmodel

import "testing"

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
