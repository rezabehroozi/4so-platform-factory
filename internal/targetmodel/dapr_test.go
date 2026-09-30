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

func TestDaprInitialProfileIsFailClosedForCrossNamespaceAndAPIAccess(t *testing.T) {
	model := DaprApplicationRuntimeModel()
	if !model.MTLSRequired || !model.APIAllowListRequired || !model.ServiceInvocationDefaultDeny || !model.NamespaceAndAppScopesRequired {
		t.Fatalf("Dapr security baseline weakened: %#v", model)
	}
	if model.CrossNamespaceInvocationDefault {
		t.Fatal("cross-namespace Dapr invocation must be opt-in, not default")
	}
}
