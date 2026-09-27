package catalog

import "testing"

func TestComponentRuntimeCertificationRegistryMatchesCatalog(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := LoadComponentRuntimeCertificationRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateComponentRuntimeCertificationRegistry(registry, components); err != nil {
		t.Fatal(err)
	}
	stats := ComponentRuntimeCertificationStatistics(registry)
	resolved := 0
	for _, component := range components {
		if component.Spec.Source.Resolved {
			resolved++
		}
	}
	heldResolved := 0
	for _, hold := range registry.Spec.RuntimeSuitabilityHolds {
		if component, ok := components[hold.Component]; ok && component.Spec.Source.Resolved {
			heldResolved++
		}
	}
	expectedExecutablePartial := resolved - 1 - heldResolved // foundation and held sources are intentionally not executable.
	if stats.Total != len(components) || stats.SourceReady != resolved || stats.SourceBlocked != len(components)-resolved || stats.FoundationHarnessPartial != 1 || stats.ComponentInstallReadinessPartial != 0 || stats.ComponentInstallReadinessDependencyPartial != 0 || stats.ComponentFailureRemovePartial != expectedExecutablePartial || stats.SourceGatedExecutor != len(components)-resolved || stats.PendingExecutor != 0 || stats.LifecycleComplete != 0 {
		t.Fatalf("unexpected component runtime registry stats: %#v resolved=%d heldResolved=%d total=%d", stats, resolved, heldResolved, len(components))
	}
}

func TestComponentRuntimeCertificationRegistryRejectsSourceDrift(t *testing.T) {
	components, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := LoadComponentRuntimeCertificationRegistry()
	if err != nil {
		t.Fatal(err)
	}
	mutated := false
	for i := range registry.Spec.Components {
		if registry.Spec.Components[i].SourceBinding.Resolved {
			registry.Spec.Components[i].SourceBinding.SourceLockDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			mutated = true
			break
		}
	}
	if !mutated {
		t.Fatal("registry fixture has no resolved source to exercise drift rejection")
	}
	if err := ValidateComponentRuntimeCertificationRegistry(registry, components); err == nil {
		t.Fatal("expected source binding drift rejection")
	}
}

func TestRebindComponentRuntimeCertificationSourceIsOneWay(t *testing.T) {
	registry := ComponentRuntimeCertificationRegistry{}
	registry.Spec.Components = []ComponentRuntimeCertificationContract{{
		Component: "fixture-component",
		Release:   "1.2.x",
		SourceBinding: ComponentRuntimeSourceBinding{
			Status: "blocked-source-lock",
		},
	}}
	component := Component{}
	component.Metadata.Name = "fixture-component"
	component.Spec.Release = "1.2.3"
	component.Spec.Source.Resolved = true
	component.Spec.Source.SourceLockDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := RebindComponentRuntimeCertificationSource(&registry, component); err != nil {
		t.Fatal(err)
	}
	if err := RebindComponentRuntimeCertificationSource(&registry, component); err != nil {
		t.Fatalf("idempotent rebind rejected: %v", err)
	}
	component.Spec.Source.SourceLockDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := RebindComponentRuntimeCertificationSource(&registry, component); err == nil {
		t.Fatal("resolved source replacement must be rejected")
	}
}

func TestRebindComponentRuntimeCertificationSourcePreservesRuntimeSuitabilityHold(t *testing.T) {
	registry := ComponentRuntimeCertificationRegistry{}
	registry.Spec.RuntimeSuitabilityHolds = []ComponentRuntimeSuitabilityHold{{
		Component: "fixture-component",
		Status: "review-required",
		Authority: "COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1",
		Reason: "runtime review remains open",
		EvidenceURL: "https://example.test/runtime-hold",
	}}
	contract := ComponentRuntimeCertificationContract{
		Component: "fixture-component",
		Release: "1.2.3",
		SourceBinding: ComponentRuntimeSourceBinding{Status: "blocked-source-lock"},
		Executor: ComponentRuntimeExecutor{Status: "source-gated-component-executor", Profile: "COMPONENT_RUNTIME_V1", Owner: "catalog-component"},
	}
	for _, name := range RequiredComponentLifecycleStages {
		status, authority := "source-gated-component-executor", "COMPONENT_RUNTIME_V1"
		if name == "upgrade" {
			status, authority = "pending-upgrade-matrix", "COMPONENT_RUNTIME_UPGRADE_V1"
		}
		contract.Lifecycle = append(contract.Lifecycle, ComponentRuntimeLifecycleStage{
			Name: name, Status: status, EvidenceContract: "component-"+name+"-evidence/v1", Authority: authority,
		})
	}
	registry.Spec.Components = []ComponentRuntimeCertificationContract{contract}
	component := Component{}
	component.Metadata.Name = "fixture-component"
	component.Spec.Release = "1.2.3"
	component.Spec.Source.Resolved = true
	component.Spec.Source.SourceLockDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := RebindComponentRuntimeCertificationSource(&registry, component); err != nil {
		t.Fatal(err)
	}
	got := registry.Spec.Components[0]
	if !got.SourceBinding.Resolved || got.Executor.Status != "runtime-suitability-held" {
		t.Fatalf("source rebind bypassed runtime hold: %#v", got)
	}
	for _, stage := range got.Lifecycle {
		if stage.Status != "pending-runtime-suitability" || stage.Authority != "COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1" {
			t.Fatalf("runtime hold leaked executable lifecycle stage: %#v", stage)
		}
	}
}


func TestMigrateComponentRuntimeCertificationSourceRequiresExplicitAuthorityAndExactPreviousBinding(t *testing.T) {
	contract := ComponentRuntimeCertificationContract{
		Component: "gateway-api",
		Release: "1.5.1",
		SourceBinding: ComponentRuntimeSourceBinding{
			Status: "source-ready", Resolved: true,
			SourceLockDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		Executor: ComponentRuntimeExecutor{
			Status: "component-install-readiness-dependency-failure-remove-partial",
			Profile: "COMPONENT_RUNTIME_V1", Owner: "catalog-component",
		},
	}
	for _, name := range RequiredComponentLifecycleStages {
		status, authority := "component-runtime-executable", "COMPONENT_RUNTIME_V1"
		if name == "upgrade" {
			status, authority = "pending-upgrade-matrix", "COMPONENT_RUNTIME_UPGRADE_V1"
		}
		contract.Lifecycle = append(contract.Lifecycle, ComponentRuntimeLifecycleStage{
			Name: name, Status: status, EvidenceContract: "component-"+name+"-evidence/v1", Authority: authority,
		})
	}
	registry := ComponentRuntimeCertificationRegistry{}
	registry.Spec.Components = []ComponentRuntimeCertificationContract{contract}

	previous := Component{}
	previous.Metadata.Name = "gateway-api"
	previous.Spec.Release = "1.5.1"
	previous.Spec.Source.Resolved = true
	previous.Spec.Source.SourceLockDigest = contract.SourceBinding.SourceLockDigest

	target := previous
	target.Spec.Release = "1.6.1"
	target.Spec.Source.SourceLockDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	if err := MigrateComponentRuntimeCertificationSource(&registry, previous, target, ""); err == nil {
		t.Fatal("resolved migration without explicit authority was accepted")
	}
	if err := MigrateComponentRuntimeCertificationSource(&registry, previous, target, "RUNTIME_DEPENDENCY_TRANSITION_V1"); err != nil {
		t.Fatalf("explicit resolved migration failed: %v", err)
	}
	got := registry.Spec.Components[0]
	if got.Release != target.Spec.Release || !got.SourceBinding.Resolved || got.SourceBinding.SourceLockDigest != target.Spec.Source.SourceLockDigest {
		t.Fatalf("registry did not move to exact target: %#v", got)
	}
	if err := MigrateComponentRuntimeCertificationSource(&registry, previous, target, "RUNTIME_DEPENDENCY_TRANSITION_V1"); err == nil {
		t.Fatal("stale previous binding replay was accepted")
	}
}
