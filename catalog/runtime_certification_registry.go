package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const ComponentRuntimeCertificationAuthority = "COMPONENT_RUNTIME_CERTIFICATION_REGISTRY_V1"

var RequiredComponentLifecycleStages = []string{"install", "readiness", "dependency", "upgrade", "remove", "failure"}

type ComponentRuntimeSourceBinding struct {
	Status           string `json:"status"`
	Resolved         bool   `json:"resolved"`
	SourceLockDigest string `json:"sourceLockDigest"`
}

type ComponentRuntimeSuitabilityHold struct {
	Component   string `json:"component"`
	Status      string `json:"status"`
	Authority   string `json:"authority"`
	Reason      string `json:"reason"`
	EvidenceURL string `json:"evidenceURL"`
}

type ComponentRuntimeExecutor struct {
	Status  string `json:"status"`
	Profile string `json:"profile"`
	Owner   string `json:"owner"`
}

type ComponentRuntimeLifecycleStage struct {
	Name             string `json:"name"`
	Status           string `json:"status"`
	EvidenceContract string `json:"evidenceContract"`
	Authority        string `json:"authority"`
}

type ComponentRuntimeCertificationContract struct {
	Component     string                           `json:"component"`
	Release       string                           `json:"release"`
	SourceBinding ComponentRuntimeSourceBinding    `json:"sourceBinding"`
	Executor      ComponentRuntimeExecutor         `json:"executor"`
	Lifecycle     []ComponentRuntimeLifecycleStage `json:"lifecycle"`
}

type ComponentRuntimeCertificationRegistry struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Policy struct {
			SourceBinding           string   `json:"sourceBinding"`
			ExecutorBinding         string   `json:"executorBinding"`
			RequiredLifecycleStages []string `json:"requiredLifecycleStages"`
			ReplacementPolicy       string   `json:"replacementPolicy"`
			RuntimeSuitabilityBinding string `json:"runtimeSuitabilityBinding"`
		} `json:"policy"`
		RuntimeSuitabilityHolds []ComponentRuntimeSuitabilityHold         `json:"runtimeSuitabilityHolds"`
		Components              []ComponentRuntimeCertificationContract   `json:"components"`
	} `json:"spec"`
}

type ComponentRuntimeCertificationStats struct {
	Total                                      int `json:"total"`
	SourceReady                                int `json:"sourceReady"`
	SourceBlocked                              int `json:"sourceBlocked"`
	FoundationHarnessPartial                   int `json:"foundationHarnessPartial"`
	ComponentInstallReadinessPartial           int `json:"componentInstallReadinessPartial"`
	ComponentInstallReadinessDependencyPartial int `json:"componentInstallReadinessDependencyPartial"`
	ComponentFailureRemovePartial              int `json:"componentFailureRemovePartial"`
	SourceGatedExecutor                        int `json:"sourceGatedExecutor"`
	PendingExecutor                            int `json:"pendingExecutor"`
	LifecycleComplete                          int `json:"lifecycleComplete"`
}

func LoadComponentRuntimeCertificationRegistry() (ComponentRuntimeCertificationRegistry, error) {
	raw, err := catalogFiles.ReadFile("component-runtime-certification.json")
	if err != nil {
		return ComponentRuntimeCertificationRegistry{}, err
	}
	var registry ComponentRuntimeCertificationRegistry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&registry); err != nil {
		return ComponentRuntimeCertificationRegistry{}, fmt.Errorf("parse component runtime certification registry: %w", err)
	}
	return registry, nil
}

func ValidateComponentRuntimeCertificationRegistry(registry ComponentRuntimeCertificationRegistry, components map[string]Component) error {
	if registry.APIVersion != "platform.4so.io/v1alpha1" || registry.Kind != "ComponentRuntimeCertificationRegistry" || registry.Metadata.Name != ComponentRuntimeCertificationAuthority {
		return fmt.Errorf("component runtime certification registry identity invalid")
	}
	if registry.Spec.Policy.SourceBinding != "exact-component-release-and-source-lock" ||
		registry.Spec.Policy.ExecutorBinding != "component-owned-no-generic-runtime-certification-claim" ||
		registry.Spec.Policy.ReplacementPolicy != "resolved-source-replacement-denied-without-explicit-versioned-migration" ||
		registry.Spec.Policy.RuntimeSuitabilityBinding != "persistent-independent-of-source-acquisition" {
		return fmt.Errorf("component runtime certification registry policy invalid")
	}
	if !equalStringSlice(registry.Spec.Policy.RequiredLifecycleStages, RequiredComponentLifecycleStages) {
		return fmt.Errorf("component runtime certification required lifecycle stages drift")
	}
	if len(registry.Spec.Components) != len(components) {
		return fmt.Errorf("component runtime certification coverage mismatch: registry=%d catalog=%d", len(registry.Spec.Components), len(components))
	}

	holds := make(map[string]ComponentRuntimeSuitabilityHold, len(registry.Spec.RuntimeSuitabilityHolds))
	for _, hold := range registry.Spec.RuntimeSuitabilityHolds {
		name := strings.TrimSpace(hold.Component)
		if name == "" || holds[name].Component != "" {
			return fmt.Errorf("component runtime suitability hold identity invalid: %q", name)
		}
		if _, ok := components[name]; !ok {
			return fmt.Errorf("component runtime suitability hold references unknown component %s", name)
		}
		status := strings.TrimSpace(hold.Status)
		if status != "dependency-transition-required" && status != "review-required" {
			return fmt.Errorf("component runtime suitability hold status invalid for %s: %s", name, status)
		}
		if strings.TrimSpace(hold.Authority) == "" || strings.TrimSpace(hold.Reason) == "" || !strings.HasPrefix(strings.TrimSpace(hold.EvidenceURL), "https://") {
			return fmt.Errorf("component runtime suitability hold evidence invalid for %s", name)
		}
		holds[name] = hold
	}

	seen := make(map[string]bool, len(registry.Spec.Components))
	for _, contract := range registry.Spec.Components {
		name := strings.TrimSpace(contract.Component)
		if name == "" || seen[name] {
			return fmt.Errorf("component runtime certification identity invalid: %q", name)
		}
		seen[name] = true
		component, ok := components[name]
		if !ok {
			return fmt.Errorf("component runtime certification extra component %s", name)
		}
		if contract.Release != component.Spec.Release {
			return fmt.Errorf("component runtime certification release drift for %s: registry=%s catalog=%s", name, contract.Release, component.Spec.Release)
		}
		expectedSourceStatus := "blocked-source-lock"
		expectedDigest := ""
		if component.Spec.Source.Resolved {
			expectedSourceStatus = "source-ready"
			expectedDigest = strings.TrimSpace(component.Spec.Source.SourceLockDigest)
			if expectedDigest == "" {
				return fmt.Errorf("resolved component %s has no source lock digest", name)
			}
		}
		if contract.SourceBinding.Resolved != component.Spec.Source.Resolved || contract.SourceBinding.Status != expectedSourceStatus || strings.TrimSpace(contract.SourceBinding.SourceLockDigest) != expectedDigest {
			return fmt.Errorf("component runtime certification source drift for %s", name)
		}
		if contract.Executor.Owner != "catalog-component" {
			return fmt.Errorf("component runtime certification executor owner invalid for %s", name)
		}
		hold, held := holds[name]
		if name == "secure-namespace-foundation" {
			if held {
				return fmt.Errorf("secure namespace foundation cannot carry external runtime suitability hold")
			}
			if contract.Executor.Status != "foundation-harness-partial" || contract.Executor.Profile != "TARGET_RUNTIME_V1" {
				return fmt.Errorf("secure namespace foundation runtime executor authority drift")
			}
		} else {
			expectedExecutor := "source-gated-component-executor"
			if component.Spec.Source.Resolved {
				if held {
					expectedExecutor = "runtime-suitability-held"
				} else {
					expectedExecutor = "component-install-readiness-dependency-failure-remove-partial"
				}
			}
			if contract.Executor.Status != expectedExecutor || contract.Executor.Profile != "COMPONENT_RUNTIME_V1" {
				return fmt.Errorf("component runtime executor authority invalid for %s", name)
			}
		}
		if len(contract.Lifecycle) != len(RequiredComponentLifecycleStages) {
			return fmt.Errorf("component runtime lifecycle coverage invalid for %s", name)
		}
		stageSeen := map[string]bool{}
		for i, stage := range contract.Lifecycle {
			if stage.Name != RequiredComponentLifecycleStages[i] || stageSeen[stage.Name] {
				return fmt.Errorf("component runtime lifecycle stage order/identity invalid for %s", name)
			}
			stageSeen[stage.Name] = true
			if strings.TrimSpace(stage.EvidenceContract) != "component-"+stage.Name+"-evidence/v1" {
				return fmt.Errorf("component runtime lifecycle evidence contract invalid for %s/%s", name, stage.Name)
			}
			expectedStatus := "source-gated-component-executor"
			expectedAuthority := "COMPONENT_RUNTIME_V1"
			if name == "secure-namespace-foundation" {
				expectedStatus = "pending-component-executor"
				expectedAuthority = "COMPONENT_RUNTIME_EXECUTOR_V1"
				if stage.Name == "install" || stage.Name == "readiness" || stage.Name == "dependency" {
					expectedStatus = "foundation-harness-executable"
					expectedAuthority = "TARGET_RUNTIME_V1"
				} else if stage.Name == "upgrade" {
					expectedStatus = "not-applicable-first-product-release"
					expectedAuthority = "COMPONENT_UPGRADE_SOURCE_ADMISSION_V1"
				}
			} else if component.Spec.Source.Resolved && held {
				expectedStatus = "pending-runtime-suitability"
				expectedAuthority = hold.Authority
			} else if stage.Name == "upgrade" {
				expectedStatus = "pending-upgrade-matrix"
				expectedAuthority = "COMPONENT_RUNTIME_UPGRADE_V1"
			} else if component.Spec.Source.Resolved {
				expectedStatus = "component-runtime-executable"
				expectedAuthority = "COMPONENT_RUNTIME_V1"
			}
			if stage.Status != expectedStatus || stage.Authority != expectedAuthority {
				return fmt.Errorf("component runtime lifecycle authority invalid for %s/%s", name, stage.Name)
			}
		}
	}
	for name := range components {
		if !seen[name] {
			return fmt.Errorf("component runtime certification missing component %s", name)
		}
	}
	return nil
}

func ComponentRuntimeCertificationStatistics(registry ComponentRuntimeCertificationRegistry) ComponentRuntimeCertificationStats {
	stats := ComponentRuntimeCertificationStats{Total: len(registry.Spec.Components)}
	for _, contract := range registry.Spec.Components {
		if contract.SourceBinding.Resolved && contract.SourceBinding.Status == "source-ready" {
			stats.SourceReady++
		} else {
			stats.SourceBlocked++
		}
		switch contract.Executor.Status {
		case "foundation-harness-partial":
			stats.FoundationHarnessPartial++
		case "component-install-readiness-partial":
			stats.ComponentInstallReadinessPartial++
		case "component-install-readiness-dependency-partial":
			stats.ComponentInstallReadinessDependencyPartial++
		case "component-install-readiness-dependency-failure-remove-partial":
			stats.ComponentFailureRemovePartial++
		case "source-gated-component-executor":
			stats.SourceGatedExecutor++
		case "pending-component-executor":
			stats.PendingExecutor++
		}
		complete := true
		for _, stage := range contract.Lifecycle {
			if stage.Status != "component-runtime-certified" {
				complete = false
				break
			}
		}
		if complete {
			stats.LifecycleComplete++
		}
	}
	return stats
}

func SortedComponentRuntimeCertificationContracts(registry ComponentRuntimeCertificationRegistry) []ComponentRuntimeCertificationContract {
	out := append([]ComponentRuntimeCertificationContract(nil), registry.Spec.Components...)
	sort.Slice(out, func(i, j int) bool { return out[i].Component < out[j].Component })
	return out
}

func RebindComponentRuntimeCertificationSource(registry *ComponentRuntimeCertificationRegistry, component Component) error {
	if registry == nil {
		return fmt.Errorf("component runtime certification registry is nil")
	}
	holdByComponent := make(map[string]ComponentRuntimeSuitabilityHold, len(registry.Spec.RuntimeSuitabilityHolds))
	for _, hold := range registry.Spec.RuntimeSuitabilityHolds {
		holdByComponent[hold.Component] = hold
	}
	for i := range registry.Spec.Components {
		contract := &registry.Spec.Components[i]
		if contract.Component != component.Metadata.Name {
			continue
		}
		if !component.Spec.Source.Resolved || strings.TrimSpace(component.Spec.Source.SourceLockDigest) == "" {
			return fmt.Errorf("cannot bind unresolved component %s into runtime certification registry", component.Metadata.Name)
		}
		if contract.SourceBinding.Resolved {
			if contract.Release != component.Spec.Release || contract.SourceBinding.SourceLockDigest != component.Spec.Source.SourceLockDigest {
				return fmt.Errorf("resolved runtime certification source replacement denied for %s", component.Metadata.Name)
			}
			return nil
		}
		contract.Release = component.Spec.Release
		contract.SourceBinding = ComponentRuntimeSourceBinding{Status: "source-ready", Resolved: true, SourceLockDigest: component.Spec.Source.SourceLockDigest}
		if contract.Component != "secure-namespace-foundation" {
			contract.Executor.Profile = "COMPONENT_RUNTIME_V1"
			if hold, held := holdByComponent[contract.Component]; held {
				contract.Executor.Status = "runtime-suitability-held"
				for j := range contract.Lifecycle {
					stage := &contract.Lifecycle[j]
					stage.Status = "pending-runtime-suitability"
					stage.Authority = hold.Authority
				}
				return nil
			}
			contract.Executor.Status = "component-install-readiness-dependency-failure-remove-partial"
			for j := range contract.Lifecycle {
				stage := &contract.Lifecycle[j]
				if stage.Name == "upgrade" {
					stage.Status = "pending-upgrade-matrix"
					stage.Authority = "COMPONENT_RUNTIME_UPGRADE_V1"
					continue
				}
				stage.Status = "component-runtime-executable"
				stage.Authority = "COMPONENT_RUNTIME_V1"
			}
		}
		return nil
	}
	return fmt.Errorf("component %s missing from runtime certification registry", component.Metadata.Name)
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
