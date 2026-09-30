package daprruntime

import (
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/targetmodel"
)

const WorkloadPolicyProjectionAuthority = "DAPR_WORKLOAD_POLICY_PROJECTION_V1"

type WorkloadPolicyObservation struct {
	Authority                  string   `json:"authority"`
	ConfigurationObserved      bool     `json:"configurationObserved"`
	ConfigurationName          string   `json:"configurationName"`
	ConfigurationPolicyDigest  string   `json:"configurationPolicyDigest"`
	ComponentScopesVerified    bool     `json:"componentScopesVerified"`
	ObservedComponents         []string `json:"observedComponents,omitempty"`
	ConfigurationBecomesSoT    bool     `json:"configurationBecomesSoT"`
	RuntimeMutationPerformed   bool     `json:"runtimeMutationPerformed"`
}

func expectedWorkloadAPIRules(plan targetmodel.DaprWorkloadRuntimePlan) []map[string]any {
	rules := make([]targetmodel.DaprAPIAccessRule, len(plan.AllowedAPIs))
	copy(rules, plan.AllowedAPIs)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Name != rules[j].Name {
			return rules[i].Name < rules[j].Name
		}
		if rules[i].Version != rules[j].Version {
			return rules[i].Version < rules[j].Version
		}
		return rules[i].Protocol < rules[j].Protocol
	})
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"name": strings.TrimSpace(rule.Name),
			"version": strings.TrimSpace(rule.Version),
			"protocol": strings.TrimSpace(rule.Protocol),
		})
	}
	return out
}

func BuildWorkloadConfigurationProjection(plan targetmodel.DaprWorkloadRuntimePlan) (map[string]any, error) {
	if plan.Authority != targetmodel.DaprWorkloadRuntimePlanAuthority ||
		plan.Capability != targetmodel.DaprApplicationRuntimeCapability ||
		!plan.ConfigurationDerived || plan.ConfigurationBecomesSoT ||
		strings.TrimSpace(plan.Namespace) == "" || strings.TrimSpace(plan.ConfigurationName) == "" ||
		strings.ToUpper(strings.TrimSpace(plan.ServiceInvocationDefault)) != "DENY" ||
		plan.CrossNamespaceInvocation || plan.SecretMaterialEmbedded {
		return nil, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_PLAN_INVALID")
	}
	if len(plan.AllowedAPIs) == 0 {
		return nil, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_API_ALLOWLIST_EMPTY")
	}
	return map[string]any{
		"apiVersion": "dapr.io/v1alpha1",
		"kind": "Configuration",
		"metadata": map[string]any{
			"name": plan.ConfigurationName,
			"namespace": plan.Namespace,
			"labels": map[string]any{
				"platform.4so.io/managed": "true",
				"platform.4so.io/authority": WorkloadPolicyProjectionAuthority,
			},
		},
		"spec": map[string]any{
			"api": map[string]any{
				"allowed": expectedWorkloadAPIRules(plan),
			},
			"accessControl": map[string]any{
				"defaultAction": "deny",
				"trustDomain": "public",
			},
		},
	}, nil
}

func WorkloadConfigurationPolicyDigest(plan targetmodel.DaprWorkloadRuntimePlan) (string, error) {
	projection, err := BuildWorkloadConfigurationProjection(plan)
	if err != nil {
		return "", err
	}
	return workloadAdmissionDigest(projection)
}

func canonicalObservedAPIRules(value any) ([]string, error) {
	rows, ok := value.([]any)
	if !ok || len(rows) == 0 {
		return nil, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_API_ALLOWLIST_INVALID")
	}
	out := make([]string, 0, len(rows))
	seen := map[string]bool{}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_API_ALLOWLIST_INVALID")
		}
		name := strings.TrimSpace(fmt.Sprint(row["name"]))
		version := strings.TrimSpace(fmt.Sprint(row["version"]))
		protocol := strings.TrimSpace(fmt.Sprint(row["protocol"]))
		key := name + "\x00" + version + "\x00" + protocol
		if name == "" || version == "" || (protocol != "http" && protocol != "grpc") || seen[key] {
			return nil, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_API_ALLOWLIST_INVALID")
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return out, nil
}

func expectedAPIRuleKeys(plan targetmodel.DaprWorkloadRuntimePlan) []string {
	out := make([]string, 0, len(plan.AllowedAPIs))
	for _, rule := range plan.AllowedAPIs {
		out = append(out,
			strings.TrimSpace(rule.Name)+"\x00"+
				strings.TrimSpace(rule.Version)+"\x00"+
				strings.TrimSpace(rule.Protocol))
	}
	sort.Strings(out)
	return out
}

func stringSlicesEqual(a, b []string) bool {
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

func ValidateWorkloadPolicyReadback(
	request WorkloadAdmissionRequest,
	configuration map[string]any,
	components map[string]map[string]any,
) (WorkloadPolicyObservation, error) {
	request, err := CanonicalWorkloadAdmissionRequest(request)
	if err != nil {
		return WorkloadPolicyObservation{}, err
	}
	plan := request.Plan
	if strings.TrimSpace(fmt.Sprint(configuration["apiVersion"])) != "dapr.io/v1alpha1" ||
		strings.TrimSpace(fmt.Sprint(configuration["kind"])) != "Configuration" {
		return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_IDENTITY_INVALID")
	}
	metadata, _ := configuration["metadata"].(map[string]any)
	if metadata == nil ||
		strings.TrimSpace(fmt.Sprint(metadata["name"])) != plan.ConfigurationName ||
		strings.TrimSpace(fmt.Sprint(metadata["namespace"])) != plan.Namespace {
		return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_IDENTITY_INVALID")
	}
	spec, _ := configuration["spec"].(map[string]any)
	if spec == nil {
		return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_SPEC_INVALID")
	}
	for key := range spec {
		switch key {
		case "api", "accessControl", "metric", "metrics":
		default:
			return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_AUTHORITY_EXPANSION_FORBIDDEN")
		}
	}
	api, _ := spec["api"].(map[string]any)
	observedRules, err := canonicalObservedAPIRules(api["allowed"])
	if err != nil || !stringSlicesEqual(observedRules, expectedAPIRuleKeys(plan)) {
		return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_API_ALLOWLIST_MISMATCH")
	}
	if denied, exists := api["denied"]; exists {
		rows, ok := denied.([]any)
		if !ok || len(rows) != 0 {
			return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_API_DENYLIST_UNEXPECTED")
		}
	}
	access, _ := spec["accessControl"].(map[string]any)
	if access == nil ||
		strings.ToLower(strings.TrimSpace(fmt.Sprint(access["defaultAction"]))) != "deny" ||
		strings.ToLower(strings.TrimSpace(fmt.Sprint(access["trustDomain"]))) != "public" {
		return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_ACCESS_CONTROL_INVALID")
	}
	if policies, exists := access["policies"]; exists {
		rows, ok := policies.([]any)
		if !ok || len(rows) != 0 {
			return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_CONFIGURATION_UNMODELED_CALLER_POLICY")
		}
	}

	expectedComponents := map[string]bool{}
	for _, scope := range plan.ComponentScopes {
		name := strings.TrimSpace(scope.ComponentName)
		if name == "" || len(scope.Scopes) != 1 || strings.TrimSpace(scope.Scopes[0]) != plan.AppID {
			return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_COMPONENT_SCOPE_PLAN_INVALID")
		}
		expectedComponents[name] = true
	}
	if len(components) != len(expectedComponents) {
		return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_COMPONENT_READBACK_INCOMPLETE")
	}
	observedComponents := make([]string, 0, len(expectedComponents))
	for name := range expectedComponents {
		component, ok := components[name]
		if !ok {
			return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_COMPONENT_READBACK_INCOMPLETE")
		}
		if strings.TrimSpace(fmt.Sprint(component["apiVersion"])) != "dapr.io/v1alpha1" ||
			strings.TrimSpace(fmt.Sprint(component["kind"])) != "Component" {
			return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_COMPONENT_IDENTITY_INVALID")
		}
		meta, _ := component["metadata"].(map[string]any)
		if meta == nil ||
			strings.TrimSpace(fmt.Sprint(meta["name"])) != name ||
			strings.TrimSpace(fmt.Sprint(meta["namespace"])) != plan.Namespace {
			return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_COMPONENT_IDENTITY_INVALID")
		}
		rawScopes, ok := component["scopes"].([]any)
		if !ok || len(rawScopes) != 1 || strings.TrimSpace(fmt.Sprint(rawScopes[0])) != plan.AppID {
			return WorkloadPolicyObservation{}, fmt.Errorf("DAPR_WORKLOAD_COMPONENT_SCOPE_MISMATCH")
		}
		observedComponents = append(observedComponents, name)
	}
	sort.Strings(observedComponents)
	policyDigest, err := WorkloadConfigurationPolicyDigest(plan)
	if err != nil {
		return WorkloadPolicyObservation{}, err
	}
	return WorkloadPolicyObservation{
		Authority: WorkloadPolicyProjectionAuthority,
		ConfigurationObserved: true,
		ConfigurationName: plan.ConfigurationName,
		ConfigurationPolicyDigest: policyDigest,
		ComponentScopesVerified: true,
		ObservedComponents: observedComponents,
		ConfigurationBecomesSoT: false,
		RuntimeMutationPerformed: false,
	}, nil
}

func ValidateWorkloadPolicyObservation(value WorkloadPolicyObservation, request WorkloadAdmissionRequest) error {
	request, err := CanonicalWorkloadAdmissionRequest(request)
	if err != nil {
		return err
	}
	value.Authority = strings.TrimSpace(value.Authority)
	value.ConfigurationName = strings.TrimSpace(value.ConfigurationName)
	value.ConfigurationPolicyDigest = strings.ToLower(strings.TrimSpace(value.ConfigurationPolicyDigest))
	value.ObservedComponents = append([]string(nil), value.ObservedComponents...)
	for i := range value.ObservedComponents {
		value.ObservedComponents[i] = strings.TrimSpace(value.ObservedComponents[i])
	}
	sort.Strings(value.ObservedComponents)
	expectedDigest, err := WorkloadConfigurationPolicyDigest(request.Plan)
	if err != nil {
		return err
	}
	expectedComponents := make([]string, 0, len(request.Plan.ComponentScopes))
	for _, scope := range request.Plan.ComponentScopes {
		expectedComponents = append(expectedComponents, strings.TrimSpace(scope.ComponentName))
	}
	sort.Strings(expectedComponents)
	if value.Authority != WorkloadPolicyProjectionAuthority || !value.ConfigurationObserved ||
		value.ConfigurationName != request.Plan.ConfigurationName ||
		value.ConfigurationPolicyDigest != expectedDigest ||
		!value.ComponentScopesVerified ||
		!stringSlicesEqual(value.ObservedComponents, expectedComponents) ||
		value.ConfigurationBecomesSoT || value.RuntimeMutationPerformed {
		return fmt.Errorf("DAPR_WORKLOAD_POLICY_OBSERVATION_INVALID")
	}
	return nil
}
