package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
)

func apiTestPlanningAPIResources() []controlplane.ClusterAPIResourceObservation {
	return []controlplane.ClusterAPIResourceObservation{
		{APIVersion: "v1", Version: "v1", Kind: "ResourceQuota", Resource: "resourcequotas", Namespaced: true, Verbs: []string{"get", "list", "patch", "delete"}},
		{APIVersion: "v1", Version: "v1", Kind: "LimitRange", Resource: "limitranges", Namespaced: true, Verbs: []string{"get", "list", "patch", "delete"}},
		{APIVersion: "v1", Version: "v1", Kind: "ServiceAccount", Resource: "serviceaccounts", Namespaced: true, Verbs: []string{"get", "list", "patch", "delete"}},
		{APIVersion: "v1", Version: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespaced: true, Verbs: []string{"get", "list", "patch", "delete"}},
		{APIVersion: "networking.k8s.io/v1", Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy", Resource: "networkpolicies", Namespaced: true, Verbs: []string{"get", "list", "patch", "delete"}},
	}
}

func apiTestCompletePlanningInventory(v controlplane.ClusterInventory) controlplane.ClusterInventory {
	if v.Distribution == "" {
		v.Distribution = "rke2"
	}
	if v.KubernetesVersion == "" {
		v.KubernetesVersion = "v1.34.1"
	}
	if len(v.Nodes) == 0 {
		v.Nodes = []controlplane.ClusterNode{{Name: "test-node", Architecture: "amd64", Ready: true}}
	}
	v.APIResources = apiTestPlanningAPIResources()
	v.Networking.CNI = "cilium"
	v.Capabilities = append(v.Capabilities, "read-only-inventory", "controlled-baseline-deployment", "cni-inventory", "runtime-probe-image-digest-pinned")
	v.APIDiscoveryComplete = true
	v.CRDDiscoveryComplete = true
	v.SchemaDiscoveryVersion = "OPENAPI_V3"
	v.SchemaDiscoveryDigest = "sha256:" + strings.Repeat("9", 64)
	v.SchemaDiscoveryComplete = true
	v.Digest = controlplane.ClusterInventoryDigest(v)
	return v
}

func apiTestPlanningImpactForTask(task controlplane.BaselineTask, changes []controlplane.BaselinePlanChange) controlplane.BaselinePlanImpact {
	evidence := make(map[string]controlplane.PlanSchemaCompatibility, len(task.Resources))
	for _, resource := range task.Resources {
		evidence[resource.Kind+"/"+resource.Name] = controlplane.PlanSchemaCompatibility{Status: "PASS", Method: controlplane.PlanSchemaValidationMethod, HTTPStatus: 200, SchemaIndexVersion: task.Inventory.SchemaDiscoveryVersion, SchemaIndexDigest: task.Inventory.SchemaDiscoveryDigest}
	}
	rollback := make(map[string]controlplane.PlanRollbackResource, len(task.Resources))
	changeByResource := map[string]controlplane.BaselinePlanChange{}
	for _, change := range changes {
		changeByResource[change.Resource] = change
	}
	for _, resource := range task.Resources {
		key := resource.Kind + "/" + resource.Name
		change, ok := changeByResource[key]
		if !ok {
			change = controlplane.BaselinePlanChange{Resource: key, Action: "NOOP"}
		}
		item := controlplane.PlanRollbackResource{Resource: key, ChangeAction: change.Action, Status: "PASS", SchemaIndexVersion: task.Inventory.SchemaDiscoveryVersion, SchemaIndexDigest: task.Inventory.SchemaDiscoveryDigest}
		switch strings.ToUpper(change.Action) {
		case "NOOP":
			item.Strategy, item.AuthorizationStatus, item.DryRunStatus = "NO_ACTION", "NOT_REQUIRED", "NOT_REQUIRED"
			item.ObservedUID = "uid-" + strings.ToLower(resource.Kind) + "-" + resource.Name
			item.ObservedObjectDigest = "sha256:" + strings.Repeat("a", 64)
		case "ADD":
			item.Strategy, item.AuthorizationStatus, item.DryRunStatus = "DELETE_CREATED_RESOURCE", "PASS", "NOT_APPLICABLE"
		default:
			item.Strategy, item.AuthorizationStatus, item.DryRunStatus, item.HTTPStatus = "RESTORE_PREIMAGE", "PASS", "PASS", 200
			item.ObservedUID = "uid-" + strings.ToLower(resource.Kind) + "-" + resource.Name
			restore := map[string]any{"apiVersion": resource.APIVersion, "kind": resource.Kind, "metadata": map[string]any{"name": resource.Name, "namespace": resource.Namespace}}
			item.RestoreObject = restore
			item.ObservedObjectDigest = controlplane.RollbackRestoreObjectDigest(restore)
			item.RestoreObjectDigest = item.ObservedObjectDigest
		}
		rollback[key] = item
	}
	impact := controlplane.AnalyzePlanningImpactWithSchema(task.Resources, map[string]map[string]any{}, changes, task.Inventory, evidence, rollback)
	artifacts := make([]controlplane.PlanEvidenceArtifact, 0, len(task.Resources)+1)
	for i, resource := range task.Resources {
		key := fmt.Sprintf("resource-readback-%02d", i+1)
		artifacts = append(artifacts, controlplane.PlanEvidenceArtifact{Key: key, Kind: "KUBE_RESOURCE_READBACK", Resource: resource.Kind + "/" + resource.Name, Authority: "KUBERNETES_API_SERVER", SourceLocation: "kubernetes://kubernetes.default.svc/test/" + key, OutputLocation: "/api/v1/baseline-deployments/" + task.DeploymentID + "/evidence/" + key, MediaType: "application/json", Phase: controlplane.PlanEvidencePhasePostApply, Required: true, RetentionDays: controlplane.PlanEvidenceRetentionDays})
	}
	artifacts = append(artifacts, controlplane.PlanEvidenceArtifact{Key: "baseline-convergence", Kind: "BASELINE_CONVERGENCE", Authority: "PLATFORM_AGENT", SourceLocation: "platform-agent://baseline-convergence", OutputLocation: "/api/v1/baseline-deployments/" + task.DeploymentID + "/evidence/baseline-convergence", MediaType: "application/json", Phase: controlplane.PlanEvidencePhasePostApply, Required: true, RetentionDays: controlplane.PlanEvidenceRetentionDays})
	impact.Evidence = controlplane.FinalizeEvidenceCollectionPlan(artifacts)
	impact.Digest = controlplane.PlanningImpactDigest(impact)
	return impact
}

func apiTestPlanningImpact(inventoryDigest string) controlplane.BaselinePlanImpact {
	v := controlplane.BaselinePlanImpact{
		SchemaVersion:   controlplane.PlanningImpactSchemaVersion,
		InventoryDigest: inventoryDigest,
		Compatibility:   controlplane.BaselineCompatibilityDecision(controlplane.ClusterInventory{Distribution: "rke2", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability}, KubernetesVersion: "v1.34.1", Nodes: []controlplane.ClusterNode{{Name: "fixture", Architecture: "amd64", Ready: true}}}),
		Capability:      controlplane.PlanCapabilityPreflight{Status: "PASS", Method: controlplane.PlanCapabilityPreflightMethod, InventoryDigest: inventoryDigest, Checks: []controlplane.PlanCapabilityCheck{{Key: "fixture", Domain: "core", Required: true, Status: "PASS", Authority: "TEST", Impact: "test planning capability", Detail: "fixture"}}},
		API:             []controlplane.PlanAPIImpact{{Resource: "ConfigMap/test", APIVersion: "v1", Kind: "ConfigMap", DiscoveryStatus: "SERVED", LifecycleStatus: "CURRENT", Schema: controlplane.PlanSchemaCompatibility{Status: "PASS", Method: controlplane.PlanSchemaValidationMethod, HTTPStatus: 200, SchemaIndexVersion: "OPENAPI_V3", SchemaIndexDigest: "sha256:" + strings.Repeat("9", 64)}, Severity: "INFO", Message: "test fixture"}},
		Capacity:        controlplane.PlanCapacityEstimate{DemandDeltaKnown: true, CeilingCheck: "NOT_APPLICABLE", CurrentUsageKnown: false},
		Disruption:      controlplane.PlanDisruptionEstimate{Level: "LOW", MaintenanceRecommendation: "NOT_REQUIRED"},
		Rollback:        controlplane.PlanRollbackFeasibility{Status: "PASS", Method: controlplane.PlanRollbackValidationMethod, Resources: []controlplane.PlanRollbackResource{{Resource: "ConfigMap/test", ChangeAction: "ADD", Strategy: "DELETE_CREATED_RESOURCE", Status: "PASS", AuthorizationStatus: "PASS", DryRunStatus: "NOT_APPLICABLE", SchemaIndexVersion: "OPENAPI_V3", SchemaIndexDigest: "sha256:" + strings.Repeat("9", 64)}}},
		ApprovalReady:   true,
	}
	v.Capability.Digest = controlplane.CapabilityPreflightDigest(v.Capability)
	v.Rollback.Digest = controlplane.RollbackFeasibilityDigest(v.Rollback)
	v.Evidence = controlplane.FinalizeEvidenceCollectionPlan([]controlplane.PlanEvidenceArtifact{
		{Key: "resource-readback-configmap-test", Kind: "KUBE_RESOURCE_READBACK", Resource: "ConfigMap/test", Authority: "KUBERNETES_API_SERVER", SourceLocation: "kubernetes://kubernetes.default.svc/api/v1/namespaces/test/configmaps/test", OutputLocation: "/api/v1/baseline-deployments/{deploymentId}/evidence/resource-readback-configmap-test", MediaType: "application/json", Phase: controlplane.PlanEvidencePhasePostApply, Required: true, RetentionDays: controlplane.PlanEvidenceRetentionDays},
		{Key: "baseline-convergence", Kind: "BASELINE_CONVERGENCE", Authority: "PLATFORM_AGENT", SourceLocation: "platform-agent://baseline-convergence", OutputLocation: "/api/v1/baseline-deployments/{deploymentId}/evidence/baseline-convergence", MediaType: "application/json", Phase: controlplane.PlanEvidencePhasePostApply, Required: true, RetentionDays: controlplane.PlanEvidenceRetentionDays},
	})
	v.Digest = controlplane.PlanningImpactDigest(v)
	return v
}

func apiTestPlanningImpactJSON(inventoryDigest string) string {
	raw, _ := json.Marshal(apiTestPlanningImpact(inventoryDigest))
	return string(raw)
}

func apiTestCollectedBaselineEvidence(plan controlplane.PlanEvidenceCollection, deploymentIDs ...string) []controlplane.BaselineEvidenceArtifact {
	out := make([]controlplane.BaselineEvidenceArtifact, 0, len(plan.Artifacts))
	deploymentID := ""
	if len(deploymentIDs) > 0 {
		deploymentID = deploymentIDs[0]
	}
	for _, spec := range plan.Artifacts {
		if deploymentID != "" {
			spec.OutputLocation = strings.ReplaceAll(spec.OutputLocation, "{deploymentId}", deploymentID)
		}
		payload := map[string]any{"key": spec.Key, "status": "PASS"}
		raw, _ := json.Marshal(payload)
		sum := sha256.Sum256(raw)
		out = append(out, controlplane.BaselineEvidenceArtifact{Key: spec.Key, Kind: spec.Kind, Resource: spec.Resource, Authority: spec.Authority, Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: spec.MediaType, Location: spec.OutputLocation, Size: int64(len(raw)), Required: spec.Required, RetentionDays: spec.RetentionDays, Payload: payload})
	}
	return out
}

func apiTestApplyResultJSON(task controlplane.BaselineTask) string {
	raw, _ := json.Marshal(controlplane.BaselineTaskResult{Action: "APPLY", Success: true, ObservedDigest: task.DesiredDigest, Evidence: apiTestCollectedBaselineEvidence(task.EvidencePlan), TaskFenceToken: task.TaskFenceToken})
	return string(raw)
}
