package controlplane

import "time"

func testPlanningImpact(inventoryDigest string, deploymentIDs ...string) BaselinePlanImpact {
	deploymentID := "{deploymentId}"
	if len(deploymentIDs) > 0 && deploymentIDs[0] != "" {
		deploymentID = deploymentIDs[0]
	}
	v := BaselinePlanImpact{
		SchemaVersion:   PlanningImpactSchemaVersion,
		InventoryDigest: inventoryDigest,
		Compatibility:   BaselineCompatibilityDecision(ClusterInventory{Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "v1.34.1", Nodes: []ClusterNode{{Name: "fixture", Architecture: "amd64", Ready: true}}}),
		Capability:      PlanCapabilityPreflight{Status: "PASS", Method: PlanCapabilityPreflightMethod, InventoryDigest: inventoryDigest, Checks: []PlanCapabilityCheck{{Key: "fixture", Domain: "core", Required: true, Status: "PASS", Authority: "TEST", Impact: "test planning capability", Detail: "fixture"}}},
		API:             []PlanAPIImpact{{Resource: "ConfigMap/test", APIVersion: "v1", Kind: "ConfigMap", DiscoveryStatus: "SERVED", LifecycleStatus: "CURRENT", Schema: PlanSchemaCompatibility{Status: "PASS", Method: PlanSchemaValidationMethod, HTTPStatus: 200, SchemaIndexVersion: "OPENAPI_V3", SchemaIndexDigest: testDigest(9900)}, Severity: "INFO", Message: "test fixture"}},
		Capacity:        PlanCapacityEstimate{DemandDeltaKnown: true, CeilingCheck: "NOT_APPLICABLE", CurrentUsageKnown: false},
		Disruption:      PlanDisruptionEstimate{Level: "LOW", MaintenanceRecommendation: "NOT_REQUIRED"},
		Rollback:        PlanRollbackFeasibility{Status: "PASS", Method: PlanRollbackValidationMethod, Resources: []PlanRollbackResource{{Resource: "ConfigMap/test", ChangeAction: "ADD", Strategy: "DELETE_CREATED_RESOURCE", Status: "PASS", AuthorizationStatus: "PASS", DryRunStatus: "NOT_APPLICABLE", SchemaIndexVersion: "OPENAPI_V3", SchemaIndexDigest: testDigest(9900)}}},
		ApprovalReady:   true,
	}
	v.Capability.Digest = CapabilityPreflightDigest(v.Capability)
	v.Rollback.Digest = RollbackFeasibilityDigest(v.Rollback)
	base := "/api/v1/baseline-deployments/" + deploymentID + "/evidence/"
	v.Evidence = FinalizeEvidenceCollectionPlan([]PlanEvidenceArtifact{
		{Key: "resource-readback-configmap-test", Kind: "KUBE_RESOURCE_READBACK", Resource: "ConfigMap/test", Authority: "KUBERNETES_API_SERVER", SourceLocation: "kubernetes://kubernetes.default.svc/api/v1/namespaces/test/configmaps/test", OutputLocation: base + "resource-readback-configmap-test", MediaType: "application/json", Phase: PlanEvidencePhasePostApply, Required: true, RetentionDays: PlanEvidenceRetentionDays},
		{Key: "baseline-convergence", Kind: "BASELINE_CONVERGENCE", Authority: "PLATFORM_AGENT", SourceLocation: "platform-agent://baseline-convergence", OutputLocation: base + "baseline-convergence", MediaType: "application/json", Phase: PlanEvidencePhasePostApply, Required: true, RetentionDays: PlanEvidenceRetentionDays},
	})
	v.Digest = PlanningImpactDigest(v)
	return v
}

func testCollectedBaselineEvidence(plan PlanEvidenceCollection) []BaselineEvidenceArtifact {
	out := make([]BaselineEvidenceArtifact, 0, len(plan.Artifacts))
	for _, spec := range plan.Artifacts {
		payload := map[string]any{"key": spec.Key, "status": "PASS"}
		digest, size := baselineEvidencePayloadDigest(payload)
		out = append(out, BaselineEvidenceArtifact{Key: spec.Key, Kind: spec.Kind, Resource: spec.Resource, Authority: spec.Authority, Digest: digest, MediaType: spec.MediaType, Location: spec.OutputLocation, Size: size, Required: spec.Required, RetentionDays: spec.RetentionDays, Payload: payload})
	}
	return out
}

var _ = time.UTC
