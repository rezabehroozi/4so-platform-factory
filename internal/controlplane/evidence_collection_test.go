package controlplane

import (
	"strings"
	"testing"
	"time"
)

func TestEvidenceCollectionPlanAndCompletionAuthority(t *testing.T) {
	resources := []BaselineTaskResource{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "4so-platform-baseline", Name: "revision"}}
	deploymentID := "bld_evidence"
	base := "/api/v1/baseline-deployments/" + deploymentID + "/evidence/"
	plan := FinalizeEvidenceCollectionPlan([]PlanEvidenceArtifact{
		{Key: "resource-readback-configmap-revision", Kind: "KUBE_RESOURCE_READBACK", Resource: "ConfigMap/revision", Authority: "KUBERNETES_API_SERVER", SourceLocation: "kubernetes://kubernetes.default.svc/api/v1/namespaces/4so-platform-baseline/configmaps/revision", OutputLocation: base + "resource-readback-configmap-revision", MediaType: "application/json", Phase: PlanEvidencePhasePostApply, Required: true, RetentionDays: PlanEvidenceRetentionDays},
		{Key: "baseline-convergence", Kind: "BASELINE_CONVERGENCE", Authority: "PLATFORM_AGENT", SourceLocation: "platform-agent://baseline-convergence", OutputLocation: base + "baseline-convergence", MediaType: "application/json", Phase: PlanEvidencePhasePostApply, Required: true, RetentionDays: PlanEvidenceRetentionDays},
	})
	if err := ValidateEvidenceCollectionPlanSemantics(plan, deploymentID, resources); err != nil {
		t.Fatal(err)
	}
	collected := make([]BaselineEvidenceArtifact, 0, len(plan.Artifacts))
	for _, spec := range plan.Artifacts {
		payload := map[string]any{"key": spec.Key, "status": "PASS"}
		digest, size := baselineEvidencePayloadDigest(payload)
		collected = append(collected, BaselineEvidenceArtifact{Key: spec.Key, Kind: spec.Kind, Resource: spec.Resource, Authority: spec.Authority, Digest: digest, MediaType: spec.MediaType, Location: spec.OutputLocation, Size: size, Required: spec.Required, RetentionDays: spec.RetentionDays, Payload: payload})
	}
	if err := ValidateCollectedBaselineEvidence(plan, deploymentID, collected[:1]); err == nil {
		t.Fatal("missing required convergence evidence accepted")
	}
	tampered := append([]BaselineEvidenceArtifact(nil), collected...)
	tampered[0].Payload = map[string]any{"key": tampered[0].Key, "status": "TAMPERED"}
	if err := ValidateCollectedBaselineEvidence(plan, deploymentID, tampered); err == nil {
		t.Fatal("tampered evidence payload accepted with stale digest")
	}
	now := time.Date(2026, 8, 8, 7, 0, 0, 0, time.UTC)
	sealed, digest, err := SealBaselineEvidence(plan, deploymentID, collected, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 2 || !strings.HasPrefix(digest, "sha256:") || sealed[0].CollectedAt == nil || sealed[0].RetainUntil == nil {
		t.Fatalf("sealed evidence incomplete: %#v digest=%s", sealed, digest)
	}
	if got := sealed[0].RetainUntil.Sub(*sealed[0].CollectedAt); got != PlanEvidenceRetentionDays*24*time.Hour {
		t.Fatalf("retention=%v", got)
	}
	dep := BaselineDeployment{ResourceMeta: ResourceMeta{ID: deploymentID}, State: BaselineDeploymentSucceeded, DesiredDigest: "sha256:" + strings.Repeat("a", 64), ObservedDigest: "sha256:" + strings.Repeat("a", 64), PlanImpact: BaselinePlanImpact{Evidence: plan}, Evidence: sealed, EvidenceDigest: digest}
	if !BaselineCompletionEvidenceReady(dep, now.Add(time.Hour)) {
		t.Fatal("sealed completion evidence was not accepted")
	}
	legacy := dep
	legacy.Evidence = nil
	legacy.EvidenceDigest = ""
	if BaselineCompletionEvidenceReady(legacy, now.Add(time.Hour)) {
		t.Fatal("legacy succeeded baseline without completion evidence was accepted")
	}
	tamperedDep := dep
	tamperedDep.Evidence = append([]BaselineEvidenceArtifact(nil), dep.Evidence...)
	tamperedDep.Evidence[0].Payload = map[string]any{"status": "TAMPERED"}
	if BaselineCompletionEvidenceReady(tamperedDep, now.Add(time.Hour)) {
		t.Fatal("tampered completion evidence was accepted")
	}
	if BaselineCompletionEvidenceReady(dep, now.Add((PlanEvidenceRetentionDays+1)*24*time.Hour)) {
		t.Fatal("expired completion evidence was accepted")
	}
}

func TestEvidenceCollectionPlanRejectsWrongOutputAndRetention(t *testing.T) {
	resources := []BaselineTaskResource{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "x"}}
	plan := FinalizeEvidenceCollectionPlan([]PlanEvidenceArtifact{
		{Key: "readback", Kind: "KUBE_RESOURCE_READBACK", Resource: "ConfigMap/x", Authority: "KUBERNETES_API_SERVER", SourceLocation: "kubernetes://kubernetes.default.svc/api/v1/namespaces/ns/configmaps/x", OutputLocation: "/wrong", MediaType: "application/json", Phase: PlanEvidencePhasePostApply, Required: true, RetentionDays: PlanEvidenceRetentionDays},
		{Key: "baseline-convergence", Kind: "BASELINE_CONVERGENCE", Authority: "PLATFORM_AGENT", SourceLocation: "platform-agent://baseline-convergence", OutputLocation: "/api/v1/baseline-deployments/bld_x/evidence/baseline-convergence", MediaType: "application/json", Phase: PlanEvidencePhasePostApply, Required: true, RetentionDays: PlanEvidenceRetentionDays},
	})
	if err := ValidateEvidenceCollectionPlanSemantics(plan, "bld_x", resources); err == nil {
		t.Fatal("wrong output location accepted")
	}
	plan.Artifacts[0].OutputLocation = "/api/v1/baseline-deployments/bld_x/evidence/readback"
	plan.Artifacts[0].RetentionDays = 7
	plan.Digest = EvidenceCollectionPlanDigest(plan)
	if err := ValidateEvidenceCollectionPlanSemantics(plan, "bld_x", resources); err == nil {
		t.Fatal("short retention accepted")
	}
}
