package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func testInputs() RuntimeClosureInputs {
	return RuntimeClosureInputs{
		CampaignID: "campaign-1", ProjectID: "project-1", ClusterID: "cluster-1",
		ClusterInventoryDigest: "sha256:" + strings.Repeat("1", 64),
		BaselineDeploymentID:   "baseline-1",
		BaselineDesiredDigest:  "sha256:" + strings.Repeat("2", 64),
		BaselineObservedDigest: "sha256:" + strings.Repeat("2", 64),
		RuntimeVerificationID:  "verification-1",
		RuntimeReportDigest:    "sha256:" + strings.Repeat("3", 64),
		RuntimeDesiredDigest:   "sha256:" + strings.Repeat("2", 64),
		RuntimeObservedDigest:  "sha256:" + strings.Repeat("2", 64),
		ReleaseArtifactDigest:  "sha256:" + strings.Repeat("4", 64),
		ProducerBinaryDigest:   "sha256:" + strings.Repeat("5", 64),
	}
}

func testReport(t *testing.T) []byte {
	t.Helper()
	inputs := testInputs()
	digest, err := inputs.Digest()
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{
		"apiVersion": RuntimeClosureAPIVersion,
		"kind":       RuntimeClosureKind,
		"metadata":   map[string]any{"id": inputs.CampaignID, "evidenceDigest": digest, "state": "SUCCEEDED"},
		"product":    map[string]any{"name": "4SO Platform Factory", "version": "0.0.21"},
		"target": map[string]any{
			"cluster":            map[string]any{"id": inputs.ClusterID, "projectId": inputs.ProjectID, "inventoryDigest": inputs.ClusterInventoryDigest},
			"baselineDeployment": map[string]any{"id": inputs.BaselineDeploymentID, "projectId": inputs.ProjectID, "clusterId": inputs.ClusterID, "desiredDigest": inputs.BaselineDesiredDigest, "observedDigest": inputs.BaselineObservedDigest},
		},
		"runtimeVerification": map[string]any{"id": inputs.RuntimeVerificationID, "projectId": inputs.ProjectID, "clusterId": inputs.ClusterID, "reportDigest": inputs.RuntimeReportDigest, "desiredDigest": inputs.RuntimeDesiredDigest, "observedDigest": inputs.RuntimeObservedDigest},
		"result":              map[string]any{"state": "SUCCEEDED", "summary": "complete", "nextAction": "download-runtime-closure-report", "lastError": ""},
		"claims":              map[string]any{"runtimeClosed": true, "runtimeCertified": false, "productionReady": false, "haCertified": false},
		"evidence":            RuntimeClosureEvidence{SchemaVersion: RuntimeClosureEvidenceSchema, Algorithm: "sha256", Canonicalization: RuntimeClosureCanonicalization, BindingAuthority: RuntimeClosureExactReleaseBindingAuthority, Inputs: inputs, Digest: digest},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRuntimeClosureInputsDigestStable(t *testing.T) {
	inputs := testInputs()
	first, err := inputs.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := inputs.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("digest is not stable: %q %q", first, second)
	}
}

func TestVerifyRuntimeClosureReport(t *testing.T) {
	result, err := VerifyRuntimeClosureReport(testReport(t))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.CampaignID != "campaign-1" || result.EvidenceDigest == "" || !result.ExactReleaseBound || result.ReleaseArtifactDigest != testInputs().ReleaseArtifactDigest || result.ProducerBinaryDigest != testInputs().ProducerBinaryDigest {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestVerifyRuntimeClosureReportRejectsTampering(t *testing.T) {
	var report map[string]any
	if err := json.Unmarshal(testReport(t), &report); err != nil {
		t.Fatal(err)
	}
	target := report["target"].(map[string]any)
	cluster := target["cluster"].(map[string]any)
	cluster["inventoryDigest"] = "sha256:" + strings.Repeat("9", 64)
	raw, _ := json.Marshal(report)
	if _, err := VerifyRuntimeClosureReport(raw); err == nil {
		t.Fatal("tampered cluster inventory digest was accepted")
	}
}

func TestVerifyRuntimeClosureReportRejectsCertificationClaim(t *testing.T) {
	var report map[string]any
	if err := json.Unmarshal(testReport(t), &report); err != nil {
		t.Fatal(err)
	}
	report["claims"].(map[string]any)["runtimeCertified"] = true
	raw, _ := json.Marshal(report)
	if _, err := VerifyRuntimeClosureReport(raw); err == nil {
		t.Fatal("unsupported runtime certification claim was accepted")
	}
}

func TestVerifyRuntimeClosureLegacyReportRemainsVerifiableButNotExactReleaseBound(t *testing.T) {
	inputs := testInputs()
	inputs.ReleaseArtifactDigest = ""
	inputs.ProducerBinaryDigest = ""
	digest, err := inputs.LegacyDigest()
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{
		"apiVersion": RuntimeClosureAPIVersion,
		"kind":       RuntimeClosureKind,
		"metadata":   map[string]any{"id": inputs.CampaignID, "evidenceDigest": digest, "state": "SUCCEEDED"},
		"product":    map[string]any{"name": "4SO Platform Factory", "version": "0.0.259"},
		"target": map[string]any{
			"cluster":            map[string]any{"id": inputs.ClusterID, "projectId": inputs.ProjectID, "inventoryDigest": inputs.ClusterInventoryDigest},
			"baselineDeployment": map[string]any{"id": inputs.BaselineDeploymentID, "projectId": inputs.ProjectID, "clusterId": inputs.ClusterID, "desiredDigest": inputs.BaselineDesiredDigest, "observedDigest": inputs.BaselineObservedDigest},
		},
		"runtimeVerification": map[string]any{"id": inputs.RuntimeVerificationID, "projectId": inputs.ProjectID, "clusterId": inputs.ClusterID, "reportDigest": inputs.RuntimeReportDigest, "desiredDigest": inputs.RuntimeDesiredDigest, "observedDigest": inputs.RuntimeObservedDigest},
		"result":              map[string]any{"state": "SUCCEEDED", "summary": "legacy", "nextAction": "download-runtime-closure-report", "lastError": ""},
		"claims":              map[string]any{"runtimeClosed": true, "runtimeCertified": false, "productionReady": false, "haCertified": false},
		"evidence": RuntimeClosureEvidence{
			SchemaVersion: RuntimeClosureLegacyEvidenceSchema, Algorithm: "sha256",
			Canonicalization: RuntimeClosureLegacyCanonicalization, Inputs: inputs, Digest: digest,
		},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyRuntimeClosureReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.ExactReleaseBound || result.EvidenceSchemaVersion != RuntimeClosureLegacyEvidenceSchema || result.ReleaseArtifactDigest != "" || result.ProducerBinaryDigest != "" {
		t.Fatalf("legacy verification truth changed: %#v", result)
	}
}

func TestVerifyRuntimeClosureRejectsSchemaV2WithoutExactReleaseIdentity(t *testing.T) {
	var report map[string]any
	if err := json.Unmarshal(testReport(t), &report); err != nil {
		t.Fatal(err)
	}
	evidenceDoc := report["evidence"].(map[string]any)
	inputs := evidenceDoc["inputs"].(map[string]any)
	delete(inputs, "releaseArtifactDigest")
	raw, _ := json.Marshal(report)
	if _, err := VerifyRuntimeClosureReport(raw); err == nil {
		t.Fatal("schema-v2 report without exact release digest was accepted")
	}
}
