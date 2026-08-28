package controlplane

import (
	"testing"
	"time"
)

func TestDriftFindingHistoryAndPolicyClassification(t *testing.T) {
	first := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	target := DriftScanTarget{ClusterID: "clu-1", DesiredDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	result := DriftTaskResult{Success: true, ObservedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Changes: []BaselinePlanChange{{Resource: "NetworkPolicy/default-deny", Action: "UPDATE"}}}
	comparison, findings := RuntimeDriftFindings(target, result, nil, first)
	if comparison.Classification != string(GitDriftLiveDrift) || len(findings) != 2 {
		t.Fatalf("unexpected first result: %#v %#v", comparison, findings)
	}
	var policy DriftFinding
	for _, f := range findings {
		if f.Category == "POLICY" {
			policy = f
		}
	}
	if policy.Fingerprint == "" || policy.Severity != DriftSeverityHigh || policy.Owner != "platform-operator" || policy.Remediation.Mode != "OPERATION" || !policy.Remediation.Eligible || policy.Occurrences != 1 || !policy.FirstSeenAt.Equal(first) {
		t.Fatalf("policy finding incomplete: %#v", policy)
	}
	prior := []DriftScan{{Targets: []DriftScanTarget{{ClusterID: target.ClusterID, Findings: findings}}}}
	second := first.Add(time.Hour)
	_, next := RuntimeDriftFindings(target, result, prior, second)
	var repeated DriftFinding
	for _, f := range next {
		if f.Fingerprint == policy.Fingerprint {
			repeated = f
		}
	}
	if repeated.Occurrences != 2 || !repeated.FirstSeenAt.Equal(first) || !repeated.LastSeenAt.Equal(second) {
		t.Fatalf("history not preserved: %#v", repeated)
	}
}
