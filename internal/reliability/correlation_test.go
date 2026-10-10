package reliability

import (
	"testing"
	"time"
)

func TestCorrelateSignalsRequiresExactScopeEvidenceAndIndependentKinds(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	signals := []SignalObservation{
		{Kind: SignalMetric, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "prometheus", Fingerprint: corrDigest('a'), EvidenceDigest: corrDigest('b'), Complete: true, Severity: 4, ObservedAt: now.Add(-2*time.Minute)},
		{Kind: SignalTrace, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "otel", Fingerprint: corrDigest('c'), EvidenceDigest: corrDigest('d'), Complete: true, Severity: 4, ObservedAt: now.Add(-time.Minute)},
		{Kind: SignalChange, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "deployment-audit", Fingerprint: corrDigest('e'), EvidenceDigest: corrDigest('f'), Complete: true, Severity: 3, ObservedAt: now},
	}
	correlation, err := CorrelateSignals(signals, now, 10*time.Minute)
	if err != nil { t.Fatal(err) }
	if correlation.Authority != SignalCorrelationAuthority || correlation.Digest == "" || len(correlation.SignalKinds) != 3 || correlation.Confidence != CorrelationHigh || !correlation.RemediationEligible {
		t.Fatalf("unexpected correlation: %#v", correlation)
	}
	if err := ValidateSignalCorrelation(correlation); err != nil { t.Fatalf("valid correlation did not revalidate: %v", err) }
	tampered := correlation
	tampered.ProjectID = "project-b"
	if err := ValidateSignalCorrelation(tampered); err == nil { t.Fatal("tampered correlation content must fail digest validation") }
	crossProject := append([]SignalObservation(nil), signals...)
	crossProject[1].ProjectID = "project-b"
	if _, err := CorrelateSignals(crossProject, now, 10*time.Minute); err == nil { t.Fatal("cross-project signals must never correlate") }
	sameKind := []SignalObservation{signals[0], signals[0]}
	sameKind[1].Fingerprint = corrDigest('9')
	sameKind[1].EvidenceDigest = corrDigest('8')
	if _, err := CorrelateSignals(sameKind, now, 10*time.Minute); err == nil { t.Fatal("same signal kind alone must not create remediation correlation") }
}

func TestIncompleteOrStaleSignalsNeverAuthorizeRemediation(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	signals := []SignalObservation{
		{Kind: SignalMetric, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "prometheus", Fingerprint: corrDigest('a'), EvidenceDigest: corrDigest('b'), Complete: false, Severity: 5, ObservedAt: now},
		{Kind: SignalLog, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "logs", Fingerprint: corrDigest('c'), EvidenceDigest: corrDigest('d'), Complete: true, Severity: 5, ObservedAt: now.Add(-30*time.Minute)},
	}
	if _, err := CorrelateSignals(signals, now, 10*time.Minute); err == nil { t.Fatal("incomplete/stale correlation must fail closed") }
}

func TestBuildRepairProposalBindsIncidentRevisionFreshnessAndForbidsRawCommand(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	correlation, err := CorrelateSignals([]SignalObservation{
		{Kind: SignalMetric, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "prometheus", Fingerprint: corrDigest('a'), EvidenceDigest: corrDigest('b'), Complete: true, Severity: 4, ObservedAt: now},
		{Kind: SignalNetwork, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "network-observer", Fingerprint: corrDigest('c'), EvidenceDigest: corrDigest('d'), Complete: true, Severity: 4, ObservedAt: now},
	}, now, 10*time.Minute)
	if err != nil { t.Fatal(err) }
	incident := Incident{ID: "inc-1", OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Revision: 7, State: IncidentOpen, Severity: "CRITICAL"}
	proposal, err := BuildRepairProposal(correlation, incident, RepairActionNodeRemediation, []string{"node-b", "node-a"}, now)
	if err != nil { t.Fatal(err) }
	if proposal.Authority != RepairProposalAuthority || proposal.IncidentRevision != 7 || proposal.ExecutionAuthority != Day2ExecutionAuthority || proposal.AdapterID != RepairAdapterNodeMaintenance || !proposal.IndependentApprovalRequired || proposal.Digest == "" || len(proposal.TargetIDs) != 2 || proposal.TargetIDs[0] != "node-a" {
		t.Fatalf("repair proposal authority drift: %#v", proposal)
	}
	if err := ValidateRepairProposal(proposal); err != nil { t.Fatalf("valid repair proposal did not revalidate: %v", err) }
	tampered := proposal
	tampered.TargetIDs = []string{"node-c"}
	if err := ValidateRepairProposal(tampered); err == nil { t.Fatal("tampered repair target must fail content digest validation") }
	if _, err := BuildRepairProposal(correlation, incident, RepairAction("kubectl-delete"), []string{"node-a"}, now); err == nil { t.Fatal("arbitrary repair command/action must be rejected") }
	if _, err := BuildRepairProposal(correlation, incident, RepairActionNodeRemediation, []string{"node-a"}, correlation.ObservedAt.Add(RepairCorrelationTTL)); err == nil { t.Fatal("correlation must expire at exact repair TTL boundary") }
	incident.State = IncidentResolved
	if _, err := BuildRepairProposal(correlation, incident, RepairActionNodeRemediation, []string{"node-a"}, now); err == nil { t.Fatal("resolved incident must not admit remediation") }
}

func corrDigest(ch byte) string { b:=make([]byte,64); for i:=range b { b[i]=ch }; return "sha256:"+string(b) }
