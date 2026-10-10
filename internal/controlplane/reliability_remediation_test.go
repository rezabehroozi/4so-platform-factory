package controlplane

import (
	"testing"
	"time"

	"platform.4so.io/factory/internal/reliability"
)

func TestRepairProposalUsesExistingDay2CampaignAuthority(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	correlation, err := reliability.CorrelateSignals([]reliability.SignalObservation{
		{Kind: reliability.SignalMetric, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "prometheus", Fingerprint: remediationDigest('a'), EvidenceDigest: remediationDigest('b'), Complete: true, Severity: 4, ObservedAt: now},
		{Kind: reliability.SignalNetwork, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "network-observer", Fingerprint: remediationDigest('c'), EvidenceDigest: remediationDigest('d'), Complete: true, Severity: 4, ObservedAt: now},
	}, now, 10*time.Minute)
	if err != nil { t.Fatal(err) }
	incident := reliability.Incident{ID: "inc-1", OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Revision: 7, State: reliability.IncidentOpen, Severity: "CRITICAL"}
	proposal, err := reliability.BuildRepairProposal(correlation, incident, reliability.RepairActionNodeRemediation, []string{"node-a"}, now)
	if err != nil { t.Fatal(err) }
	window := ClusterMaintenanceWindow{
		ResourceMeta: ResourceMeta{ID: "mw-1", Revision: 1},
		ProjectID: "project-a", ClusterID: "cluster-a", State: ClusterMaintenanceWindowActive,
		StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), MaxUnavailable: 1,
	}
	contract, err := Day2ContractForRepairProposal(proposal, incident, window, now)
	if err != nil { t.Fatal(err) }
	if contract.Authority != GeneralizedDay2CampaignAuthorityMethod || contract.Adapter != Day2CampaignAdapterNodeMaintenance || !contract.IndependentApproval || !contract.WindowRequired || !contract.FencedExecution || !contract.VerificationRequired || !contract.EvidenceRequired {
		t.Fatalf("repair proposal did not reuse day2 authority: %#v", contract)
	}
	if contract.TargetCount != 1 || contract.MaxUnavailable != 1 || !contract.WindowStart.Equal(window.StartsAt) || !contract.WindowEnd.Equal(window.EndsAt) {
		t.Fatalf("repair proposal/window binding drift: %#v", contract)
	}
	tampered := proposal
	tampered.TargetIDs = []string{"node-b"}
	if _, err := Day2ContractForRepairProposal(tampered, incident, window, now); err == nil { t.Fatal("tampered repair proposal must fail owner digest validation") }
	window.ProjectID = "project-b"
	if _, err := Day2ContractForRepairProposal(proposal, incident, window, now); err == nil { t.Fatal("cross-project maintenance window must fail closed") }
	window.ProjectID = "project-a"
	window.State = ClusterMaintenanceWindowCancelled
	if _, err := Day2ContractForRepairProposal(proposal, incident, window, now); err == nil { t.Fatal("inactive maintenance window must fail closed") }
	window.State = ClusterMaintenanceWindowActive
	if _, err := Day2ContractForRepairProposal(proposal, incident, window, proposal.ValidUntil); err == nil { t.Fatal("repair proposal must expire at exact ValidUntil boundary") }
}

func remediationDigest(ch byte) string { b:=make([]byte,64); for i:=range b { b[i]=ch }; return "sha256:"+string(b) }
