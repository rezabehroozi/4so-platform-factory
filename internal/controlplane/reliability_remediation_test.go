package controlplane

import (
	"testing"

	"platform.4so.io/factory/internal/reliability"
)

func TestRepairProposalUsesExistingDay2CampaignAuthority(t *testing.T) {
	proposal := reliability.RepairProposal{
		Authority: reliability.RepairProposalAuthority,
		ExecutionAuthority: reliability.Day2ExecutionAuthority,
		AdapterID: Day2CampaignAdapterNodeMaintenance,
		OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders",
		IncidentID: "inc-1", IncidentRevision: 7, CorrelationDigest: remediationDigest('a'),
		Action: reliability.RepairActionNodeRemediation, TargetIDs: []string{"node-a"},
		IndependentApprovalRequired: true, Impact: "targeted", Digest: remediationDigest('b'),
	}
	window := ClusterMaintenanceWindow{ID: "mw-1", ProjectID: "project-a", ClusterID: "cluster-a", MaxUnavailable: 1}
	contract, err := Day2ContractForRepairProposal(proposal, window)
	if err != nil { t.Fatal(err) }
	if contract.Authority != Day2CampaignEngineAuthority || contract.Adapter.ID != Day2CampaignAdapterNodeMaintenance || !contract.Impact.RequireApproval || !contract.Impact.RequireMaintenanceWindow || !contract.Impact.RequireRecoveryCheckpoint {
		t.Fatalf("repair proposal did not reuse day2 authority: %#v", contract)
	}
	if contract.Impact.MaintenanceWindowID != window.ID || contract.Impact.MaxUnavailable != 1 || len(contract.Adapter.TargetIDs) != 1 || contract.Adapter.TargetIDs[0] != "node-a" {
		t.Fatalf("repair proposal/window binding drift: %#v", contract)
	}
	proposal.IndependentApprovalRequired = false
	if _, err := Day2ContractForRepairProposal(proposal, window); err == nil { t.Fatal("repair proposal must never bypass independent approval") }
	proposal.IndependentApprovalRequired = true
	proposal.AdapterID = "raw-shell"
	if _, err := Day2ContractForRepairProposal(proposal, window); err == nil { t.Fatal("unregistered repair adapter must fail closed") }
	proposal.AdapterID = Day2CampaignAdapterNodeMaintenance
	window.ProjectID = "project-b"
	if _, err := Day2ContractForRepairProposal(proposal, window); err == nil { t.Fatal("cross-project maintenance window must fail closed") }
	window.ProjectID = "project-a"
	window.MaxUnavailable = 0
	if _, err := Day2ContractForRepairProposal(proposal, window); err == nil { t.Fatal("maintenance window without maxUnavailable must fail closed") }
}

func remediationDigest(ch byte) string { b:=make([]byte,64); for i:=range b { b[i]=ch }; return "sha256:"+string(b) }
