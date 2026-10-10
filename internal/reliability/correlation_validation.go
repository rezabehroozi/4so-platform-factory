package reliability

import (
	"errors"
	"strings"
)

// ValidateRepairProposal replays the owner-layer structural and content-address
// checks before a repair proposal crosses into an execution authority. It does
// not authorize execution; the Day-2 engine still owns window, approval, fence,
// execution and recovery semantics.
func ValidateRepairProposal(proposal RepairProposal) error {
	if proposal.Authority != RepairProposalAuthority || proposal.ExecutionAuthority != Day2ExecutionAuthority {
		return errors.New("repair proposal authority is invalid")
	}
	if strings.TrimSpace(proposal.OrganizationID) == "" || strings.TrimSpace(proposal.ProjectID) == "" || strings.TrimSpace(proposal.ClusterID) == "" || strings.TrimSpace(proposal.Service) == "" || strings.TrimSpace(proposal.IncidentID) == "" || proposal.IncidentRevision <= 0 {
		return errors.New("repair proposal scope/incident authority is incomplete")
	}
	if !isCorrelationDigest(proposal.CorrelationDigest) || !isCorrelationDigest(proposal.Digest) || !proposal.IndependentApprovalRequired {
		return errors.New("repair proposal evidence/approval authority is incomplete")
	}
	if proposal.AdapterID != "kubernetes-node-maintenance-v1" || (proposal.Action != RepairActionNodeRemediation && proposal.Action != RepairActionNodeMaintenance) || proposal.Impact != "targeted" {
		return errors.New("repair proposal action/adapter/impact is not admitted")
	}
	if _, err := normalizeCorrelationTargets(proposal.TargetIDs); err != nil {
		return err
	}
	copy := proposal
	copy.Digest = ""
	if correlationDigest(copy) != strings.ToLower(strings.TrimSpace(proposal.Digest)) {
		return errors.New("repair proposal content digest does not match proposal fields")
	}
	return nil
}
