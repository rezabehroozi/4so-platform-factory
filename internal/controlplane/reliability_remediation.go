package controlplane

import (
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/reliability"
)

func Day2ContractForRepairProposal(proposal reliability.RepairProposal) (Day2CampaignContract, error) {
	if proposal.Authority != reliability.RepairProposalAuthority || proposal.ExecutionAuthority != Day2CampaignEngineAuthority || proposal.ExecutionAuthority != reliability.Day2ExecutionAuthority {
		return Day2CampaignContract{}, fmt.Errorf("%w: repair proposal execution authority is invalid", ErrValidation)
	}
	if strings.TrimSpace(proposal.OrganizationID) == "" || strings.TrimSpace(proposal.ProjectID) == "" || strings.TrimSpace(proposal.ClusterID) == "" || strings.TrimSpace(proposal.IncidentID) == "" || proposal.IncidentRevision <= 0 || !applicationPlatformDigestPattern.MatchString(strings.ToLower(strings.TrimSpace(proposal.CorrelationDigest))) || !applicationPlatformDigestPattern.MatchString(strings.ToLower(strings.TrimSpace(proposal.Digest))) {
		return Day2CampaignContract{}, fmt.Errorf("%w: repair proposal scope/incident/evidence is incomplete", ErrValidation)
	}
	if !proposal.IndependentApprovalRequired {
		return Day2CampaignContract{}, fmt.Errorf("%w: reliability repair proposals require independent approval", ErrValidation)
	}
	var contract Day2CampaignContract
	switch strings.TrimSpace(proposal.AdapterID) {
	case Day2CampaignAdapterNodeMaintenance:
		if proposal.Action != reliability.RepairActionNodeRemediation && proposal.Action != reliability.RepairActionNodeMaintenance {
			return Day2CampaignContract{}, fmt.Errorf("%w: repair action does not match node-maintenance adapter", ErrValidation)
		}
		contract = Day2ContractForMaintenance(ClusterMaintenanceRun{})
	case Day2CampaignAdapterFleetUpgrade:
		if proposal.Action != reliability.RepairActionFleetUpgrade {
			return Day2CampaignContract{}, fmt.Errorf("%w: repair action does not match fleet-upgrade adapter", ErrValidation)
		}
		contract = Day2ContractForFleetUpgrade(FleetUpgradeCampaign{})
	default:
		return Day2CampaignContract{}, fmt.Errorf("%w: repair proposal adapter is not registered", ErrValidation)
	}
	if contract.Authority != Day2CampaignEngineAuthority || contract.Adapter.ID != proposal.AdapterID || !contract.Impact.RequireApproval || !contract.Impact.RequireMaintenanceWindow || !contract.Impact.RequireRecoveryCheckpoint || len(contract.ExecutionFences) == 0 || len(contract.RequiredEvidence) == 0 {
		return Day2CampaignContract{}, fmt.Errorf("%w: selected day2 adapter does not satisfy repair safety contract", ErrValidation)
	}
	return contract, nil
}
