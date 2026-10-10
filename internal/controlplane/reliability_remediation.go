package controlplane

import (
	"fmt"
	"strings"

	"platform.4so.io/factory/internal/reliability"
)

func Day2ContractForRepairProposal(proposal reliability.RepairProposal, window ClusterMaintenanceWindow) (Day2CampaignContract, error) {
	if err := reliability.ValidateRepairProposal(proposal); err != nil {
		return Day2CampaignContract{}, fmt.Errorf("%w: invalid repair proposal: %v", ErrValidation, err)
	}
	if proposal.ExecutionAuthority != Day2CampaignEngineAuthority || proposal.AdapterID != Day2CampaignAdapterNodeMaintenance {
		return Day2CampaignContract{}, fmt.Errorf("%w: repair proposal execution adapter is not admitted", ErrValidation)
	}
	if strings.TrimSpace(window.ID) == "" || strings.TrimSpace(window.ProjectID) != strings.TrimSpace(proposal.ProjectID) || strings.TrimSpace(window.ClusterID) != strings.TrimSpace(proposal.ClusterID) || window.MaxUnavailable <= 0 {
		return Day2CampaignContract{}, fmt.Errorf("%w: maintenance window authority/scope/maxUnavailable is invalid", ErrValidation)
	}
	if proposal.Action != reliability.RepairActionNodeRemediation && proposal.Action != reliability.RepairActionNodeMaintenance {
		return Day2CampaignContract{}, fmt.Errorf("%w: repair action does not map to node-maintenance authority", ErrValidation)
	}
	run := ClusterMaintenanceRun{
		NodeNames:      append([]string(nil), proposal.TargetIDs...),
		MaxUnavailable: window.MaxUnavailable,
	}
	contract := Day2ContractForMaintenance(run, window)
	if err := ValidateDay2CampaignContract(contract); err != nil {
		return Day2CampaignContract{}, fmt.Errorf("%w: day2 repair contract invalid: %v", ErrValidation, err)
	}
	if contract.Authority != Day2CampaignEngineAuthority || contract.Adapter.ID != proposal.AdapterID || contract.Impact.MaintenanceWindowID != window.ID || !contract.Impact.RequireApproval || !contract.Impact.RequireMaintenanceWindow || !contract.Impact.RequireRecoveryCheckpoint || len(contract.ExecutionFences) == 0 || len(contract.RequiredEvidence) == 0 {
		return Day2CampaignContract{}, fmt.Errorf("%w: selected day2 adapter does not satisfy repair safety contract", ErrValidation)
	}
	return contract, nil
}
