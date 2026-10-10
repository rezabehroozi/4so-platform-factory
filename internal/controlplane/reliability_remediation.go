package controlplane

import (
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/reliability"
)

func Day2ContractForRepairProposal(proposal reliability.RepairProposal, window ClusterMaintenanceWindow, now time.Time) (Day2CampaignContract, error) {
	if err := reliability.ValidateRepairProposal(proposal); err != nil {
		return Day2CampaignContract{}, fmt.Errorf("%w: invalid repair proposal: %v", ErrValidation, err)
	}
	if proposal.ExecutionAuthority != GeneralizedDay2CampaignAuthorityMethod || proposal.AdapterID != string(Day2CampaignAdapterNodeMaintenance) {
		return Day2CampaignContract{}, fmt.Errorf("%w: repair proposal execution adapter is not admitted", ErrValidation)
	}
	if now.IsZero() || now.Before(proposal.CreatedAt) || !now.Before(proposal.ValidUntil) {
		return Day2CampaignContract{}, fmt.Errorf("%w: repair proposal is not currently valid", ErrPrerequisite)
	}
	if strings.TrimSpace(window.ID) == "" || window.State != ClusterMaintenanceWindowActive || strings.TrimSpace(window.ProjectID) != strings.TrimSpace(proposal.ProjectID) || strings.TrimSpace(window.ClusterID) != strings.TrimSpace(proposal.ClusterID) || window.MaxUnavailable <= 0 {
		return Day2CampaignContract{}, fmt.Errorf("%w: maintenance window authority/scope/maxUnavailable is invalid", ErrValidation)
	}
	if err := ValidateDay2ExecutionWindow(window.StartsAt, window.EndsAt, now); err != nil {
		return Day2CampaignContract{}, err
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
	if contract.Authority != GeneralizedDay2CampaignAuthorityMethod || contract.Adapter != Day2CampaignAdapterNodeMaintenance || !contract.IndependentApproval || !contract.WindowRequired || !contract.FencedExecution || !contract.VerificationRequired || !contract.EvidenceRequired || contract.TargetCount != len(proposal.TargetIDs) || contract.MaxUnavailable != window.MaxUnavailable || !contract.WindowStart.Equal(window.StartsAt) || !contract.WindowEnd.Equal(window.EndsAt) {
		return Day2CampaignContract{}, fmt.Errorf("%w: selected day2 adapter does not satisfy repair safety contract", ErrValidation)
	}
	return contract, nil
}
