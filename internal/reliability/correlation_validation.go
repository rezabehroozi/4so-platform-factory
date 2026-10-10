package reliability

import (
	"errors"
	"strings"
)

// ValidateSignalCorrelation replays the bounded owner-layer authority checks on
// a correlation packet. The packet remains advisory; execution authority is
// owned by the Day-2 engine.
func ValidateSignalCorrelation(correlation SignalCorrelation) error {
	if correlation.Authority != SignalCorrelationAuthority || strings.TrimSpace(correlation.OrganizationID) == "" || strings.TrimSpace(correlation.ProjectID) == "" || strings.TrimSpace(correlation.ClusterID) == "" || strings.TrimSpace(correlation.Service) == "" {
		return errors.New("signal correlation authority/scope is invalid")
	}
	if correlation.SignalCount < 2 || correlation.SignalCount > 64 || len(correlation.SignalKinds) < 2 || len(correlation.SignalKinds) > correlation.SignalCount || len(correlation.EvidenceDigests) != correlation.SignalCount || len(correlation.SignalFingerprints) != correlation.SignalCount {
		return errors.New("signal correlation cardinality is invalid")
	}
	if correlation.MaxSeverity < 1 || correlation.MaxSeverity > 5 || correlation.WindowStartedAt.IsZero() || correlation.ObservedAt.IsZero() || !correlation.ObservedAt.After(correlation.WindowStartedAt) || correlation.ObservedAt.Sub(correlation.WindowStartedAt) > 24*60*60*1e9 {
		return errors.New("signal correlation severity/window is invalid")
	}
	for i, kind := range correlation.SignalKinds {
		if !validSignalKind(kind) || (i > 0 && correlation.SignalKinds[i-1] >= kind) {
			return errors.New("signal correlation kinds are invalid or non-canonical")
		}
	}
	for _, values := range [][]string{correlation.EvidenceDigests, correlation.SignalFingerprints} {
		for i, value := range values {
			if !isCorrelationDigest(value) || (i > 0 && values[i-1] >= value) {
				return errors.New("signal correlation evidence identities are invalid or non-canonical")
			}
		}
	}
	expectedConfidence := CorrelationMedium
	if len(correlation.SignalKinds) >= 3 {
		expectedConfidence = CorrelationHigh
	}
	if correlation.Confidence != expectedConfidence || correlation.RemediationEligible != (correlation.MaxSeverity >= 4) {
		return errors.New("signal correlation confidence/remediation eligibility is inconsistent")
	}
	if !isCorrelationDigest(correlation.Digest) || digestSignalCorrelation(correlation) != strings.ToLower(strings.TrimSpace(correlation.Digest)) {
		return errors.New("signal correlation content digest does not match correlation fields")
	}
	return nil
}

// ValidateRepairProposal replays the owner-layer structural and content-address
// checks before a repair proposal crosses into an execution authority. It does
// not authorize execution; the Day-2 engine still owns window, approval, fence,
// execution, verification, evidence and recovery semantics.
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
	if proposal.AdapterID != RepairAdapterNodeMaintenance || (proposal.Action != RepairActionNodeRemediation && proposal.Action != RepairActionNodeMaintenance) || proposal.Impact != "targeted" {
		return errors.New("repair proposal action/adapter/impact is not admitted")
	}
	targets, err := normalizeCorrelationTargets(proposal.TargetIDs)
	if err != nil {
		return err
	}
	for i := range targets {
		if proposal.TargetIDs[i] != targets[i] {
			return errors.New("repair proposal target identities are not canonical")
		}
	}
	if proposal.CorrelationObservedAt.IsZero() || proposal.CreatedAt.IsZero() || proposal.ValidUntil.IsZero() || proposal.CreatedAt.Before(proposal.CorrelationObservedAt) || !proposal.CreatedAt.Before(proposal.ValidUntil) || !proposal.ValidUntil.Equal(proposal.CorrelationObservedAt.Add(RepairCorrelationTTL)) {
		return errors.New("repair proposal temporal authority is invalid")
	}
	if digestRepairProposal(proposal) != strings.ToLower(strings.TrimSpace(proposal.Digest)) {
		return errors.New("repair proposal content digest does not match proposal fields")
	}
	return nil
}
