package controlplane

import (
	"testing"
	"time"

	"platform.4so.io/factory/internal/reliability"
)

func TestRepairProposalAdmissionRequiresCurrentIncidentRevisionAndState(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	correlation, err := reliability.CorrelateSignals([]reliability.SignalObservation{
		{Kind: reliability.SignalMetric, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "prometheus", Fingerprint: remediationDigest('a'), EvidenceDigest: remediationDigest('b'), Complete: true, Severity: 4, ObservedAt: now},
		{Kind: reliability.SignalNetwork, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Source: "network-observer", Fingerprint: remediationDigest('c'), EvidenceDigest: remediationDigest('d'), Complete: true, Severity: 4, ObservedAt: now},
	}, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	incident := reliability.Incident{ID: "inc-1", OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", Service: "orders", Revision: 7, State: reliability.IncidentOpen, Severity: "CRITICAL"}
	proposal, err := reliability.BuildRepairProposal(correlation, incident, reliability.RepairActionNodeRemediation, []string{"node-a"}, now)
	if err != nil {
		t.Fatal(err)
	}
	window := ClusterMaintenanceWindow{
		ResourceMeta: ResourceMeta{ID: "mw-1", Revision: 1},
		ProjectID: "project-a", ClusterID: "cluster-a", State: ClusterMaintenanceWindowActive,
		StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), MaxUnavailable: 1,
	}

	if _, err := Day2ContractForRepairProposal(proposal, incident, window, now); err != nil {
		t.Fatalf("matching current incident must remain eligible: %v", err)
	}

	advanced := incident
	advanced.Revision++
	if _, err := Day2ContractForRepairProposal(proposal, advanced, window, now); err == nil {
		t.Fatal("repair proposal must not execute after incident revision advances")
	}

	resolved := incident
	resolved.State = reliability.IncidentResolved
	if _, err := Day2ContractForRepairProposal(proposal, resolved, window, now); err == nil {
		t.Fatal("repair proposal must not execute after incident resolves")
	}

	foreign := incident
	foreign.ProjectID = "project-b"
	if _, err := Day2ContractForRepairProposal(proposal, foreign, window, now); err == nil {
		t.Fatal("repair proposal must not execute against a cross-project incident readback")
	}
}
