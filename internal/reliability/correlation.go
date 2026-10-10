package reliability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	SignalCorrelationAuthority = "FLEET_SIGNAL_CORRELATION_AUTHORITY_V1"
	RepairProposalAuthority     = "DURABLE_REPAIR_PROPOSAL_AUTHORITY_V1"
	Day2ExecutionAuthority      = "GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1"

	CorrelationMedium = "MEDIUM"
	CorrelationHigh   = "HIGH"
)

type SignalKind string

const (
	SignalMetric  SignalKind = "METRIC"
	SignalLog     SignalKind = "LOG"
	SignalTrace   SignalKind = "TRACE"
	SignalNetwork SignalKind = "NETWORK"
	SignalChange  SignalKind = "CHANGE"
)

type SignalObservation struct {
	Kind           SignalKind `json:"kind"`
	OrganizationID string     `json:"organizationId"`
	ProjectID      string     `json:"projectId"`
	ClusterID      string     `json:"clusterId"`
	Service        string     `json:"service"`
	Source         string     `json:"source"`
	Fingerprint    string     `json:"fingerprint"`
	EvidenceDigest string     `json:"evidenceDigest"`
	Complete       bool       `json:"complete"`
	Severity       int        `json:"severity"`
	ObservedAt     time.Time  `json:"observedAt"`
}

type SignalCorrelation struct {
	Authority           string       `json:"authority"`
	OrganizationID      string       `json:"organizationId"`
	ProjectID           string       `json:"projectId"`
	ClusterID           string       `json:"clusterId"`
	Service             string       `json:"service"`
	SignalKinds         []SignalKind `json:"signalKinds"`
	SignalCount         int          `json:"signalCount"`
	MaxSeverity         int          `json:"maxSeverity"`
	WindowStartedAt     time.Time    `json:"windowStartedAt"`
	ObservedAt          time.Time    `json:"observedAt"`
	Confidence          string       `json:"confidence"`
	RemediationEligible bool         `json:"remediationEligible"`
	EvidenceDigests     []string     `json:"evidenceDigests"`
	SignalFingerprints  []string     `json:"signalFingerprints"`
	Digest              string       `json:"digest"`
}

func CorrelateSignals(signals []SignalObservation, now time.Time, window time.Duration) (SignalCorrelation, error) {
	if now.IsZero() || window <= 0 || window > 24*time.Hour {
		return SignalCorrelation{}, errors.New("correlation now/window is invalid")
	}
	if len(signals) < 2 || len(signals) > 64 {
		return SignalCorrelation{}, errors.New("correlation requires between 2 and 64 signals")
	}
	canonical := append([]SignalObservation(nil), signals...)
	var orgID, projectID, clusterID, service string
	kindSet := map[SignalKind]bool{}
	evidenceSet := map[string]bool{}
	fingerprintSet := map[string]bool{}
	maxSeverity := 0
	windowStart := now.Add(-window)
	for i := range canonical {
		s := &canonical[i]
		s.OrganizationID = strings.TrimSpace(s.OrganizationID)
		s.ProjectID = strings.TrimSpace(s.ProjectID)
		s.ClusterID = strings.TrimSpace(s.ClusterID)
		s.Service = strings.TrimSpace(s.Service)
		s.Source = strings.TrimSpace(s.Source)
		s.Fingerprint = strings.ToLower(strings.TrimSpace(s.Fingerprint))
		s.EvidenceDigest = strings.ToLower(strings.TrimSpace(s.EvidenceDigest))
		if !validSignalKind(s.Kind) || s.OrganizationID == "" || s.ProjectID == "" || s.ClusterID == "" || s.Service == "" || s.Source == "" {
			return SignalCorrelation{}, errors.New("signal identity/scope/source is incomplete")
		}
		if !s.Complete || s.ObservedAt.IsZero() || s.ObservedAt.Before(windowStart) || s.ObservedAt.After(now) {
			return SignalCorrelation{}, errors.New("signal is incomplete, stale or from the future")
		}
		if s.Severity < 1 || s.Severity > 5 || !isCorrelationDigest(s.Fingerprint) || !isCorrelationDigest(s.EvidenceDigest) {
			return SignalCorrelation{}, errors.New("signal severity/fingerprint/evidence is invalid")
		}
		if i == 0 {
			orgID, projectID, clusterID, service = s.OrganizationID, s.ProjectID, s.ClusterID, s.Service
		} else if s.OrganizationID != orgID || s.ProjectID != projectID || s.ClusterID != clusterID || s.Service != service {
			return SignalCorrelation{}, errors.New("signals must share exact organization/project/cluster/service scope")
		}
		kindSet[s.Kind] = true
		evidenceSet[s.EvidenceDigest] = true
		fingerprintSet[s.Fingerprint] = true
		if s.Severity > maxSeverity {
			maxSeverity = s.Severity
		}
	}
	if len(kindSet) < 2 {
		return SignalCorrelation{}, errors.New("correlation requires at least two independent signal kinds")
	}
	if len(evidenceSet) != len(canonical) || len(fingerprintSet) != len(canonical) {
		return SignalCorrelation{}, errors.New("duplicate signal evidence/fingerprint is not independent correlation evidence")
	}
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Kind != canonical[j].Kind {
			return canonical[i].Kind < canonical[j].Kind
		}
		if canonical[i].Source != canonical[j].Source {
			return canonical[i].Source < canonical[j].Source
		}
		return canonical[i].Fingerprint < canonical[j].Fingerprint
	})
	kinds := make([]SignalKind, 0, len(kindSet))
	for kind := range kindSet {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	confidence := CorrelationMedium
	if len(kinds) >= 3 {
		confidence = CorrelationHigh
	}
	out := SignalCorrelation{
		Authority: SignalCorrelationAuthority,
		OrganizationID: orgID,
		ProjectID: projectID,
		ClusterID: clusterID,
		Service: service,
		SignalKinds: kinds,
		SignalCount: len(canonical),
		MaxSeverity: maxSeverity,
		WindowStartedAt: windowStart.UTC(),
		ObservedAt: now.UTC(),
		Confidence: confidence,
		RemediationEligible: maxSeverity >= 4 && len(kinds) >= 2,
		EvidenceDigests: sortedCorrelationKeys(evidenceSet),
		SignalFingerprints: sortedCorrelationKeys(fingerprintSet),
	}
	out.Digest = correlationDigest(struct {
		Authority           string              `json:"authority"`
		OrganizationID      string              `json:"organizationId"`
		ProjectID           string              `json:"projectId"`
		ClusterID           string              `json:"clusterId"`
		Service             string              `json:"service"`
		Signals             []SignalObservation `json:"signals"`
		Confidence          string              `json:"confidence"`
		RemediationEligible bool                `json:"remediationEligible"`
	}{out.Authority, out.OrganizationID, out.ProjectID, out.ClusterID, out.Service, canonical, out.Confidence, out.RemediationEligible})
	return out, nil
}

func validSignalKind(kind SignalKind) bool {
	switch kind {
	case SignalMetric, SignalLog, SignalTrace, SignalNetwork, SignalChange:
		return true
	default:
		return false
	}
}

type RepairAction string

const (
	RepairActionNodeRemediation RepairAction = "NODE_REMEDIATION"
	RepairActionNodeMaintenance RepairAction = "NODE_MAINTENANCE"
)

type RepairProposal struct {
	Authority                   string       `json:"authority"`
	ExecutionAuthority          string       `json:"executionAuthority"`
	AdapterID                   string       `json:"adapterId"`
	OrganizationID              string       `json:"organizationId"`
	ProjectID                   string       `json:"projectId"`
	ClusterID                   string       `json:"clusterId"`
	Service                     string       `json:"service"`
	IncidentID                  string       `json:"incidentId"`
	IncidentRevision            int64        `json:"incidentRevision"`
	CorrelationDigest           string       `json:"correlationDigest"`
	Action                      RepairAction `json:"action"`
	TargetIDs                   []string     `json:"targetIds"`
	IndependentApprovalRequired bool         `json:"independentApprovalRequired"`
	Impact                      string       `json:"impact"`
	Digest                      string       `json:"digest"`
}

func BuildRepairProposal(correlation SignalCorrelation, incident Incident, action RepairAction, targetIDs []string) (RepairProposal, error) {
	if correlation.Authority != SignalCorrelationAuthority || !isCorrelationDigest(correlation.Digest) || !correlation.RemediationEligible {
		return RepairProposal{}, errors.New("correlation is not eligible for remediation")
	}
	if strings.TrimSpace(incident.ID) == "" || incident.Revision <= 0 || (incident.State != IncidentOpen && incident.State != IncidentAcknowledged) {
		return RepairProposal{}, errors.New("incident must be open/acknowledged with a valid revision")
	}
	if strings.TrimSpace(incident.OrganizationID) != correlation.OrganizationID || strings.TrimSpace(incident.ProjectID) != correlation.ProjectID || strings.TrimSpace(incident.ClusterID) != correlation.ClusterID || strings.TrimSpace(incident.Service) != correlation.Service {
		return RepairProposal{}, errors.New("incident scope does not match signal correlation")
	}
	if action != RepairActionNodeRemediation && action != RepairActionNodeMaintenance {
		return RepairProposal{}, fmt.Errorf("repair action %q is not allow-listed by the current durable bridge", action)
	}
	targets, err := normalizeCorrelationTargets(targetIDs)
	if err != nil {
		return RepairProposal{}, err
	}
	proposal := RepairProposal{
		Authority: RepairProposalAuthority,
		ExecutionAuthority: Day2ExecutionAuthority,
		AdapterID: "kubernetes-node-maintenance-v1",
		OrganizationID: correlation.OrganizationID,
		ProjectID: correlation.ProjectID,
		ClusterID: correlation.ClusterID,
		Service: correlation.Service,
		IncidentID: strings.TrimSpace(incident.ID),
		IncidentRevision: incident.Revision,
		CorrelationDigest: correlation.Digest,
		Action: action,
		TargetIDs: targets,
		IndependentApprovalRequired: true,
		Impact: "targeted",
	}
	proposal.Digest = correlationDigest(proposal)
	return proposal, nil
}

func normalizeCorrelationTargets(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 1000 {
		return nil, errors.New("repair proposal requires 1..1000 bounded target ids")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || seen[value] {
			return nil, errors.New("repair target ids contain empty or duplicate identity")
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func sortedCorrelationKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func correlationDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isCorrelationDigest(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
