package reliability

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	HealthObservationAuthority = "HEALTH_OBSERVATION_AUTHORITY_V1"
	ServiceHealthAuthority     = "SERVICE_HEALTH_AUTHORITY_V1"
	IncidentAuthority          = "INCIDENT_AUTHORITY_V1"
	SLOErrorBudgetAuthority    = "SLO_ERROR_BUDGET_AUTHORITY_V1"

	IncidentOpen         = "OPEN"
	IncidentAcknowledged = "ACKNOWLEDGED"
	IncidentResolved     = "RESOLVED"

	IncidentActionAcknowledge = "ACKNOWLEDGE"
	IncidentActionResolve     = "RESOLVE"

	CoverageUnknown  = "UNKNOWN"
	CoverageComplete = "COMPLETE"
)

type HealthObservation struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	ProjectID      string    `json:"projectId"`
	ClusterID      string    `json:"clusterId"`
	Health         string    `json:"health"`
	ObservedAt     time.Time `json:"observedAt"`
	SourceDigest   string    `json:"sourceDigest"`
}

type Incident struct {
	ID                string    `json:"id"`
	OrganizationID    string    `json:"organizationId"`
	ProjectID         string    `json:"projectId"`
	OperationID       string    `json:"operationId,omitempty"`
	ClusterID         string    `json:"clusterId,omitempty"`
	Service           string    `json:"service,omitempty"`
	Severity          string    `json:"severity"`
	State             string    `json:"state"`
	Revision          int64     `json:"revision"`
	AcknowledgedBy    string    `json:"acknowledgedBy,omitempty"`
	ResolvedBy        string    `json:"resolvedBy,omitempty"`
	ResolutionSummary string    `json:"resolutionSummary,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type SLOPolicy struct {
	ID                         string `json:"id"`
	OrganizationID             string `json:"organizationId"`
	ProjectID                  string `json:"projectId"`
	ClusterID                  string `json:"clusterId"`
	Name                       string `json:"name"`
	Revision                   int64  `json:"revision"`
	ObjectiveBasisPoints       int    `json:"objectiveBasisPoints"`
	WindowSeconds              int64  `json:"windowSeconds"`
	ObservationIntervalSeconds int64  `json:"observationIntervalSeconds"`
}

type ErrorBudgetProjection struct {
	CoverageStatus             string `json:"coverageStatus"`
	ExpectedObservations       int    `json:"expectedObservations"`
	ObservedObservations       int    `json:"observedObservations"`
	BadObservations            int    `json:"badObservations"`
	RemainingBudgetBasisPoints *int   `json:"remainingBudgetBasisPoints,omitempty"`
	BurnRatioMilli             *int   `json:"burnRatioMilli,omitempty"`
}

func ObservationIdentity(observation HealthObservation) (string, error) {
	if strings.TrimSpace(observation.OrganizationID) == "" || strings.TrimSpace(observation.ProjectID) == "" || strings.TrimSpace(observation.ClusterID) == "" {
		return "", errors.New("observation scope is required")
	}
	if strings.TrimSpace(observation.Health) == "" || observation.ObservedAt.IsZero() || strings.TrimSpace(observation.SourceDigest) == "" {
		return "", errors.New("observation health, timestamp and source digest are required")
	}
	canonical := strings.Join([]string{
		observation.OrganizationID,
		observation.ProjectID,
		observation.ClusterID,
		observation.Health,
		observation.ObservedAt.UTC().Format(time.RFC3339Nano),
		observation.SourceDigest,
	}, "\x00")
	digest := sha256.Sum256([]byte(canonical))
	return "hob_" + hex.EncodeToString(digest[:16]), nil
}

func TransitionIncident(current Incident, action, actor, summary string) (Incident, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return Incident{}, errors.New("incident lifecycle actor is required")
	}
	if current.State == IncidentResolved {
		return Incident{}, errors.New("resolved incident is terminal")
	}
	next := current
	switch action {
	case IncidentActionAcknowledge:
		if current.State != IncidentOpen {
			return Incident{}, fmt.Errorf("cannot acknowledge incident in state %s", current.State)
		}
		next.State = IncidentAcknowledged
		next.AcknowledgedBy = actor
	case IncidentActionResolve:
		if current.State != IncidentOpen && current.State != IncidentAcknowledged {
			return Incident{}, fmt.Errorf("cannot resolve incident in state %s", current.State)
		}
		summary = strings.TrimSpace(summary)
		if summary == "" {
			return Incident{}, errors.New("resolution summary is required")
		}
		next.State = IncidentResolved
		next.ResolvedBy = actor
		next.ResolutionSummary = summary
	default:
		return Incident{}, fmt.Errorf("unsupported incident action %q", action)
	}
	next.Revision++
	return next, nil
}

func ValidateSLOPolicy(policy SLOPolicy) error {
	if strings.TrimSpace(policy.OrganizationID) == "" || strings.TrimSpace(policy.ProjectID) == "" || strings.TrimSpace(policy.ClusterID) == "" || strings.TrimSpace(policy.Name) == "" {
		return errors.New("SLO policy organization, project, cluster and name are required")
	}
	if policy.ObjectiveBasisPoints <= 0 || policy.ObjectiveBasisPoints > 10000 {
		return errors.New("SLO objective must be between 1 and 10000 basis points")
	}
	if policy.WindowSeconds <= 0 {
		return errors.New("SLO window must be positive")
	}
	if policy.ObservationIntervalSeconds <= 0 || policy.ObservationIntervalSeconds > policy.WindowSeconds {
		return errors.New("SLO observation interval must be positive and no larger than the window")
	}
	if policy.WindowSeconds%policy.ObservationIntervalSeconds != 0 {
		return errors.New("SLO window must be an exact multiple of the observation interval")
	}
	return nil
}

func ProjectErrorBudget(policy SLOPolicy, observations []HealthObservation, windowStart, windowEnd time.Time) (ErrorBudgetProjection, error) {
	if err := ValidateSLOPolicy(policy); err != nil {
		return ErrorBudgetProjection{}, err
	}
	windowStart = windowStart.UTC()
	windowEnd = windowEnd.UTC()
	if !windowEnd.After(windowStart) {
		return ErrorBudgetProjection{}, errors.New("error budget window must have positive duration")
	}
	windowSeconds := int64(windowEnd.Sub(windowStart) / time.Second)
	if windowSeconds != policy.WindowSeconds {
		return ErrorBudgetProjection{}, errors.New("error budget projection window must match the SLO policy window")
	}
	expected := int(policy.WindowSeconds / policy.ObservationIntervalSeconds)
	interval := time.Duration(policy.ObservationIntervalSeconds) * time.Second
	buckets := make(map[int]HealthObservation, expected)
	observed := 0
	duplicate := false
	for _, observation := range observations {
		if observation.OrganizationID != policy.OrganizationID || observation.ProjectID != policy.ProjectID || observation.ClusterID != policy.ClusterID {
			continue
		}
		at := observation.ObservedAt.UTC()
		if at.Before(windowStart) || !at.Before(windowEnd) {
			continue
		}
		observed++
		bucket := int(at.Sub(windowStart) / interval)
		if _, exists := buckets[bucket]; exists {
			duplicate = true
			continue
		}
		buckets[bucket] = observation
	}
	projection := ErrorBudgetProjection{CoverageStatus: CoverageUnknown, ExpectedObservations: expected, ObservedObservations: observed}
	if duplicate || len(buckets) != expected {
		return projection, nil
	}
	bad := 0
	for index := 0; index < expected; index++ {
		observation, exists := buckets[index]
		if !exists {
			return projection, nil
		}
		switch observation.Health {
		case "HEALTHY":
		case "WARNING", "DEGRADED", "STALE", "CRITICAL":
			bad++
		default:
			return projection, nil
		}
	}
	projection.CoverageStatus = CoverageComplete
	projection.BadObservations = bad
	allowedBadBasisPoints := 10000 - policy.ObjectiveBasisPoints
	actualBadBasisPoints := bad * 10000 / expected
	remaining := allowedBadBasisPoints - actualBadBasisPoints
	burn := 0
	if allowedBadBasisPoints > 0 {
		burn = actualBadBasisPoints * 1000 / allowedBadBasisPoints
	}
	projection.RemainingBudgetBasisPoints = &remaining
	projection.BurnRatioMilli = &burn
	return projection, nil
}
