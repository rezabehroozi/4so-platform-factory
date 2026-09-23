package api

import (
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

const (
	applicationDeploymentOperationKind = "application.deploy"
	applicationDeploymentTargetPrefix  = "environment-binding:"
)

func projectApplicationDeliveryEvidence(projectID string, releases []controlplane.ApplicationRelease, bindings []controlplane.EnvironmentBinding, operations []controlplane.Operation) ([]reliability.DeliveryEvidence, error) {
	projectID = strings.TrimSpace(projectID)
	releasesByDigest := make(map[string]controlplane.ApplicationRelease, len(releases))
	for _, release := range releases {
		if release.ProjectID == projectID {
			releasesByDigest[release.Digest] = release
		}
	}
	bindingsByID := make(map[string]controlplane.EnvironmentBinding, len(bindings))
	for _, binding := range bindings {
		if binding.ProjectID == projectID {
			bindingsByID[binding.ID] = binding
		}
	}

	out := make([]reliability.DeliveryEvidence, 0)
	seenOperation := map[string]bool{}
	for _, operation := range operations {
		if operation.ProjectID != projectID || strings.TrimSpace(operation.Kind) != applicationDeploymentOperationKind {
			continue
		}
		eventType := ""
		switch operation.State {
		case controlplane.OperationSucceeded:
			eventType = reliability.DeliveryEventDeploymentSucceeded
		case controlplane.OperationFailed, controlplane.OperationRollbackFailed, controlplane.OperationNeedsOperator:
			eventType = reliability.DeliveryEventDeploymentFailed
		default:
			continue
		}
		if operation.ID == "" || seenOperation[operation.ID] {
			return nil, fmt.Errorf("duplicate or empty application deployment operation identity")
		}
		seenOperation[operation.ID] = true
		target := strings.TrimSpace(operation.TargetRef)
		if !strings.HasPrefix(target, applicationDeploymentTargetPrefix) {
			return nil, fmt.Errorf("application deployment %s has an invalid environment binding target", operation.ID)
		}
		bindingID := strings.TrimSpace(strings.TrimPrefix(target, applicationDeploymentTargetPrefix))
		binding, ok := bindingsByID[bindingID]
		if !ok {
			return nil, fmt.Errorf("application deployment %s references an unknown project environment binding", operation.ID)
		}
		release, ok := releasesByDigest[strings.TrimSpace(operation.DesiredRevision)]
		if !ok {
			return nil, fmt.Errorf("application deployment %s desired revision is not an immutable project release digest", operation.ID)
		}
		if operation.UpdatedAt.IsZero() {
			return nil, fmt.Errorf("application deployment %s has no terminal timestamp", operation.ID)
		}
		var committedAt *time.Time
		if release.SourceCommittedAt != nil {
			value := release.SourceCommittedAt.UTC()
			committedAt = &value
		}
		out = append(out, reliability.DeliveryEvidence{
			EvidenceID:        "deployment-result:" + operation.ID,
			ProjectID:         projectID,
			EventType:         eventType,
			OccurredAt:        operation.UpdatedAt.UTC(),
			OperationID:       operation.ID,
			ReleaseDigest:     release.Digest,
			Environment:       binding.Environment,
			SourceCommittedAt: committedAt,
		})
	}
	return out, nil
}
