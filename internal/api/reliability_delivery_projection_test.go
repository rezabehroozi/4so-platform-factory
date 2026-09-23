package api

import (
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

func TestApplicationDeliveryProjectionUsesTerminalDurableOperationAndReleaseProvenance(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	committed := start.Add(time.Hour)
	deployed := start.Add(3 * time.Hour)
	digest := "sha256:" + strings.Repeat("a", 64)
	release := controlplane.ApplicationRelease{
		ResourceMeta:       controlplane.ResourceMeta{ID: "rel-1"},
		ProjectID:          "prj-1",
		Digest:             digest,
		SourceCommittedAt:  &committed,
	}
	binding := controlplane.EnvironmentBinding{
		ResourceMeta: controlplane.ResourceMeta{ID: "binding-1"},
		ProjectID:    "prj-1",
		Environment:  "production",
	}
	operation := controlplane.Operation{
		ResourceMeta:    controlplane.ResourceMeta{ID: "op-1", UpdatedAt: deployed},
		ProjectID:       "prj-1",
		Kind:            applicationDeploymentOperationKind,
		TargetRef:       applicationDeploymentTargetPrefix + binding.ID,
		DesiredRevision: digest,
		State:           controlplane.OperationSucceeded,
	}
	evidence, err := projectApplicationDeliveryEvidence("prj-1", []controlplane.ApplicationRelease{release}, []controlplane.EnvironmentBinding{binding}, []controlplane.Operation{operation})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].OperationID != operation.ID || evidence[0].ReleaseDigest != digest || evidence[0].Environment != "production" || evidence[0].SourceCommittedAt == nil || !evidence[0].SourceCommittedAt.Equal(committed) {
		t.Fatalf("deployment evidence=%#v", evidence)
	}
	insights, err := reliability.BuildDeliveryInsights("prj-1", start, start.Add(24*time.Hour), evidence)
	if err != nil {
		t.Fatal(err)
	}
	if insights.DeploymentFrequency.Status != reliability.DeliveryMetricObserved || insights.ChangeFailureRate.Status != reliability.DeliveryMetricObserved || insights.LeadTimeForChanges.Status != reliability.DeliveryMetricObserved || insights.LeadTimeForChanges.Value != 7200 {
		t.Fatalf("insights=%#v", insights)
	}
}

func TestApplicationDeliveryProjectionFailsClosedOnUnknownReleaseDigest(t *testing.T) {
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	binding := controlplane.EnvironmentBinding{ResourceMeta: controlplane.ResourceMeta{ID: "binding-1"}, ProjectID: "prj-1", Environment: "production"}
	operation := controlplane.Operation{
		ResourceMeta:    controlplane.ResourceMeta{ID: "op-1", UpdatedAt: now},
		ProjectID:       "prj-1",
		Kind:            applicationDeploymentOperationKind,
		TargetRef:       applicationDeploymentTargetPrefix + binding.ID,
		DesiredRevision: "sha256:" + strings.Repeat("f", 64),
		State:           controlplane.OperationFailed,
	}
	if _, err := projectApplicationDeliveryEvidence("prj-1", nil, []controlplane.EnvironmentBinding{binding}, []controlplane.Operation{operation}); err == nil {
		t.Fatal("unknown release digest became delivery evidence")
	}
}
