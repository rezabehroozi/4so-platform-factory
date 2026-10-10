package accelerator

import (
	"testing"
	"time"
)

func TestHealthDecisionRequiresFreshNonFutureObservation(t *testing.T) {
	now := time.Date(2026, 10, 10, 13, 0, 0, 0, time.UTC)
	base := DeviceObservation{
		DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a",
		Observed: true, Source: SourceTargetAgent, Health: HealthDegraded,
	}

	fresh := base
	fresh.ObservedAt = now.Add(-5 * time.Minute)
	decision := AssessHealth(fresh, now)
	if !decision.RepairRequired || !decision.ReplacementAllowed || decision.RequiredAuthority != PartitionLifecycleAuthority {
		t.Fatalf("fresh admitted observation must retain durable remediation authority: %#v", decision)
	}

	stale := base
	stale.ObservedAt = now.Add(-MaxHealthObservationAge - time.Second)
	decision = AssessHealth(stale, now)
	if decision.RepairRequired || decision.ReplacementAllowed || decision.RequiredAuthority != "" {
		t.Fatalf("stale health observation must not authorize remediation: %#v", decision)
	}

	future := base
	future.ObservedAt = now.Add(time.Second)
	decision = AssessHealth(future, now)
	if decision.RepairRequired || decision.ReplacementAllowed || decision.RequiredAuthority != "" {
		t.Fatalf("future health observation must not authorize remediation: %#v", decision)
	}
}
