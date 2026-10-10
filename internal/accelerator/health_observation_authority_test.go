package accelerator

import (
	"testing"
	"time"
)

func TestHealthDecisionRequiresObservedDeviceIdentityAndAdmittedSource(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 30, 0, 0, time.UTC)

	anonymous := AssessHealth(DeviceObservation{Observed: true, ObservedAt: now, Health: HealthDegraded})
	if anonymous.RepairRequired || anonymous.ReplacementAllowed || anonymous.RequiredAuthority != "" {
		t.Fatalf("anonymous health observation must not authorize remediation: %#v", anonymous)
	}

	unadmitted := AssessHealth(DeviceObservation{DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a", Observed: true, ObservedAt: now, Source: ObservationSource("static-label"), Health: HealthUnhealthy})
	if unadmitted.RepairRequired || unadmitted.ReplacementAllowed || unadmitted.RequiredAuthority != "" {
		t.Fatalf("unadmitted health source must not authorize remediation: %#v", unadmitted)
	}
}
