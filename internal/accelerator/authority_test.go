package accelerator

import (
	"testing"
	"time"
)

func TestInventoryRequiresObservedTargetEvidence(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	_, err := BuildInventory([]DeviceObservation{{
		DeviceID: "gpu-0", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100",
		MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now, Observed: false,
	}})
	if err == nil {
		t.Fatal("unobserved accelerator inventory must fail closed")
	}
	_, err = BuildInventory([]DeviceObservation{{
		DeviceID: "gpu-0", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100",
		MemoryMiB: 81920, Health: HealthHealthy, Source: "static-label", ObservedAt: now, Observed: true,
	}})
	if err == nil {
		t.Fatal("static labels must not become accelerator inventory authority")
	}
	inv, err := BuildInventory([]DeviceObservation{{
		DeviceID: "gpu-0", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100",
		MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now, Observed: true,
		Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Authority != InventoryAuthority || len(inv.Devices) != 1 || inv.Devices[0].DeviceID != "gpu-0" {
		t.Fatalf("unexpected inventory: %#v", inv)
	}
}

func TestPlacementIsScopedCapacityAwareAndNeverReselectsAllocatedDevice(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	inv, err := BuildInventory([]DeviceObservation{
		{DeviceID: "gpu-b", ClusterID: "cluster-a", NodeID: "node-b", Vendor: "nvidia", Model: "h100", MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now, Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
		{DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100", MemoryMiB: 81920, Health: HealthHealthy, Source: SourceDevicePlugin, ObservedAt: now, Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
		{DeviceID: "gpu-unknown", ClusterID: "cluster-a", NodeID: "node-c", Vendor: "nvidia", Model: "h100", MemoryMiB: 81920, Health: HealthUnknown, Source: SourceDevicePlugin, ObservedAt: now, Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
	})
	if err != nil { t.Fatal(err) }
	class := GPUClass{Authority: GPUClassAuthority, ID: "h100-mig", Vendor: "nvidia", MinMemoryMiB: 80000, RequiredCapabilities: []string{"compute.cuda", "partition.mig"}, AllowedPartitionModes: []PartitionMode{PartitionMIG}}
	quota := Quota{Authority: QuotaPlacementAuthority, OrganizationID: "org-a", ProjectID: "project-a", ClassID: class.ID, MaxDevices: 2, MaxMemoryMiB: 163840}
	usage := Usage{Devices: 0, MemoryMiB: 0}
	plan, err := PlanPlacement(inv, class, quota, usage, PlacementRequest{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: class.ID, Devices: 2, MemoryMiB: 160000, PartitionMode: PartitionMIG}, now)
	if err != nil { t.Fatal(err) }
	if len(plan.DeviceIDs) != 2 || plan.DeviceIDs[0] != "gpu-a" || plan.DeviceIDs[1] != "gpu-b" {
		t.Fatalf("placement must be deterministic over healthy observed capacity: %#v", plan)
	}
	one, err := PlanPlacement(inv, class, quota, Usage{Devices: 1, MemoryMiB: 81920, AllocatedDeviceIDs: []string{"gpu-a"}}, PlacementRequest{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: class.ID, Devices: 1, MemoryMiB: 80000, PartitionMode: PartitionMIG}, now)
	if err != nil { t.Fatal(err) }
	if len(one.DeviceIDs) != 1 || one.DeviceIDs[0] != "gpu-b" {
		t.Fatalf("already allocated gpu must never be selected again: %#v", one)
	}
	if _, err := PlanPlacement(inv, class, quota, Usage{Devices: 1, MemoryMiB: 81920}, PlacementRequest{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: class.ID, Devices: 2, MemoryMiB: 160000, PartitionMode: PartitionMIG}, now); err == nil {
		t.Fatal("quota oversubscription must be rejected")
	}
	if _, err := PlanPlacement(inv, class, quota, usage, PlacementRequest{OrganizationID: "org-a", ProjectID: "project-b", ClusterID: "cluster-a", ClassID: class.ID, Devices: 1, MemoryMiB: 80000, PartitionMode: PartitionMIG}, now); err == nil {
		t.Fatal("cross-project quota use must be rejected")
	}
}

func TestPartitionLifecycleUsesFenceAndAuthoritativeReadbackForUnknownOutcome(t *testing.T) {
	plan := PlacementPlan{Authority: QuotaPlacementAuthority, OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: "h100-mig", DeviceIDs: []string{"gpu-a"}, PartitionMode: PartitionMIG, RequestedDevices: 1, RequestedMemoryMiB: 40000, PlanDigest: digest64('a')}
	op, err := NewPartitionOperation(plan, "op-1", "idem-1", 7, PartitionCreate, "gpu-a", "partition-1", 3)
	if err != nil { t.Fatal(err) }
	unknown := ResolvePartitionOutcome(op, OutcomeUnknown, PartitionReadback{})
	if unknown.State != PartitionStateRecoveryRequired || !unknown.RecoveryRequired || unknown.RetryAllowed {
		t.Fatalf("unknown outcome must require readback without replay: %#v", unknown)
	}
	resolved := ResolvePartitionOutcome(op, OutcomeUnknown, PartitionReadback{Observed: true, OperationID: op.OperationID, FenceToken: op.FenceToken, PlanDigest: op.PlanDigest, DeviceID: "gpu-a", PartitionID: "partition-1", Generation: 4, State: PartitionStateReady, EvidenceDigest: digest64('b')})
	if resolved.State != PartitionStateReady || resolved.RecoveryRequired || resolved.RetryAllowed || resolved.EvidenceDigest == "" {
		t.Fatalf("authoritative readback must resolve matching ambiguous mutation: %#v", resolved)
	}
	stale := ResolvePartitionOutcome(op, OutcomeUnknown, PartitionReadback{Observed: true, OperationID: op.OperationID, FenceToken: op.FenceToken, PlanDigest: op.PlanDigest, DeviceID: "gpu-a", PartitionID: "partition-1", Generation: 3, State: PartitionStateReady, EvidenceDigest: digest64('c')})
	if stale.State != PartitionStateRecoveryRequired {
		t.Fatalf("stale generation must not resolve ambiguous mutation: %#v", stale)
	}
}

func TestHealthDecisionRequiresDurableRemediationAndModelServingRemainsDeferred(t *testing.T) {
	unknown := AssessHealth(DeviceObservation{DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a", Health: HealthUnknown, Observed: true, Source: SourceTargetAgent, ObservedAt: time.Now().UTC()})
	if unknown.ReplacementAllowed || unknown.RepairRequired {
		t.Fatalf("unknown health must not authorize replacement: %#v", unknown)
	}
	degraded := AssessHealth(DeviceObservation{DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a", Health: HealthDegraded, Observed: true, Source: SourceTargetAgent, ObservedAt: time.Now().UTC()})
	if !degraded.RepairRequired || !degraded.ReplacementAllowed || degraded.RequiredAuthority != PartitionLifecycleAuthority {
		t.Fatalf("degraded health must route through durable lifecycle authority: %#v", degraded)
	}
	if ModelServingAdmission != "DEFERRED_UNTIL_ACCELERATOR_LIFECYCLE_CERTIFIED" {
		t.Fatalf("model serving boundary drift: %s", ModelServingAdmission)
	}
}

func digest64(ch byte) string {
	buf := make([]byte, 64)
	for i := range buf { buf[i] = ch }
	return "sha256:" + string(buf)
}
