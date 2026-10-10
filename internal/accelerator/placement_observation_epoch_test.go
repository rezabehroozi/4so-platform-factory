package accelerator

import (
	"testing"
	"time"
)

func TestPlacementRequiresFreshNonFutureInventoryObservations(t *testing.T) {
	now := time.Date(2026, 10, 10, 14, 0, 0, 0, time.UTC)
	build := func(observedAt time.Time) Inventory {
		inv, err := BuildInventory([]DeviceObservation{{
			DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100",
			MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: observedAt, Observed: true,
			Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return inv
	}
	class := GPUClass{Authority: GPUClassAuthority, ID: "h100-mig", Vendor: "nvidia", MinMemoryMiB: 80000, RequiredCapabilities: []string{"compute.cuda", "partition.mig"}, AllowedPartitionModes: []PartitionMode{PartitionMIG}}
	quota := Quota{Authority: QuotaPlacementAuthority, OrganizationID: "org-a", ProjectID: "project-a", ClassID: class.ID, MaxDevices: 1, MaxMemoryMiB: 81920}
	request := PlacementRequest{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: class.ID, Devices: 1, MemoryMiB: 80000, PartitionMode: PartitionMIG}

	if _, err := PlanPlacement(build(now.Add(-5*time.Minute)), class, quota, Usage{}, request, now); err != nil {
		t.Fatalf("fresh observed inventory must remain eligible for placement: %v", err)
	}
	if _, err := PlanPlacement(build(now.Add(-MaxPlacementObservationAge-time.Second)), class, quota, Usage{}, request, now); err == nil {
		t.Fatal("stale accelerator inventory must not authorize placement")
	}
	if _, err := PlanPlacement(build(now.Add(time.Second)), class, quota, Usage{}, request, now); err == nil {
		t.Fatal("future accelerator inventory must not authorize placement")
	}
}
