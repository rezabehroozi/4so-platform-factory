package accelerator

import (
	"testing"
	"time"
)

func TestPlacementRejectsInventoryWhoseContentNoLongerMatchesDigest(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	inv, err := BuildInventory([]DeviceObservation{{
		DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100",
		MemoryMiB: 40960, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now, Observed: true,
		Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG},
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate content drift after the observed inventory was sealed. A stale
	// digest must never authorize placement against mutated capacity.
	inv.Devices[0].MemoryMiB = 81920

	class := GPUClass{Authority: GPUClassAuthority, ID: "h100-mig", Vendor: "nvidia", MinMemoryMiB: 80000, RequiredCapabilities: []string{"compute.cuda", "partition.mig"}, AllowedPartitionModes: []PartitionMode{PartitionMIG}}
	quota := Quota{Authority: QuotaPlacementAuthority, OrganizationID: "org-a", ProjectID: "project-a", ClassID: class.ID, MaxDevices: 1, MaxMemoryMiB: 81920}
	_, err = PlanPlacement(inv, class, quota, Usage{}, PlacementRequest{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: class.ID, Devices: 1, MemoryMiB: 80000, PartitionMode: PartitionMIG}, now)
	if err == nil {
		t.Fatal("placement must reject accelerator inventory whose content no longer matches its sealed digest")
	}
}
