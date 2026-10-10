package accelerator

import (
	"testing"
	"time"
)

func TestPlacementSelectsCapacitySatisfyingDevicesDeterministically(t *testing.T) {
	now := time.Date(2026, 10, 10, 14, 30, 0, 0, time.UTC)
	inv, err := BuildInventory([]DeviceObservation{
		{DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100", MemoryMiB: 40960, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now, Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
		{DeviceID: "gpu-b", ClusterID: "cluster-a", NodeID: "node-b", Vendor: "nvidia", Model: "h100", MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now, Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
	})
	if err != nil {
		t.Fatal(err)
	}
	class := GPUClass{Authority: GPUClassAuthority, ID: "h100-mig", Vendor: "nvidia", MinMemoryMiB: 40000, RequiredCapabilities: []string{"compute.cuda", "partition.mig"}, AllowedPartitionModes: []PartitionMode{PartitionMIG}}
	quota := Quota{Authority: QuotaPlacementAuthority, OrganizationID: "org-a", ProjectID: "project-a", ClassID: class.ID, MaxDevices: 1, MaxMemoryMiB: 81920}
	plan, err := PlanPlacement(inv, class, quota, Usage{}, PlacementRequest{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: class.ID, Devices: 1, MemoryMiB: 80000, PartitionMode: PartitionMIG}, now)
	if err != nil {
		t.Fatalf("placement must choose available capacity that satisfies the request: %v", err)
	}
	if len(plan.DeviceIDs) != 1 || plan.DeviceIDs[0] != "gpu-b" {
		t.Fatalf("placement must deterministically select the capacity-satisfying device: %#v", plan)
	}
}
