package accelerator

import (
	"testing"
	"time"
)

func TestAllocatedDeviceIdentityIsCasePreservingOpaque(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	inv, err := BuildInventory([]DeviceObservation{
		{DeviceID: "GPU-AAA", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100", MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now, Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
		{DeviceID: "GPU-BBB", ClusterID: "cluster-a", NodeID: "node-b", Vendor: "nvidia", Model: "h100", MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now, Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
	})
	if err != nil { t.Fatal(err) }
	class := GPUClass{Authority: GPUClassAuthority, ID: "h100-mig", Vendor: "nvidia", MinMemoryMiB: 80000, RequiredCapabilities: []string{"compute.cuda", "partition.mig"}, AllowedPartitionModes: []PartitionMode{PartitionMIG}}
	quota := Quota{Authority: QuotaPlacementAuthority, OrganizationID: "org-a", ProjectID: "project-a", ClassID: class.ID, MaxDevices: 2, MaxMemoryMiB: 163840}
	plan, err := PlanPlacement(inv, class, quota, Usage{Devices: 1, MemoryMiB: 81920, AllocatedDeviceIDs: []string{"GPU-AAA"}}, PlacementRequest{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: class.ID, Devices: 1, MemoryMiB: 80000, PartitionMode: PartitionMIG})
	if err != nil { t.Fatal(err) }
	if len(plan.DeviceIDs) != 1 || plan.DeviceIDs[0] != "GPU-BBB" {
		t.Fatalf("opaque allocated device identity was normalized or reselected: %#v", plan)
	}
}
