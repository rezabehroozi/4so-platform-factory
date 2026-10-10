package accelerator

import (
	"testing"
	"time"
)

func TestPlacementIgnoresStaleObservationsOutsideRequestedCluster(t *testing.T) {
	now := time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC)
	inv, err := BuildInventory([]DeviceObservation{
		{DeviceID: "gpu-a", ClusterID: "cluster-a", NodeID: "node-a", Vendor: "nvidia", Model: "h100", MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now.Add(-time.Minute), Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
		{DeviceID: "gpu-b", ClusterID: "cluster-b", NodeID: "node-b", Vendor: "nvidia", Model: "h100", MemoryMiB: 81920, Health: HealthHealthy, Source: SourceTargetAgent, ObservedAt: now.Add(-MaxPlacementObservationAge - time.Second), Observed: true, Capabilities: []string{"compute.cuda", "partition.mig"}, PartitionModes: []PartitionMode{PartitionMIG}},
	})
	if err != nil {
		t.Fatal(err)
	}
	class := GPUClass{Authority: GPUClassAuthority, ID: "h100-mig", Vendor: "nvidia", MinMemoryMiB: 40000, RequiredCapabilities: []string{"compute.cuda", "partition.mig"}, AllowedPartitionModes: []PartitionMode{PartitionMIG}}
	quota := Quota{Authority: QuotaPlacementAuthority, OrganizationID: "org-a", ProjectID: "project-a", ClassID: class.ID, MaxDevices: 1, MaxMemoryMiB: 81920}
	plan, err := PlanPlacement(inv, class, quota, Usage{}, PlacementRequest{OrganizationID: "org-a", ProjectID: "project-a", ClusterID: "cluster-a", ClassID: class.ID, Devices: 1, MemoryMiB: 40000, PartitionMode: PartitionMIG}, now)
	if err != nil {
		t.Fatalf("stale accelerator observation in another cluster must not block scoped placement: %v", err)
	}
	if len(plan.DeviceIDs) != 1 || plan.DeviceIDs[0] != "gpu-a" {
		t.Fatalf("placement must stay scoped to the requested cluster: %#v", plan)
	}
}
