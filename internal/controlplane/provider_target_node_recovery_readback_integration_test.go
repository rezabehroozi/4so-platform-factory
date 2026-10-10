package controlplane

import (
	"testing"
	"time"
)

func TestProviderTargetNodeRecoveryInspectSurvivesExpiredMutationWindow(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile := readyProviderProfile(t, s, ctx, project, management, agentToken)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }

	inventoryDigest := digestTenantTest("target-node-recovery-inventory")
	targetID := "target-node-recovery"
	windowID := "window-target-node-recovery-expired"
	windowEnd := now.Add(-time.Minute)
	v := ProviderCluster{
		ResourceMeta:        ResourceMeta{ID: "pcl-target-node-recovery", Revision: 7, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-2 * time.Minute)},
		ProjectID:           project.ID,
		ProviderProfileID:   profile.ID,
		ManagementClusterID: management.ID,
		State:               ProviderClusterReconciling,
		PendingAction:       "TARGET_NODE_REPLACE",
		DesiredDigest:       digestTenantTest("target-node-recovery-desired"),
		TaskFenceToken:      11,
		TargetNodeMutation: TargetNodeProviderMutation{
			Authority:       TargetNodeProviderMachineLifecycleAuthority,
			Action:          TargetNodeActionReplace,
			TargetClusterID: targetID,
			NodeName:        "worker-1",
			NodeUID:         "uid-worker-1",
			InventoryDigest: inventoryDigest,
			WindowID:        windowID,
			WindowEndsAt:    windowEnd,
		},
	}

	s.mu.Lock()
	s.providerClusters[v.ID] = v
	s.clusterInventories[targetID] = ClusterInventory{
		ClusterID: targetID,
		ObservedAt: now,
		Digest:     inventoryDigest,
		Nodes:      []ClusterNode{{Name: "worker-1", UID: "uid-worker-1", Roles: []string{"worker"}, Ready: true}},
	}
	s.clusterMaintenanceWindows[windowID] = ClusterMaintenanceWindow{
		ResourceMeta: ResourceMeta{ID: windowID, Revision: 1, CreatedAt: now.Add(-3 * time.Hour), UpdatedAt: now.Add(-3 * time.Hour)},
		ProjectID:    project.ID,
		ClusterID:    targetID,
		Name:         "expired-after-mutation",
		StartsAt:     now.Add(-2 * time.Hour),
		EndsAt:       windowEnd,
		State:        ClusterMaintenanceWindowActive,
	}
	s.mu.Unlock()

	claimed, claimedProfile, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil {
		t.Fatalf("read-only recovery inspection must remain claimable after mutation window expiry: %v", err)
	}
	if claimed.ID != v.ID || claimed.State != ProviderClusterReconciling || claimed.PendingAction != v.PendingAction {
		t.Fatalf("unexpected recovery inspection claim: %#v", claimed)
	}
	if claimedProfile.ID != profile.ID || claimed.TaskFenceToken != v.TaskFenceToken+1 || !AgentTaskLeaseActive(claimed.TaskLeaseExpiresAt, now) {
		t.Fatalf("recovery inspection claim lost provider/fence/lease authority: cluster=%#v profile=%#v", claimed, claimedProfile)
	}
}
