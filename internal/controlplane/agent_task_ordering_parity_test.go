package controlplane

import (
	"context"
	"testing"
	"time"
)

func newDeterministicAgentOrderingStore(t *testing.T) (*MemoryStore, string, string, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore()
	s.now = func() time.Time { return now }
	token := "sha256:agent-token"
	importID := "imp_order"
	clusterID := "clu_order"
	s.clusterImports[importID] = ClusterImport{
		ResourceMeta:     ResourceMeta{ID: importID, Revision: 1, CreatedAt: now, UpdatedAt: now},
		ProjectID:        "prj_order",
		State:            ClusterImportClaimed,
		AgentTokenDigest: token,
		ClusterID:        clusterID,
	}
	inv := ClusterInventory{
		ResourceMeta: ResourceMeta{ID: "inv_order", Revision: 1, CreatedAt: now, UpdatedAt: now},
		ClusterID:    clusterID,
		ObservedAt:   now,
		Distribution: "rke2",
		Capabilities: []string{TargetMutationRBACActiveCapability},
		Digest:       "sha256:inventory-order",
	}
	s.clusterInventories[clusterID] = inv
	s.managedClusters[clusterID] = ManagedCluster{
		ResourceMeta:                ResourceMeta{ID: clusterID, Revision: 1, CreatedAt: now, UpdatedAt: now},
		ProjectID:                   "prj_order",
		ImportID:                    importID,
		ConnectionState:             "CONNECTED",
		Distribution:                "rke2",
		LastSeenAt:                  &now,
		InventoryUpdatedAt:          &now,
		InventoryObservedAt:         &now,
		Capabilities:                []string{TargetMutationRBACActiveCapability, TargetMutationRBACActivationIssuedCapability},
		InventoryDigest:             inv.Digest,
		MutationRBACBasisDigest:     inv.Digest,
		MutationRBACIssuedForDigest: inv.Digest,
	}
	return s, clusterID, token, now
}

func TestAgentTaskQueuesUseDeterministicTieBreakers(t *testing.T) {
	ctx := context.Background()

	t.Run("baseline", func(t *testing.T) {
		s, clusterID, token, now := newDeterministicAgentOrderingStore(t)
		for _, id := range []string{"bsl_b", "bsl_a"} {
			s.baselineDeployments[id] = BaselineDeployment{ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_order", ClusterID: clusterID, State: BaselineDeploymentPlanning}
		}
		list, err := s.ListBaselineDeployments(ctx, "prj_order", clusterID)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].ID != "bsl_a" || list[1].ID != "bsl_b" {
			t.Fatalf("baseline list=%v", []string{list[0].ID, list[1].ID})
		}
		got, err := s.NextBaselineTask(ctx, clusterID, token)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "bsl_a" {
			t.Fatalf("baseline claim=%s want bsl_a", got.ID)
		}
	})

	t.Run("runtime-verification", func(t *testing.T) {
		s, clusterID, token, now := newDeterministicAgentOrderingStore(t)
		for _, id := range []string{"rtv_b", "rtv_a"} {
			s.runtimeVerifications[id] = RuntimeVerification{ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_order", ClusterID: clusterID, State: RuntimeVerificationQueued}
		}
		list, err := s.ListRuntimeVerifications(ctx, "prj_order", clusterID, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].ID != "rtv_a" || list[1].ID != "rtv_b" {
			t.Fatalf("runtime verification list order is not deterministic: %#v", list)
		}
		got, err := s.NextRuntimeVerificationTask(ctx, clusterID, token)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "rtv_a" {
			t.Fatalf("runtime verification claim=%s want rtv_a", got.ID)
		}
	})

	t.Run("runtime-certification", func(t *testing.T) {
		s, clusterID, token, now := newDeterministicAgentOrderingStore(t)
		inv := s.clusterInventories[clusterID]
		fp := RuntimeEnvironmentFingerprint(inv)
		for _, id := range []string{"rtc_b", "rtc_a"} {
			s.runtimeCertifications[id] = RuntimeCertificationRun{ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_order", ClusterID: clusterID, State: RuntimeCertificationQueued, InventoryDigest: inv.Digest, EnvironmentFingerprint: fp}
		}
		list, err := s.ListRuntimeCertifications(ctx, "prj_order", clusterID)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].ID != "rtc_a" || list[1].ID != "rtc_b" {
			t.Fatalf("runtime certification list order is not deterministic: %#v", list)
		}
		got, err := s.NextRuntimeCertificationTask(ctx, clusterID, token)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "rtc_a" {
			t.Fatalf("runtime certification claim=%s want rtc_a", got.ID)
		}
	})

	t.Run("provider-profile", func(t *testing.T) {
		s, clusterID, token, now := newDeterministicAgentOrderingStore(t)
		for _, id := range []string{"ppr_b", "ppr_a"} {
			s.providerProfiles[id] = ProviderProfile{ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_order", ManagementClusterID: clusterID, State: ProviderProfileVerifyQueued}
		}
		list, err := s.ListProviderProfiles(ctx, "prj_order", clusterID)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].ID != "ppr_a" || list[1].ID != "ppr_b" {
			t.Fatalf("provider profile list order is not deterministic: %#v", list)
		}
		got, err := s.NextProviderProfileTask(ctx, clusterID, token)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "ppr_a" {
			t.Fatalf("provider profile claim=%s want ppr_a", got.ID)
		}
	})

	t.Run("provider-cluster", func(t *testing.T) {
		s, clusterID, token, now := newDeterministicAgentOrderingStore(t)
		profileID := "ppr_ready"
		s.providerProfiles[profileID] = ProviderProfile{ResourceMeta: ResourceMeta{ID: profileID, Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_order", ManagementClusterID: clusterID, State: ProviderProfileReady}
		for _, id := range []string{"pcl_b", "pcl_a"} {
			s.providerClusters[id] = ProviderCluster{ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_order", ProviderProfileID: profileID, ManagementClusterID: clusterID, State: ProviderClusterQueued}
		}
		list, err := s.ListProviderClusters(ctx, "prj_order", profileID)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].ID != "pcl_a" || list[1].ID != "pcl_b" {
			t.Fatalf("provider cluster list order is not deterministic: %#v", list)
		}
		got, _, err := s.NextProviderClusterTask(ctx, clusterID, token)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "pcl_a" {
			t.Fatalf("provider cluster claim=%s want pcl_a", got.ID)
		}
	})

	t.Run("drift", func(t *testing.T) {
		s, clusterID, token, now := newDeterministicAgentOrderingStore(t)
		for _, id := range []string{"drs_b", "drs_a"} {
			s.driftScans[id] = DriftScan{ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_order", State: DriftScanQueued, Targets: []DriftScanTarget{{ClusterID: clusterID, State: DriftTargetPending}}}
		}
		list, err := s.ListDriftScans(ctx, "prj_order", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].ID != "drs_a" || list[1].ID != "drs_b" {
			t.Fatalf("drift list order is not deterministic: %#v", list)
		}
		got, _, err := s.NextDriftTask(ctx, clusterID, token)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "drs_a" {
			t.Fatalf("drift claim=%s want drs_a", got.ID)
		}
	})
}

func TestAgentTaskOrderingSurvivesFileStoreRestart(t *testing.T) {
	ctx := context.Background()
	s, clusterID, token, now := newDeterministicAgentOrderingStore(t)
	for _, id := range []string{"bsl_b", "bsl_a"} {
		s.baselineDeployments[id] = BaselineDeployment{ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: "prj_order", ClusterID: clusterID, State: BaselineDeploymentPlanning}
	}
	path := t.TempDir() + "/state.json"
	f := &FileStore{MemoryStore: s, path: path}
	if err := f.persist(ctx); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return now }
	got, err := reopened.NextBaselineTask(ctx, clusterID, token)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "bsl_a" {
		t.Fatalf("baseline claim after restart=%s want bsl_a", got.ID)
	}
}
