package controlplane

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGeneralizedDay2CampaignEngineAdaptersShareSafetyContract(t *testing.T) {
	now := time.Date(2026, 9, 6, 5, 0, 0, 0, time.UTC)
	window := ClusterMaintenanceWindow{StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), MaxUnavailable: 1}
	maintenance := ClusterMaintenanceRun{NodeNames: []string{"worker-1"}, MaxUnavailable: 1}
	mc := Day2ContractForMaintenance(maintenance, window)
	if err := ValidateDay2CampaignContract(mc); err != nil {
		t.Fatal(err)
	}
	if mc.Adapter != Day2CampaignAdapterNodeMaintenance || !mc.FencedExecution || !mc.VerificationRequired || !mc.EvidenceRequired {
		t.Fatalf("maintenance contract=%+v", mc)
	}

	digest := "sha256:" + strings.Repeat("a", 64)
	upgrade := UpgradeCampaign{
		Targets:     []UpgradeCampaignTarget{{ClusterID: "c1"}, {ClusterID: "c2"}},
		CanaryCount: 1, WaveSize: 1, HaltAfterFailures: 1,
		MaintenanceWindowStart: now.Add(-time.Minute), MaintenanceWindowEnd: now.Add(time.Hour),
		RecoveryCheckpointIDs: []string{"cp1", "cp2"}, TargetInventoryDigests: map[string]string{"c1": digest, "c2": digest},
	}
	uc := Day2ContractForUpgrade(upgrade)
	if err := ValidateDay2CampaignContract(uc); err != nil {
		t.Fatal(err)
	}
	if uc.Adapter != Day2CampaignAdapterFleetUpgrade || !uc.RecoveryRequired || uc.RecoveryEvidenceCount != 2 {
		t.Fatalf("upgrade contract=%+v", uc)
	}
}

func TestGeneralizedDay2CampaignRejectsUnsafeApprovalWindowRecoveryAndFence(t *testing.T) {
	now := time.Now().UTC()
	if err := ValidateDay2IndependentApproval("same", "same"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("self approval accepted: %v", err)
	}
	if err := ValidateDay2IndependentApproval("local-development", "local-development"); err != nil {
		t.Fatalf("development-mode single-principal exception drift: %v", err)
	}
	if err := ValidateDay2ExecutionWindow(now.Add(time.Minute), now.Add(time.Hour), now); !errors.Is(err, ErrMaintenanceWindow) {
		t.Fatalf("future window accepted: %v", err)
	}
	lease := now.Add(time.Minute)
	if err := ValidateDay2Fence(2, 1, &lease, now); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale fence accepted: %v", err)
	}
	expired := now.Add(-time.Second)
	if err := ValidateDay2Fence(2, 2, &expired, now); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("expired lease accepted: %v", err)
	}
	c := Day2CampaignContract{
		Authority: GeneralizedDay2CampaignAuthorityMethod, Adapter: Day2CampaignAdapterFleetUpgrade,
		StageOrder: append([]string(nil), GeneralizedDay2CampaignStages...), TargetCount: 2, CanaryCount: 1, WaveSize: 1,
		HaltAfterFailures: 1, MaxUnavailable: 1, IndependentApproval: true, WindowRequired: true,
		WindowStart: now.Add(-time.Minute), WindowEnd: now.Add(time.Hour), FencedExecution: true,
		VerificationRequired: true, EvidenceRequired: true, RecoveryRequired: true, RecoveryEvidenceCount: 1,
		ExecutionBoundary: "test",
	}
	if err := ValidateDay2CampaignContract(c); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("partial recovery evidence accepted: %v", err)
	}
}

func TestNormalizeDay2RolloutBoundsClampsToActualTargetSet(t *testing.T) {
	canary, wave, halt, err := NormalizeDay2RolloutBounds(1, 1, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if canary != 1 || wave != 1 || halt != 1 {
		t.Fatalf("unexpected normalized bounds: canary=%d wave=%d halt=%d", canary, wave, halt)
	}
	if _, _, _, err := NormalizeDay2RolloutBounds(0, 1, 1, 1); !errors.Is(err, ErrValidation) {
		t.Fatalf("empty target set must fail closed, got %v", err)
	}
}
