package controlplane

import (
	"fmt"
	"strings"
	"time"
)

// GeneralizedDay2CampaignAuthorityMethod is the shared product contract for
// disruptive Day-2 workflows. Concrete lifecycle stores remain authoritative
// for their resource-specific state, but they must pass through this policy
// boundary for planning, windowing, approval, bounded rollout, fencing,
// verification/evidence and recovery semantics.
const GeneralizedDay2CampaignAuthorityMethod = "GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1"

type Day2CampaignAdapter string

const (
	Day2CampaignAdapterNodeMaintenance Day2CampaignAdapter = "node-maintenance"
	Day2CampaignAdapterFleetUpgrade    Day2CampaignAdapter = "fleet-upgrade"
)

var GeneralizedDay2CampaignStages = []string{
	"PLAN", "IMPACT", "WINDOW", "APPROVAL", "CANARY_WAVES",
	"FENCE", "EXECUTE", "VERIFY", "EVIDENCE", "RECOVERY",
}

type Day2CampaignContract struct {
	Authority             string              `json:"authority"`
	Adapter               Day2CampaignAdapter `json:"adapter"`
	StageOrder            []string            `json:"stageOrder"`
	TargetCount           int                 `json:"targetCount"`
	CanaryCount           int                 `json:"canaryCount"`
	WaveSize              int                 `json:"waveSize"`
	HaltAfterFailures     int                 `json:"haltAfterFailures"`
	MaxUnavailable        int                 `json:"maxUnavailable"`
	IndependentApproval   bool                `json:"independentApproval"`
	WindowRequired        bool                `json:"windowRequired"`
	WindowStart           time.Time           `json:"windowStart"`
	WindowEnd             time.Time           `json:"windowEnd"`
	FencedExecution       bool                `json:"fencedExecution"`
	VerificationRequired  bool                `json:"verificationRequired"`
	EvidenceRequired      bool                `json:"evidenceRequired"`
	RecoveryRequired      bool                `json:"recoveryRequired"`
	RecoveryEvidenceCount int                 `json:"recoveryEvidenceCount"`
	ExecutionBoundary     string              `json:"executionBoundary"`
}

type Day2CampaignEngineDescriptor struct {
	Authority  string                `json:"authority"`
	StageOrder []string              `json:"stageOrder"`
	Adapters   []Day2CampaignAdapter `json:"adapters"`
	Policies   map[string]string     `json:"policies"`
}

func Day2CampaignEngineModel() Day2CampaignEngineDescriptor {
	return Day2CampaignEngineDescriptor{
		Authority:  GeneralizedDay2CampaignAuthorityMethod,
		StageOrder: append([]string(nil), GeneralizedDay2CampaignStages...),
		Adapters:   []Day2CampaignAdapter{Day2CampaignAdapterNodeMaintenance, Day2CampaignAdapterFleetUpgrade},
		Policies: map[string]string{
			"approval":     "independent actor for disruptive mutations",
			"window":       "execution may start only inside the bound maintenance window",
			"rollout":      "bounded canary/waves or single-target serial adapter semantics",
			"fence":        "worker execution must be lease/fence protected directly or through the delegated durable operation",
			"verification": "successful mutation is not campaign success until adapter verification completes",
			"evidence":     "terminal success must remain evidence-addressable through the owning workflow",
			"recovery":     "high-impact rollout requires current recovery evidence before execution",
		},
	}
}

func Day2ContractForMaintenance(run ClusterMaintenanceRun, window ClusterMaintenanceWindow) Day2CampaignContract {
	targetCount := len(run.NodeNames)
	wave := run.MaxUnavailable
	if wave <= 0 {
		wave = window.MaxUnavailable
	}
	return Day2CampaignContract{
		Authority:             GeneralizedDay2CampaignAuthorityMethod,
		Adapter:               Day2CampaignAdapterNodeMaintenance,
		StageOrder:            append([]string(nil), GeneralizedDay2CampaignStages...),
		TargetCount:           targetCount,
		CanaryCount:           minPositive(targetCount, 1),
		WaveSize:              wave,
		HaltAfterFailures:     1,
		MaxUnavailable:        wave,
		IndependentApproval:   true,
		WindowRequired:        true,
		WindowStart:           window.StartsAt,
		WindowEnd:             window.EndsAt,
		FencedExecution:       true,
		VerificationRequired:  true,
		EvidenceRequired:      true,
		RecoveryRequired:      false,
		RecoveryEvidenceCount: 0,
		ExecutionBoundary:     "durable-operation-fence+cluster-agent-node-identity",
	}
}

func Day2ContractForUpgrade(c UpgradeCampaign) Day2CampaignContract {
	return Day2CampaignContract{
		Authority:             GeneralizedDay2CampaignAuthorityMethod,
		Adapter:               Day2CampaignAdapterFleetUpgrade,
		StageOrder:            append([]string(nil), GeneralizedDay2CampaignStages...),
		TargetCount:           len(c.Targets),
		CanaryCount:           c.CanaryCount,
		WaveSize:              c.WaveSize,
		HaltAfterFailures:     c.HaltAfterFailures,
		MaxUnavailable:        c.WaveSize,
		IndependentApproval:   true,
		WindowRequired:        true,
		WindowStart:           c.MaintenanceWindowStart,
		WindowEnd:             c.MaintenanceWindowEnd,
		FencedExecution:       true,
		VerificationRequired:  true,
		EvidenceRequired:      true,
		RecoveryRequired:      true,
		RecoveryEvidenceCount: len(c.RecoveryCheckpointIDs),
		ExecutionBoundary:     "baseline-deployment+runtime-verification+recovery-checkpoint",
	}
}

func ValidateDay2CampaignContract(c Day2CampaignContract) error {
	if c.Authority != GeneralizedDay2CampaignAuthorityMethod || len(c.StageOrder) != len(GeneralizedDay2CampaignStages) {
		return fmt.Errorf("%w: invalid generalized Day-2 campaign authority", ErrValidation)
	}
	for i := range GeneralizedDay2CampaignStages {
		if c.StageOrder[i] != GeneralizedDay2CampaignStages[i] {
			return fmt.Errorf("%w: invalid generalized Day-2 stage order", ErrValidation)
		}
	}
	if c.TargetCount < 1 || c.CanaryCount < 1 || c.CanaryCount > c.TargetCount || c.WaveSize < 1 || c.WaveSize > c.TargetCount || c.HaltAfterFailures < 1 || c.MaxUnavailable < 1 {
		return fmt.Errorf("%w: invalid generalized Day-2 rollout bounds", ErrValidation)
	}
	if c.WindowRequired && (c.WindowStart.IsZero() || !c.WindowEnd.After(c.WindowStart)) {
		return ErrMaintenanceWindow
	}
	if !c.IndependentApproval || !c.FencedExecution || !c.VerificationRequired || !c.EvidenceRequired || strings.TrimSpace(c.ExecutionBoundary) == "" {
		return fmt.Errorf("%w: generalized Day-2 safety contract is incomplete", ErrPrerequisite)
	}
	if c.RecoveryRequired && c.RecoveryEvidenceCount < c.TargetCount {
		return fmt.Errorf("%w: recovery evidence is required for every disruptive rollout target", ErrPrerequisite)
	}
	return nil
}

func ValidateDay2IndependentApproval(requestedBy, approver string) error {
	requestedBy, approver = strings.TrimSpace(requestedBy), strings.TrimSpace(approver)
	// Development mode intentionally uses one authenticated local principal so
	// executable smoke/lab workflows can exercise approval transitions without
	// manufacturing a second untrusted header identity. Production auth never
	// emits this principal; keep the exception identical to API approvalActor.
	if requestedBy == "local-development" && approver == "local-development" {
		return nil
	}
	if approver == "" || requestedBy == "" || approver == requestedBy {
		return fmt.Errorf("%w: generalized Day-2 campaign requires an independent approver", ErrPrerequisite)
	}
	return nil
}

func ValidateDay2ExecutionWindow(start, end, now time.Time) error {
	if start.IsZero() || !end.After(start) || now.Before(start) || !now.Before(end) {
		return ErrMaintenanceWindow
	}
	return nil
}

func ValidateDay2Fence(expected, observed int64, leaseExpiresAt *time.Time, now time.Time) error {
	if expected <= 0 || observed <= 0 || expected != observed {
		return ErrStaleFence
	}
	if leaseExpiresAt == nil || !leaseExpiresAt.After(now) {
		return ErrLeaseHeld
	}
	return nil
}

// NormalizeDay2RolloutBounds converts caller defaults into bounds that are valid for
// the actual target set. REST and MCP share this normalization so single-target and
// multi-target campaigns enter the same durable validation boundary.
func NormalizeDay2RolloutBounds(targetCount, canaryCount, waveSize, haltAfterFailures int) (int, int, int, error) {
	if targetCount < 1 {
		return 0, 0, 0, ErrValidation
	}
	if canaryCount < 1 {
		canaryCount = 1
	}
	if waveSize < 1 {
		waveSize = 1
	}
	if haltAfterFailures < 1 {
		haltAfterFailures = 1
	}
	if canaryCount > targetCount {
		canaryCount = targetCount
	}
	if waveSize > targetCount {
		waveSize = targetCount
	}
	return canaryCount, waveSize, haltAfterFailures, nil
}

func minPositive(a, b int) int {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a < b {
		return a
	}
	return b
}

// ValidateDay2UpgradeTopology validates the immutable rollout partition before
// any campaign is admitted. Wave 1 is the canary wave; subsequent waves are
// bounded by WaveSize and wave numbering must be contiguous.
func ValidateDay2UpgradeTopology(c UpgradeCampaign) error {
	if err := ValidateDay2CampaignContract(Day2ContractForUpgrade(c)); err != nil {
		return err
	}
	counts := map[int]int{}
	maxWave := 0
	seenClusters := map[string]bool{}
	for _, target := range c.Targets {
		clusterID := strings.TrimSpace(target.ClusterID)
		if clusterID == "" || seenClusters[clusterID] || target.Wave < 1 {
			return fmt.Errorf("%w: upgrade campaign targets must have unique cluster identities and positive waves", ErrValidation)
		}
		seenClusters[clusterID] = true
		counts[target.Wave]++
		if target.Wave > maxWave {
			maxWave = target.Wave
		}
	}
	if counts[1] != c.CanaryCount {
		return fmt.Errorf("%w: wave 1 must contain exactly the configured canary count", ErrValidation)
	}
	for wave := 1; wave <= maxWave; wave++ {
		count := counts[wave]
		if count == 0 {
			return fmt.Errorf("%w: upgrade campaign waves must be contiguous", ErrValidation)
		}
		if wave > 1 && count > c.WaveSize {
			return fmt.Errorf("%w: upgrade campaign wave exceeds configured wave size", ErrValidation)
		}
	}
	return nil
}

// ValidateDay2UpgradeProgression prevents the durable store from accepting a
// caller-mutated rollout plan. Only execution state/progress fields may change;
// target identities, wave assignment and rollback baseline identity are frozen
// once the plan is created.
func ValidateDay2UpgradeProgression(current, next UpgradeCampaign) error {
	if current.CanaryCount != next.CanaryCount || current.WaveSize != next.WaveSize || current.HaltAfterFailures != next.HaltAfterFailures || len(current.Targets) != len(next.Targets) {
		return fmt.Errorf("%w: generalized Day-2 rollout policy is immutable after planning", ErrValidation)
	}
	if next.CurrentWave < current.CurrentWave || next.CurrentWave > current.CurrentWave+1 {
		return fmt.Errorf("%w: generalized Day-2 campaign cannot skip or rewind waves", ErrInvalidTransition)
	}
	for i := range current.Targets {
		before, after := current.Targets[i], next.Targets[i]
		if before.ClusterID != after.ClusterID || before.Wave != after.Wave || before.PreviousBaselineDeploymentID != after.PreviousBaselineDeploymentID || before.PreviousVersion != after.PreviousVersion || before.PreviousDigest != after.PreviousDigest {
			return fmt.Errorf("%w: generalized Day-2 target identity and recovery baseline are immutable", ErrValidation)
		}
		if before.State == UpgradeTargetPending && after.State != UpgradeTargetPending && after.Wave > next.CurrentWave {
			return fmt.Errorf("%w: generalized Day-2 target cannot start before its wave", ErrInvalidTransition)
		}
	}
	return ValidateDay2UpgradeTopology(next)
}
