package lifecycle

import "time"

type Action string

const (
	ActionBackup          Action = "backup"
	ActionRestore         Action = "restore"
	ActionUpgrade         Action = "upgrade"
	ActionUpgradeRecovery Action = "upgrade-recovery"
)

type State string

const (
	StateQueued    State = "QUEUED"
	StateRunning   State = "RUNNING"
	StateSucceeded State = "SUCCEEDED"
	StateFailed    State = "FAILED"
)

type UpgradePhase string

type UpgradeRecoveryPhase string

const (
	UpgradePhaseBackupPending     UpgradePhase = "BACKUP_PENDING"
	UpgradePhaseApplyPending      UpgradePhase = "APPLY_PENDING"
	UpgradePhaseApplyVerified     UpgradePhase = "APPLY_VERIFIED"
	UpgradePhaseRollbackPending   UpgradePhase = "ROLLBACK_PENDING"   // legacy 0.0.145-and-earlier state; converted fail-closed on replay
	UpgradePhaseRollbackCompleted UpgradePhase = "ROLLBACK_COMPLETED" // legacy image-only rollback state
	UpgradePhaseRecoveryRequired  UpgradePhase = "RECOVERY_REQUIRED"
	UpgradePhaseRecoveryCompleted UpgradePhase = "RECOVERY_COMPLETED"
)

const (
	UpgradeRecoveryPhaseRestorePending   UpgradeRecoveryPhase = "RESTORE_PENDING"
	UpgradeRecoveryPhaseRestoreCompleted UpgradeRecoveryPhase = "RESTORE_COMPLETED"
	UpgradeRecoveryPhaseResumeVerified   UpgradeRecoveryPhase = "RESUME_VERIFIED"
)

type Run struct {
	ID                   string               `json:"id"`
	Service              string               `json:"service"`
	ProfileID            string               `json:"profileId"`
	ExecutionNode        string               `json:"executionNode,omitempty"`
	BundleDigest         string               `json:"bundleDigest,omitempty"`
	Action               Action               `json:"action"`
	State                State                `json:"state"`
	BackupID             string               `json:"backupId,omitempty"`
	RequestedImage       string               `json:"requestedImage,omitempty"`
	PreviousImage        string               `json:"previousImage,omitempty"`
	UpgradePhase         UpgradePhase         `json:"upgradePhase,omitempty"`
	UpgradeFailure       string               `json:"upgradeFailure,omitempty"`
	UpgradeRecoveryPhase UpgradeRecoveryPhase `json:"upgradeRecoveryPhase,omitempty"`
	SourceUpgradeRunID   string               `json:"sourceUpgradeRunId,omitempty"`
	RecoveryRequired     bool                 `json:"recoveryRequired,omitempty"`
	Error                string               `json:"error,omitempty"`
	CreatedAt            time.Time            `json:"createdAt"`
	StartedAt            *time.Time           `json:"startedAt,omitempty"`
	FinishedAt           *time.Time           `json:"finishedAt,omitempty"`
}

type BackupMetadata struct {
	ID        string       `json:"id"`
	Service   string       `json:"service"`
	ProfileID string       `json:"profileId,omitempty"`
	CreatedAt time.Time    `json:"createdAt"`
	Files     []BackupFile `json:"files"`
}

type BackupFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type RestoreRequest struct {
	Service  string `json:"service"`
	BackupID string `json:"backupId"`
}
type UpgradeRequest struct {
	Service string `json:"service"`
	Image   string `json:"image"`
}
type UpgradeRecoveryRequest struct {
	UpgradeRunID string `json:"upgradeRunId"`
}

const UpgradeInterruptionRecoveryMatrixAuthority = "INSTALLER_UPGRADE_INTERRUPTION_RECOVERY_MATRIX_V1"

type UpgradeInterruptionRecoveryScenario struct {
	Checkpoint       string `json:"checkpoint"`
	PersistedPhase   string `json:"persistedPhase"`
	RestartBehavior  string `json:"restartBehavior"`
	RecoveryBoundary string `json:"recoveryBoundary"`
	AutomaticReplay  bool   `json:"automaticReplay"`
}

// UpgradeInterruptionRecoveryMatrix is descriptive authority for the durable
// boundaries already enforced by Manager. It is intentionally source/runtime
// semantics evidence only; physical interruption evidence belongs to the exact-
// artifact certification phase.
func UpgradeInterruptionRecoveryMatrix() []UpgradeInterruptionRecoveryScenario {
	return []UpgradeInterruptionRecoveryScenario{
		{Checkpoint: "before-pre-upgrade-backup", PersistedPhase: string(UpgradePhaseBackupPending), RestartBehavior: "resume the same run and idempotently establish the bound backup before any image mutation", RecoveryBoundary: "no destructive recovery required", AutomaticReplay: true},
		{Checkpoint: "after-backup-before-image-apply", PersistedPhase: string(UpgradePhaseApplyPending), RestartBehavior: "resume the same run only when the digest-pinned previous image and requested image still match durable authority", RecoveryBoundary: "image drift fails closed", AutomaticReplay: true},
		{Checkpoint: "after-image-apply-before-final-state", PersistedPhase: string(UpgradePhaseApplyVerified), RestartBehavior: "verify the requested digest and replicas; never replay SetImage after verified completion", RecoveryBoundary: "verification drift fails closed", AutomaticReplay: true},
		{Checkpoint: "upgrade-rollout-or-image-verification-failure", PersistedPhase: string(UpgradePhaseRecoveryRequired), RestartBehavior: "do not image-only rollback or replay the failed upgrade", RecoveryBoundary: "explicit confirmation-bound upgrade recovery restores the exact bound backup and previous digest", AutomaticReplay: false},
		{Checkpoint: "recovery-after-state-restore", PersistedPhase: string(UpgradeRecoveryPhaseRestoreCompleted), RestartBehavior: "resume recovery after the destructive restore boundary without restoring the backup twice", RecoveryBoundary: "verify previous digest and replicas before closure", AutomaticReplay: true},
		{Checkpoint: "recovery-after-resume-verification", PersistedPhase: string(UpgradeRecoveryPhaseResumeVerified), RestartBehavior: "re-verify the previous digest and replicas and close the source upgrade authority without repeating destructive work", RecoveryBoundary: "source upgrade becomes RECOVERY_COMPLETED", AutomaticReplay: true},
	}
}

type BackupRequest struct {
	Service string `json:"service"`
}
