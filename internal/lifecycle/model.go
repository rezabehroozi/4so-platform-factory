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
type BackupRequest struct {
	Service string `json:"service"`
}
