package disasterrecovery

import (
	"time"

	"platform.4so.io/factory/internal/installation"
)

type Action string

const (
	ActionBackup  Action = "backup"
	ActionRestore Action = "restore"
)

type State string

const (
	StateQueued    State = "QUEUED"
	StateRunning   State = "RUNNING"
	StateSucceeded State = "SUCCEEDED"
	StateFailed    State = "FAILED"
)

type RestoreTargetIdentity struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
}

type Run struct {
	ID                  string                   `json:"id"`
	Action              Action                   `json:"action"`
	State               State                    `json:"state"`
	BackupID            string                   `json:"backupId"`
	ObjectPrefix        string                   `json:"objectPrefix"`
	ObjectStorage       installation.ServiceSpec `json:"objectStorage"`
	ProfileID           string                   `json:"profileId,omitempty"`
	BackupFormat        string                   `json:"backupFormat,omitempty"`
	CompletedComponents []string                 `json:"completedComponents,omitempty"`
	RestoreTargets      []RestoreTargetIdentity  `json:"restoreTargets,omitempty"`
	AuthorityBackupNode string                   `json:"authorityBackupNode,omitempty"`
	ForgejoBackupNode   string                   `json:"forgejoBackupNode,omitempty"`
	ZotBackupNode       string                   `json:"zotBackupNode,omitempty"`
	RecoveryRequired    bool                     `json:"recoveryRequired,omitempty"`
	Error               string                   `json:"error,omitempty"`
	CreatedAt           time.Time                `json:"createdAt"`
	StartedAt           *time.Time               `json:"startedAt,omitempty"`
	FinishedAt          *time.Time               `json:"finishedAt,omitempty"`
}
type RestoreRequest struct {
	BackupID string `json:"backupId"`
}
