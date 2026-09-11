package installation

const RecoveryConsoleAuthority = "INSTALLER_RECOVERY_CONSOLE_AUTHORITY_V1"

type RecoveryAction struct {
	ID           string `json:"id"`
	Category     string `json:"category"`
	Risk         string `json:"risk"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Confirmation string `json:"confirmation,omitempty"`
	Description  string `json:"description"`
}

type RecoveryConsoleDescriptor struct {
	Authority              string           `json:"authority"`
	SeparateBootstrapPlane bool             `json:"separateBootstrapPlane"`
	Reason                 string           `json:"reason"`
	CredentialBoundary     string           `json:"credentialBoundary"`
	Actions                []RecoveryAction `json:"actions"`
}

func RecoveryConsoleModel() RecoveryConsoleDescriptor {
	return RecoveryConsoleDescriptor{
		Authority:              RecoveryConsoleAuthority,
		SeparateBootstrapPlane: true,
		Reason:                 "Recovery authority remains available when the product API is unavailable, degraded, reset, or being reinstalled.",
		CredentialBoundary:     "The Platform Console never stores or proxies the installer bootstrap token. Operators authenticate directly to the standalone Installer Recovery Console.",
		Actions: []RecoveryAction{
			{ID: "status", Category: "readiness", Risk: "LOW", Method: "GET", Path: "/api/v1/status", Description: "Inspect durable installation state and resumability."},
			{ID: "resume", Category: "installation", Risk: "MEDIUM", Method: "POST", Path: "/api/v1/resume", Description: "Resume an interrupted installation using persisted authority."},
			{ID: "diagnostics", Category: "support", Risk: "LOW", Method: "GET", Path: "/api/v1/diagnostics/report", Description: "Generate local installer diagnostics for verification or escalation."},
			{ID: "reset", Category: "recovery", Risk: "HIGH", Method: "POST", Path: "/api/v1/reset/start", Confirmation: "release-bound reset confirmation", Description: "Start journaled product-owned reset before a clean reinstall."},
			{ID: "reset-resume", Category: "recovery", Risk: "HIGH", Method: "POST", Path: "/api/v1/reset/resume", Confirmation: "run-bound resume confirmation", Description: "Resume an interrupted journaled reset."},
			{ID: "dr-backup", Category: "disaster-recovery", Risk: "MEDIUM", Method: "POST", Path: "/api/v1/disaster-recovery/backup", Description: "Create an off-node appliance backup using persisted storage authority."},
			{ID: "dr-restore", Category: "disaster-recovery", Risk: "HIGH", Method: "POST", Path: "/api/v1/disaster-recovery/restore", Confirmation: "backup-bound restore confirmation", Description: "Restore the appliance from an exact persisted backup authority."},
			{ID: "service-backup", Category: "service-lifecycle", Risk: "MEDIUM", Method: "POST", Path: "/api/v1/lifecycle/backup", Description: "Create a service-scoped lifecycle backup."},
			{ID: "service-restore", Category: "service-lifecycle", Risk: "HIGH", Method: "POST", Path: "/api/v1/lifecycle/restore", Description: "Restore a service from a verified lifecycle backup."},
			{ID: "service-upgrade", Category: "service-lifecycle", Risk: "HIGH", Method: "POST", Path: "/api/v1/lifecycle/upgrade", Description: "Run a digest-pinned service lifecycle upgrade."},
			{ID: "upgrade-recovery", Category: "service-lifecycle", Risk: "HIGH", Method: "POST", Path: "/api/v1/lifecycle/upgrade-recovery", Description: "Perform explicit recovery for an interrupted or failed lifecycle upgrade."},
		},
	}
}
