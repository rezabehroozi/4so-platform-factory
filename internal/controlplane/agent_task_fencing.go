package controlplane

import "time"

// AgentTaskLeaseDuration bounds single-agent ownership of external side effects.
// Active leases are never reissued. Safe/idempotent non-destructive work may be
// reclaimed only after expiry with a strictly larger fence token. Destructive
// work must be failed and resubmitted through its recovery authority instead.
const AgentTaskLeaseDuration = 10 * time.Minute

func AgentTaskLeaseActive(expires *time.Time, now time.Time) bool {
	return expires != nil && expires.After(now.UTC())
}
