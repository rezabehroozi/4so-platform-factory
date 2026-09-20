package controlplane

import (
	"context"
	"strings"
	"time"
)

// AgentTaskQueueCounts is a bounded, read-only aggregate over product-owned
// task families consumed by the cluster Agent. It deliberately exposes no
// claim tokens, fence tokens, credentials, task payloads or mutation controls.
// Pending means runnable/reclaimable without an active lease; Executing means
// an active lease exists; ExpiredClaims is a subset of Pending whose previous
// lease elapsed before completion. Age is derived from the canonical resource
// UpdatedAt timestamp for the current durable state.
type AgentTaskQueueCounts struct {
	Pending           int
	Executing         int
	Attention         int
	ExpiredClaims     int
	Retried           int
	MaxAttempt        int
	OldestPendingAt   *time.Time
	OldestExecutingAt *time.Time
	States            map[string]int
}

func earlierTime(current *time.Time, candidate *time.Time) *time.Time {
	if candidate == nil || candidate.IsZero() {
		return current
	}
	if current == nil || candidate.Before(*current) {
		v := candidate.UTC()
		return &v
	}
	return current
}

// AddAgentTaskQueueState applies the canonical state/lease/retry/age
// classification used by both development stores and PostgreSQL aggregates.
func AddAgentTaskQueueState(out *AgentTaskQueueCounts, family, state string, total, activeLeases, expiredLeases, retried, maxAttempt int, oldestPendingAt, oldestExecutingAt *time.Time) {
	if out == nil || total <= 0 {
		return
	}
	family = strings.TrimSpace(family)
	state = strings.TrimSpace(state)
	if family == "" || state == "" {
		return
	}
	if out.States == nil {
		out.States = map[string]int{}
	}
	out.States[family+"/"+state] += total
	candidate, attention := agentTaskQueueStateClass(family, state)
	if attention {
		out.Attention += total
		return
	}
	if !candidate {
		return
	}
	if activeLeases < 0 {
		activeLeases = 0
	}
	if activeLeases > total {
		activeLeases = total
	}
	if expiredLeases < 0 {
		expiredLeases = 0
	}
	if expiredLeases > total-activeLeases {
		expiredLeases = total - activeLeases
	}
	if retried < 0 {
		retried = 0
	}
	if retried > total {
		retried = total
	}
	out.Executing += activeLeases
	out.Pending += total - activeLeases
	out.ExpiredClaims += expiredLeases
	out.Retried += retried
	if maxAttempt > out.MaxAttempt {
		out.MaxAttempt = maxAttempt
	}
	if total-activeLeases > 0 {
		out.OldestPendingAt = earlierTime(out.OldestPendingAt, oldestPendingAt)
	}
	if activeLeases > 0 {
		out.OldestExecutingAt = earlierTime(out.OldestExecutingAt, oldestExecutingAt)
	}
}

func agentTaskQueueStateClass(family, state string) (candidate bool, attention bool) {
	switch family {
	case "baseline":
		switch BaselineDeploymentState(state) {
		case BaselineDeploymentPlanning, BaselineDeploymentQueued, BaselineDeploymentApplying, BaselineDeploymentRollbackQueued, BaselineDeploymentRollingBack:
			return true, false
		case BaselineDeploymentFailed:
			return false, true
		}
	case "runtime-verification":
		switch RuntimeVerificationState(state) {
		case RuntimeVerificationQueued, RuntimeVerificationRunning:
			return true, false
		case RuntimeVerificationFailed:
			return false, true
		}
	case "runtime-certification":
		switch RuntimeCertificationState(state) {
		case RuntimeCertificationQueued, RuntimeCertificationInstalling, RuntimeCertificationVerifying:
			return true, false
		case RuntimeCertificationBlocked, RuntimeCertificationFailed:
			return false, true
		}
	case "tenant":
		switch TenantState(state) {
		case TenantQueued, TenantProvisioning, TenantSuspendQueued, TenantSuspending, TenantResumeQueued, TenantResuming, TenantResizeQueued, TenantResizing, TenantDeleteQueued, TenantDeleting:
			return true, false
		case TenantFailed:
			return false, true
		}
	case "provider-profile":
		switch ProviderProfileState(state) {
		case ProviderProfileVerifyQueued, ProviderProfileVerifying:
			return true, false
		case ProviderProfileFailed:
			return false, true
		}
	case "provider-cluster":
		switch ProviderClusterState(state) {
		case ProviderClusterQueued, ProviderClusterApplying, ProviderClusterReconciling, ProviderClusterDeleteQueued, ProviderClusterDeleting:
			return true, false
		case ProviderClusterRecoveryRequired, ProviderClusterFailed:
			return false, true
		}
	}
	return false, false
}

func agentLeaseCounts(expires *time.Time, now time.Time) (active, expired int) {
	if expires == nil {
		return 0, 0
	}
	if expires.After(now) {
		return 1, 0
	}
	return 0, 1
}

func observeMemoryAgentTask(out *AgentTaskQueueCounts, family, state string, expires *time.Time, attempt int, updatedAt, now time.Time) {
	active, expired := agentLeaseCounts(expires, now)
	retried := 0
	if attempt > 1 {
		retried = 1
	}
	var pendingAt, executingAt *time.Time
	stamp := updatedAt.UTC()
	if active > 0 {
		executingAt = &stamp
	} else {
		pendingAt = &stamp
	}
	AddAgentTaskQueueState(out, family, state, 1, active, expired, retried, attempt, pendingAt, executingAt)
}

// AgentTaskQueueCounts returns project-scoped aggregate queue health without
// materializing operation evidence or exposing task payloads. FileStore gains
// the same method through its embedded MemoryStore.
func (s *MemoryStore) AgentTaskQueueCounts(_ context.Context, projectIDs []string, allProjects bool) (AgentTaskQueueCounts, error) {
	allowed := map[string]bool{}
	for _, id := range projectIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			allowed[id] = true
		}
	}
	visible := func(projectID string) bool { return allProjects || allowed[projectID] }
	now := nowUTC(s.now)
	out := AgentTaskQueueCounts{States: map[string]int{}}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.baselineDeployments {
		if visible(v.ProjectID) {
			observeMemoryAgentTask(&out, "baseline", string(v.State), v.TaskLeaseExpiresAt, v.TaskAttempt, v.UpdatedAt, now)
		}
	}
	for _, v := range s.runtimeVerifications {
		if visible(v.ProjectID) {
			observeMemoryAgentTask(&out, "runtime-verification", string(v.State), v.TaskLeaseExpiresAt, v.TaskAttempt, v.UpdatedAt, now)
		}
	}
	for _, v := range s.runtimeCertifications {
		if visible(v.ProjectID) {
			observeMemoryAgentTask(&out, "runtime-certification", string(v.State), v.TaskLeaseExpiresAt, v.TaskAttempt, v.UpdatedAt, now)
		}
	}
	for _, v := range s.tenants {
		if visible(v.ProjectID) {
			observeMemoryAgentTask(&out, "tenant", string(v.State), v.TaskLeaseExpiresAt, v.TaskAttempt, v.UpdatedAt, now)
		}
	}
	for _, v := range s.providerProfiles {
		if visible(v.ProjectID) {
			observeMemoryAgentTask(&out, "provider-profile", string(v.State), v.TaskLeaseExpiresAt, v.TaskAttempt, v.UpdatedAt, now)
		}
	}
	for _, v := range s.providerClusters {
		if visible(v.ProjectID) {
			observeMemoryAgentTask(&out, "provider-cluster", string(v.State), v.TaskLeaseExpiresAt, v.TaskAttempt, v.UpdatedAt, now)
		}
	}
	return out, nil
}
