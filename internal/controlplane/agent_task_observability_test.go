package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestAgentTaskQueueCountsScopesAndClassifiesLeaseHealth(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { return prefix + "_fixed" })
	active := now.Add(time.Minute)
	expired := now.Add(-time.Second)
	pendingAt := now.Add(-10 * time.Minute)
	activeAt := now.Add(-5 * time.Minute)
	expiredAt := now.Add(-20 * time.Minute)
	blockedAt := now.Add(-30 * time.Minute)
	profileAt := now.Add(-2 * time.Minute)
	otherAt := now.Add(-time.Hour)
	store.baselineDeployments["b-pending"] = BaselineDeployment{ResourceMeta: ResourceMeta{ID: "b-pending", UpdatedAt: pendingAt}, ProjectID: "p-a", State: BaselineDeploymentQueued}
	store.baselineDeployments["b-active"] = BaselineDeployment{ResourceMeta: ResourceMeta{ID: "b-active", UpdatedAt: activeAt}, ProjectID: "p-a", State: BaselineDeploymentApplying, TaskLeaseExpiresAt: &active, TaskAttempt: 2}
	store.runtimeVerifications["rv-expired"] = RuntimeVerification{ResourceMeta: ResourceMeta{ID: "rv-expired", UpdatedAt: expiredAt}, ProjectID: "p-a", State: RuntimeVerificationRunning, TaskLeaseExpiresAt: &expired, TaskAttempt: 3}
	store.runtimeCertifications["rc-blocked"] = RuntimeCertificationRun{ResourceMeta: ResourceMeta{ID: "rc-blocked", UpdatedAt: blockedAt}, ProjectID: "p-a", State: RuntimeCertificationBlocked, TaskAttempt: 2}
	store.tenants["tenant-failed"] = TenantEnvironment{ResourceMeta: ResourceMeta{ID: "tenant-failed", UpdatedAt: blockedAt}, ProjectID: "p-a", State: TenantFailed}
	store.providerProfiles["profile-active"] = ProviderProfile{ResourceMeta: ResourceMeta{ID: "profile-active", UpdatedAt: profileAt}, ProjectID: "p-a", State: ProviderProfileVerifying, TaskLeaseExpiresAt: &active, TaskAttempt: 1}
	store.providerClusters["other-project"] = ProviderCluster{ResourceMeta: ResourceMeta{ID: "other-project", UpdatedAt: otherAt}, ProjectID: "p-b", State: ProviderClusterQueued, TaskAttempt: 9}

	got, err := store.AgentTaskQueueCounts(context.Background(), []string{"p-a"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pending != 2 || got.Executing != 2 || got.Attention != 2 || got.ExpiredClaims != 1 {
		t.Fatalf("agent task counts=%+v", got)
	}
	if got.Retried != 2 || got.MaxAttempt != 3 {
		t.Fatalf("retry truth=%+v want retried=2 maxAttempt=3", got)
	}
	if got.OldestPendingAt == nil || !got.OldestPendingAt.Equal(expiredAt) {
		t.Fatalf("oldest pending=%v want=%v", got.OldestPendingAt, expiredAt)
	}
	if got.OldestExecutingAt == nil || !got.OldestExecutingAt.Equal(activeAt) {
		t.Fatalf("oldest executing=%v want=%v", got.OldestExecutingAt, activeAt)
	}
	if got.States["provider-cluster/QUEUED"] != 0 {
		t.Fatalf("cross-project agent task leaked into state aggregate: %+v", got.States)
	}
	for _, key := range []string{"baseline/QUEUED", "baseline/APPLYING", "runtime-verification/RUNNING", "runtime-certification/BLOCKED", "tenant/FAILED", "provider-profile/VERIFYING"} {
		if got.States[key] != 1 {
			t.Fatalf("state %s=%d want=1 states=%+v", key, got.States[key], got.States)
		}
	}
}

func TestAddAgentTaskQueueStateTreatsExpiredRunningLeaseAsReclaimable(t *testing.T) {
	got := AgentTaskQueueCounts{}
	pendingAt := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	executingAt := pendingAt.Add(time.Minute)
	AddAgentTaskQueueState(&got, "provider-cluster", "RECONCILING", 3, 1, 1, 2, 4, &pendingAt, &executingAt)
	if got.Executing != 1 || got.Pending != 2 || got.ExpiredClaims != 1 || got.Attention != 0 || got.Retried != 2 || got.MaxAttempt != 4 {
		t.Fatalf("counts=%+v", got)
	}
	if got.OldestPendingAt == nil || !got.OldestPendingAt.Equal(pendingAt) || got.OldestExecutingAt == nil || !got.OldestExecutingAt.Equal(executingAt) {
		t.Fatalf("age truth=%+v", got)
	}
}
