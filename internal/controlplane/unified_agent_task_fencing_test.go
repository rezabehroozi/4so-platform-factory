package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestBaselineLeasePreventsConcurrentClaimAndFencesRecoveredAttempt(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "baseline-fence", DisplayName: "Baseline Fence"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	cluster, agentToken, _ := seedFleetCluster(t, store, project, "baseline-fence-edge", 71)
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	dep, _, err := store.CreateBaselineDeployment(ctx, BaselineDeployment{ProjectID: project.ID, ClusterID: cluster.ID, BaselineID: "secure-namespace-foundation", BaselineVersion: "1.0.0", TargetNamespace: "4so-platform-baseline", Risk: "medium", DesiredDigest: testDigest(8101), RequestDigest: testDigest(8102), IdempotencyKey: "baseline-fence"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	type claimResult struct {
		deployment BaselineDeployment
		err        error
	}
	start := make(chan struct{})
	claims := make(chan claimResult, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			v, claimErr := store.NextBaselineTask(ctx, cluster.ID, agentToken)
			claims <- claimResult{deployment: v, err: claimErr}
		}()
	}
	close(start)
	var first BaselineDeployment
	successes, blocked := 0, 0
	for i := 0; i < 2; i++ {
		result := <-claims
		switch {
		case result.err == nil:
			first = result.deployment
			successes++
		case errors.Is(result.err, ErrNotFound):
			blocked++
		default:
			t.Fatalf("concurrent baseline claim err=%v", result.err)
		}
	}
	if successes != 1 || blocked != 1 || first.ID != dep.ID || first.TaskFenceToken != 1 || first.TaskLeaseExpiresAt == nil {
		t.Fatalf("baseline claim ownership successes=%d blocked=%d first=%+v", successes, blocked, first)
	}
	if _, err = store.NextBaselineTask(ctx, cluster.ID, agentToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active baseline lease was reissued: %v", err)
	}
	now = first.TaskLeaseExpiresAt.Add(time.Second)
	cluster = refreshClusterTaskInventoryAt(t, store, ctx, cluster.ID, agentToken, now)
	second, err := store.NextBaselineTask(ctx, cluster.ID, agentToken)
	if err != nil || second.TaskFenceToken != 2 || second.TaskAttempt != 2 || second.Revision <= first.Revision {
		t.Fatalf("recovered baseline claim=%+v err=%v", second, err)
	}
	if _, err = store.ReportBaselineTask(ctx, cluster.ID, agentToken, first.Revision, BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: false, Error: "stale", TaskFenceToken: first.TaskFenceToken}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale baseline report err=%v", err)
	}
	failed, err := store.ReportBaselineTask(ctx, cluster.ID, agentToken, second.Revision, BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: false, Error: "expected test stop", TaskFenceToken: second.TaskFenceToken})
	if err != nil || failed.State != BaselineDeploymentFailed {
		t.Fatalf("baseline current report=%+v err=%v", failed, err)
	}
}

func TestBaselineRollbackLeaseExpiryDoesNotReplayDestructiveTask(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, Organization{Name: "rollback-fence", DisplayName: "Rollback Fence"}, "operator")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	cluster, agentToken, applied := seedFleetCluster(t, store, project, "rollback-fence-edge", 72)
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	cp, err := store.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: cluster.ID, Provider: "s3", Reference: "baseline-fence-backup", EvidenceDigest: testDigest(8201), CompletedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	queued, err := store.QueueBaselineRollback(ctx, applied.ID, applied.Revision, "operator", cp.ID, testDigest(8202))
	if err != nil || queued.State != BaselineDeploymentRollbackQueued {
		t.Fatalf("queue rollback=%+v err=%v", queued, err)
	}
	claim, err := store.NextBaselineTask(ctx, cluster.ID, agentToken)
	if err != nil || claim.State != BaselineDeploymentRollingBack || claim.TaskLeaseExpiresAt == nil {
		t.Fatalf("rollback claim=%+v err=%v", claim, err)
	}
	now = claim.TaskLeaseExpiresAt.Add(time.Second)
	cluster = refreshClusterTaskInventoryAt(t, store, ctx, cluster.ID, agentToken, now)
	if _, err = store.NextBaselineTask(ctx, cluster.ID, agentToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired rollback was automatically replayed: %v", err)
	}
	failed, err := store.GetBaselineDeployment(ctx, applied.ID)
	if err != nil || failed.State != BaselineDeploymentFailed || failed.TaskLeaseExpiresAt != nil {
		t.Fatalf("expired rollback deployment=%+v err=%v", failed, err)
	}
	op, err := store.GetOperation(ctx, failed.DestructiveOperationID)
	if err != nil || op.State != OperationFailed || !op.RetryExhausted {
		t.Fatalf("expired rollback operation=%+v err=%v", op, err)
	}
}

func TestRuntimeVerificationLeasePreventsConcurrentClaimAndFencesRecovery(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, Organization{Name: "verification-fence", DisplayName: "Verification Fence"}, "operator")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	cluster, agentToken, applied := seedFleetCluster(t, store, project, "verification-fence-edge", 73)
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	verification, _, err := store.CreateRuntimeVerification(ctx, RuntimeVerification{ProjectID: project.ID, ClusterID: cluster.ID, BaselineDeploymentID: applied.ID, ProbeImage: "registry.test/probe@sha256:" + fmt.Sprintf("%064x", 8301), RequestDigest: testDigest(8302), IdempotencyKey: "verification-fence"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	type claimResult struct {
		verification RuntimeVerification
		err          error
	}
	start := make(chan struct{})
	claims := make(chan claimResult, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			v, claimErr := store.NextRuntimeVerificationTask(ctx, cluster.ID, agentToken)
			claims <- claimResult{verification: v, err: claimErr}
		}()
	}
	close(start)
	var first RuntimeVerification
	successes, blocked := 0, 0
	for i := 0; i < 2; i++ {
		result := <-claims
		if result.err == nil {
			first = result.verification
			successes++
		} else if errors.Is(result.err, ErrNotFound) {
			blocked++
		} else {
			t.Fatalf("concurrent verification claim err=%v", result.err)
		}
	}
	if successes != 1 || blocked != 1 || first.ID != verification.ID || first.TaskFenceToken != 1 || first.TaskLeaseExpiresAt == nil {
		t.Fatalf("verification ownership successes=%d blocked=%d first=%+v", successes, blocked, first)
	}
	now = first.TaskLeaseExpiresAt.Add(time.Second)
	cluster = refreshClusterTaskInventoryAt(t, store, ctx, cluster.ID, agentToken, now)
	second, err := store.NextRuntimeVerificationTask(ctx, cluster.ID, agentToken)
	if err != nil || second.TaskFenceToken != 2 || second.Revision <= first.Revision {
		t.Fatalf("recovered verification=%+v err=%v", second, err)
	}
	if _, err = store.ReportRuntimeVerificationTask(ctx, cluster.ID, agentToken, first.Revision, RuntimeVerificationResult{VerificationID: verification.ID, TaskFenceToken: first.TaskFenceToken, Success: false, Error: "stale"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale verification report err=%v", err)
	}
	failed, err := store.ReportRuntimeVerificationTask(ctx, cluster.ID, agentToken, second.Revision, RuntimeVerificationResult{VerificationID: verification.ID, TaskFenceToken: second.TaskFenceToken, Success: false, Error: "expected test stop"})
	if err != nil || failed.State != RuntimeVerificationFailed {
		t.Fatalf("verification current report=%+v err=%v", failed, err)
	}
}

func TestRuntimeCertificationLeasePreventsConcurrentClaimAndFencesRecovery(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, Organization{Name: "cert-fence", DisplayName: "Certification Fence"}, "operator")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	cluster, agentToken, _ := seedFleetCluster(t, store, project, "cert-fence-edge", 74)
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	inv := store.clusterInventories[cluster.ID]
	run := RuntimeCertificationRun{ResourceMeta: ResourceMeta{ID: "rtc_fence", Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: project.ID, ClusterID: cluster.ID, Profile: RuntimeCertificationFoundationV1, State: RuntimeCertificationQueued, Phase: RuntimeCertificationPhaseInstall, Namespace: "4so-cert-fence", InventoryDigest: inv.Digest, EnvironmentFingerprint: RuntimeEnvironmentFingerprint(inv), RenderedDigest: testDigest(8401), ResourceCount: 1, IdempotencyKey: "cert-fence", RequestDigest: testDigest(8402)}
	store.runtimeCertifications[run.ID] = cloneRuntimeCertification(run)
	type claimResult struct {
		run RuntimeCertificationRun
		err error
	}
	start := make(chan struct{})
	claims := make(chan claimResult, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			v, claimErr := store.NextRuntimeCertificationTask(ctx, cluster.ID, agentToken)
			claims <- claimResult{run: v, err: claimErr}
		}()
	}
	close(start)
	var first RuntimeCertificationRun
	successes, blocked := 0, 0
	for i := 0; i < 2; i++ {
		result := <-claims
		if result.err == nil {
			first = result.run
			successes++
		} else if errors.Is(result.err, ErrNotFound) {
			blocked++
		} else {
			t.Fatalf("concurrent certification claim err=%v", result.err)
		}
	}
	if successes != 1 || blocked != 1 || first.TaskFenceToken != 1 || first.TaskLeaseExpiresAt == nil {
		t.Fatalf("certification ownership successes=%d blocked=%d first=%+v", successes, blocked, first)
	}
	if len(first.CleanupGenerations) != 1 || first.CleanupGenerations[0].TaskAttempt != 1 || first.CleanupGenerations[0].Phase != RuntimeCertificationPhaseInstall || first.CleanupGenerations[0].Token == "" {
		t.Fatalf("first cleanup generation not durably claimed: %+v", first.CleanupGenerations)
	}
	now = first.TaskLeaseExpiresAt.Add(time.Second)
	cluster = refreshClusterTaskInventoryAt(t, store, ctx, cluster.ID, agentToken, now)
	second, err := store.NextRuntimeCertificationTask(ctx, cluster.ID, agentToken)
	if err != nil || second.TaskFenceToken != 2 || second.Revision <= first.Revision {
		t.Fatalf("recovered certification=%+v err=%v", second, err)
	}
	if len(second.CleanupGenerations) != 2 || second.CleanupGenerations[0].Token != first.CleanupGenerations[0].Token || second.CleanupGenerations[1].Token == "" || second.CleanupGenerations[1].Token == first.CleanupGenerations[0].Token {
		t.Fatalf("recovery cleanup generations are not monotonic/durable: first=%+v second=%+v", first.CleanupGenerations, second.CleanupGenerations)
	}
	stale := RuntimeCertificationResult{RunID: run.ID, Phase: first.Phase, TaskFenceToken: first.TaskFenceToken, InventoryDigest: first.InventoryDigest, RenderedDigest: first.RenderedDigest, Success: false, Error: "stale"}
	if _, err = store.ReportRuntimeCertificationTask(ctx, cluster.ID, agentToken, first.Revision, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale certification report err=%v", err)
	}
	current := stale
	current.TaskFenceToken = second.TaskFenceToken
	current.Phase = second.Phase
	failed, err := store.ReportRuntimeCertificationTask(ctx, cluster.ID, agentToken, second.Revision, current)
	if err != nil || failed.State != RuntimeCertificationFailed {
		t.Fatalf("certification current report=%+v err=%v", failed, err)
	}
}

func TestBaselineReportAcceptsLeasedResultAfterInventoryFreshnessWindow(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "baseline-long-result", DisplayName: "Baseline Long Result"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	cluster, agentToken, _ := seedFleetCluster(t, store, project, "baseline-long-result-edge", 75)
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	dep, _, err := store.CreateBaselineDeployment(ctx, BaselineDeployment{ProjectID: project.ID, ClusterID: cluster.ID, BaselineID: "secure-namespace-foundation", BaselineVersion: "1.0.0", TargetNamespace: "4so-platform-baseline", Risk: "medium", DesiredDigest: testDigest(8501), RequestDigest: testDigest(8502), IdempotencyKey: "baseline-long-result"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.NextBaselineTask(ctx, cluster.ID, agentToken)
	if err != nil || claim.TaskLeaseExpiresAt == nil {
		t.Fatalf("claim=%+v err=%v", claim, err)
	}
	now = now.Add(ClusterInventoryAuthorityFreshness + time.Second)
	if !claim.TaskLeaseExpiresAt.After(now) {
		t.Fatalf("test requires the task lease to outlive the inventory freshness window: lease=%v now=%v", claim.TaskLeaseExpiresAt, now)
	}
	if ClusterTaskClaimAdmittedAt(store.managedClusters[cluster.ID], now) {
		t.Fatal("stale inventory unexpectedly remained eligible for a new task claim")
	}
	failed, err := store.ReportBaselineTask(ctx, cluster.ID, agentToken, claim.Revision, BaselineTaskResult{DeploymentID: dep.ID, Action: "PLAN", Success: false, Error: "expected long-running result", TaskFenceToken: claim.TaskFenceToken})
	if err != nil || failed.State != BaselineDeploymentFailed {
		t.Fatalf("valid leased result was rejected solely because inventory freshness elapsed: deployment=%+v err=%v", failed, err)
	}
}
