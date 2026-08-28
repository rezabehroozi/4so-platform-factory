package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func providerFixture(t *testing.T) (*MemoryStore, context.Context, Project, ManagedCluster, string) {
	t.Helper()
	ctx := context.Background()
	s := NewMemoryStore()
	org, err := s.CreateOrganization(ctx, Organization{Name: "provider-org", DisplayName: "Provider Org"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "provider-project", DisplayName: "Provider Project"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	enrollment, agentToken := "provider-enrollment-token-abcdefghijklmnopqrstuvwxyz", "provider-agent-token-abcdefghijklmnopqrstuvwxyz"
	imp, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: "management", DisplayName: "Management", TokenDigest: digestTenantTest(enrollment), ExpiresAt: time.Now().Add(time.Hour)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = s.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := s.ClaimClusterImport(ctx, imp.ID, digestTenantTest(enrollment), digestTenantTest(agentToken), "uid-provider-management", "0.0.17")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err = upsertMutationReadyInventoryForTest(t, s, ctx, cluster.ID, digestTenantTest(agentToken), cluster.ExternalUID, ClusterInventory{
		ObservedAt: time.Now().UTC(), Distribution: "rke2", KubernetesVersion: "v1.33.2",
		Capabilities: []string{TargetMutationRBACActiveCapability, "controlled-baseline-deployment"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, ctx, project, cluster, agentToken
}

func readyProviderProfile(t *testing.T, s *MemoryStore, ctx context.Context, project Project, cluster ManagedCluster, agentToken string) ProviderProfile {
	t.Helper()
	profile, replay, err := s.CreateProviderProfile(ctx, ProviderProfile{
		ProjectID: project.ID, ManagementClusterID: cluster.ID,
		Name: "vsphere-standard", DisplayName: "vSphere Standard",
		Adapter: clusterAPIAdapter, Namespace: providerSystemNamespace,
		ClusterClassName: "vsphere-standard", WorkerClassName: "worker-standard",
		DefaultKubernetesVersion: "v1.33.2", KubernetesSeries: []string{"v1.32", "v1.33"}, MaxWorkerReplicas: 20,
		DesiredDigest: digestTenantTest("profile-desired"), RequestDigest: digestTenantTest("profile-request"), IdempotencyKey: "profile-1",
	}, "admin")
	if err != nil || replay || profile.State != ProviderProfileVerifyQueued {
		t.Fatalf("profile=%#v replay=%v err=%v", profile, replay, err)
	}
	claimed, err := s.NextProviderProfileTask(ctx, cluster.ID, digestTenantTest(agentToken))
	if err != nil || claimed.State != ProviderProfileVerifying {
		t.Fatalf("claimed profile=%#v err=%v", claimed, err)
	}
	profile, err = s.ReportProviderProfileTask(ctx, cluster.ID, digestTenantTest(agentToken), claimed.Revision, ProviderProfileTaskResult{ProfileID: profile.ID, TaskFenceToken: claimed.TaskFenceToken, Success: true, ObservedDigest: digestTenantTest("cluster-class")})
	if err != nil || profile.State != ProviderProfileReady {
		t.Fatalf("ready profile=%#v err=%v", profile, err)
	}
	return profile
}

func runProviderClusterToActive(t *testing.T, s *MemoryStore, ctx context.Context, cluster ManagedCluster, agentToken string, v ProviderCluster) ProviderCluster {
	t.Helper()
	claimed, _, err := s.NextProviderClusterTask(ctx, cluster.ID, digestTenantTest(agentToken))
	if err != nil || claimed.State != ProviderClusterApplying {
		t.Fatalf("apply claim=%#v err=%v", claimed, err)
	}
	v, err = s.ReportProviderClusterTask(ctx, cluster.ID, digestTenantTest(agentToken), claimed.Revision, ProviderClusterTaskResult{ProviderClusterID: v.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "APPLY", Success: true, ObservedDigest: v.DesiredDigest, Phase: "Provisioning"})
	if err != nil || v.State != ProviderClusterReconciling {
		t.Fatalf("reconciling=%#v err=%v", v, err)
	}
	claimed, _, err = s.NextProviderClusterTask(ctx, cluster.ID, digestTenantTest(agentToken))
	if err != nil || claimed.State != ProviderClusterReconciling {
		t.Fatalf("inspect claim=%#v err=%v", claimed, err)
	}
	v, err = s.ReportProviderClusterTask(ctx, cluster.ID, digestTenantTest(agentToken), claimed.Revision, ProviderClusterTaskResult{ProviderClusterID: v.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "INSPECT", Success: true, Ready: true, ObservedDigest: v.DesiredDigest, Phase: "Provisioned"})
	if err != nil || v.State != ProviderClusterActive || v.Applied != v.Desired {
		t.Fatalf("active=%#v err=%v", v, err)
	}
	return v
}

func TestProviderLifecycleCreateScaleUpgradeDelete(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile := readyProviderProfile(t, s, ctx, project, management, agentToken)

	v, replay, err := s.CreateProviderCluster(ctx, ProviderCluster{
		ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "customer-a", DisplayName: "Customer A",
		Desired:       ProviderClusterSpec{KubernetesVersion: "v1.33.2", ControlPlaneReplicas: 3, WorkerReplicas: 3},
		DesiredDigest: digestTenantTest("cluster-v1"), RequestDigest: digestTenantTest("cluster-request"), IdempotencyKey: "cluster-1",
	}, "operator")
	if err != nil || replay || v.State != ProviderClusterAwaitingApproval || v.Namespace != providerSystemNamespace || v.ResourceName == "" {
		t.Fatalf("cluster=%#v replay=%v err=%v", v, replay, err)
	}
	v, err = s.ApproveProviderCluster(ctx, v.ID, v.Revision, "approver")
	if err != nil || v.State != ProviderClusterQueued {
		t.Fatalf("approved=%#v err=%v", v, err)
	}
	v = runProviderClusterToActive(t, s, ctx, management, agentToken, v)

	desired := v.Desired
	desired.WorkerReplicas = 5
	v, err = s.QueueProviderClusterChange(ctx, v.ID, v.Revision, "SCALE", desired, digestTenantTest("cluster-scale"), "operator", digestTenantTest("scale-request"), "")
	if err != nil || v.State != ProviderClusterAwaitingApproval || v.PendingAction != "SCALE" {
		t.Fatalf("scale queue=%#v err=%v", v, err)
	}
	v, _ = s.ApproveProviderCluster(ctx, v.ID, v.Revision, "approver")
	v = runProviderClusterToActive(t, s, ctx, management, agentToken, v)
	if v.Applied.WorkerReplicas != 5 {
		t.Fatalf("applied scale=%#v", v.Applied)
	}

	desired = v.Desired
	desired.KubernetesVersion = "v1.33.3"
	v, err = s.QueueProviderClusterChange(ctx, v.ID, v.Revision, "UPGRADE", desired, digestTenantTest("cluster-upgrade"), "operator", digestTenantTest("upgrade-request"), "")
	if err != nil {
		t.Fatal(err)
	}
	v, _ = s.ApproveProviderCluster(ctx, v.ID, v.Revision, "approver")
	v = runProviderClusterToActive(t, s, ctx, management, agentToken, v)
	if v.Applied.KubernetesVersion != "v1.33.3" {
		t.Fatalf("applied upgrade=%#v", v.Applied)
	}

	management, _, err = upsertMutationReadyInventoryForTest(t, s, ctx, management.ID, digestTenantTest(agentToken), management.ExternalUID, ClusterInventory{ObservedAt: time.Now(), Distribution: "rke2", Capabilities: []string{TargetMutationRBACActiveCapability}, KubernetesVersion: "v1.33.2", Digest: digestTenantTest("provider-delete-inventory")})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.CreateRecoveryCheckpoint(ctx, RecoveryCheckpoint{ProjectID: project.ID, ClusterID: management.ID, Provider: "s3", Reference: "provider-delete-backup", EvidenceDigest: digestTenantTest("provider-delete-backup-evidence"), CompletedAt: time.Now().Add(-5 * time.Minute), ExpiresAt: time.Now().Add(4 * time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	v, err = s.QueueProviderClusterChange(ctx, v.ID, v.Revision, "DELETE", v.Desired, v.DesiredDigest, "operator", digestTenantTest("delete-request"), cp.ID)
	if err != nil || v.State != ProviderClusterDeleteApproval {
		t.Fatalf("delete queue=%#v err=%v", v, err)
	}
	v, _ = s.ApproveProviderCluster(ctx, v.ID, v.Revision, "approver")
	claimed, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || claimed.State != ProviderClusterDeleting {
		t.Fatalf("delete claim=%#v err=%v", claimed, err)
	}
	v, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), claimed.Revision, ProviderClusterTaskResult{ProviderClusterID: v.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "DELETE", Success: true, Deleted: true, Phase: "Deleted"})
	if err != nil || v.State != ProviderClusterDeleted {
		t.Fatalf("deleted=%#v err=%v", v, err)
	}

	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewMemoryStore()
	if err = restored.Restore(snap); err != nil {
		t.Fatal(err)
	}
	got, err := restored.GetProviderCluster(ctx, v.ID)
	if err != nil || got.State != ProviderClusterDeleted {
		t.Fatalf("restored=%#v err=%v", got, err)
	}
}

func TestProviderLifecycleRejectsInvalidSeriesAndStaleTaskAction(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile := readyProviderProfile(t, s, ctx, project, management, agentToken)
	_, _, err := s.CreateProviderCluster(ctx, ProviderCluster{
		ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "bad-series", DisplayName: "Bad Series",
		Desired:       ProviderClusterSpec{KubernetesVersion: "v1.34.0", ControlPlaneReplicas: 3, WorkerReplicas: 3},
		DesiredDigest: digestTenantTest("bad"), RequestDigest: digestTenantTest("bad-request"), IdempotencyKey: "bad-series",
	}, "operator")
	if err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("unsupported series accepted: %v", err)
	}
	v, _, err := s.CreateProviderCluster(ctx, ProviderCluster{
		ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "safe-cluster", DisplayName: "Safe Cluster",
		Desired:       ProviderClusterSpec{KubernetesVersion: "v1.33.2", ControlPlaneReplicas: 1, WorkerReplicas: 1},
		DesiredDigest: digestTenantTest("safe"), RequestDigest: digestTenantTest("safe-request"), IdempotencyKey: "safe",
	}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), v.Revision, ProviderClusterTaskResult{ProviderClusterID: v.ID, Action: "APPLY", Success: false, Error: fmt.Sprintf("%s", "forged")})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("stale task action changed non-task state: %v", err)
	}
}

func TestProviderTasksLeasePreventsConcurrentReissueAndFencesRecoveredAttempt(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	now := management.LastSeenAt.UTC()
	s.now = func() time.Time { return now }
	profile, replay, err := s.CreateProviderProfile(ctx, ProviderProfile{
		ProjectID: project.ID, ManagementClusterID: management.ID,
		Name: "retry-profile", DisplayName: "Retry Profile",
		Adapter: clusterAPIAdapter, Namespace: providerSystemNamespace,
		ClusterClassName: "retry-class", WorkerClassName: "retry-worker",
		DefaultKubernetesVersion: "v1.33.2", KubernetesSeries: []string{"v1.33"}, MaxWorkerReplicas: 10,
		DesiredDigest: digestTenantTest("retry-profile-desired"), RequestDigest: digestTenantTest("retry-profile-request"), IdempotencyKey: "retry-profile",
	}, "admin")
	if err != nil || replay {
		t.Fatalf("create profile replay=%v err=%v", replay, err)
	}
	first, err := s.NextProviderProfileTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || first.State != ProviderProfileVerifying || first.TaskAttempt != 1 || first.TaskFenceToken != 1 || first.TaskLeaseExpiresAt == nil {
		t.Fatalf("first profile claim=%+v err=%v", first, err)
	}
	if _, err = s.NextProviderProfileTask(ctx, management.ID, digestTenantTest(agentToken)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active profile lease was reissued: %v", err)
	}
	now = first.TaskLeaseExpiresAt.Add(time.Second)
	management = refreshClusterTaskInventoryAt(t, s, ctx, management.ID, digestTenantTest(agentToken), now)
	second, err := s.NextProviderProfileTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || second.TaskAttempt != 2 || second.TaskFenceToken != 2 || second.Revision <= first.Revision {
		t.Fatalf("recovered profile=%+v err=%v", second, err)
	}
	if _, err = s.ReportProviderProfileTask(ctx, management.ID, digestTenantTest(agentToken), first.Revision, ProviderProfileTaskResult{ProfileID: profile.ID, TaskFenceToken: first.TaskFenceToken, Success: true, ObservedDigest: digestTenantTest("retry-profile-observed")}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale profile report err=%v", err)
	}
	profile, err = s.ReportProviderProfileTask(ctx, management.ID, digestTenantTest(agentToken), second.Revision, ProviderProfileTaskResult{ProfileID: profile.ID, TaskFenceToken: second.TaskFenceToken, Success: true, ObservedDigest: digestTenantTest("retry-profile-observed")})
	if err != nil || profile.State != ProviderProfileReady {
		t.Fatalf("profile completion=%+v err=%v", profile, err)
	}

	cluster, replay, err := s.CreateProviderCluster(ctx, ProviderCluster{ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "retry-cluster", DisplayName: "Retry Cluster", Desired: ProviderClusterSpec{KubernetesVersion: "v1.33.2", ControlPlaneReplicas: 1, WorkerReplicas: 1}, DesiredDigest: digestTenantTest("retry-cluster-desired"), RequestDigest: digestTenantTest("retry-cluster-request"), IdempotencyKey: "retry-cluster"}, "operator")
	if err != nil || replay {
		t.Fatalf("create cluster replay=%v err=%v", replay, err)
	}
	cluster, err = s.ApproveProviderCluster(ctx, cluster.ID, cluster.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	apply1, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || apply1.State != ProviderClusterApplying || apply1.TaskAttempt != 1 || apply1.TaskFenceToken != 1 {
		t.Fatalf("first apply=%+v err=%v", apply1, err)
	}
	if _, _, err = s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active apply lease was reissued: %v", err)
	}
	now = apply1.TaskLeaseExpiresAt.Add(time.Second)
	management = refreshClusterTaskInventoryAt(t, s, ctx, management.ID, digestTenantTest(agentToken), now)
	apply2, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || apply2.TaskAttempt != 2 || apply2.TaskFenceToken != 2 || apply2.Revision <= apply1.Revision {
		t.Fatalf("recovered apply=%+v err=%v", apply2, err)
	}
	if _, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), apply1.Revision, ProviderClusterTaskResult{ProviderClusterID: cluster.ID, TaskFenceToken: apply1.TaskFenceToken, Action: "APPLY", Success: true, ObservedDigest: cluster.DesiredDigest, Phase: "Provisioning"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale apply report err=%v", err)
	}
	cluster, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), apply2.Revision, ProviderClusterTaskResult{ProviderClusterID: cluster.ID, TaskFenceToken: apply2.TaskFenceToken, Action: "APPLY", Success: true, ObservedDigest: cluster.DesiredDigest, Phase: "Provisioning"})
	if err != nil || cluster.State != ProviderClusterReconciling {
		t.Fatalf("apply completion=%+v err=%v", cluster, err)
	}
}
