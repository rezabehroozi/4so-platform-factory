package controlplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
		Capabilities: []string{TargetMutationRBACActiveCapability, TargetNodeProviderMachineLifecycleCapability, "controlled-baseline-deployment"},
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
	inspect, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || inspect.State != ProviderClusterReconciling || inspect.TaskAttempt != 2 || inspect.TaskFenceToken != 2 || inspect.Revision <= apply1.Revision || inspect.Phase != "RecoveryInspectQueued" {
		t.Fatalf("expired apply was not converted to readback-only recovery: %+v err=%v", inspect, err)
	}
	if _, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), apply1.Revision, ProviderClusterTaskResult{ProviderClusterID: cluster.ID, TaskFenceToken: apply1.TaskFenceToken, Action: "APPLY", Success: true, ObservedDigest: cluster.DesiredDigest, Phase: "Provisioning"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale apply report err=%v", err)
	}
	cluster, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), inspect.Revision, ProviderClusterTaskResult{ProviderClusterID: cluster.ID, TaskFenceToken: inspect.TaskFenceToken, Action: "INSPECT", Success: true, Ready: true, ObservedDigest: cluster.DesiredDigest, Phase: "Provisioned"})
	if err != nil || cluster.State != ProviderClusterActive {
		t.Fatalf("readback recovery completion=%+v err=%v", cluster, err)
	}
}

func TestVMwareProviderProfileAdmissionIsFailClosed(t *testing.T) {
	s, ctx, project, management, _ := providerFixture(t)
	base := ProviderProfile{
		ProjectID: project.ID, ManagementClusterID: management.ID,
		Name: "vmware-prod", DisplayName: "VMware Production",
		Adapter: clusterAPIAdapter, Namespace: providerSystemNamespace,
		ClusterClassName: "vmware-prod", WorkerClassName: "worker-standard",
		DefaultKubernetesVersion: "v1.33.2", KubernetesSeries: []string{"v1.33"},
		Architectures: []string{"amd64"}, DistributionProfiles: []string{"kubernetes"}, MaxWorkerReplicas: 20,
		InfrastructureProvider: "vmware", InfrastructureEndpoint: "https://vcenter.example.test",
		CredentialRef: "external-secret://4so-provider-system/vcenter-prod",
		DesiredDigest: digestTenantTest("vmware-profile-desired"), RequestDigest: digestTenantTest("vmware-profile-request"), IdempotencyKey: "vmware-profile",
	}
	created, replay, err := s.CreateProviderProfile(ctx, base, "admin")
	if err != nil || replay || created.InfrastructureProvider != "vmware" || created.InfrastructureEndpoint != "https://vcenter.example.test" || created.CredentialRef != base.CredentialRef {
		t.Fatalf("vmware profile=%#v replay=%v err=%v", created, replay, err)
	}

	bad := []ProviderProfile{
		func() ProviderProfile {
			v := base
			v.Name = "bad-http"
			v.IdempotencyKey = "bad-http"
			v.InfrastructureEndpoint = "http://vcenter.example.test"
			return v
		}(),
		func() ProviderProfile {
			v := base
			v.Name = "bad-userinfo"
			v.IdempotencyKey = "bad-userinfo"
			v.InfrastructureEndpoint = "https://admin:secret@vcenter.example.test"
			return v
		}(),
		func() ProviderProfile {
			v := base
			v.Name = "bad-query"
			v.IdempotencyKey = "bad-query"
			v.InfrastructureEndpoint = "https://vcenter.example.test/?token=secret"
			return v
		}(),
		func() ProviderProfile {
			v := base
			v.Name = "bad-secret"
			v.IdempotencyKey = "bad-secret"
			v.CredentialRef = "admin:secret"
			return v
		}(),
		func() ProviderProfile {
			v := base
			v.Name = "bad-secret-ns"
			v.IdempotencyKey = "bad-secret-ns"
			v.CredentialRef = "external-secret://other/vcenter"
			return v
		}(),
		func() ProviderProfile {
			v := base
			v.Name = "bad-arm"
			v.IdempotencyKey = "bad-arm"
			v.Architectures = []string{"arm64"}
			return v
		}(),
	}
	for _, candidate := range bad {
		candidate.RequestDigest = digestTenantTest(candidate.Name + "-request")
		candidate.DesiredDigest = digestTenantTest(candidate.Name + "-desired")
		if _, _, err := s.CreateProviderProfile(ctx, candidate, "admin"); err == nil || !errors.Is(err, ErrValidation) {
			t.Fatalf("unsafe VMware profile %s accepted: %v", candidate.Name, err)
		}
	}
}

func TestVMwareProviderProfilePropagatesInfrastructureIdentity(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile, _, err := s.CreateProviderProfile(ctx, ProviderProfile{
		ProjectID: project.ID, ManagementClusterID: management.ID, Name: "vmware", DisplayName: "VMware",
		Adapter: clusterAPIAdapter, Namespace: providerSystemNamespace, ClusterClassName: "vmware", WorkerClassName: "workers",
		DefaultKubernetesVersion: "v1.33.2", KubernetesSeries: []string{"v1.33"}, Architectures: []string{"amd64"}, DistributionProfiles: []string{"kubernetes"}, MaxWorkerReplicas: 10,
		InfrastructureProvider: "vmware", InfrastructureEndpoint: "https://vcenter.example.test", CredentialRef: "external-secret://4so-provider-system/vcenter",
		DesiredDigest: digestTenantTest("vmware-d"), RequestDigest: digestTenantTest("vmware-r"), IdempotencyKey: "vmware",
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.NextProviderProfileTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	profile, err = s.ReportProviderProfileTask(ctx, management.ID, digestTenantTest(agentToken), claimed.Revision, ProviderProfileTaskResult{ProfileID: profile.ID, TaskFenceToken: claimed.TaskFenceToken, Success: true, ObservedDigest: digestTenantTest("vmware-observed")})
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err := s.CreateProviderCluster(ctx, ProviderCluster{ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "tenant-vm", DisplayName: "Tenant VM", Desired: ProviderClusterSpec{KubernetesVersion: "v1.33.2", Architecture: "amd64", DistributionIdentity: "kubernetes", ControlPlaneReplicas: 3, WorkerReplicas: 3}, RequestDigest: digestTenantTest("vmcluster-r"), IdempotencyKey: "vmcluster"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if cluster.Desired.InfrastructureProvider != "vmware" {
		t.Fatalf("VMware identity was not propagated: %#v", cluster.Desired)
	}
}


func TestPublicCloudProviderProfileAdmissionIsFailClosed(t *testing.T) {
	s, ctx, project, management, _ := providerFixture(t)
	for _, provider := range []string{"aws", "azure", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			base := ProviderProfile{
				ProjectID: project.ID, ManagementClusterID: management.ID,
				Name: provider + "-prod", DisplayName: strings.ToUpper(provider) + " Production",
				Adapter: clusterAPIAdapter, Namespace: providerSystemNamespace,
				ClusterClassName: provider + "-prod", WorkerClassName: "worker-standard",
				DefaultKubernetesVersion: "v1.33.2", KubernetesSeries: []string{"v1.33"},
				Architectures: []string{"amd64"}, DistributionProfiles: []string{"kubernetes"}, MaxWorkerReplicas: 20,
				InfrastructureProvider: provider,
				CredentialRef: "external-secret://4so-provider-system/" + provider + "-prod",
				DesiredDigest: digestTenantTest(provider + "-profile-desired"),
				RequestDigest: digestTenantTest(provider + "-profile-request"),
				IdempotencyKey: provider + "-profile",
			}
			created, replay, err := s.CreateProviderProfile(ctx, base, "admin")
			if err != nil || replay || created.InfrastructureProvider != provider || created.CredentialRef != base.CredentialRef {
				t.Fatalf("%s profile=%#v replay=%v err=%v", provider, created, replay, err)
			}

			badEndpoint := base
			badEndpoint.Name += "-endpoint"
			badEndpoint.IdempotencyKey += "-endpoint"
			badEndpoint.RequestDigest = digestTenantTest(provider + "-endpoint-request")
			badEndpoint.DesiredDigest = digestTenantTest(provider + "-endpoint-desired")
			badEndpoint.InfrastructureEndpoint = "https://custom.example.test"
			if _, _, err = s.CreateProviderProfile(ctx, badEndpoint, "admin"); err == nil || !errors.Is(err, ErrValidation) {
				t.Fatalf("%s custom endpoint was admitted: %v", provider, err)
			}

			badSecret := base
			badSecret.Name += "-secret"
			badSecret.IdempotencyKey += "-secret"
			badSecret.RequestDigest = digestTenantTest(provider + "-secret-request")
			badSecret.DesiredDigest = digestTenantTest(provider + "-secret-desired")
			badSecret.CredentialRef = "inline-secret"
			if _, _, err = s.CreateProviderProfile(ctx, badSecret, "admin"); err == nil || !errors.Is(err, ErrValidation) {
				t.Fatalf("%s inline credential was admitted: %v", provider, err)
			}

			badArch := base
			badArch.Name += "-arm"
			badArch.IdempotencyKey += "-arm"
			badArch.RequestDigest = digestTenantTest(provider + "-arm-request")
			badArch.DesiredDigest = digestTenantTest(provider + "-arm-desired")
			badArch.Architectures = []string{"arm64"}
			if _, _, err = s.CreateProviderProfile(ctx, badArch, "admin"); err == nil || !errors.Is(err, ErrValidation) {
				t.Fatalf("%s unsupported architecture was admitted: %v", provider, err)
			}
		})
	}
}


func TestProviderClusterRecoveryRequiredRetryQueuesReadbackOnly(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile := readyProviderProfile(t, s, ctx, project, management, agentToken)
	v, _, err := s.CreateProviderCluster(ctx, ProviderCluster{
		ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "ambiguous-cluster", DisplayName: "Ambiguous Cluster",
		Desired: ProviderClusterSpec{KubernetesVersion: "v1.33.2", ControlPlaneReplicas: 1, WorkerReplicas: 1},
		DesiredDigest: digestTenantTest("ambiguous-desired"), RequestDigest: digestTenantTest("ambiguous-request"), IdempotencyKey: "ambiguous-cluster",
	}, "operator")
	if err != nil { t.Fatal(err) }
	v, err = s.ApproveProviderCluster(ctx, v.ID, v.Revision, "approver")
	if err != nil { t.Fatal(err) }
	claimed, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || claimed.State != ProviderClusterApplying { t.Fatalf("claim=%+v err=%v", claimed, err) }
	v, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), claimed.Revision, ProviderClusterTaskResult{
		ProviderClusterID: v.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "APPLY",
		RecoveryRequired: true, Error: "mutation outcome unknown after transport failure",
	})
	if err != nil || v.State != ProviderClusterRecoveryRequired || v.Phase != "RecoveryRequired" {
		t.Fatalf("recovery-required report=%+v err=%v", v, err)
	}
	v, err = s.RetryProviderCluster(ctx, v.ID, v.Revision, "operator")
	if err != nil || v.State != ProviderClusterReconciling || v.Phase != "RecoveryInspectQueued" {
		t.Fatalf("safe retry=%+v err=%v", v, err)
	}
	inspect, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || inspect.State != ProviderClusterReconciling || inspect.TaskAttempt != 2 {
		t.Fatalf("readback claim=%+v err=%v", inspect, err)
	}
	if _, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), inspect.Revision, ProviderClusterTaskResult{
		ProviderClusterID: v.ID, TaskFenceToken: inspect.TaskFenceToken, Action: "APPLY", Success: true, ObservedDigest: v.DesiredDigest,
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("recovery readback lane accepted a replayed APPLY: %v", err)
	}
}


func TestProviderDeleteLeaseExpiryRequiresReadbackBeforeReplay(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile := readyProviderProfile(t, s, ctx, project, management, agentToken)
	now := management.LastSeenAt.UTC()
	s.now = func() time.Time { return now }
	expired := now.Add(-time.Second)
	v := ProviderCluster{
		ResourceMeta: ResourceMeta{ID: "pcl_delete_ambiguous", Revision: 9, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Minute)},
		ProjectID: project.ID, ProviderProfileID: profile.ID, ManagementClusterID: management.ID,
		Name: "delete-ambiguous", DisplayName: "Delete Ambiguous", ResourceName: "pf-delete-ambiguous",
		Namespace: providerSystemNamespace, State: ProviderClusterDeleting,
		Desired: ProviderClusterSpec{KubernetesVersion: "v1.33.2", ControlPlaneReplicas: 1, WorkerReplicas: 1},
		DesiredDigest: digestTenantTest("delete-ambiguous-desired"), PendingAction: "DELETE",
		TaskAttempt: 1, TaskFenceToken: 1, TaskLeaseExpiresAt: &expired, Phase: "Deleting",
	}
	s.mu.Lock()
	s.providerClusters[v.ID] = v
	s.mu.Unlock()

	if _, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired DELETE should stop at recovery-required before another claim: %v", err)
	}
	v, err := s.GetProviderCluster(ctx, v.ID)
	if err != nil || v.State != ProviderClusterRecoveryRequired || v.Phase != "RecoveryRequired" || v.TaskLeaseExpiresAt != nil {
		t.Fatalf("expired DELETE recovery=%+v err=%v", v, err)
	}
	v, err = s.RetryProviderCluster(ctx, v.ID, v.Revision, "operator")
	if err != nil || v.State != ProviderClusterDeleting || v.Phase != "RecoveryInspectQueued" {
		t.Fatalf("DELETE recovery retry=%+v err=%v", v, err)
	}
	inspect, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || inspect.State != ProviderClusterDeleting || inspect.TaskAttempt != 2 || inspect.Phase != "RecoveryInspectQueued" {
		t.Fatalf("DELETE recovery readback claim=%+v err=%v", inspect, err)
	}
}
