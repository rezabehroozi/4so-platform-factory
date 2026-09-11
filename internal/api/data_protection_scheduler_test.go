package api

import (
	"context"
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"testing"
	"time"
)

func TestScheduledBackupMaterializationIsMinuteIdempotent(t *testing.T) {
	at := time.Now().UTC().Add(2 * time.Second)
	store := controlplane.NewMemoryStoreWith(func() time.Time { return at }, nil)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "sched-org", DisplayName: "Sched Org"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "sched-project", DisplayName: "Sched Project"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	cluster, agent, _ := seedAPICluster(t, store, project, "sched-target", 72)
	cluster, _, err = upsertMutationReadyInventoryForAPITest(t, store, ctx, cluster.ID, credentialDigest(agent), cluster.ExternalUID, controlplane.ClusterInventory{ObservedAt: at, Distribution: "rke2", KubernetesVersion: "1.33.1", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Capabilities: []string{controlplane.TargetMutationRBACActiveCapability, controlplane.DataProtectionAgentCapability}, Nodes: []controlplane.ClusterNode{{Name: "w", UID: "w1", Ready: true}}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := store.UpsertBackupPolicy(ctx, controlplane.BackupPolicy{ProjectID: project.ID, ClusterID: cluster.ID, Name: "scheduled", Provider: "velero", BackupStorageLocation: "primary", CredentialRef: "k8s-secret://velero/cloud", Schedule: fmt.Sprintf("%d %d * * *", at.Minute(), at.Hour()), Retention: "24h", IncludedNamespaces: []string{"app"}}, 0, "operator")
	if err != nil {
		t.Fatal(err)
	}
	s := testServer(t)
	s.store = store
	created, err := s.enqueueScheduledBackupsAt(ctx, at)
	if err != nil || created != 1 {
		t.Fatalf("created=%d err=%v", created, err)
	}
	created, err = s.enqueueScheduledBackupsAt(ctx, at)
	if err != nil || created != 0 {
		t.Fatalf("replay created=%d err=%v", created, err)
	}
	runs, err := store.ListDataProtectionRuns(ctx, project.ID, cluster.ID, controlplane.DataProtectionBackup)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].PolicyID != policy.ID || runs[0].RequestedBy != dataProtectionSchedulerActor {
		t.Fatalf("runs=%+v", runs)
	}
	created, err = s.enqueueScheduledBackupsAt(ctx, at.Add(time.Minute))
	if err != nil || created != 0 {
		t.Fatalf("non-due created=%d err=%v", created, err)
	}
}

func TestNormalizeDataProtectionPollEnv(t *testing.T) {
	if d, err := normalizeDataProtectionPollEnv(""); err != nil || d != 20*time.Second {
		t.Fatalf("default=%v err=%v", d, err)
	}
	for _, bad := range []string{"500ms", "2m", "nope"} {
		if _, err := normalizeDataProtectionPollEnv(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
