package virtualcluster

import (
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func fixture() (controlplane.Workspace, controlplane.WorkspaceBinding) {
	now := time.Now().UTC()
	workspace := controlplane.Workspace{
		ResourceMeta: controlplane.ResourceMeta{ID: "wsp_payments", Revision: 1, CreatedAt: now, UpdatedAt: now},
		ProjectID: "prj_payments", Name: "payments", DisplayName: "Payments",
		Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	binding := controlplane.WorkspaceBinding{
		ResourceMeta: controlplane.ResourceMeta{ID: "wsb_payments", Revision: 3, CreatedAt: now, UpdatedAt: now},
		WorkspaceID: workspace.ID, ProjectID: workspace.ProjectID, ClusterID: "clu_dev",
		Namespace: "payments-dev", State: controlplane.WorkspaceBindingActive,
	}
	return workspace, binding
}

func developerRequest() Request {
	return Request{
		Name: "api-dev", Profile: ProfileDeveloper, KubernetesVersion: "v1.34.2",
		CPUMilli: 2000, MemoryMiB: 4096, StorageGiB: 20, MaxNamespaces: 3, SleepAfterMinutes: 60,
	}
}

func TestDeveloperPlanBindsWorkspaceAndHostNamespace(t *testing.T) {
	workspace, binding := fixture()
	got, err := BuildPlan(workspace, binding, developerRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got.Authority != Authority || got.ProjectID != workspace.ProjectID || got.WorkspaceID != workspace.ID || got.BindingID != binding.ID || got.BindingRevision != binding.Revision {
		t.Fatalf("workspace authority drift: %#v", got)
	}
	if got.HostClusterID != binding.ClusterID || got.HostNamespace != binding.Namespace || !got.DeveloperMode || !got.MutationEligible {
		t.Fatalf("host/developer authority drift: %#v", got)
	}
	if len(got.DesiredDigest) != 71 || got.DesiredDigest[:7] != "sha256:" {
		t.Fatalf("desired digest missing: %q", got.DesiredDigest)
	}
}

func TestPlanIsDeterministicAndBindingRevisionFenced(t *testing.T) {
	workspace, binding := fixture()
	req := developerRequest()
	a, err := BuildPlan(workspace, binding, req)
	if err != nil { t.Fatal(err) }
	b, err := BuildPlan(workspace, binding, req)
	if err != nil { t.Fatal(err) }
	if a.DesiredDigest != b.DesiredDigest {
		t.Fatalf("deterministic digest drift: %s != %s", a.DesiredDigest, b.DesiredDigest)
	}
	binding.Revision++
	c, err := BuildPlan(workspace, binding, req)
	if err != nil { t.Fatal(err) }
	if c.DesiredDigest == a.DesiredDigest {
		t.Fatal("binding revision change did not invalidate virtual cluster plan")
	}
}

func TestRevokedOrCrossProjectBindingFailsClosed(t *testing.T) {
	workspace, binding := fixture()
	binding.State = controlplane.WorkspaceBindingRevoked
	if _, err := BuildPlan(workspace, binding, developerRequest()); err == nil {
		t.Fatal("revoked workspace binding was admitted")
	}
	_, binding = fixture()
	binding.ProjectID = "prj_other"
	if _, err := BuildPlan(workspace, binding, developerRequest()); err == nil {
		t.Fatal("cross-project workspace binding was admitted")
	}
}

func TestProfilesEnforceBoundedQuotaAndSleepPolicy(t *testing.T) {
	workspace, binding := fixture()
	cases := []Request{}
	r := developerRequest(); r.CPUMilli = 4001; cases = append(cases, r)
	r = developerRequest(); r.MemoryMiB = 8193; cases = append(cases, r)
	r = developerRequest(); r.StorageGiB = 101; cases = append(cases, r)
	r = developerRequest(); r.MaxNamespaces = 6; cases = append(cases, r)
	r = developerRequest(); r.SleepAfterMinutes = 14; cases = append(cases, r)
	r = developerRequest(); r.KubernetesVersion = "latest"; cases = append(cases, r)
	for i, req := range cases {
		if _, err := BuildPlan(workspace, binding, req); err == nil {
			t.Fatalf("unsafe request %d admitted: %#v", i, req)
		}
	}
}

func TestTeamProfileDoesNotInventASecondWorkspaceAuthority(t *testing.T) {
	workspace, binding := fixture()
	req := Request{
		Name: "shared-dev", Profile: ProfileTeam, KubernetesVersion: "v1.34.2",
		CPUMilli: 8000, MemoryMiB: 16384, StorageGiB: 200, MaxNamespaces: 10,
	}
	got, err := BuildPlan(workspace, binding, req)
	if err != nil { t.Fatal(err) }
	if got.DeveloperMode || got.HostNamespace != binding.Namespace || got.ProjectID != workspace.ProjectID {
		t.Fatalf("team plan authority drift: %#v", got)
	}
}

func TestProfilesReturnCopies(t *testing.T) {
	got := Profiles()
	if len(got) != 2 {
		t.Fatalf("profiles=%#v", got)
	}
	got[0].Limits.MaxCPUMilli = 1
	fresh, ok := ProfileFor(ProfileDeveloper)
	if !ok || fresh.Limits.MaxCPUMilli != 4000 {
		t.Fatalf("profile registry was mutated through returned copy: %#v", fresh)
	}
}
