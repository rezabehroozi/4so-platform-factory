package virtualcluster

import "testing"

func fixture() WorkspaceAuthority {
	return WorkspaceAuthority{
		WorkspaceID: "wsp_payments",
		ProjectID: "prj_payments",
		WorkspaceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BindingID: "wsb_payments",
		BindingRevision: 3,
		HostClusterID: "clu_dev",
		HostNamespace: "payments-dev",
		BindingActive: true,
	}
}

func developerRequest() Request {
	return Request{
		Name: "api-dev", Profile: ProfileDeveloper, KubernetesVersion: "v1.34.2",
		CPUMilli: 2000, MemoryMiB: 4096, StorageGiB: 20, MaxNamespaces: 3, SleepAfterMinutes: 60,
	}
}

func TestDeveloperPlanBindsWorkspaceAndHostNamespace(t *testing.T) {
	authority := fixture()
	got, err := BuildPlan(authority, developerRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got.Authority != Authority || got.ProjectID != authority.ProjectID || got.WorkspaceID != authority.WorkspaceID || got.BindingID != authority.BindingID || got.BindingRevision != authority.BindingRevision {
		t.Fatalf("workspace authority drift: %#v", got)
	}
	if got.HostClusterID != authority.HostClusterID || got.HostNamespace != authority.HostNamespace || !got.DeveloperMode || !got.MutationEligible {
		t.Fatalf("host/developer authority drift: %#v", got)
	}
	if len(got.DesiredDigest) != 71 || got.DesiredDigest[:7] != "sha256:" {
		t.Fatalf("desired digest missing: %q", got.DesiredDigest)
	}
}

func TestPlanIsDeterministicAndBindingRevisionFenced(t *testing.T) {
	authority := fixture()
	req := developerRequest()
	a, err := BuildPlan(authority, req)
	if err != nil { t.Fatal(err) }
	b, err := BuildPlan(authority, req)
	if err != nil { t.Fatal(err) }
	if a.DesiredDigest != b.DesiredDigest {
		t.Fatalf("deterministic digest drift: %s != %s", a.DesiredDigest, b.DesiredDigest)
	}
	authority.BindingRevision++
	c, err := BuildPlan(authority, req)
	if err != nil { t.Fatal(err) }
	if c.DesiredDigest == a.DesiredDigest {
		t.Fatal("binding revision change did not invalidate virtual cluster plan")
	}
}

func TestRevokedOrCrossProjectBindingFailsClosed(t *testing.T) {
	authority := fixture()
	authority.BindingActive = false
	if _, err := BuildPlan(authority, developerRequest()); err == nil {
		t.Fatal("revoked workspace binding was admitted")
	}
	authority = fixture()
	authority.ProjectID = ""
	if _, err := BuildPlan(authority, developerRequest()); err == nil {
		t.Fatal("incomplete workspace authority was admitted")
	}
}

func TestProfilesEnforceBoundedQuotaAndSleepPolicy(t *testing.T) {
	authority := fixture()
	cases := []Request{}
	r := developerRequest(); r.CPUMilli = 4001; cases = append(cases, r)
	r = developerRequest(); r.MemoryMiB = 8193; cases = append(cases, r)
	r = developerRequest(); r.StorageGiB = 101; cases = append(cases, r)
	r = developerRequest(); r.MaxNamespaces = 6; cases = append(cases, r)
	r = developerRequest(); r.SleepAfterMinutes = 14; cases = append(cases, r)
	r = developerRequest(); r.KubernetesVersion = "latest"; cases = append(cases, r)
	for i, req := range cases {
		if _, err := BuildPlan(authority, req); err == nil {
			t.Fatalf("unsafe request %d admitted: %#v", i, req)
		}
	}
}

func TestTeamProfileDoesNotInventASecondWorkspaceAuthority(t *testing.T) {
	authority := fixture()
	req := Request{
		Name: "shared-dev", Profile: ProfileTeam, KubernetesVersion: "v1.34.2",
		CPUMilli: 8000, MemoryMiB: 16384, StorageGiB: 200, MaxNamespaces: 10,
	}
	got, err := BuildPlan(authority, req)
	if err != nil { t.Fatal(err) }
	if got.DeveloperMode || got.HostNamespace != authority.HostNamespace || got.ProjectID != authority.ProjectID {
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
