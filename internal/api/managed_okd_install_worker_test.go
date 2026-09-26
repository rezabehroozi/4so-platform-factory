package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/bootmedia"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/managedinstall"
)

type managedInstallFakeBoot struct{}

func (managedInstallFakeBoot) Attach(bootmedia.Request) error         { return nil }
func (managedInstallFakeBoot) SetOneTimeBoot(bootmedia.Request) error { return nil }
func (managedInstallFakeBoot) PowerCycle(bootmedia.Request) error     { return nil }
func (managedInstallFakeBoot) Observe(bootmedia.Request) (bootmedia.Observation, error) {
	return bootmedia.Observation{Attached: true, OneTimeBootSet: true, Powered: true, BootState: "REDFISH_ON"}, nil
}

type managedInstallFakeArtifactValidator struct{}

func (managedInstallFakeArtifactValidator) ValidateManagedInstallArtifacts(_ context.Context, req managedinstall.Request, token string) (map[string]any, error) {
	if token == "" {
		tpanic("missing artifact validation token")
	}
	digest, err := managedinstall.DigestRequest(req)
	if err != nil {
		return nil, err
	}
	return map[string]any{"validated": true, "requestDigest": digest, "workspaceDigestBound": true}, nil
}

type managedInstallFakeMedia struct{}

func (managedInstallFakeMedia) ResolveAgentISOMediaURL(_ context.Context, _ managedinstall.Request, artifact managedinstall.Artifact, token string) (string, error) {
	if token == "" {
		tpanic("missing media token")
	}
	return artifact.URL, nil
}

func (managedInstallFakeMedia) ValidateAgentISOMedia(_ context.Context, req managedinstall.Request, artifact managedinstall.Artifact) (map[string]any, error) {
	digest, err := managedinstall.DigestRequest(req)
	if err != nil {
		return nil, err
	}
	return map[string]any{"validated": true, "requestDigest": digest, "sha256": artifact.SHA256, "locallyStaged": true}, nil
}

func managedInstallReadyExecutor(installer *managedInstallFakeInstaller) *managedinstall.Executor {
	media := managedInstallFakeMedia{}
	return &managedinstall.Executor{
		BootProvider: managedInstallFakeBoot{},
		MediaResolver: media,
		ArtifactValidator: managedInstallFakeArtifactValidator{},
		MediaValidator: media,
		Installer: installer,
	}
}

type managedInstallFakeInstaller struct{ installs, registers int }

func (f *managedInstallFakeInstaller) InstallConnectedOKD(_ context.Context, _ managedinstall.Request, token string) (map[string]any, error) {
	if token == "" {
		tpanic("missing operation token")
	}
	f.installs++
	return map[string]any{"installed": true}, nil
}
func (f *managedInstallFakeInstaller) RegisterManagedCluster(_ context.Context, _ managedinstall.Request, token string) (map[string]any, error) {
	if token == "" {
		tpanic("missing operation token")
	}
	f.registers++
	return map[string]any{"registered": true}, nil
}
func tpanic(s string) { panic(s) }

func managedInstallTestRequest(orgID, projectID string) managedinstall.Request {
	d := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return managedinstall.Request{
		OrganizationID: orgID, ProjectID: projectID, TargetVersion: "4.19.0", ClusterName: "prod-a", BaseDomain: "example.test",
		APIVIP: "10.0.0.10", IngressVIP: "10.0.0.11",
		Machines: []managedinstall.Machine{
			{ID: "cp-1", Endpoint: "https://bmc-1.example.test", CredentialRef: "redfish-cp-1", SystemResource: "/redfish/v1/Systems/1", VirtualMediaResource: "/redfish/v1/Managers/1/VirtualMedia/CD"},
			{ID: "cp-2", Endpoint: "https://bmc-2.example.test", CredentialRef: "redfish-cp-2", SystemResource: "/redfish/v1/Systems/1", VirtualMediaResource: "/redfish/v1/Managers/1/VirtualMedia/CD"},
			{ID: "cp-3", Endpoint: "https://bmc-3.example.test", CredentialRef: "redfish-cp-3", SystemResource: "/redfish/v1/Systems/1", VirtualMediaResource: "/redfish/v1/Managers/1/VirtualMedia/CD"},
		},
		Artifacts: []managedinstall.Artifact{
			{Name: "release-payload", Version: "4.19.0", URL: "https://mirror.example.test/okd/release", SHA256: d},
			{Name: "fcos", Version: "42.20250818.3.0", URL: "https://mirror.example.test/fcos.raw.xz", SHA256: d},
			{Name: "agent-iso", Version: "4.19.0", URL: "https://mirror.example.test/agent.iso", SHA256: d},
		},
	}
}

func TestManagedOKDInstallWorkerDurableApprovalAndResume(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "managed-install", DisplayName: "Managed Install"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	req := managedInstallTestRequest(org.ID, project.ID)
	raw, digest, err := managedinstall.MarshalCanonicalRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	op, replay, err := store.CreateOperationAwaitingApprovalWithPayload(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: managedOKDInstallOperationKind, TargetRef: "managed-okd-install/" + req.ClusterName, DesiredRevision: digest, Risk: "critical", Class: controlplane.OperationClassMutating}, "install-1", "requester", "req-1", managedinstall.PayloadMediaType, raw)
	if err != nil || replay {
		t.Fatalf("create err=%v replay=%v", err, replay)
	}
	if op.State != controlplane.OperationAwaitingApproval {
		t.Fatalf("state=%s", op.State)
	}
	if _, err = store.ApproveOperationAndQueue(ctx, op.ID, op.Revision, "requester"); err == nil {
		t.Fatal("self approval must fail")
	}
	op, err = store.ApproveOperationAndQueue(ctx, op.ID, op.Revision, "independent-admin")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != controlplane.OperationQueued {
		t.Fatalf("approved state=%s", op.State)
	}

	installer := &managedInstallFakeInstaller{}
	s := New("test", nil, nil, store)
	s.ConfigureManagedOKDInstallExecutor(managedInstallReadyExecutor(installer))
	for i := 0; i < len(managedinstall.OrderedSteps())+2; i++ {
		if err = s.ProcessManagedOKDInstallJobsOnce(ctx, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != controlplane.OperationSucceeded {
		t.Fatalf("terminal state=%s error=%s", op.State, op.LastError)
	}
	evidence, err := store.ListEvidence(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != len(managedinstall.OrderedSteps()) {
		t.Fatalf("evidence=%d", len(evidence))
	}
	if installer.installs != 1 || installer.registers != 1 {
		t.Fatalf("installer calls install=%d register=%d", installer.installs, installer.registers)
	}
}

func TestClaimableQueueRecoversExpiredRunningOperation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "reclaim", DisplayName: "Reclaim"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "p", DisplayName: "P"}, "owner")
	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: managedOKDInstallOperationKind, TargetRef: "managed-okd-install/test", DesiredRevision: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Risk: "medium", Class: controlplane.OperationClassMutating}, "reclaim-key", "owner", "req")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationPlanning, "", "owner")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationQueued, "", "owner")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-a", time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, "worker-a", claim.FenceToken, "worker-a"); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.ListClaimableOperationsByKind(ctx, managedOKDInstallOperationKind, now.Add(2*time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].ID != op.ID {
		t.Fatalf("expired running operation was not rediscovered: %#v", jobs)
	}
	claim2, err := store.ClaimOperation(ctx, op.ID, "worker-b", time.Second, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claim2.FenceToken <= claim.FenceToken {
		t.Fatalf("fence did not advance: %d -> %d", claim.FenceToken, claim2.FenceToken)
	}
}

type slowManagedInstallInstaller struct{ delay time.Duration }

func (s slowManagedInstallInstaller) InstallConnectedOKD(ctx context.Context, _ managedinstall.Request, _ string) (map[string]any, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(s.delay):
		return map[string]any{"installed": true}, nil
	}
}
func (s slowManagedInstallInstaller) RegisterManagedCluster(context.Context, managedinstall.Request, string) (map[string]any, error) {
	return map[string]any{"registered": true}, nil
}

func TestManagedOKDLongStepRenewsLeaseWithoutUsingStaleRevision(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := controlplane.NewMemoryStoreWith(func() time.Time { return time.Now().UTC() }, nil)
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "lease", DisplayName: "Lease"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: managedOKDInstallOperationKind, TargetRef: "managed-okd-install/lease", DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "critical", Class: controlplane.OperationClassMutating}, "lease-key", "owner", "req")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationPlanning, "", "owner")
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationQueued, "", "owner")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, op.ID, managedOKDInstallWorkerID, 90*time.Millisecond, now)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeRevision := op.Revision
	s := New("test", nil, nil, store)
	s.ConfigureManagedOKDInstallExecutor(&managedinstall.Executor{Installer: slowManagedInstallInstaller{delay: 160 * time.Millisecond}})
	payload, execErr, heartbeatErr := s.executeManagedOKDInstallStepWithLease(ctx, op, claim, managedInstallTestRequest(org.ID, project.ID), managedinstall.StepConnectedInstall, 90*time.Millisecond)
	if heartbeatErr != nil || execErr != nil {
		t.Fatalf("heartbeat=%v exec=%v", heartbeatErr, execErr)
	}
	if len(payload) == 0 {
		t.Fatal("missing step evidence payload")
	}
	current, err := store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision <= beforeRevision || current.FenceToken != claim.FenceToken || current.LeaseOwner != managedOKDInstallWorkerID {
		t.Fatalf("lease was not renewed safely: before=%d current=%#v", beforeRevision, current)
	}
}

type managedInstallFakeDisconnected struct{ prepares, installs int }

func (f *managedInstallFakeDisconnected) PrepareDisconnectedMirror(_ context.Context, req managedinstall.Request, token string) (map[string]any, error) {
	if token == "" || !managedinstall.IsDisconnected(req) {
		tpanic("invalid disconnected prepare")
	}
	f.prepares++
	return map[string]any{"mirrored": true, "networkSourceRequired": false}, nil
}
func (f *managedInstallFakeDisconnected) InstallDisconnectedOKD(_ context.Context, req managedinstall.Request, token string) (map[string]any, error) {
	if token == "" || !managedinstall.IsDisconnected(req) {
		tpanic("invalid disconnected install")
	}
	f.installs++
	return map[string]any{"installed": true, "connectivity": "disconnected"}, nil
}

func TestManagedOKDInstallWorkerDisconnectedSequenceIsDurableAndDistinct(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC)
	store := controlplane.NewMemoryStoreWith(func() time.Time { return now }, nil)
	org, _ := store.CreateOrganization(ctx, controlplane.Organization{Name: "managed-disconnected", DisplayName: "Managed Disconnected"}, "owner")
	project, _ := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "owner")
	req := managedInstallTestRequest(org.ID, project.ID)
	req.Connectivity = "disconnected"
	req.Disconnected = &managedinstall.DisconnectedConfig{
		MirrorRegistry:              "registry.internal.test/okd",
		ImageSetConfigurationSHA256: "sha256:" + strings.Repeat("b", 64),
		MirrorInventorySHA256:       "sha256:" + strings.Repeat("c", 64),
	}
	raw, digest, err := managedinstall.MarshalCanonicalRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperationAwaitingApprovalWithPayload(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: managedOKDInstallOperationKind, TargetRef: "managed-okd-install/" + req.ClusterName, DesiredRevision: digest, Risk: "critical", Class: controlplane.OperationClassMutating}, "install-disconnected-1", "requester", "req-disc", managedinstall.PayloadMediaType, raw)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.ApproveOperationAndQueue(ctx, op.ID, op.Revision, "independent-admin")
	if err != nil {
		t.Fatal(err)
	}
	connected := &managedInstallFakeInstaller{}
	disconnected := &managedInstallFakeDisconnected{}
	s := New("test", nil, nil, store)
	executor := managedInstallReadyExecutor(connected)
	executor.DisconnectedInstaller = disconnected
	s.ConfigureManagedOKDInstallExecutor(executor)
	for i := 0; i < len(managedinstall.OrderedStepsFor(req))+2; i++ {
		if err = s.ProcessManagedOKDInstallJobsOnce(ctx, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != controlplane.OperationSucceeded {
		t.Fatalf("terminal state=%s error=%s", op.State, op.LastError)
	}
	evidence, err := store.ListEvidence(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != len(managedinstall.OrderedStepsFor(req)) {
		t.Fatalf("disconnected evidence=%d want=%d", len(evidence), len(managedinstall.OrderedStepsFor(req)))
	}
	kinds := map[string]bool{}
	for _, item := range evidence {
		kinds[item.Kind] = true
	}
	if !kinds[managedOKDInstallEvidenceKind+string(managedinstall.StepPrepareMirror)] || !kinds[managedOKDInstallEvidenceKind+string(managedinstall.StepDisconnectedInstall)] || kinds[managedOKDInstallEvidenceKind+string(managedinstall.StepConnectedInstall)] {
		t.Fatalf("connected/disconnected evidence conflated: %#v", kinds)
	}
	if disconnected.prepares != 1 || disconnected.installs != 1 || connected.installs != 0 || connected.registers != 1 {
		t.Fatalf("unexpected execution counts disconnected=%+v connected=%+v", disconnected, connected)
	}
}
