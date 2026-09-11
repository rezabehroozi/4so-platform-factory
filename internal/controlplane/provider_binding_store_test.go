package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func seedProviderBackedTarget(t *testing.T, s *MemoryStore, project Project, name string) ManagedCluster {
	t.Helper()
	ctx := context.Background()
	enroll := digestTenantTest("provider-target-enroll-" + name)
	agent := digestTenantTest("provider-target-agent-" + name)
	imp, err := s.CreateClusterImport(ctx, ClusterImport{ProjectID: project.ID, Name: name, DisplayName: name, TokenDigest: enroll, ExpiresAt: time.Now().Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	imp, err = s.ApproveClusterImport(ctx, imp.ID, imp.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	_, cluster, err := s.ClaimClusterImport(ctx, imp.ID, enroll, agent, "uid-"+name, "0.0.313")
	if err != nil {
		t.Fatal(err)
	}
	return cluster
}

func TestProviderBindingUnlocksAddAndMachineCapabilityGatesRemoveReplace(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile := readyProviderProfile(t, s, ctx, project, management, agentToken)
	provider, replay, err := s.CreateProviderCluster(ctx, ProviderCluster{
		ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "customer-bound", DisplayName: "Customer Bound",
		Desired:       ProviderClusterSpec{KubernetesVersion: "v1.33.2", ControlPlaneReplicas: 3, WorkerReplicas: 3},
		RequestDigest: digestTenantTest("provider-bound-request"), IdempotencyKey: "provider-bound",
	}, "operator")
	if err != nil || replay {
		t.Fatalf("create provider replay=%v err=%v", replay, err)
	}
	provider, err = s.ApproveProviderCluster(ctx, provider.ID, provider.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	provider = runProviderClusterToActive(t, s, ctx, management, agentToken, provider)

	target := seedProviderBackedTarget(t, s, project, "target-bound")
	before := BuildTargetNodeLifecycleAuthority(target, ClusterInventory{Distribution: "rke2", Digest: digestTenantTest("target-inventory"), ObservedAt: time.Now()}, false)
	addBefore, _ := findLifecycleDescriptor(before, TargetNodeActionAdd)
	if addBefore.Executable || !testStringSliceContains(addBefore.Blockers, "TARGET_NODE_PROVIDER_BINDING_PENDING") {
		t.Fatalf("ADD advertised before provider binding: %#v", addBefore)
	}

	target, err = s.BindManagedClusterProvider(ctx, target.ID, target.Revision, provider.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if target.ProviderClusterID != provider.ID || target.Labels[TargetNodeProviderBindingLabel] != provider.ID {
		t.Fatalf("binding not persisted: %#v", target)
	}
	authority := BuildTargetNodeLifecycleAuthority(target, ClusterInventory{Distribution: "rke2", Digest: digestTenantTest("target-inventory-2"), ObservedAt: time.Now()}, true, false)
	add, _ := findLifecycleDescriptor(authority, TargetNodeActionAdd)
	remove, _ := findLifecycleDescriptor(authority, TargetNodeActionRemove)
	replace, _ := findLifecycleDescriptor(authority, TargetNodeActionReplace)
	if !add.Executable || add.Executor != "infrastructure-provider-adapter" {
		t.Fatalf("bound ADD not executable: %#v", add)
	}
	if remove.Executable || !testStringSliceContains(remove.MissingCapabilities, TargetNodeProviderMachineLifecycleCapability) {
		t.Fatalf("REMOVE must remain live-capability gated: %#v", remove)
	}
	if replace.Executable || !testStringSliceContains(replace.MissingCapabilities, TargetNodeProviderMachineLifecycleCapability) {
		t.Fatalf("REPLACE must remain live-capability gated: %#v", replace)
	}
	withMachine := BuildTargetNodeLifecycleAuthority(target, ClusterInventory{Distribution: "rke2", Digest: digestTenantTest("target-inventory-3"), ObservedAt: time.Now()}, true, true)
	remove, _ = findLifecycleDescriptor(withMachine, TargetNodeActionRemove)
	replace, _ = findLifecycleDescriptor(withMachine, TargetNodeActionReplace)
	if !remove.Executable || !replace.Executable {
		t.Fatalf("provider Machine capability did not unlock source-implemented REMOVE/REPLACE: remove=%#v replace=%#v", remove, replace)
	}

	other := seedProviderBackedTarget(t, s, project, "target-other")
	if _, err = s.BindManagedClusterProvider(ctx, other.ID, other.Revision, provider.ID, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("same provider bound to a second active target: %v", err)
	}
}

func TestProviderBindingRejectsManagementClusterAndRevokedTarget(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile := readyProviderProfile(t, s, ctx, project, management, agentToken)
	provider, _, err := s.CreateProviderCluster(ctx, ProviderCluster{ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "binding-guard", DisplayName: "Binding Guard", Desired: ProviderClusterSpec{KubernetesVersion: "v1.33.2", ControlPlaneReplicas: 1, WorkerReplicas: 1}, RequestDigest: digestTenantTest("binding-guard-request"), IdempotencyKey: "binding-guard"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	provider, err = s.ApproveProviderCluster(ctx, provider.ID, provider.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	provider = runProviderClusterToActive(t, s, ctx, management, agentToken, provider)
	if _, err = s.BindManagedClusterProvider(ctx, management.ID, management.Revision, provider.ID, "admin"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("management cluster accepted as its own provider target: %v", err)
	}
	target := seedProviderBackedTarget(t, s, project, "revoked-target")
	target.ConnectionState = "REVOKED"
	s.mu.Lock()
	s.managedClusters[target.ID] = target
	s.mu.Unlock()
	if _, err = s.BindManagedClusterProvider(ctx, target.ID, target.Revision, provider.ID, "admin"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("revoked target acquired provider binding: %v", err)
	}
}

func testStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestProviderMachineReplaceDurableWorkflowAndStoreLevelNodeAdmission(t *testing.T) {
	s, ctx, project, management, agentToken := providerFixture(t)
	profile := readyProviderProfile(t, s, ctx, project, management, agentToken)
	provider, _, err := s.CreateProviderCluster(ctx, ProviderCluster{
		ProjectID: project.ID, ProviderProfileID: profile.ID, Name: "replace-bound", DisplayName: "Replace Bound",
		Desired:       ProviderClusterSpec{KubernetesVersion: "v1.33.2", ControlPlaneReplicas: 3, WorkerReplicas: 3},
		RequestDigest: digestTenantTest("replace-bound-request"), IdempotencyKey: "replace-bound",
	}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	provider, err = s.ApproveProviderCluster(ctx, provider.ID, provider.Revision, "approver")
	if err != nil {
		t.Fatal(err)
	}
	provider = runProviderClusterToActive(t, s, ctx, management, agentToken, provider)
	target := seedProviderBackedTarget(t, s, project, "replace-target")
	target, err = s.BindManagedClusterProvider(ctx, target.ID, target.Revision, provider.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpsertClusterMaintenanceProfile(ctx, ClusterMaintenanceProfile{ProjectID: project.ID, ClusterID: target.ID, Environment: ClusterEnvironmentProduction, DefaultDrainTimeoutSeconds: 120}, 0, "operator"); err != nil {
		t.Fatal(err)
	}
	window, err := s.CreateClusterMaintenanceWindow(ctx, ClusterMaintenanceWindow{ProjectID: project.ID, ClusterID: target.ID, Name: "replace-window", StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour), MaxUnavailable: 1, DrainTimeoutSeconds: 120}, "operator")
	if err != nil {
		t.Fatal(err)
	}

	setInventory := func(digest string, node ClusterNode) {
		s.mu.Lock()
		s.clusterInventories[target.ID] = ClusterInventory{ClusterID: target.ID, ObservedAt: time.Now().UTC(), Distribution: "kubernetes", Digest: digest, Nodes: []ClusterNode{node}}
		s.mu.Unlock()
	}
	badDigest := digestTenantTest("replace-control-plane-inventory")
	setInventory(badDigest, ClusterNode{Name: "cp-1", UID: "uid-cp-1", Roles: []string{"control-plane"}, Ready: true})
	badMutation := TargetNodeProviderMutation{Authority: TargetNodeProviderMachineLifecycleAuthority, Action: TargetNodeActionReplace, TargetClusterID: target.ID, NodeName: "cp-1", NodeUID: "uid-cp-1", InventoryDigest: badDigest, WindowID: window.ID, WindowEndsAt: window.EndsAt}
	if _, err = s.QueueTargetNodeProviderMutation(ctx, provider.ID, provider.Revision, badMutation, provider.Desired, "operator", digestTenantTest("replace-control-plane-request")); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("store accepted control-plane node for replacement: %v", err)
	}

	inventoryDigest := digestTenantTest("replace-worker-inventory")
	setInventory(inventoryDigest, ClusterNode{Name: "worker-1", UID: "uid-worker-1", Roles: []string{"worker"}, Ready: true})
	mutation := TargetNodeProviderMutation{Authority: TargetNodeProviderMachineLifecycleAuthority, Action: TargetNodeActionReplace, TargetClusterID: target.ID, NodeName: "worker-1", NodeUID: "uid-worker-1", InventoryDigest: inventoryDigest, WindowID: window.ID, WindowEndsAt: window.EndsAt}

	s.mu.Lock()
	managementInventory := s.clusterInventories[management.ID]
	managementInventory.Capabilities = []string{TargetMutationRBACActiveCapability, "controlled-baseline-deployment"}
	s.clusterInventories[management.ID] = managementInventory
	s.mu.Unlock()
	if _, err = s.QueueTargetNodeProviderMutation(ctx, provider.ID, provider.Revision, mutation, provider.Desired, "operator", digestTenantTest("replace-without-management-capability")); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("store accepted provider mutation without management Machine capability: %v", err)
	}
	s.mu.Lock()
	managementInventory.Capabilities = append(managementInventory.Capabilities, TargetNodeProviderMachineLifecycleCapability)
	s.clusterInventories[management.ID] = managementInventory
	s.mu.Unlock()

	provider, err = s.QueueTargetNodeProviderMutation(ctx, provider.ID, provider.Revision, mutation, provider.Desired, "operator", digestTenantTest("replace-worker-request"))
	if err != nil || provider.State != ProviderClusterAwaitingApproval || provider.PendingAction != "TARGET_NODE_REPLACE" {
		t.Fatalf("replace queue=%#v err=%v", provider, err)
	}
	provider, err = s.ApproveProviderCluster(ctx, provider.ID, provider.Revision, "approver")
	if err != nil || provider.State != ProviderClusterQueued {
		t.Fatalf("replace approval=%#v err=%v", provider, err)
	}
	claimed, _, err := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || claimed.State != ProviderClusterApplying || claimed.TargetNodeMutation.NodeUID != mutation.NodeUID {
		t.Fatalf("replace claim=%#v err=%v", claimed, err)
	}
	evidence := claimed.TargetNodeMutation
	evidence.MachineName = "machine-worker-1"
	evidence.MachineUID = "machine-uid-1"
	evidence.MachineResourceVersion = "17"
	evidence.MachineSetName = "md-0-abc"
	evidence.MachineDeploymentName = "md-0"
	evidence.EvidenceDigest = digestTenantTest("replace-machine-evidence")
	provider, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), claimed.Revision, ProviderClusterTaskResult{ProviderClusterID: claimed.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "APPLY", Success: true, ObservedDigest: claimed.DesiredDigest, Phase: "Replacing", TargetNodeMutation: evidence})
	if err != nil || provider.State != ProviderClusterReconciling || provider.TargetNodeMutation.MachineUID != evidence.MachineUID {
		t.Fatalf("replace apply=%#v err=%v", provider, err)
	}
	claimed, _, err = s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
	if err != nil || claimed.State != ProviderClusterReconciling {
		t.Fatalf("replace inspect claim=%#v err=%v", claimed, err)
	}
	provider, err = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), claimed.Revision, ProviderClusterTaskResult{ProviderClusterID: claimed.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "INSPECT", Success: true, Ready: true, ObservedDigest: claimed.DesiredDigest, Phase: "Provisioned", TargetNodeMutation: evidence})
	if err != nil || provider.State != ProviderClusterActive || provider.PendingAction != "" || provider.Applied != provider.Desired {
		t.Fatalf("replace completion=%#v err=%v", provider, err)
	}

	runReplacementAction := func(action TargetNodeLifecycleAction, ready bool, suffix string) {
		digest := digestTenantTest("provider-worker-" + suffix)
		setInventory(digest, ClusterNode{Name: "worker-1", UID: "uid-worker-1", Roles: []string{"worker"}, Ready: ready})
		m := TargetNodeProviderMutation{Authority: TargetNodeProviderMachineLifecycleAuthority, Action: action, TargetClusterID: target.ID, NodeName: "worker-1", NodeUID: "uid-worker-1", InventoryDigest: digest, WindowID: window.ID, WindowEndsAt: window.EndsAt}
		var queueErr error
		provider, queueErr = s.QueueTargetNodeProviderMutation(ctx, provider.ID, provider.Revision, m, provider.Desired, "operator", digestTenantTest("request-"+suffix))
		if queueErr != nil || provider.State != ProviderClusterAwaitingApproval || provider.PendingAction != "TARGET_NODE_"+string(action) {
			t.Fatalf("%s queue=%#v err=%v", action, provider, queueErr)
		}
		provider, queueErr = s.ApproveProviderCluster(ctx, provider.ID, provider.Revision, "approver")
		if queueErr != nil || provider.State != ProviderClusterQueued {
			t.Fatalf("%s approval=%#v err=%v", action, provider, queueErr)
		}
		claimed, _, queueErr := s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
		if queueErr != nil || claimed.TargetNodeMutation.Action != action {
			t.Fatalf("%s claim=%#v err=%v", action, claimed, queueErr)
		}
		ev := claimed.TargetNodeMutation
		ev.MachineName = "machine-worker-1-" + suffix
		ev.MachineUID = "machine-uid-" + suffix
		ev.MachineResourceVersion = "21"
		ev.MachineSetName = "md-0-" + suffix
		ev.MachineDeploymentName = "md-0"
		ev.EvidenceDigest = digestTenantTest("evidence-" + suffix)
		provider, queueErr = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), claimed.Revision, ProviderClusterTaskResult{ProviderClusterID: claimed.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "APPLY", Success: true, ObservedDigest: claimed.DesiredDigest, Phase: "Replacing", TargetNodeMutation: ev})
		if queueErr != nil || provider.State != ProviderClusterReconciling {
			t.Fatalf("%s apply=%#v err=%v", action, provider, queueErr)
		}
		claimed, _, queueErr = s.NextProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken))
		if queueErr != nil || claimed.State != ProviderClusterReconciling {
			t.Fatalf("%s inspect claim=%#v err=%v", action, claimed, queueErr)
		}
		provider, queueErr = s.ReportProviderClusterTask(ctx, management.ID, digestTenantTest(agentToken), claimed.Revision, ProviderClusterTaskResult{ProviderClusterID: claimed.ID, TaskFenceToken: claimed.TaskFenceToken, Action: "INSPECT", Success: true, Ready: true, ObservedDigest: claimed.DesiredDigest, Phase: "Provisioned", TargetNodeMutation: ev})
		if queueErr != nil || provider.State != ProviderClusterActive || provider.PendingAction != "" {
			t.Fatalf("%s completion=%#v err=%v", action, provider, queueErr)
		}
	}

	runReplacementAction(TargetNodeActionCertificateRenewal, true, "cert-renewal")
	runReplacementAction(TargetNodeActionRemediate, false, "remediation")
}
