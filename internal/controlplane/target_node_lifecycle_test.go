package controlplane

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func lifecycleFixture() (ManagedCluster, ClusterInventory) {
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	cluster := ManagedCluster{ResourceMeta: ResourceMeta{ID: "cluster-1"}, ProjectID: "project-1", ConnectionState: "CONNECTED"}
	inv := ClusterInventory{ClusterID: cluster.ID, ObservedAt: now, Distribution: "rke2", Digest: "sha256:" + strings.Repeat("a", 64), Capabilities: []string{TargetMutationRBACActiveCapability, ClusterMaintenanceFencedReportCapability}, Nodes: []ClusterNode{{Name: "worker-1", UID: "uid-1", Roles: []string{"worker"}, Ready: true}}}
	return cluster, inv
}

func TestTargetNodeLifecycleAuthorityIsTruthfulAboutExecutableAdapters(t *testing.T) {
	cluster, inv := lifecycleFixture()
	authority := BuildTargetNodeLifecycleAuthority(cluster, inv)
	if authority.Authority != TargetNodeLifecycleAuthorityMethod || authority.CampaignAuthority != GeneralizedDay2CampaignAuthorityMethod || authority.PhysicalCertificationStatus != TargetNodePhysicalCertificationDeferred {
		t.Fatalf("authority drift: %#v", authority)
	}
	byAction := map[TargetNodeLifecycleAction]TargetNodeLifecycleActionDescriptor{}
	for _, action := range authority.Actions {
		byAction[action.Action] = action
	}
	if !byAction[TargetNodeActionDrain].Executable || len(byAction[TargetNodeActionDrain].Blockers) != 0 {
		t.Fatalf("existing fenced drain adapter should be executable: %#v", byAction[TargetNodeActionDrain])
	}
	if byAction[TargetNodeActionAdd].Executable || len(byAction[TargetNodeActionAdd].Blockers) == 0 {
		t.Fatalf("ADD must remain provider-binding gated: %#v", byAction[TargetNodeActionAdd])
	}
	for _, action := range []TargetNodeLifecycleAction{TargetNodeActionRemove, TargetNodeActionReplace, TargetNodeActionCertificateRenewal, TargetNodeActionRemediate} {
		v := byAction[action]
		if v.Executable || len(v.Blockers) != 0 || !hasLifecycleString(v.MissingCapabilities, TargetNodeProviderMachineLifecycleCapability) || !hasLifecycleString(v.MissingCapabilities, TargetNodeProviderLifecycleCapability) {
			t.Fatalf("implemented provider Machine executor must remain binding/management-capability gated for %s: %#v", action, v)
		}
	}
	patch := byAction[TargetNodeActionOSPatch]
	if patch.Executable || len(patch.Blockers) != 0 || len(patch.MissingCapabilities) != 2 {
		t.Fatalf("implemented OS patch executor must remain target-capability gated: %#v", patch)
	}
}

func TestTargetNodeLifecyclePlanPinsNodeUIDAndInventory(t *testing.T) {
	cluster, inv := lifecycleFixture()
	plan, err := BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionDrain, NodeName: "worker-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable || plan.NodeUID != "uid-1" || plan.InventoryDigest != inv.Digest || !strings.HasPrefix(plan.PlanDigest, "sha256:") || len(plan.Blockers) != 0 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	inv.Nodes[0].Ready = false
	blocked, err := BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionDrain, NodeName: "worker-1"})
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Executable || !hasLifecycleString(blocked.Blockers, "TARGET_NODE_NOT_READY") {
		t.Fatalf("not-ready node was admitted: %#v", blocked)
	}
}

func TestTargetNodeLifecyclePlanRejectsStaleIdentityAndUnsupportedPromotion(t *testing.T) {
	cluster, inv := lifecycleFixture()
	if _, err := BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionDrain, NodeName: "missing"}); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("missing node identity accepted: %v", err)
	}
	plan, err := BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionOSPatch, NodeName: "worker-1"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable || len(plan.Blockers) != 2 || !hasLifecycleString(plan.Blockers, "TARGET_CAPABILITY_MISSING:"+TargetNodeHostMaintenanceCapability) || !hasLifecycleString(plan.Blockers, "TARGET_CAPABILITY_MISSING:"+TargetNodeOSPatchCapability) {
		t.Fatalf("OS patch was promoted without live target capability: %#v", plan)
	}
	inv.Capabilities = append(inv.Capabilities, TargetNodeHostMaintenanceCapability, TargetNodeOSPatchCapability)
	ready, err := BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionOSPatch, NodeName: "worker-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !ready.Executable || len(ready.Blockers) != 0 || ready.Executor != "cluster-agent-host-maintenance-job" {
		t.Fatalf("implemented OS patch executor was not admitted with live capabilities: %#v", ready)
	}
}

func TestProviderBackedCertificateRenewalAndRemediationHealthAdmission(t *testing.T) {
	cluster, inv := lifecycleFixture()
	cluster.ProviderClusterID = "provider-1"
	cert, err := BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionCertificateRenewal, NodeName: "worker-1"}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Executable || cert.Executor != "infrastructure-provider-machine-replacement-certificate-renewal" || len(cert.Blockers) != 0 {
		t.Fatalf("Ready provider worker certificate renewal should be executable: %#v", cert)
	}
	remediate, err := BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionRemediate, NodeName: "worker-1"}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if remediate.Executable || !hasLifecycleString(remediate.Blockers, "TARGET_NODE_REMEDIATION_REQUIRES_NOT_READY") {
		t.Fatalf("healthy node remediation must be rejected: %#v", remediate)
	}
	inv.Nodes[0].Ready = false
	cert, err = BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionCertificateRenewal, NodeName: "worker-1"}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Executable || !hasLifecycleString(cert.Blockers, "TARGET_NODE_NOT_READY") {
		t.Fatalf("certificate renewal must start from a Ready worker: %#v", cert)
	}
	remediate, err = BuildTargetNodeLifecyclePlan(cluster, inv, TargetNodeLifecyclePlanRequest{Action: TargetNodeActionRemediate, NodeName: "worker-1"}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !remediate.Executable || remediate.Executor != "infrastructure-provider-machine-remediation" || len(remediate.Blockers) != 0 {
		t.Fatalf("NotReady provider worker remediation should be executable: %#v", remediate)
	}
}

func hasLifecycleString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
