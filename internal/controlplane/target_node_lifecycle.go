package controlplane

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	TargetNodeLifecycleAuthorityMethod          = "TARGET_NODE_LIFECYCLE_AUTHORITY_V1"
	TargetNodeProviderMachineLifecycleAuthority = "TARGET_NODE_PROVIDER_MACHINE_LIFECYCLE_V1"
	TargetNodePhysicalCertificationDeferred     = "DEFERRED_UNTIL_DEVELOPMENT_CLOSURE"

	TargetNodeProviderLifecycleCapability        = "target-node-provider-lifecycle"
	TargetNodeProviderMachineLifecycleCapability = "provider-machine-lifecycle-v1"
	TargetNodeHostMaintenanceCapability          = "target-node-host-maintenance-executor-v1"
	TargetNodeOSPatchCapability                  = "target-node-os-patch"
	TargetNodeCertificateRenewalCapability       = "target-node-certificate-renewal"
	TargetNodeRemediationCapability              = "target-node-remediation"
)

type TargetNodeLifecycleAction string

const (
	TargetNodeActionAdd                TargetNodeLifecycleAction = "ADD"
	TargetNodeActionDrain              TargetNodeLifecycleAction = "DRAIN"
	TargetNodeActionRemove             TargetNodeLifecycleAction = "REMOVE"
	TargetNodeActionReplace            TargetNodeLifecycleAction = "REPLACE"
	TargetNodeActionOSPatch            TargetNodeLifecycleAction = "OS_PATCH"
	TargetNodeActionCertificateRenewal TargetNodeLifecycleAction = "CERTIFICATE_RENEWAL"
	TargetNodeActionRemediate          TargetNodeLifecycleAction = "REMEDIATE"
)

type TargetNodeLifecycleActionDescriptor struct {
	Action                      TargetNodeLifecycleAction `json:"action"`
	Executor                    string                    `json:"executor"`
	Risk                        string                    `json:"risk"`
	RequiresNode                bool                      `json:"requiresNode"`
	RequiresMaintenanceWindow   bool                      `json:"requiresMaintenanceWindow"`
	RequiresIndependentApproval bool                      `json:"requiresIndependentApproval"`
	RequiredCapabilities        []string                  `json:"requiredCapabilities,omitempty"`
	MissingCapabilities         []string                  `json:"missingCapabilities,omitempty"`
	DevelopmentReady            bool                      `json:"developmentReady"`
	Executable                  bool                      `json:"executable"`
	Blockers                    []string                  `json:"blockers,omitempty"`
}

type TargetNodeLifecycleAuthority struct {
	Authority                   string                                `json:"authority"`
	ProviderClusterID           string                                `json:"providerClusterId,omitempty"`
	ProviderBindingReady        bool                                  `json:"providerBindingReady"`
	CampaignAuthority           string                                `json:"campaignAuthority"`
	ClusterID                   string                                `json:"clusterId"`
	ProjectID                   string                                `json:"projectId"`
	Distribution                string                                `json:"distribution"`
	InventoryDigest             string                                `json:"inventoryDigest"`
	InventoryObservedAt         time.Time                             `json:"inventoryObservedAt"`
	PhysicalCertificationStatus string                                `json:"physicalCertificationStatus"`
	Actions                     []TargetNodeLifecycleActionDescriptor `json:"actions"`
}

type TargetNodeLifecyclePlanRequest struct {
	Action   TargetNodeLifecycleAction `json:"action"`
	NodeName string                    `json:"nodeName,omitempty"`
}

type TargetNodeLifecyclePlan struct {
	Authority                   string                    `json:"authority"`
	ProviderClusterID           string                    `json:"providerClusterId,omitempty"`
	ProviderBindingReady        bool                      `json:"providerBindingReady"`
	CampaignAuthority           string                    `json:"campaignAuthority"`
	PlanDigest                  string                    `json:"planDigest"`
	ClusterID                   string                    `json:"clusterId"`
	ProjectID                   string                    `json:"projectId"`
	Distribution                string                    `json:"distribution"`
	Action                      TargetNodeLifecycleAction `json:"action"`
	NodeName                    string                    `json:"nodeName,omitempty"`
	NodeUID                     string                    `json:"nodeUid,omitempty"`
	InventoryDigest             string                    `json:"inventoryDigest"`
	Executable                  bool                      `json:"executable"`
	Executor                    string                    `json:"executor"`
	RequiresMaintenanceWindow   bool                      `json:"requiresMaintenanceWindow"`
	RequiresIndependentApproval bool                      `json:"requiresIndependentApproval"`
	Impact                      []string                  `json:"impact"`
	Recovery                    []string                  `json:"recovery"`
	Blockers                    []string                  `json:"blockers,omitempty"`
	PhysicalCertificationStatus string                    `json:"physicalCertificationStatus"`
}

func lifecycleCapabilitySet(inv ClusterInventory) map[string]bool {
	out := make(map[string]bool, len(inv.Capabilities))
	for _, raw := range inv.Capabilities {
		if v := strings.ToLower(strings.TrimSpace(raw)); v != "" {
			out[v] = true
		}
	}
	return out
}

// TargetNodeProviderMutationEligible requires an inventory-stable, Ready worker-only
// node before provider-backed REMOVE/REPLACE can enter the durable approval queue.
// Store implementations call this again so API/UI planning cannot be used to bypass
// the destructive-node admission boundary.
func TargetNodeProviderWorkerEligible(node ClusterNode) bool {
	if strings.TrimSpace(node.Name) == "" || strings.TrimSpace(node.UID) == "" {
		return false
	}
	worker, controlPlane := false, false
	for _, role := range node.Roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "worker":
			worker = true
		case "control-plane", "controlplane", "master", "server":
			controlPlane = true
		}
	}
	return worker && !controlPlane
}

// TargetNodeProviderMutationEligible keeps destructive lifecycle semantics action-aware.
// REMOVE/REPLACE/CERTIFICATE_RENEWAL require a currently Ready worker so planned
// disruption starts from a healthy identity. REMEDIATE is intentionally the inverse:
// it is only admissible for an inventory-stable worker that is currently NotReady.
func TargetNodeProviderMutationEligibleFor(action TargetNodeLifecycleAction, node ClusterNode) bool {
	if !TargetNodeProviderWorkerEligible(node) {
		return false
	}
	switch action {
	case TargetNodeActionRemediate:
		return !node.Ready
	case TargetNodeActionRemove, TargetNodeActionReplace, TargetNodeActionCertificateRenewal:
		return node.Ready
	default:
		return false
	}
}

func TargetNodeProviderMutationEligible(node ClusterNode) bool {
	return TargetNodeProviderMutationEligibleFor(TargetNodeActionReplace, node)
}

func IsTargetNodeProviderReplacementAction(action TargetNodeLifecycleAction) bool {
	switch TargetNodeLifecycleAction(strings.ToUpper(strings.TrimSpace(string(action)))) {
	case TargetNodeActionReplace, TargetNodeActionCertificateRenewal, TargetNodeActionRemediate:
		return true
	default:
		return false
	}
}

func IsTargetNodeProviderPendingAction(action string) bool {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "TARGET_NODE_REMOVE", "TARGET_NODE_REPLACE", "TARGET_NODE_CERTIFICATE_RENEWAL", "TARGET_NODE_REMEDIATE":
		return true
	default:
		return false
	}
}

func lifecycleDescriptor(action TargetNodeLifecycleAction, inv ClusterInventory, providerBound bool, providerMachineReady ...bool) TargetNodeLifecycleActionDescriptor {
	capabilities := lifecycleCapabilitySet(inv)
	if providerBound {
		capabilities[strings.ToLower(TargetNodeProviderLifecycleCapability)] = true
	}
	if len(providerMachineReady) > 0 && providerMachineReady[0] {
		capabilities[strings.ToLower(TargetNodeProviderMachineLifecycleCapability)] = true
	}
	d := TargetNodeLifecycleActionDescriptor{Action: action, Risk: "high", RequiresIndependentApproval: true, RequiresMaintenanceWindow: true, DevelopmentReady: true}
	switch action {
	case TargetNodeActionDrain:
		d.Executor = "cluster-agent"
		d.RequiresNode = true
		d.RequiredCapabilities = []string{TargetMutationRBACActiveCapability, ClusterMaintenanceFencedReportCapability}
	case TargetNodeActionAdd:
		d.Executor = "infrastructure-provider-adapter"
		d.RequiresMaintenanceWindow = false
		d.RequiredCapabilities = []string{TargetNodeProviderLifecycleCapability}
		if !providerBound {
			d.Blockers = append(d.Blockers, "TARGET_NODE_PROVIDER_BINDING_PENDING")
		}
	case TargetNodeActionRemove:
		d.Executor = "infrastructure-provider-adapter"
		d.RequiresNode = true
		d.RequiredCapabilities = []string{TargetNodeProviderLifecycleCapability, TargetNodeProviderMachineLifecycleCapability}
	case TargetNodeActionReplace:
		d.Executor = "infrastructure-provider-adapter"
		d.RequiresNode = true
		d.RequiredCapabilities = []string{TargetNodeProviderLifecycleCapability, TargetNodeProviderMachineLifecycleCapability}
	case TargetNodeActionOSPatch:
		d.Executor = "cluster-agent-host-maintenance-job"
		d.RequiresNode = true
		d.RequiredCapabilities = []string{TargetMutationRBACActiveCapability, ClusterMaintenanceFencedReportCapability, TargetNodeHostMaintenanceCapability, TargetNodeOSPatchCapability}
	case TargetNodeActionCertificateRenewal:
		d.Executor = "infrastructure-provider-machine-replacement-certificate-renewal"
		d.RequiresNode = true
		d.RequiredCapabilities = []string{TargetNodeProviderLifecycleCapability, TargetNodeProviderMachineLifecycleCapability}
	case TargetNodeActionRemediate:
		d.Executor = "infrastructure-provider-machine-remediation"
		d.RequiresNode = true
		d.RequiredCapabilities = []string{TargetNodeProviderLifecycleCapability, TargetNodeProviderMachineLifecycleCapability}
	default:
		d.DevelopmentReady = false
		d.Blockers = []string{"TARGET_NODE_ACTION_UNKNOWN"}
		return d
	}
	for _, requirement := range d.RequiredCapabilities {
		if !capabilities[strings.ToLower(requirement)] {
			d.MissingCapabilities = append(d.MissingCapabilities, requirement)
		}
	}
	sort.Strings(d.MissingCapabilities)
	// Executability is derived from both source-owned adapter closure (no explicit
	// development blocker) and live target capabilities. This prevents a newly
	// implemented executor from being advertised on targets that have not activated
	// the required RBAC/image/runtime contract.
	switch action {
	case TargetNodeActionDrain, TargetNodeActionOSPatch, TargetNodeActionAdd, TargetNodeActionRemove, TargetNodeActionReplace, TargetNodeActionCertificateRenewal, TargetNodeActionRemediate:
		d.Executable = len(d.MissingCapabilities) == 0 && len(d.Blockers) == 0
	default:
		d.Executable = false
	}
	return d
}

func BuildTargetNodeLifecycleAuthority(cluster ManagedCluster, inv ClusterInventory, providerReadiness ...bool) TargetNodeLifecycleAuthority {
	providerReady := strings.TrimSpace(cluster.ProviderClusterID) != ""
	providerMachineReady := false
	if len(providerReadiness) > 0 {
		providerReady = providerReadiness[0]
	}
	if len(providerReadiness) > 1 {
		providerMachineReady = providerReadiness[1]
	}
	actions := []TargetNodeLifecycleAction{TargetNodeActionAdd, TargetNodeActionDrain, TargetNodeActionRemove, TargetNodeActionReplace, TargetNodeActionOSPatch, TargetNodeActionCertificateRenewal, TargetNodeActionRemediate}
	descriptors := make([]TargetNodeLifecycleActionDescriptor, 0, len(actions))
	for _, action := range actions {
		descriptors = append(descriptors, lifecycleDescriptor(action, inv, providerReady, providerMachineReady))
	}
	return TargetNodeLifecycleAuthority{
		Authority:                   TargetNodeLifecycleAuthorityMethod,
		ProviderClusterID:           strings.TrimSpace(cluster.ProviderClusterID),
		ProviderBindingReady:        providerReady,
		CampaignAuthority:           GeneralizedDay2CampaignAuthorityMethod,
		ClusterID:                   cluster.ID,
		ProjectID:                   cluster.ProjectID,
		Distribution:                strings.ToLower(strings.TrimSpace(inv.Distribution)),
		InventoryDigest:             inv.Digest,
		InventoryObservedAt:         inv.ObservedAt,
		PhysicalCertificationStatus: TargetNodePhysicalCertificationDeferred,
		Actions:                     descriptors,
	}
}

func findLifecycleDescriptor(authority TargetNodeLifecycleAuthority, action TargetNodeLifecycleAction) (TargetNodeLifecycleActionDescriptor, bool) {
	for _, descriptor := range authority.Actions {
		if descriptor.Action == action {
			return descriptor, true
		}
	}
	return TargetNodeLifecycleActionDescriptor{}, false
}

func BuildTargetNodeLifecyclePlan(cluster ManagedCluster, inv ClusterInventory, request TargetNodeLifecyclePlanRequest, providerReadiness ...bool) (TargetNodeLifecyclePlan, error) {
	action := TargetNodeLifecycleAction(strings.ToUpper(strings.TrimSpace(string(request.Action))))
	authority := BuildTargetNodeLifecycleAuthority(cluster, inv, providerReadiness...)
	descriptor, ok := findLifecycleDescriptor(authority, action)
	if !ok || !descriptor.DevelopmentReady {
		return TargetNodeLifecyclePlan{}, fmt.Errorf("%w: unsupported target node lifecycle action %q", ErrValidation, request.Action)
	}
	nodeName := strings.TrimSpace(request.NodeName)
	var node ClusterNode
	if descriptor.RequiresNode {
		if nodeName == "" {
			return TargetNodeLifecyclePlan{}, fmt.Errorf("%w: nodeName is required for %s", ErrValidation, action)
		}
		found := false
		for _, candidate := range inv.Nodes {
			if candidate.Name == nodeName {
				node = candidate
				found = true
				break
			}
		}
		if !found || strings.TrimSpace(node.UID) == "" {
			return TargetNodeLifecyclePlan{}, fmt.Errorf("%w: node must exist in the approved inventory with a stable UID", ErrPrerequisite)
		}
	} else if nodeName != "" {
		return TargetNodeLifecyclePlan{}, fmt.Errorf("%w: nodeName must be empty for %s planning", ErrValidation, action)
	}

	blockers := append([]string(nil), descriptor.Blockers...)
	for _, missing := range descriptor.MissingCapabilities {
		blockers = append(blockers, "TARGET_CAPABILITY_MISSING:"+missing)
	}
	if action == TargetNodeActionDrain && !node.Ready {
		blockers = append(blockers, "TARGET_NODE_NOT_READY")
	}
	if action == TargetNodeActionRemove || action == TargetNodeActionReplace || action == TargetNodeActionCertificateRenewal || action == TargetNodeActionRemediate {
		if !TargetNodeProviderWorkerEligible(node) {
			blockers = append(blockers, "TARGET_NODE_NOT_WORKER_ONLY")
		}
		if action == TargetNodeActionRemediate {
			if node.Ready {
				blockers = append(blockers, "TARGET_NODE_REMEDIATION_REQUIRES_NOT_READY")
			}
		} else if !node.Ready {
			blockers = append(blockers, "TARGET_NODE_NOT_READY")
		}
	}
	sort.Strings(blockers)

	impact := []string{"inventory identity is pinned to " + inv.Digest, "independent approval is required before mutation"}
	recovery := []string{"unsafe replay after lease/fence loss is rejected", "operator recovery uses durable operation/evidence state"}
	switch action {
	case TargetNodeActionDrain:
		impact = append(impact, "selected node is cordoned, PDB-aware drained and uncordoned with maxUnavailable=1")
		recovery = append(recovery, "uncordon is attempted even when drain fails")
	case TargetNodeActionAdd:
		impact = append(impact, "new infrastructure capacity and cluster membership would be created by a provider adapter")
	case TargetNodeActionRemove:
		impact = append(impact, "selected node would be drained before provider-backed membership/infrastructure removal")
	case TargetNodeActionReplace:
		impact = append(impact, "replacement capacity must be established and verified before old-node removal")
	case TargetNodeActionOSPatch:
		impact = append(impact, "node workloads are safely evacuated before a node-pinned host package update; reboot is never automatic and is reported separately when required")
	case TargetNodeActionCertificateRenewal:
		impact = append(impact, "selected Ready provider-managed worker is replaced one-for-one so the joining node receives fresh RKE2 node identity and certificates")
		recovery = append(recovery, "exact CAPI Machine identity is persisted before delete and replacement readiness is required before completion")
	case TargetNodeActionRemediate:
		impact = append(impact, "selected NotReady provider-managed worker is replaced one-for-one using exact CAPI Machine identity")
		recovery = append(recovery, "retry reuses persisted Machine recovery evidence and cannot resolve a second target")
	}

	plan := TargetNodeLifecyclePlan{
		Authority:                   TargetNodeLifecycleAuthorityMethod,
		ProviderClusterID:           strings.TrimSpace(cluster.ProviderClusterID),
		ProviderBindingReady:        authority.ProviderBindingReady,
		CampaignAuthority:           GeneralizedDay2CampaignAuthorityMethod,
		ClusterID:                   cluster.ID,
		ProjectID:                   cluster.ProjectID,
		Distribution:                strings.ToLower(strings.TrimSpace(inv.Distribution)),
		Action:                      action,
		NodeName:                    nodeName,
		NodeUID:                     node.UID,
		InventoryDigest:             inv.Digest,
		Executable:                  descriptor.Executable && len(blockers) == 0,
		Executor:                    descriptor.Executor,
		RequiresMaintenanceWindow:   descriptor.RequiresMaintenanceWindow,
		RequiresIndependentApproval: descriptor.RequiresIndependentApproval,
		Impact:                      impact,
		Recovery:                    recovery,
		Blockers:                    blockers,
		PhysicalCertificationStatus: TargetNodePhysicalCertificationDeferred,
	}
	canonical := struct {
		ClusterID         string                    `json:"clusterId"`
		Distribution      string                    `json:"distribution"`
		Action            TargetNodeLifecycleAction `json:"action"`
		NodeName          string                    `json:"nodeName,omitempty"`
		NodeUID           string                    `json:"nodeUid,omitempty"`
		InventoryDigest   string                    `json:"inventoryDigest"`
		Executor          string                    `json:"executor"`
		ProviderClusterID string                    `json:"providerClusterId,omitempty"`
		Blockers          []string                  `json:"blockers,omitempty"`
	}{plan.ClusterID, plan.Distribution, plan.Action, plan.NodeName, plan.NodeUID, plan.InventoryDigest, plan.Executor, plan.ProviderClusterID, plan.Blockers}
	raw, _ := json.Marshal(canonical)
	plan.PlanDigest = digestBytes(raw)
	return plan, nil
}

// DescribeTargetNodeLifecycleAction resolves source readiness and live target
// capabilities for one lifecycle action. Durable stores use the same authority
// to prevent API-only admission from diverging from execution-time admission.
func DescribeTargetNodeLifecycleAction(action TargetNodeLifecycleAction, inv ClusterInventory) TargetNodeLifecycleActionDescriptor {
	return lifecycleDescriptor(action, inv, false, false)
}
