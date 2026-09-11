package controlplane

import (
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/targetmodel"
)

const (
	OKDHealthAuthorityMethod     = "OKD_CLUSTER_OPERATOR_HEALTH_AUTHORITY_V1"
	OKDProfileCompilerAuthority  = "TARGET_DESIRED_OBSERVED_PROFILE_COMPILER_V1"
	OKDImportAdmissionCapability = "okd-import-admitted"
	OKDHealthHealthyCapability   = "okd-health-healthy"
	OKDClusterVersionCapability  = "okd-cluster-version-authority"
)

type OKDHealthSummary struct {
	Authority        string   `json:"authority"`
	Status           string   `json:"status"`
	ClusterVersion   string   `json:"clusterVersion,omitempty"`
	DesiredImage     string   `json:"desiredImage,omitempty"`
	OperatorCount    int      `json:"operatorCount"`
	Unavailable      []string `json:"unavailable,omitempty"`
	Progressing      []string `json:"progressing,omitempty"`
	Degraded         []string `json:"degraded,omitempty"`
	UpgradeBlocked   []string `json:"upgradeBlocked,omitempty"`
	Messages         []string `json:"messages,omitempty"`
	MutationEligible bool     `json:"mutationEligible"`
}

type TargetProfileCompilation struct {
	Authority            string                           `json:"authority"`
	DistributionIdentity string                           `json:"distributionIdentity"`
	Status               string                           `json:"status"`
	RequestedComponents  []string                         `json:"requestedComponents"`
	ObservedCapabilities []string                         `json:"observedCapabilities"`
	Resolution           targetmodel.CapabilityResolution `json:"resolution"`
	Blockers             []string                         `json:"blockers,omitempty"`
}

var okdServerOwnedCapabilities = map[string]struct{}{
	OKDImportAdmissionCapability: {},
	OKDHealthHealthyCapability:   {},
	OKDClusterVersionCapability:  {},
	"networking.ovn-kubernetes":  {},
	"network-policy.native":      {},
	"monitoring.cluster":         {},
	"operator-lifecycle.olm":     {},
	"security.scc":               {},
	"tenancy.projects":           {},
}

func stripOKDServerOwnedCapabilities(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, owned := okdServerOwnedCapabilities[strings.TrimSpace(value)]; owned {
			continue
		}
		out = append(out, value)
	}
	return dedupeSortedStrings(out)
}

func clusterAddOnKind(addon ClusterAddOn, kind string) bool {
	return strings.EqualFold(strings.TrimSpace(addon.Kind), kind)
}

func conditionTrue(v string) bool  { return strings.EqualFold(strings.TrimSpace(v), "true") }
func conditionFalse(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "false") }

func TranslateOKDHealth(inv ClusterInventory) OKDHealthSummary {
	out := OKDHealthSummary{Authority: OKDHealthAuthorityMethod, Status: "NOT_APPLICABLE"}
	if targetmodel.CanonicalDistribution(inv.Distribution) != targetmodel.DistributionOKD {
		return out
	}
	out.Status = "BLOCKED"
	foundVersion := false
	foundOperators := false
	for _, addon := range inv.AddOns {
		switch {
		case clusterAddOnKind(addon, "cluster-version"):
			foundVersion = true
			out.ClusterVersion = strings.TrimSpace(addon.Version)
			if conditionFalse(addon.Available) {
				out.Unavailable = append(out.Unavailable, "cluster-version")
			}
			if conditionTrue(addon.Progressing) {
				out.Progressing = append(out.Progressing, "cluster-version")
			}
			if conditionTrue(addon.Degraded) {
				out.Degraded = append(out.Degraded, "cluster-version")
			}
			if conditionFalse(addon.Upgradeable) {
				out.UpgradeBlocked = append(out.UpgradeBlocked, "cluster-version")
			}
			if strings.TrimSpace(addon.Message) != "" {
				out.Messages = append(out.Messages, strings.TrimSpace(addon.Message))
			}
		case clusterAddOnKind(addon, "cluster-operator"):
			foundOperators = true
			out.OperatorCount++
			name := strings.TrimSpace(addon.Name)
			if name == "" {
				name = "unknown-operator"
			}
			if conditionFalse(addon.Available) || strings.EqualFold(strings.TrimSpace(addon.Available), "Unknown") {
				out.Unavailable = append(out.Unavailable, name)
			}
			if conditionTrue(addon.Progressing) {
				out.Progressing = append(out.Progressing, name)
			}
			if conditionTrue(addon.Degraded) {
				out.Degraded = append(out.Degraded, name)
			}
			if conditionFalse(addon.Upgradeable) {
				out.UpgradeBlocked = append(out.UpgradeBlocked, name)
			}
			if strings.TrimSpace(addon.Message) != "" && (conditionTrue(addon.Degraded) || conditionTrue(addon.Progressing) || conditionFalse(addon.Available)) {
				out.Messages = append(out.Messages, name+": "+strings.TrimSpace(addon.Message))
			}
		}
	}
	for _, values := range [][]string{out.Unavailable, out.Progressing, out.Degraded, out.UpgradeBlocked, out.Messages} {
		sort.Strings(values)
	}
	switch {
	case !foundVersion || !foundOperators:
		out.Status = "BLOCKED"
	case len(out.Degraded) > 0:
		out.Status = "DEGRADED"
	case len(out.Unavailable) > 0:
		out.Status = "BLOCKED"
	case len(out.Progressing) > 0:
		out.Status = "PROGRESSING"
	default:
		out.Status = "HEALTHY"
	}
	out.MutationEligible = out.Status == "HEALTHY"
	return out
}

func apiResourcePresent(inv ClusterInventory, group, resource string) bool {
	for _, item := range inv.APIResources {
		if strings.EqualFold(strings.TrimSpace(item.Group), group) && strings.EqualFold(strings.TrimSpace(item.Resource), resource) {
			return true
		}
	}
	return false
}

func operatorPresent(inv ClusterInventory, name string) bool {
	for _, item := range inv.AddOns {
		if clusterAddOnKind(item, "cluster-operator") && strings.EqualFold(strings.TrimSpace(item.Name), name) {
			return true
		}
	}
	return false
}

func NormalizeOKDInventoryAuthority(inv ClusterInventory) ClusterInventory {
	if targetmodel.CanonicalDistribution(inv.Distribution) != targetmodel.DistributionOKD {
		return inv
	}
	inv.Capabilities = stripOKDServerOwnedCapabilities(inv.Capabilities)
	derived := []string{OKDClusterVersionCapability}
	if strings.Contains(strings.ToLower(strings.TrimSpace(inv.Networking.CNI)), "ovn") {
		derived = append(derived, "networking.ovn-kubernetes", "network-policy.native")
	}
	if operatorPresent(inv, "monitoring") {
		derived = append(derived, "monitoring.cluster")
	}
	if apiResourcePresent(inv, "operators.coreos.com", "clusterserviceversions") || operatorPresent(inv, "operator-lifecycle-manager") {
		derived = append(derived, "operator-lifecycle.olm")
	}
	if apiResourcePresent(inv, "security.openshift.io", "securitycontextconstraints") {
		derived = append(derived, "security.scc")
	}
	if apiResourcePresent(inv, "project.openshift.io", "projects") {
		derived = append(derived, "tenancy.projects")
	}
	health := TranslateOKDHealth(inv)
	if health.Status == "HEALTHY" {
		derived = append(derived, OKDHealthHealthyCapability)
	}
	inv.Capabilities = dedupeSortedStrings(append(inv.Capabilities, derived...))
	required := []string{"networking.ovn-kubernetes", "monitoring.cluster", "operator-lifecycle.olm", "security.scc", "tenancy.projects", OKDHealthHealthyCapability}
	ready := inv.APIDiscoveryComplete && inv.CRDDiscoveryComplete && inv.SchemaDiscoveryComplete
	for _, capability := range required {
		if !clusterHasCapability(ManagedCluster{Capabilities: inv.Capabilities}, capability) {
			ready = false
		}
	}
	if ready {
		inv.Capabilities = dedupeSortedStrings(append(inv.Capabilities, OKDImportAdmissionCapability))
	}
	return inv
}

func ClusterInventoryMutationEligible(inv ClusterInventory) bool {
	switch targetmodel.CanonicalDistribution(inv.Distribution) {
	case targetmodel.DistributionKubernetes, targetmodel.DistributionRKE2:
		return true
	case targetmodel.DistributionOKD:
		return clusterHasCapability(ManagedCluster{Capabilities: inv.Capabilities}, OKDImportAdmissionCapability)
	default:
		return false
	}
}

func ClusterMutationAdmissionEligible(c ManagedCluster) bool {
	switch targetmodel.CanonicalDistribution(c.Distribution) {
	case targetmodel.DistributionKubernetes, targetmodel.DistributionRKE2:
		return true
	case targetmodel.DistributionOKD:
		return clusterHasCapability(c, OKDImportAdmissionCapability)
	default:
		return false
	}
}

func DefaultImportedTargetComponents() []string {
	return []string{"argocd", "capsule", "cilium", "snapshot-controller", "victoria-metrics"}
}

func CompileTargetProfile(inv ClusterInventory, requested []string) TargetProfileCompilation {
	if len(requested) == 0 {
		requested = DefaultImportedTargetComponents()
	}
	requested = dedupeSortedStrings(requested)
	resolution := targetmodel.ResolveTargetComponents(inv.Distribution, requested, inv.Capabilities)
	// A complete inventory can resolve absence-dependent defaults deterministically.
	// Snapshot controller is included only when discovery proves that the target does
	// not already own that capability; this keeps install and import on one compiler.
	for i := range resolution.Decisions {
		decision := &resolution.Decisions[i]
		if decision.Component == "snapshot-controller" && decision.Action == targetmodel.ResolutionActionConditional && inv.APIDiscoveryComplete {
			decision.Action = targetmodel.ResolutionActionInclude
			decision.Reason = "complete target discovery does not report a native volume snapshot controller; include the product default rather than leaving profile convergence ambiguous"
		}
	}
	out := TargetProfileCompilation{Authority: OKDProfileCompilerAuthority, DistributionIdentity: targetmodel.CanonicalDistribution(inv.Distribution), Status: "BLOCKED", RequestedComponents: requested, ObservedCapabilities: dedupeSortedStrings(inv.Capabilities), Resolution: resolution}
	if !resolution.Admitted {
		out.Blockers = append(out.Blockers, resolution.Blockers...)
	}
	for _, decision := range resolution.Decisions {
		if decision.Action == targetmodel.ResolutionActionConditional {
			out.Blockers = append(out.Blockers, "UNRESOLVED_COMPONENT:"+decision.Component)
		}
	}
	if len(out.Blockers) == 0 {
		out.Status = "CONVERGED"
	}
	out.Blockers = dedupeSortedStrings(out.Blockers)
	return out
}

type ClusterReconnectSummary struct {
	Authority                   string `json:"authority"`
	Status                      string `json:"status"`
	Automatic                   bool   `json:"automatic"`
	SameClusterIdentityRequired bool   `json:"sameClusterIdentityRequired"`
	TargetRBACFenceRequired     bool   `json:"targetRbacFenceRequired"`
	Next                        string `json:"next"`
}

func ClusterReconnectAuthority(c ManagedCluster, now time.Time) ClusterReconnectSummary {
	out := ClusterReconnectSummary{Authority: "CLUSTER_RECONNECT_AUTHORITY_V1", SameClusterIdentityRequired: true}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if c.ConnectionState == "REVOKED" {
		out.Status = "REENROLLMENT_REQUIRED"
		out.TargetRBACFenceRequired = ClusterMayHaveTargetMutationRBAC(c) && !ClusterTargetRBACRevocationAcknowledged(c)
		if out.TargetRBACFenceRequired {
			out.Next = "apply the target-side RBAC revocation manifest, acknowledge its exact fence digest, then create a new enrollment request for the same physical cluster UID"
		} else {
			out.Next = "create and approve a new enrollment request; the same physical cluster UID may re-enroll without creating duplicate active authority"
		}
		return out
	}
	if c.LastSeenAt == nil || now.Sub(c.LastSeenAt.UTC()) > ClusterInventoryAuthorityFreshness {
		out.Status = "WAITING_FOR_AGENT"
		out.Automatic = true
		out.Next = "the existing agent retries the same Hub identity automatically; do not create a duplicate import while the existing cluster authority is active"
		return out
	}
	out.Status = "CONNECTED"
	out.Automatic = true
	out.Next = "no reconnect action is required"
	return out
}
