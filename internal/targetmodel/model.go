package targetmodel

import (
	"sort"
	"strings"
)

const AuthorityMethod = "TARGET_ARCHITECTURE_MODEL_V1"

const (
	DistributionKubernetes = "kubernetes"
	DistributionRKE2       = "rke2"
	DistributionOKD        = "okd"
	DistributionOpenShift  = "openshift"

	ProvisioningImportExisting = "import-existing"
	ProvisioningClusterAPI     = "cluster-api"
	ProvisioningManagedInstall = "managed-install"

	InfrastructureExisting    = "existing"
	InfrastructureUnspecified = "unspecified"
	InfrastructureBareMetal   = "bare-metal"
	InfrastructureVMware      = "vmware"
)

type Target struct {
	DistributionIdentity   string `json:"distributionIdentity"`
	ProvisioningMode       string `json:"provisioningMode"`
	InfrastructureProvider string `json:"infrastructureProvider"`
	ProvisioningAdapter    string `json:"provisioningAdapter,omitempty"`
	LegacyDistribution     string `json:"legacyDistribution,omitempty"`
}

type VocabularyEntry struct {
	ID                    string `json:"id"`
	Status                string `json:"status"`
	ImportSupported       bool   `json:"importSupported,omitempty"`
	ManagedInstallSupport bool   `json:"managedInstallSupported,omitempty"`
	Description           string `json:"description"`
}

type Model struct {
	Authority               string                       `json:"authority"`
	Distributions           []VocabularyEntry            `json:"distributions"`
	ProvisioningModes       []VocabularyEntry            `json:"provisioningModes"`
	InfrastructureProviders []VocabularyEntry            `json:"infrastructureProviders"`
	LegacyDistributionMap   map[string]string            `json:"legacyDistributionMap"`
	LegacyAdapterMap        map[string]string            `json:"legacyAdapterMap"`
	ManagementPlane         Target                       `json:"managementPlane"`
	CapabilityResolver      CapabilityResolverDescriptor `json:"capabilityResolver"`
	ProgramRoadmap          ProgramRoadmap               `json:"programRoadmap"`
}

func ArchitectureModel() Model {
	return Model{
		Authority: AuthorityMethod,
		Distributions: []VocabularyEntry{
			{ID: DistributionKubernetes, Status: "SUPPORTED", ImportSupported: true, Description: "Upstream-conformant Kubernetes distribution identity. Installer history such as Kubespray is not part of this identity."},
			{ID: DistributionRKE2, Status: "SUPPORTED", ImportSupported: true, Description: "RKE2 distribution identity. The Factory management appliance is also RKE2 but remains a separate internal boundary."},
			{ID: DistributionOKD, Status: "RECOGNIZED_NOT_YET_ADMITTED", Description: "Reserved first-class OKD identity. Import, capability resolution and managed lifecycle require their dedicated phases before admission."},
			{ID: DistributionOpenShift, Status: "RECOGNIZED_NOT_YET_ADMITTED", Description: "Red Hat OpenShift identity detected from ClusterVersion authority. It is intentionally distinct from OKD and is not admitted by the current OKD target phases."},
		},
		ProvisioningModes: []VocabularyEntry{
			{ID: ProvisioningImportExisting, Status: "SUPPORTED", Description: "Connect an already-running Kubernetes target through the fleet enrollment workflow."},
			{ID: ProvisioningClusterAPI, Status: "SUPPORTED", Description: "Provision through the admitted Cluster API topology adapter; this is a provisioning method, not a distribution or infrastructure provider."},
			{ID: ProvisioningManagedInstall, Status: "MANAGEMENT_PLANE_ONLY", ManagedInstallSupport: true, Description: "Used by the internal RKE2 management-appliance installer. First-class managed target installation is a later target-adapter capability."},
		},
		InfrastructureProviders: []VocabularyEntry{
			{ID: InfrastructureExisting, Status: "SUPPORTED_FOR_IMPORT", Description: "Infrastructure is pre-existing and remains outside Factory lifecycle ownership."},
			{ID: InfrastructureUnspecified, Status: "SUPPORTED_FOR_EXTERNAL_ADAPTER", Description: "Infrastructure identity is intentionally unknown because an external provisioning adapter owns that detail."},
			{ID: InfrastructureBareMetal, Status: "RECOGNIZED_NOT_YET_ADMITTED", Description: "Recognized infrastructure identity for future managed-target adapters."},
			{ID: InfrastructureVMware, Status: "RECOGNIZED_NOT_YET_ADMITTED", Description: "Recognized infrastructure identity for future managed-target adapters."},
		},
		LegacyDistributionMap: map[string]string{
			"generic-imported":    DistributionKubernetes,
			"kubespray":           DistributionKubernetes,
			"kubernetes":          DistributionKubernetes,
			"upstream-kubernetes": DistributionKubernetes,
			"rke2":                DistributionRKE2,
			"okd":                 DistributionOKD,
			"openshift":           DistributionOpenShift,
		},
		LegacyAdapterMap: map[string]string{
			"imported":                     ProvisioningImportExisting,
			"cluster-api-topology-v1beta2": ProvisioningClusterAPI,
		},
		ManagementPlane: Target{
			DistributionIdentity:   DistributionRKE2,
			ProvisioningMode:       ProvisioningManagedInstall,
			InfrastructureProvider: InfrastructureExisting,
			ProvisioningAdapter:    "internal-rke2-appliance-installer",
		},
		CapabilityResolver: CapabilityResolverModel(),
		ProgramRoadmap:     ProgramRoadmapModel(),
	}
}

func CanonicalDistribution(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case v == "":
		return ""
	case strings.Contains(v, "rke2"):
		return DistributionRKE2
	case v == "okd" || strings.Contains(v, "okd"):
		return DistributionOKD
	case v == "openshift" || strings.Contains(v, "openshift"):
		return DistributionOpenShift
	case v == "generic-imported" || v == "kubespray" || v == "kubernetes" || v == "upstream-kubernetes" || strings.Contains(v, "kubespray"):
		return DistributionKubernetes
	default:
		// Unknown runtime strings remain Kubernetes-compatible only when the
		// caller explicitly chooses that identity. Do not silently classify
		// arbitrary distributions as supported.
		return v
	}
}

func CanonicalDistributionSet(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := CanonicalDistribution(raw)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func ProvisioningModeFromAdapter(adapter string) string {
	switch strings.ToLower(strings.TrimSpace(adapter)) {
	case "imported":
		return ProvisioningImportExisting
	case "cluster-api-topology-v1beta2":
		return ProvisioningClusterAPI
	case "internal-rke2-appliance-installer":
		return ProvisioningManagedInstall
	default:
		return ""
	}
}

func ImportedTarget(observedDistribution string) Target {
	return Target{
		DistributionIdentity:   CanonicalDistribution(observedDistribution),
		ProvisioningMode:       ProvisioningImportExisting,
		InfrastructureProvider: InfrastructureExisting,
		ProvisioningAdapter:    "fleet-agent-enrollment",
		LegacyDistribution:     strings.TrimSpace(observedDistribution),
	}
}

func AdapterTarget(distributionIdentity, adapter string) Target {
	return Target{
		DistributionIdentity:   CanonicalDistribution(distributionIdentity),
		ProvisioningMode:       ProvisioningModeFromAdapter(adapter),
		InfrastructureProvider: InfrastructureUnspecified,
		ProvisioningAdapter:    strings.ToLower(strings.TrimSpace(adapter)),
	}
}

func SupportedDistribution(identity string) bool {
	switch CanonicalDistribution(identity) {
	case DistributionKubernetes, DistributionRKE2:
		return true
	default:
		return false
	}
}
