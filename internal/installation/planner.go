package installation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

var profiles = []DeploymentProfile{
	{
		ID: "evaluation-single-node", DisplayName: "Evaluation — Single Node",
		Description: "One-node appliance for evaluation and demonstrations. It is never presented as HA or production certified.",
		Production:  false, HighAvailability: false, MinNodes: 1, RecommendedNodes: 1,
		SupportedConnectivity: []string{"connected", "restricted-egress", "disconnected"},
		CustomerInputs:        []string{"one reachable Linux node", "product endpoint", "administrator email"},
		ManagedServices:       []string{"RKE2", "PostgreSQL", "Forgejo", "zot", "local evidence storage", "identity", "4SO control plane"},
		Sizing:                ApplianceSizing{Authority: "APPLIANCE_SIZING_AUTHORITY_V1", Status: "SOURCE_ENFORCED_PHYSICAL_TUNING_PENDING", Scope: "single-node-appliance", MinimumVCPU: 4, MinimumMemoryGiB: 8, MinimumDiskGiB: 80, MinimumFreeDiskGiB: 60, RecommendedVCPU: 8, RecommendedMemoryGiB: 16, RecommendedDiskGiB: 150},
	},
	{
		ID: "production-standard-ha", DisplayName: "Production — Standard HA", Default: true,
		Description: "The default three-node appliance. Required platform services are installed and lifecycle-managed by the product.",
		Production:  true, HighAvailability: true, MinNodes: 3, RecommendedNodes: 3,
		SupportedConnectivity: []string{"connected", "restricted-egress", "disconnected"},
		CustomerInputs:        []string{"three reachable Linux nodes", "product endpoint and DNS ownership", "credential references", "backup destination", "administrator identity"},
		ManagedServices:       []string{"RKE2 HA", "PostgreSQL HA", "Forgejo", "zot", "S3-compatible evidence/backup storage", "Keycloak", "4SO control plane"},
		Sizing:                ApplianceSizing{Authority: "APPLIANCE_SIZING_AUTHORITY_V1", Status: "SOURCE_ENFORCED_PHYSICAL_TUNING_PENDING", Scope: "per-management-node", MinimumVCPU: 8, MinimumMemoryGiB: 16, MinimumDiskGiB: 160, MinimumFreeDiskGiB: 120, RecommendedVCPU: 12, RecommendedMemoryGiB: 32, RecommendedDiskGiB: 300},
	},
	{
		ID: "integrated-enterprise", DisplayName: "Enterprise — Existing Services",
		Description: "Installs the product on a supported management cluster and can connect to approved customer-managed Git, registry, database, identity and object storage services.",
		Production:  true, HighAvailability: true, MinNodes: 0, RecommendedNodes: 0,
		SupportedConnectivity: []string{"connected", "restricted-egress", "disconnected"},
		CustomerInputs:        []string{"management cluster enrollment reference", "storage class", "product endpoint", "approved external service references"},
		ManagedServices:       []string{"4SO control plane", "installation authority", "GitOps handover", "certification and evidence"},
		Sizing:                ApplianceSizing{Authority: "APPLIANCE_SIZING_AUTHORITY_V1", Status: "EXTERNAL_CLUSTER_CAPACITY_OWNED_BY_ADMISSION", Scope: "existing-management-cluster"},
	},
}

func Profiles() []DeploymentProfile {
	out := make([]DeploymentProfile, len(profiles))
	copy(out, profiles)
	return out
}

// BootstrapProfiles returns only profiles that the appliance bootstrap runtime
// can execute in this release. Planning-only profiles stay available through
// Profiles without appearing as dead-end choices in the executable installer.
func BootstrapProfiles() []DeploymentProfile {
	out := make([]DeploymentProfile, 0, 2)
	for _, profile := range profiles {
		if profile.ID == "evaluation-single-node" || profile.ID == "production-standard-ha" {
			out = append(out, profile)
		}
	}
	return out
}

func Integrations() map[string][]map[string]any {
	return map[string][]map[string]any{
		"git": {
			{"id": "managed-forgejo", "mode": ServiceModeManaged, "default": true, "customerInstallRequired": false},
			{"id": "external-forgejo", "mode": ServiceModeExternal},
			{"id": "external-gitea", "mode": ServiceModeExternal},
			{"id": "external-gitlab", "mode": ServiceModeExternal},
			{"id": "external-github", "mode": ServiceModeExternal},
		},
		"registry": {
			{"id": "managed-zot", "mode": ServiceModeManaged, "default": true, "customerInstallRequired": false},
			{"id": "external-harbor", "mode": ServiceModeExternal},
			{"id": "external-oci", "mode": ServiceModeExternal},
		},
		"database": {
			{"id": "managed-cloudnative-pg", "mode": ServiceModeManaged, "default": true, "customerInstallRequired": false},
			{"id": "external-postgresql", "mode": ServiceModeExternal},
		},
		"identity": {
			{"id": "managed-keycloak", "mode": ServiceModeManaged, "default": true, "customerInstallRequired": false},
			{"id": "external-oidc", "mode": ServiceModeExternal},
		},
		"objectStorage": {
			{"id": "managed-local-evidence", "mode": ServiceModeManaged, "default": true, "production": false},
			{"id": "external-s3-compatible", "mode": ServiceModeExternal},
		},
	}
}

// BootstrapIntegrations exposes only service modes backed by the appliance
// bootstrap executor. External S3 remains available because it is a real
// production backup dependency; the other external adapters are planning-only.
func BootstrapIntegrations() map[string][]map[string]any {
	all := Integrations()
	out := make(map[string][]map[string]any, len(all))
	for kind, entries := range all {
		for _, entry := range entries {
			mode, _ := entry["mode"].(ServiceMode)
			if mode == ServiceModeManaged || kind == "objectStorage" {
				copyEntry := make(map[string]any, len(entry))
				for key, value := range entry {
					copyEntry[key] = value
				}
				out[kind] = append(out[kind], copyEntry)
			}
		}
	}
	return out
}

func findProfile(id string) (DeploymentProfile, bool) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return DeploymentProfile{}, false
}

func normalizeService(spec ServiceSpec, provider string) ServiceSpec {
	if spec.Mode == "" {
		spec.Mode = ServiceModeManaged
	}
	if spec.Mode == ServiceModeManaged && strings.TrimSpace(spec.Provider) == "" {
		spec.Provider = provider
	}
	spec.Provider = strings.TrimSpace(spec.Provider)
	spec.URL = strings.TrimSpace(spec.URL)
	spec.CredentialRef = strings.TrimSpace(spec.CredentialRef)
	spec.Bucket = strings.TrimSpace(spec.Bucket)
	spec.Prefix = strings.Trim(strings.TrimSpace(spec.Prefix), "/")
	spec.Region = strings.TrimSpace(spec.Region)
	return spec
}

func NormalizeRequest(request InstallRequest) InstallRequest {
	request.ProfileID = strings.TrimSpace(request.ProfileID)
	if request.ProfileID == "" {
		request.ProfileID = "production-standard-ha"
	}
	if request.Connectivity == "" {
		request.Connectivity = ConnectivityConnected
	}
	request.Infrastructure.Provider = strings.TrimSpace(request.Infrastructure.Provider)
	for index := range request.Infrastructure.NodeAddresses {
		request.Infrastructure.NodeAddresses[index] = strings.TrimSpace(request.Infrastructure.NodeAddresses[index])
	}
	for index := range request.Infrastructure.ClusterNodeAddresses {
		request.Infrastructure.ClusterNodeAddresses[index] = strings.TrimSpace(request.Infrastructure.ClusterNodeAddresses[index])
	}
	request.Infrastructure.ClusterInterface = strings.TrimSpace(request.Infrastructure.ClusterInterface)
	request.Infrastructure.CredentialRef = strings.TrimSpace(request.Infrastructure.CredentialRef)
	request.Infrastructure.SSHUser = strings.TrimSpace(request.Infrastructure.SSHUser)
	if request.Infrastructure.SSHUser == "" {
		request.Infrastructure.SSHUser = "root"
	}
	request.Infrastructure.StorageClass = strings.TrimSpace(request.Infrastructure.StorageClass)
	for index := range request.Infrastructure.StorageDataDevices {
		request.Infrastructure.StorageDataDevices[index] = strings.TrimSpace(request.Infrastructure.StorageDataDevices[index])
	}
	request.Infrastructure.StorageDeviceMode = strings.TrimSpace(request.Infrastructure.StorageDeviceMode)
	request.Infrastructure.Region = strings.TrimSpace(request.Infrastructure.Region)
	request.Network.PublicEndpoint = strings.TrimSpace(request.Network.PublicEndpoint)
	request.Network.DNSZone = strings.TrimSuffix(strings.TrimSpace(request.Network.DNSZone), ".")
	request.Network.TLSMode = strings.TrimSpace(request.Network.TLSMode)
	request.Network.CertificateRef = strings.TrimSpace(request.Network.CertificateRef)

	request.Services.Git.ServiceSpec = normalizeService(request.Services.Git.ServiceSpec, "forgejo")
	request.Services.Git.Organization = strings.TrimSpace(request.Services.Git.Organization)
	request.Services.Git.Repository = strings.TrimSpace(request.Services.Git.Repository)
	request.Services.Git.WebhookMode = strings.TrimSpace(request.Services.Git.WebhookMode)
	if request.Services.Git.Mode == ServiceModeManaged {
		if request.Services.Git.Organization == "" {
			request.Services.Git.Organization = "platform"
		}
		if request.Services.Git.Repository == "" {
			request.Services.Git.Repository = "desired-state"
		}
	}
	request.Services.Registry = normalizeService(request.Services.Registry, "zot")
	request.Services.Database.ServiceSpec = normalizeService(request.Services.Database.ServiceSpec, "cloudnative-pg")
	request.Services.Database.VolumeSize = strings.TrimSpace(request.Services.Database.VolumeSize)
	if request.Services.Database.VolumeSize == "" {
		request.Services.Database.VolumeSize = "50Gi"
	}
	request.Services.ObjectStorage = normalizeService(request.Services.ObjectStorage, "local-evidence")
	request.Services.Identity.ServiceSpec = normalizeService(request.Services.Identity.ServiceSpec, "keycloak")
	request.Services.Identity.AdminEmail = strings.TrimSpace(request.Services.Identity.AdminEmail)
	request.Services.Identity.IssuerURL = strings.TrimSpace(request.Services.Identity.IssuerURL)
	request.Services.Identity.ClientID = strings.TrimSpace(request.Services.Identity.ClientID)
	request.ExecutionMilestone = strings.TrimSpace(request.ExecutionMilestone)
	request.ExecutionStartStep = strings.TrimSpace(request.ExecutionStartStep)
	return request
}

func validHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func isSecretRef(value string) bool {
	return strings.HasPrefix(value, "secret://") || strings.HasPrefix(value, "vault://") || strings.HasPrefix(value, "external-secret://")
}

func canonicalNodeAddress(value string) string {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String()
	}
	return strings.ToLower(strings.TrimSuffix(value, "."))
}

func hasDuplicateNodeAddresses(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := canonicalNodeAddress(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

func validClusterInterface(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 15 {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func validStorageDevicePath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/dev/") || path.Clean(value) != value {
		return false
	}
	for _, ch := range strings.TrimPrefix(value, "/dev/") {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '/' {
			continue
		}
		return false
	}
	return true
}

func hasDuplicateStorageDevices(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

func validDNSSubdomain(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validPlatformExternalSecretRef(value string) bool {
	const prefix = "external-secret://platform-system/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	name := strings.TrimPrefix(value, prefix)
	return !strings.Contains(name, "/") && validDNSSubdomain(name)
}

func validateExternal(name string, spec ServiceSpec, blockers *[]string) {
	if spec.Mode != ServiceModeExternal {
		return
	}
	if spec.Provider == "" {
		*blockers = append(*blockers, name+" external mode requires provider")
	}
	if !validHTTPS(spec.URL) {
		*blockers = append(*blockers, name+" external mode requires a valid HTTPS URL")
	}
	if !isSecretRef(spec.CredentialRef) {
		*blockers = append(*blockers, name+" external mode requires a secret reference; plaintext credentials are forbidden")
	}
}

func validateServiceProvider(name string, spec ServiceSpec, managedProvider string, externalProviders []string, blockers *[]string) {
	switch spec.Mode {
	case ServiceModeManaged:
		if spec.Provider != managedProvider {
			*blockers = append(*blockers, fmt.Sprintf("%s managed mode requires provider %s", name, managedProvider))
		}
	case ServiceModeExternal:
		if !contains(externalProviders, spec.Provider) {
			*blockers = append(*blockers, name+" external provider is not supported")
		}
	default:
		*blockers = append(*blockers, name+" service mode is not supported")
	}
}

type RuntimeCapabilities struct {
	AuthorityRuntimeAvailable   bool
	ApplianceBootstrapAvailable bool
	HAInstallerAvailable        bool
}

func CreatePlan(request InstallRequest) (InstallationPlan, error) {
	return CreatePlanWithCapabilities(request, RuntimeCapabilities{})
}

func CreateBootstrapPlan(request InstallRequest) (InstallationPlan, error) {
	return CreatePlanWithCapabilities(request, RuntimeCapabilities{ApplianceBootstrapAvailable: true, HAInstallerAvailable: true})
}

func CreatePlanWithCapabilities(request InstallRequest, capabilities RuntimeCapabilities) (InstallationPlan, error) {
	request = NormalizeRequest(request)
	profile, ok := findProfile(request.ProfileID)
	if !ok {
		return InstallationPlan{}, fmt.Errorf("unknown installation profile %q", request.ProfileID)
	}

	warnings := []string{}
	blockers := []string{}
	functionalRKE2Milestone := request.ExecutionMilestone == "rke2-quorum"
	functionalStorageMilestone := request.ExecutionMilestone == "ha-storage"
	functionalMilestone := functionalRKE2Milestone || functionalStorageMilestone
	fullExecution := !functionalMilestone
	if !contains(profile.SupportedConnectivity, string(request.Connectivity)) {
		blockers = append(blockers, fmt.Sprintf("profile %s does not support connectivity mode %s", profile.ID, request.Connectivity))
	}
	switch request.Infrastructure.Provider {
	case "existing-hosts", "existing-kubernetes":
	case "":
		blockers = append(blockers, "infrastructure provider is required")
	default:
		blockers = append(blockers, "infrastructure provider is not supported")
	}
	if (profile.ID == "evaluation-single-node" || profile.ID == "production-standard-ha") && request.Infrastructure.Provider != "existing-hosts" {
		blockers = append(blockers, profile.ID+" requires existing-hosts infrastructure")
	}
	if profile.ID == "integrated-enterprise" && request.Infrastructure.Provider != "existing-kubernetes" {
		blockers = append(blockers, "integrated-enterprise requires existing-kubernetes infrastructure")
	}
	if request.Infrastructure.Provider == "existing-kubernetes" {
		if !request.Infrastructure.ExistingCluster {
			blockers = append(blockers, "existing-kubernetes provider requires existingCluster=true")
		}
		if !isSecretRef(request.Infrastructure.CredentialRef) {
			blockers = append(blockers, "existing Kubernetes enrollment requires a secret reference")
		}
	} else {
		if len(request.Infrastructure.NodeAddresses) < profile.MinNodes {
			blockers = append(blockers, fmt.Sprintf("profile %s requires at least %d reachable nodes", profile.ID, profile.MinNodes))
		}
		if hasDuplicateNodeAddresses(request.Infrastructure.NodeAddresses) {
			blockers = append(blockers, "management node addresses must be unique")
		}
		if !isSecretRef(request.Infrastructure.CredentialRef) {
			blockers = append(blockers, "infrastructure access requires a secret reference; plaintext credentials are forbidden")
		}
	}
	if !validHTTPS(request.Network.PublicEndpoint) {
		blockers = append(blockers, "a valid HTTPS product endpoint is required")
	}
	if capabilities.ApplianceBootstrapAvailable && !validDNSSubdomain(request.Network.DNSZone) {
		blockers = append(blockers, "appliance bootstrap requires a valid lowercase DNS zone")
	}
	switch request.Network.TLSMode {
	case "bootstrap-self-signed", "managed-private-ca", "managed-acme", "external-certificate":
	case "":
		blockers = append(blockers, "TLS mode is required")
	default:
		blockers = append(blockers, "TLS mode is not supported")
	}
	if request.Network.TLSMode == "external-certificate" && !isSecretRef(request.Network.CertificateRef) {
		blockers = append(blockers, "external-certificate TLS mode requires certificateRef")
	}
	if capabilities.ApplianceBootstrapAvailable && (request.Network.TLSMode == "managed-acme" || request.Network.TLSMode == "external-certificate") {
		blockers = append(blockers, request.Network.TLSMode+" TLS mode is not executable by the appliance bootstrap runtime; use managed-private-ca or bootstrap-self-signed as allowed by the selected profile")
	}
	if request.ExecutionMilestone != "" && request.ExecutionMilestone != "rke2-quorum" && request.ExecutionMilestone != "ha-storage" && request.ExecutionMilestone != "full" {
		blockers = append(blockers, "executionMilestone must be one of rke2-quorum, ha-storage or full")
	}
	if request.ExecutionMilestone != "" && request.ExecutionMilestone != "full" && request.ProfileID != "production-standard-ha" {
		blockers = append(blockers, "functional execution milestones are only supported for production-standard-ha")
	}
	if request.ExecutionStartStep != "" {
		if request.ExecutionStartStep != "prepare-storage-devices" {
			blockers = append(blockers, "executionStartStep must be prepare-storage-devices when set")
		}
		if request.ExecutionMilestone != "ha-storage" || request.ProfileID != "production-standard-ha" {
			blockers = append(blockers, "executionStartStep prepare-storage-devices requires production-standard-ha with executionMilestone ha-storage")
		}
	}
	if profile.ID == "production-standard-ha" {
		if len(request.Infrastructure.NodeAddresses) != 3 {
			blockers = append(blockers, "production-standard-ha requires exactly three management nodes")
		}
		clusterAddresses := request.Infrastructure.ClusterNodeAddresses
		if len(clusterAddresses) > 0 {
			if len(clusterAddresses) != len(request.Infrastructure.NodeAddresses) {
				blockers = append(blockers, "clusterNodeAddresses must contain one east-west address for each management node")
			}
			if hasDuplicateNodeAddresses(clusterAddresses) {
				blockers = append(blockers, "clusterNodeAddresses must be unique")
			}
			for _, address := range clusterAddresses {
				if net.ParseIP(strings.Trim(address, "[]")) == nil {
					blockers = append(blockers, "clusterNodeAddresses must be literal IP addresses")
					break
				}
			}
		}
		if !validClusterInterface(request.Infrastructure.ClusterInterface) {
			blockers = append(blockers, "clusterInterface must be a valid Linux interface name")
		}
		if request.Infrastructure.ClusterInterface != "" && len(clusterAddresses) == 0 {
			blockers = append(blockers, "clusterInterface requires explicit clusterNodeAddresses; installer never invents or assigns east-west IP addresses")
		}
		if len(clusterAddresses) == 0 {
			warnings = append(warnings, "HA east-west traffic will use nodeAddresses; set clusterNodeAddresses when SSH/public access and cluster traffic use different NICs")
		}
		if !functionalRKE2Milestone {
			if request.Infrastructure.StorageClass == "" {
				blockers = append(blockers, "production-standard-ha requires a replicated storageClass")
			}
			if len(request.Infrastructure.StorageDataDevices) == 0 {
				blockers = append(blockers, "production-standard-ha requires at least one explicit storageDataDevices entry; root-disk Longhorn scheduling is forbidden")
			}
			if request.Infrastructure.StorageDeviceMode != "format-empty" {
				blockers = append(blockers, "production-standard-ha requires storageDeviceMode format-empty for dedicated Longhorn data devices")
			}
			if hasDuplicateStorageDevices(request.Infrastructure.StorageDataDevices) {
				blockers = append(blockers, "storageDataDevices must be unique")
			}
			for _, device := range request.Infrastructure.StorageDataDevices {
				if !validStorageDevicePath(device) {
					blockers = append(blockers, "storageDataDevices must contain canonical Linux /dev paths")
					break
				}
				if strings.HasPrefix(device, "/dev/sd") || strings.HasPrefix(device, "/dev/vd") || strings.HasPrefix(device, "/dev/xvd") {
					warnings = append(warnings, "kernel storage device names can reorder across hardware changes; /dev/disk/by-id paths are preferred when available")
				}
			}
			if request.Infrastructure.StorageClass != "" && !validDNSSubdomain(request.Infrastructure.StorageClass) {
				blockers = append(blockers, "production-standard-ha storageClass must be a valid lowercase DNS subdomain")
			}
		}
		if fullExecution && (request.Services.ObjectStorage.Mode != ServiceModeExternal || request.Services.ObjectStorage.Bucket == "") {
			blockers = append(blockers, "production-standard-ha requires external S3-compatible object storage with bucket")
		}
	}
	if request.Services.Database.VolumeSize != "" {
		validVolumeSize := regexp.MustCompile(`^[1-9][0-9]*(?:Mi|Gi|Ti)package installation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

var profiles = []DeploymentProfile{
	{
		ID: "evaluation-single-node", DisplayName: "Evaluation — Single Node",
		Description: "One-node appliance for evaluation and demonstrations. It is never presented as HA or production certified.",
		Production:  false, HighAvailability: false, MinNodes: 1, RecommendedNodes: 1,
		SupportedConnectivity: []string{"connected", "restricted-egress", "disconnected"},
		CustomerInputs:        []string{"one reachable Linux node", "product endpoint", "administrator email"},
		ManagedServices:       []string{"RKE2", "PostgreSQL", "Forgejo", "zot", "local evidence storage", "identity", "4SO control plane"},
		Sizing:                ApplianceSizing{Authority: "APPLIANCE_SIZING_AUTHORITY_V1", Status: "SOURCE_ENFORCED_PHYSICAL_TUNING_PENDING", Scope: "single-node-appliance", MinimumVCPU: 4, MinimumMemoryGiB: 8, MinimumDiskGiB: 80, MinimumFreeDiskGiB: 60, RecommendedVCPU: 8, RecommendedMemoryGiB: 16, RecommendedDiskGiB: 150},
	},
	{
		ID: "production-standard-ha", DisplayName: "Production — Standard HA", Default: true,
		Description: "The default three-node appliance. Required platform services are installed and lifecycle-managed by the product.",
		Production:  true, HighAvailability: true, MinNodes: 3, RecommendedNodes: 3,
		SupportedConnectivity: []string{"connected", "restricted-egress", "disconnected"},
		CustomerInputs:        []string{"three reachable Linux nodes", "product endpoint and DNS ownership", "credential references", "backup destination", "administrator identity"},
		ManagedServices:       []string{"RKE2 HA", "PostgreSQL HA", "Forgejo", "zot", "S3-compatible evidence/backup storage", "Keycloak", "4SO control plane"},
		Sizing:                ApplianceSizing{Authority: "APPLIANCE_SIZING_AUTHORITY_V1", Status: "SOURCE_ENFORCED_PHYSICAL_TUNING_PENDING", Scope: "per-management-node", MinimumVCPU: 8, MinimumMemoryGiB: 16, MinimumDiskGiB: 160, MinimumFreeDiskGiB: 120, RecommendedVCPU: 12, RecommendedMemoryGiB: 32, RecommendedDiskGiB: 300},
	},
	{
		ID: "integrated-enterprise", DisplayName: "Enterprise — Existing Services",
		Description: "Installs the product on a supported management cluster and can connect to approved customer-managed Git, registry, database, identity and object storage services.",
		Production:  true, HighAvailability: true, MinNodes: 0, RecommendedNodes: 0,
		SupportedConnectivity: []string{"connected", "restricted-egress", "disconnected"},
		CustomerInputs:        []string{"management cluster enrollment reference", "storage class", "product endpoint", "approved external service references"},
		ManagedServices:       []string{"4SO control plane", "installation authority", "GitOps handover", "certification and evidence"},
		Sizing:                ApplianceSizing{Authority: "APPLIANCE_SIZING_AUTHORITY_V1", Status: "EXTERNAL_CLUSTER_CAPACITY_OWNED_BY_ADMISSION", Scope: "existing-management-cluster"},
	},
}

func Profiles() []DeploymentProfile {
	out := make([]DeploymentProfile, len(profiles))
	copy(out, profiles)
	return out
}

// BootstrapProfiles returns only profiles that the appliance bootstrap runtime
// can execute in this release. Planning-only profiles stay available through
// Profiles without appearing as dead-end choices in the executable installer.
func BootstrapProfiles() []DeploymentProfile {
	out := make([]DeploymentProfile, 0, 2)
	for _, profile := range profiles {
		if profile.ID == "evaluation-single-node" || profile.ID == "production-standard-ha" {
			out = append(out, profile)
		}
	}
	return out
}

func Integrations() map[string][]map[string]any {
	return map[string][]map[string]any{
		"git": {
			{"id": "managed-forgejo", "mode": ServiceModeManaged, "default": true, "customerInstallRequired": false},
			{"id": "external-forgejo", "mode": ServiceModeExternal},
			{"id": "external-gitea", "mode": ServiceModeExternal},
			{"id": "external-gitlab", "mode": ServiceModeExternal},
			{"id": "external-github", "mode": ServiceModeExternal},
		},
		"registry": {
			{"id": "managed-zot", "mode": ServiceModeManaged, "default": true, "customerInstallRequired": false},
			{"id": "external-harbor", "mode": ServiceModeExternal},
			{"id": "external-oci", "mode": ServiceModeExternal},
		},
		"database": {
			{"id": "managed-cloudnative-pg", "mode": ServiceModeManaged, "default": true, "customerInstallRequired": false},
			{"id": "external-postgresql", "mode": ServiceModeExternal},
		},
		"identity": {
			{"id": "managed-keycloak", "mode": ServiceModeManaged, "default": true, "customerInstallRequired": false},
			{"id": "external-oidc", "mode": ServiceModeExternal},
		},
		"objectStorage": {
			{"id": "managed-local-evidence", "mode": ServiceModeManaged, "default": true, "production": false},
			{"id": "external-s3-compatible", "mode": ServiceModeExternal},
		},
	}
}

// BootstrapIntegrations exposes only service modes backed by the appliance
// bootstrap executor. External S3 remains available because it is a real
// production backup dependency; the other external adapters are planning-only.
func BootstrapIntegrations() map[string][]map[string]any {
	all := Integrations()
	out := make(map[string][]map[string]any, len(all))
	for kind, entries := range all {
		for _, entry := range entries {
			mode, _ := entry["mode"].(ServiceMode)
			if mode == ServiceModeManaged || kind == "objectStorage" {
				copyEntry := make(map[string]any, len(entry))
				for key, value := range entry {
					copyEntry[key] = value
				}
				out[kind] = append(out[kind], copyEntry)
			}
		}
	}
	return out
}

func findProfile(id string) (DeploymentProfile, bool) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return DeploymentProfile{}, false
}

func normalizeService(spec ServiceSpec, provider string) ServiceSpec {
	if spec.Mode == "" {
		spec.Mode = ServiceModeManaged
	}
	if spec.Mode == ServiceModeManaged && strings.TrimSpace(spec.Provider) == "" {
		spec.Provider = provider
	}
	spec.Provider = strings.TrimSpace(spec.Provider)
	spec.URL = strings.TrimSpace(spec.URL)
	spec.CredentialRef = strings.TrimSpace(spec.CredentialRef)
	spec.Bucket = strings.TrimSpace(spec.Bucket)
	spec.Prefix = strings.Trim(strings.TrimSpace(spec.Prefix), "/")
	spec.Region = strings.TrimSpace(spec.Region)
	return spec
}

func NormalizeRequest(request InstallRequest) InstallRequest {
	request.ProfileID = strings.TrimSpace(request.ProfileID)
	if request.ProfileID == "" {
		request.ProfileID = "production-standard-ha"
	}
	if request.Connectivity == "" {
		request.Connectivity = ConnectivityConnected
	}
	request.Infrastructure.Provider = strings.TrimSpace(request.Infrastructure.Provider)
	for index := range request.Infrastructure.NodeAddresses {
		request.Infrastructure.NodeAddresses[index] = strings.TrimSpace(request.Infrastructure.NodeAddresses[index])
	}
	for index := range request.Infrastructure.ClusterNodeAddresses {
		request.Infrastructure.ClusterNodeAddresses[index] = strings.TrimSpace(request.Infrastructure.ClusterNodeAddresses[index])
	}
	request.Infrastructure.ClusterInterface = strings.TrimSpace(request.Infrastructure.ClusterInterface)
	request.Infrastructure.CredentialRef = strings.TrimSpace(request.Infrastructure.CredentialRef)
	request.Infrastructure.SSHUser = strings.TrimSpace(request.Infrastructure.SSHUser)
	if request.Infrastructure.SSHUser == "" {
		request.Infrastructure.SSHUser = "root"
	}
	request.Infrastructure.StorageClass = strings.TrimSpace(request.Infrastructure.StorageClass)
	for index := range request.Infrastructure.StorageDataDevices {
		request.Infrastructure.StorageDataDevices[index] = strings.TrimSpace(request.Infrastructure.StorageDataDevices[index])
	}
	request.Infrastructure.StorageDeviceMode = strings.TrimSpace(request.Infrastructure.StorageDeviceMode)
	request.Infrastructure.Region = strings.TrimSpace(request.Infrastructure.Region)
	request.Network.PublicEndpoint = strings.TrimSpace(request.Network.PublicEndpoint)
	request.Network.DNSZone = strings.TrimSuffix(strings.TrimSpace(request.Network.DNSZone), ".")
	request.Network.TLSMode = strings.TrimSpace(request.Network.TLSMode)
	request.Network.CertificateRef = strings.TrimSpace(request.Network.CertificateRef)

	request.Services.Git.ServiceSpec = normalizeService(request.Services.Git.ServiceSpec, "forgejo")
	request.Services.Git.Organization = strings.TrimSpace(request.Services.Git.Organization)
	request.Services.Git.Repository = strings.TrimSpace(request.Services.Git.Repository)
	request.Services.Git.WebhookMode = strings.TrimSpace(request.Services.Git.WebhookMode)
	if request.Services.Git.Mode == ServiceModeManaged {
		if request.Services.Git.Organization == "" {
			request.Services.Git.Organization = "platform"
		}
		if request.Services.Git.Repository == "" {
			request.Services.Git.Repository = "desired-state"
		}
	}
	request.Services.Registry = normalizeService(request.Services.Registry, "zot")
	request.Services.Database.ServiceSpec = normalizeService(request.Services.Database.ServiceSpec, "cloudnative-pg")
	request.Services.Database.VolumeSize = strings.TrimSpace(request.Services.Database.VolumeSize)
	if request.Services.Database.VolumeSize == "" {
		request.Services.Database.VolumeSize = "50Gi"
	}
	request.Services.ObjectStorage = normalizeService(request.Services.ObjectStorage, "local-evidence")
	request.Services.Identity.ServiceSpec = normalizeService(request.Services.Identity.ServiceSpec, "keycloak")
	request.Services.Identity.AdminEmail = strings.TrimSpace(request.Services.Identity.AdminEmail)
	request.Services.Identity.IssuerURL = strings.TrimSpace(request.Services.Identity.IssuerURL)
	request.Services.Identity.ClientID = strings.TrimSpace(request.Services.Identity.ClientID)
	request.ExecutionMilestone = strings.TrimSpace(request.ExecutionMilestone)
	request.ExecutionStartStep = strings.TrimSpace(request.ExecutionStartStep)
	return request
}

func validHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func isSecretRef(value string) bool {
	return strings.HasPrefix(value, "secret://") || strings.HasPrefix(value, "vault://") || strings.HasPrefix(value, "external-secret://")
}

func canonicalNodeAddress(value string) string {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String()
	}
	return strings.ToLower(strings.TrimSuffix(value, "."))
}

func hasDuplicateNodeAddresses(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := canonicalNodeAddress(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

func validClusterInterface(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 15 {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func validStorageDevicePath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/dev/") || path.Clean(value) != value {
		return false
	}
	for _, ch := range strings.TrimPrefix(value, "/dev/") {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '/' {
			continue
		}
		return false
	}
	return true
}

func hasDuplicateStorageDevices(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

func validDNSSubdomain(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validPlatformExternalSecretRef(value string) bool {
	const prefix = "external-secret://platform-system/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	name := strings.TrimPrefix(value, prefix)
	return !strings.Contains(name, "/") && validDNSSubdomain(name)
}

func validateExternal(name string, spec ServiceSpec, blockers *[]string) {
	if spec.Mode != ServiceModeExternal {
		return
	}
	if spec.Provider == "" {
		*blockers = append(*blockers, name+" external mode requires provider")
	}
	if !validHTTPS(spec.URL) {
		*blockers = append(*blockers, name+" external mode requires a valid HTTPS URL")
	}
	if !isSecretRef(spec.CredentialRef) {
		*blockers = append(*blockers, name+" external mode requires a secret reference; plaintext credentials are forbidden")
	}
}

func validateServiceProvider(name string, spec ServiceSpec, managedProvider string, externalProviders []string, blockers *[]string) {
	switch spec.Mode {
	case ServiceModeManaged:
		if spec.Provider != managedProvider {
			*blockers = append(*blockers, fmt.Sprintf("%s managed mode requires provider %s", name, managedProvider))
		}
	case ServiceModeExternal:
		if !contains(externalProviders, spec.Provider) {
			*blockers = append(*blockers, name+" external provider is not supported")
		}
	default:
		*blockers = append(*blockers, name+" service mode is not supported")
	}
}

type RuntimeCapabilities struct {
	AuthorityRuntimeAvailable   bool
	ApplianceBootstrapAvailable bool
	HAInstallerAvailable        bool
}

func CreatePlan(request InstallRequest) (InstallationPlan, error) {
	return CreatePlanWithCapabilities(request, RuntimeCapabilities{})
}

func CreateBootstrapPlan(request InstallRequest) (InstallationPlan, error) {
	return CreatePlanWithCapabilities(request, RuntimeCapabilities{ApplianceBootstrapAvailable: true, HAInstallerAvailable: true})
}

func CreatePlanWithCapabilities(request InstallRequest, capabilities RuntimeCapabilities) (InstallationPlan, error) {
	request = NormalizeRequest(request)
	profile, ok := findProfile(request.ProfileID)
	if !ok {
		return InstallationPlan{}, fmt.Errorf("unknown installation profile %q", request.ProfileID)
	}

	warnings := []string{}
	blockers := []string{}
	functionalRKE2Milestone := request.ExecutionMilestone == "rke2-quorum"
	functionalStorageMilestone := request.ExecutionMilestone == "ha-storage"
	functionalMilestone := functionalRKE2Milestone || functionalStorageMilestone
	fullExecution := !functionalMilestone
	if !contains(profile.SupportedConnectivity, string(request.Connectivity)) {
		blockers = append(blockers, fmt.Sprintf("profile %s does not support connectivity mode %s", profile.ID, request.Connectivity))
	}
	switch request.Infrastructure.Provider {
	case "existing-hosts", "existing-kubernetes":
	case "":
		blockers = append(blockers, "infrastructure provider is required")
	default:
		blockers = append(blockers, "infrastructure provider is not supported")
	}
	if (profile.ID == "evaluation-single-node" || profile.ID == "production-standard-ha") && request.Infrastructure.Provider != "existing-hosts" {
		blockers = append(blockers, profile.ID+" requires existing-hosts infrastructure")
	}
	if profile.ID == "integrated-enterprise" && request.Infrastructure.Provider != "existing-kubernetes" {
		blockers = append(blockers, "integrated-enterprise requires existing-kubernetes infrastructure")
	}
	if request.Infrastructure.Provider == "existing-kubernetes" {
		if !request.Infrastructure.ExistingCluster {
			blockers = append(blockers, "existing-kubernetes provider requires existingCluster=true")
		}
		if !isSecretRef(request.Infrastructure.CredentialRef) {
			blockers = append(blockers, "existing Kubernetes enrollment requires a secret reference")
		}
	} else {
		if len(request.Infrastructure.NodeAddresses) < profile.MinNodes {
			blockers = append(blockers, fmt.Sprintf("profile %s requires at least %d reachable nodes", profile.ID, profile.MinNodes))
		}
		if hasDuplicateNodeAddresses(request.Infrastructure.NodeAddresses) {
			blockers = append(blockers, "management node addresses must be unique")
		}
		if !isSecretRef(request.Infrastructure.CredentialRef) {
			blockers = append(blockers, "infrastructure access requires a secret reference; plaintext credentials are forbidden")
		}
	}
	if !validHTTPS(request.Network.PublicEndpoint) {
		blockers = append(blockers, "a valid HTTPS product endpoint is required")
	}
	if capabilities.ApplianceBootstrapAvailable && !validDNSSubdomain(request.Network.DNSZone) {
		blockers = append(blockers, "appliance bootstrap requires a valid lowercase DNS zone")
	}
	switch request.Network.TLSMode {
	case "bootstrap-self-signed", "managed-private-ca", "managed-acme", "external-certificate":
	case "":
		blockers = append(blockers, "TLS mode is required")
	default:
		blockers = append(blockers, "TLS mode is not supported")
	}
	if request.Network.TLSMode == "external-certificate" && !isSecretRef(request.Network.CertificateRef) {
		blockers = append(blockers, "external-certificate TLS mode requires certificateRef")
	}
	if capabilities.ApplianceBootstrapAvailable && (request.Network.TLSMode == "managed-acme" || request.Network.TLSMode == "external-certificate") {
		blockers = append(blockers, request.Network.TLSMode+" TLS mode is not executable by the appliance bootstrap runtime; use managed-private-ca or bootstrap-self-signed as allowed by the selected profile")
	}
	if request.ExecutionMilestone != "" && request.ExecutionMilestone != "rke2-quorum" && request.ExecutionMilestone != "ha-storage" && request.ExecutionMilestone != "full" {
		blockers = append(blockers, "executionMilestone must be one of rke2-quorum, ha-storage or full")
	}
	if request.ExecutionMilestone != "" && request.ExecutionMilestone != "full" && request.ProfileID != "production-standard-ha" {
		blockers = append(blockers, "functional execution milestones are only supported for production-standard-ha")
	}
	if request.ExecutionStartStep != "" {
		if request.ExecutionStartStep != "prepare-storage-devices" {
			blockers = append(blockers, "executionStartStep must be prepare-storage-devices when set")
		}
		if request.ExecutionMilestone != "ha-storage" || request.ProfileID != "production-standard-ha" {
			blockers = append(blockers, "executionStartStep prepare-storage-devices requires production-standard-ha with executionMilestone ha-storage")
		}
	}
	if profile.ID == "production-standard-ha" {
		if len(request.Infrastructure.NodeAddresses) != 3 {
			blockers = append(blockers, "production-standard-ha requires exactly three management nodes")
		}
		clusterAddresses := request.Infrastructure.ClusterNodeAddresses
		if len(clusterAddresses) > 0 {
			if len(clusterAddresses) != len(request.Infrastructure.NodeAddresses) {
				blockers = append(blockers, "clusterNodeAddresses must contain one east-west address for each management node")
			}
			if hasDuplicateNodeAddresses(clusterAddresses) {
				blockers = append(blockers, "clusterNodeAddresses must be unique")
			}
			for _, address := range clusterAddresses {
				if net.ParseIP(strings.Trim(address, "[]")) == nil {
					blockers = append(blockers, "clusterNodeAddresses must be literal IP addresses")
					break
				}
			}
		}
		if !validClusterInterface(request.Infrastructure.ClusterInterface) {
			blockers = append(blockers, "clusterInterface must be a valid Linux interface name")
		}
		if request.Infrastructure.ClusterInterface != "" && len(clusterAddresses) == 0 {
			blockers = append(blockers, "clusterInterface requires explicit clusterNodeAddresses; installer never invents or assigns east-west IP addresses")
		}
		if len(clusterAddresses) == 0 {
			warnings = append(warnings, "HA east-west traffic will use nodeAddresses; set clusterNodeAddresses when SSH/public access and cluster traffic use different NICs")
		}
		if !functionalRKE2Milestone {
			if request.Infrastructure.StorageClass == "" {
				blockers = append(blockers, "production-standard-ha requires a replicated storageClass")
			}
			if len(request.Infrastructure.StorageDataDevices) == 0 {
				blockers = append(blockers, "production-standard-ha requires at least one explicit storageDataDevices entry; root-disk Longhorn scheduling is forbidden")
			}
			if request.Infrastructure.StorageDeviceMode != "format-empty" {
				blockers = append(blockers, "production-standard-ha requires storageDeviceMode format-empty for dedicated Longhorn data devices")
			}
			if hasDuplicateStorageDevices(request.Infrastructure.StorageDataDevices) {
				blockers = append(blockers, "storageDataDevices must be unique")
			}
			for _, device := range request.Infrastructure.StorageDataDevices {
				if !validStorageDevicePath(device) {
					blockers = append(blockers, "storageDataDevices must contain canonical Linux /dev paths")
					break
				}
				if strings.HasPrefix(device, "/dev/sd") || strings.HasPrefix(device, "/dev/vd") || strings.HasPrefix(device, "/dev/xvd") {
					warnings = append(warnings, "kernel storage device names can reorder across hardware changes; /dev/disk/by-id paths are preferred when available")
				}
			}
			if request.Infrastructure.StorageClass != "" && !validDNSSubdomain(request.Infrastructure.StorageClass) {
				blockers = append(blockers, "production-standard-ha storageClass must be a valid lowercase DNS subdomain")
			}
		}
		if fullExecution && (request.Services.ObjectStorage.Mode != ServiceModeExternal || request.Services.ObjectStorage.Bucket == "") {
			blockers = append(blockers, "production-standard-ha requires external S3-compatible object storage with bucket")
		}
	}
).MatchString(request.Services.Database.VolumeSize)
		if !validVolumeSize {
			blockers = append(blockers, "database volumeSize must be a positive Kubernetes binary quantity using Mi, Gi or Ti")
		}
	}
	if profile.ID == "production-standard-ha" && capabilities.ApplianceBootstrapAvailable {
		if request.Infrastructure.CredentialRef != "secret://installer/ssh-private-key" {
			blockers = append(blockers, "production-standard-ha appliance bootstrap requires credentialRef secret://installer/ssh-private-key")
		}
		if fullExecution && !validPlatformExternalSecretRef(request.Services.ObjectStorage.CredentialRef) {
			blockers = append(blockers, "production-standard-ha appliance bootstrap requires object storage credentialRef external-secret://platform-system/<valid-kubernetes-secret>")
		}
		if request.Network.TLSMode == "bootstrap-self-signed" {
			blockers = append(blockers, "production-standard-ha appliance bootstrap requires managed-private-ca until another production TLS executor is available")
		}
	}
	if profile.ID == "evaluation-single-node" && request.Network.TLSMode != "bootstrap-self-signed" {
		blockers = append(blockers, "evaluation execution currently requires tlsMode bootstrap-self-signed")
	}

	validateExternal("Git", request.Services.Git.ServiceSpec, &blockers)
	validateExternal("registry", request.Services.Registry, &blockers)
	validateExternal("database", request.Services.Database.ServiceSpec, &blockers)
	validateExternal("object storage", request.Services.ObjectStorage, &blockers)
	validateExternal("identity", request.Services.Identity.ServiceSpec, &blockers)
	validateServiceProvider("Git", request.Services.Git.ServiceSpec, "forgejo", []string{"forgejo", "gitea", "gitlab", "github"}, &blockers)
	validateServiceProvider("registry", request.Services.Registry, "zot", []string{"harbor", "oci"}, &blockers)
	validateServiceProvider("database", request.Services.Database.ServiceSpec, "cloudnative-pg", []string{"postgresql"}, &blockers)
	validateServiceProvider("object storage", request.Services.ObjectStorage, "local-evidence", []string{"s3-compatible"}, &blockers)
	validateServiceProvider("identity", request.Services.Identity.ServiceSpec, "keycloak", []string{"oidc"}, &blockers)
	if capabilities.ApplianceBootstrapAvailable {
		for _, service := range []struct {
			name string
			mode ServiceMode
		}{
			{name: "Git", mode: request.Services.Git.Mode},
			{name: "registry", mode: request.Services.Registry.Mode},
			{name: "database", mode: request.Services.Database.Mode},
			{name: "identity", mode: request.Services.Identity.Mode},
		} {
			if service.mode == ServiceModeExternal {
				blockers = append(blockers, service.name+" external mode is not executable by the appliance bootstrap runtime; use managed-internal mode")
			}
		}
	}
	if request.Services.Git.Mode == ServiceModeExternal && (request.Services.Git.Organization == "" || request.Services.Git.Repository == "") {
		blockers = append(blockers, "external Git requires organization and repository")
	}
	if fullExecution && request.Services.Identity.Mode == ServiceModeManaged && request.Services.Identity.AdminEmail == "" {
		blockers = append(blockers, "managed identity requires bootstrap administrator email")
	}
	if request.Services.Identity.Mode == ServiceModeExternal && (request.Services.Identity.IssuerURL == "" || request.Services.Identity.ClientID == "") {
		blockers = append(blockers, "external identity requires issuerUrl and clientId")
	}
	if fullExecution && profile.Production && request.Services.ObjectStorage.Mode == ServiceModeManaged && request.Services.ObjectStorage.Provider == "local-evidence" {
		blockers = append(blockers, "production profiles require a certified durable S3-compatible object storage target")
	}
	if profile.Production && !request.AcceptRisk {
		blockers = append(blockers, "production profile requires explicit risk acceptance after plan review")
	}
	if functionalMilestone {
		warnings = append(warnings, "functional Lab milestone stops before the full production dependency stack and is not Final Physical Certification")
	}
	if request.Connectivity == ConnectivityDisconnected {
		warnings = append(warnings, "disconnected installation uses only the digest-locked local bundle and requires reachable local DNS/NTP")
		if request.Services.Git.Mode == ServiceModeExternal || request.Services.Registry.Mode == ServiceModeExternal || request.Services.Identity.Mode == ServiceModeExternal {
			blockers = append(blockers, "disconnected installation requires managed-internal Git, registry and identity")
		}
	}

	dependencies := []ManagedDependency{
		{Name: "PostgreSQL", Role: "product resource authority", Mode: request.Services.Database.Mode, Provider: request.Services.Database.Provider, Replaceable: true, CustomerInstallRequired: false, LifecycleContract: []string{"install", "upgrade", "health", "backup", "restore", "migrate"}},
		{Name: "Git", Role: "signed desired-state and promotion history", Mode: request.Services.Git.Mode, Provider: request.Services.Git.Provider, Replaceable: true, CustomerInstallRequired: false, LifecycleContract: []string{"install/connect", "upgrade", "health", "backup", "restore", "migrate"}},
		{Name: "OCI registry", Role: "images, charts and OCI artifacts", Mode: request.Services.Registry.Mode, Provider: request.Services.Registry.Provider, Replaceable: true, CustomerInstallRequired: false, LifecycleContract: []string{"install/connect", "upgrade", "health", "backup", "restore", "migrate"}},
		{Name: "Object storage", Role: "evidence, support bundles and backups", Mode: request.Services.ObjectStorage.Mode, Provider: request.Services.ObjectStorage.Provider, Replaceable: true, CustomerInstallRequired: false, LifecycleContract: []string{"install/connect", "health", "backup", "restore", "migrate"}},
		{Name: "Identity", Role: "OIDC/SAML identity service", Mode: request.Services.Identity.Mode, Provider: request.Services.Identity.Provider, Replaceable: true, CustomerInstallRequired: false, LifecycleContract: []string{"bootstrap", "connect", "upgrade", "health", "break-glass", "restore"}},
		{Name: "4SO Platform Factory", Role: "authority, operation and certification control plane", Mode: ServiceModeManaged, Provider: "4so", Replaceable: false, CustomerInstallRequired: false, LifecycleContract: []string{"install", "upgrade", "health", "backup", "restore"}},
	}

	steps := []PlanStep{
		{Order: 10, Stage: "foundation", Key: "preflight", Title: "Validate installer request, sealed bundle, host access, east-west topology, required ports and credentials", Executor: "bootstrap-controller", Risk: "low", Verification: []string{"local and HA peer host admission", "pinned SSH reachability", "east-west cluster addresses are already assigned to the declared interface", "dedicated Longhorn devices are explicit, blank or product-owned, and not the root disk", "required bootstrap ports available"}, Rollback: "no mutation"},
		{Order: 20, Stage: "authority", Key: "authority-runtime-gate", Title: "Verify PostgreSQL authority runtime certification", Executor: "authority-gate", Risk: "critical", DependsOn: []string{"preflight"}, Verification: []string{"migration integration", "transaction atomicity", "lease/fencing", "crash/restart", "backup/restore"}, Rollback: "no installation mutation until gate passes"},
		{Order: 30, Stage: "foundation", Key: "management-kubernetes", Title: "Bootstrap or validate the management Kubernetes cluster", Executor: "rke2-or-existing-cluster-adapter", Risk: "critical", DependsOn: []string{"authority-runtime-gate"}, Verification: []string{"API availability", "quorum", "storage readiness"}, Rollback: "remove only resources created by the operation"},
		{Order: 40, Stage: "foundation", Key: "database", Title: "Install or connect PostgreSQL authority", Executor: "database-adapter", Risk: "critical", DependsOn: []string{"management-kubernetes"}, Verification: []string{"TLS connection", "migration", "backup target", "restore rehearsal"}, Rollback: "restore previous database release and snapshot"},
		{Order: 50, Stage: "bootstrap", Key: "bootstrap-control-plane", Title: "Install bootstrap control plane and resume durable installation state", Executor: "bootstrap-controller", Risk: "critical", DependsOn: []string{"database"}, Verification: []string{"API readiness", "operation state persistence", "audit/outbox continuity"}, Rollback: "restore previous control-plane revision"},
		{Order: 60, Stage: "services", Key: "git", Title: "Install managed Git or connect approved external Git", Executor: "git-adapter", Risk: "high", DependsOn: []string{"bootstrap-control-plane"}, Verification: []string{"repository round trip", "protected branch", "signed commit", "backup/restore"}, Rollback: "restore service snapshot or remove product integration only"},
		{Order: 70, Stage: "services", Key: "registry", Title: "Install managed OCI registry or connect approved external registry", Executor: "registry-adapter", Risk: "high", DependsOn: []string{"bootstrap-control-plane"}, Verification: []string{"push/pull by digest", "signature verification", "artifact retention", "backup/restore"}, Rollback: "restore service snapshot or remove product integration only"},
		{Order: 80, Stage: "services", Key: "identity", Title: "Install managed identity or connect customer identity", Executor: "identity-adapter", Risk: "high", DependsOn: []string{"bootstrap-control-plane"}, Verification: []string{"login", "RBAC", "break-glass", "certificate rotation"}, Rollback: "restore prior identity configuration"},
		{Order: 90, Stage: "services", Key: "evidence-storage", Title: "Configure evidence and backup storage", Executor: "object-storage-adapter", Risk: "high", DependsOn: []string{"bootstrap-control-plane"}, Verification: []string{"write/read/delete", "retention", "encryption", "restore"}, Rollback: "remove product credentials without deleting customer data"},
		{Order: 100, Stage: "handover", Key: "gitops-handover", Title: "Create signed repositories and transfer desired-state ownership to GitOps", Executor: "gitops-handover-controller", Risk: "critical", DependsOn: []string{"git", "registry", "identity", "evidence-storage"}, Verification: []string{"initial signed commit", "reconciliation equality", "drift baseline", "bootstrap evidence sealed"}, Rollback: "return authority to bootstrap revision"},
		{Order: 110, Stage: "certification", Key: "appliance-certification", Title: "Run appliance health, backup/restore and restart certification", Executor: "certifier", Risk: "medium", DependsOn: []string{"gitops-handover"}, Verification: []string{"service health", "API restart", "database restore", "Git restore", "registry round trip", "sealed evidence"}, Rollback: "installation remains incomplete until certification passes"},
	}
	if request.Infrastructure.Provider == "existing-kubernetes" {
		for i := range steps {
			if steps[i].Key == "management-kubernetes" {
				steps[i].Title = "Validate and admit the existing management Kubernetes cluster"
			}
		}
	}

	customerActions := []string{
		"choose evaluation, standard HA or integrated enterprise profile",
		"provide host addresses or an existing-cluster enrollment reference",
		"for Standard HA, provide explicit dedicated Longhorn data devices that are safe to format when empty",
		"provide product endpoint, DNS ownership and TLS mode",
		"provide only secret references and a backup destination",
		"review and approve the generated risk plan",
	}

	canonical, _ := json.Marshal(request)
	sum := sha256.Sum256(canonical)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	authorityGate := "blocked-pending-postgresql-runtime"
	if profile.ID == "evaluation-single-node" && capabilities.ApplianceBootstrapAvailable {
		authorityGate = "bootstrap-local-journal"
	} else if profile.ID == "production-standard-ha" && capabilities.ApplianceBootstrapAvailable && capabilities.HAInstallerAvailable {
		authorityGate = "bootstrap-ha-local-journal"
	} else if capabilities.AuthorityRuntimeAvailable {
		authorityGate = "postgresql-authority-ready"
	} else {
		blockers = append(blockers, "PostgreSQL authority runtime is not available")
	}
	if !capabilities.ApplianceBootstrapAvailable {
		blockers = append(blockers, "appliance bootstrap executor is not available")
	}
	if profile.ID == "production-standard-ha" && !capabilities.HAInstallerAvailable {
		blockers = append(blockers, "three-node HA bootstrap executor is not available")
	}
	if profile.ID == "integrated-enterprise" && capabilities.ApplianceBootstrapAvailable && !capabilities.AuthorityRuntimeAvailable {
		blockers = append(blockers, "integrated-enterprise requires an already available durable authority")
	}
	if strings.HasPrefix(authorityGate, "bootstrap-") {
		for i := range steps {
			switch steps[i].Key {
			case "authority-runtime-gate":
				steps[i].Key = "bootstrap-authority-gate"
				steps[i].Title = "Verify durable bootstrap journal and interrupted-operation recovery authority"
				steps[i].Executor = authorityGate
				steps[i].Verification = []string{"atomic journal persistence", "spec and bundle digest binding", "mutation exclusivity", "explicit interrupted-step recovery policy"}
				steps[i].Rollback = "no host mutation until bootstrap journal authority passes"
			case "management-kubernetes":
				steps[i].DependsOn = []string{"bootstrap-authority-gate"}
			}
		}
	}
	blockers = uniqueSorted(blockers)
	warnings = uniqueSorted(warnings)
	executable := len(blockers) == 0
	status := "planning-only"
	if executable {
		status = "execution-ready"
	}
	return InstallationPlan{
		ID: "install-plan-" + hex.EncodeToString(sum[:])[:20], SpecDigest: digest, CreatedAt: time.Unix(0, 0).UTC(),
		Profile: profile, EffectiveRequest: request, EffectiveServices: request.Services, Dependencies: dependencies, Steps: steps,
		CustomerActions: customerActions, Warnings: warnings, Blockers: blockers,
		AuthorityGate: authorityGate, Status: status, Executable: executable,
	}, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func uniqueSorted(values []string) []string {
	m := map[string]struct{}{}
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			m[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
