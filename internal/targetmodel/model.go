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

type ManagementPlaneStorageDescriptor struct {
	Authority         string   `json:"authority"`
	Provider          string   `json:"provider"`
	Version           string   `json:"version"`
	DataEngine        string   `json:"dataEngine"`
	ReplicaCount      int      `json:"replicaCount"`
	Scope             string   `json:"scope"`
	Status            string   `json:"status"`
	SourceLockID      string   `json:"sourceLockId"`
	HostPrerequisites []string `json:"hostPrerequisites"`
	TargetDefault     bool     `json:"targetDefault"`
}

type SearchProjectionDescriptor struct {
	Authority             string   `json:"authority"`
	Role                  string   `json:"role"`
	DefaultBackend        string   `json:"defaultBackend"`
	OptionalBackends      []string `json:"optionalBackends"`
	Status                string   `json:"status"`
	AuthoritativeStores   []string `json:"authoritativeStores"`
	ProjectionSources     []string `json:"projectionSources"`
	RebuildAuthority      string   `json:"rebuildAuthority"`
	RebuildRequired       bool     `json:"rebuildRequired"`
	ObservabilityBoundary string   `json:"observabilityBoundary"`
	MCPBoundary           string   `json:"mcpBoundary"`
}

// MCPRemoteOAuthDescriptor is the canonical architecture contract for remote
// human-delegated MCP access. It is product architecture, not an assertion that
// OAuth interoperability has already been implemented or certified.
type MCPRemoteOAuthDescriptor struct {
	Authority                   string   `json:"authority"`
	Status                      string   `json:"status"`
	ProtocolVersion             string   `json:"protocolVersion"`
	Transport                   string   `json:"transport"`
	ResourceServer              string   `json:"resourceServer"`
	AuthorizationAuthority      string   `json:"authorizationAuthority"`
	ProtectedResourceMetadata   string   `json:"protectedResourceMetadata"`
	ClientRegistrationPolicy    string   `json:"clientRegistrationPolicy"`
	TokenAudience               string   `json:"tokenAudience"`
	TokenLifetimePolicy         string   `json:"tokenLifetimePolicy"`
	GrantAuthority              string   `json:"grantAuthority"`
	GrantResourceScopes         []string `json:"grantResourceScopes"`
	EffectiveAuthorization      []string `json:"effectiveAuthorization"`
	UserJourney                 []string `json:"userJourney"`
	ToolFamilies                []string `json:"toolFamilies"`
	ExternalInteropTargets      []string `json:"externalInteropTargets"`
	ActionRegistryAuthority     string   `json:"actionRegistryAuthority"`
	EffectiveToolFiltering      string   `json:"effectiveToolFiltering"`
	PendingC7WBlockers          []string `json:"pendingC7WBlockers"`
	ForbiddenDirectAuthorities  []string `json:"forbiddenDirectAuthorities"`
	PasswordOrSecretToModel     bool     `json:"passwordOrSecretToModel"`
	EveryWriteCreatesDurableJob bool     `json:"everyWriteCreatesDurableJob"`
}

func MCPRemoteOAuthModel() MCPRemoteOAuthDescriptor {
	return MCPRemoteOAuthDescriptor{
		Authority:                 "MCP_REMOTE_OAUTH_DELEGATION_ARCHITECTURE_V1",
		Status:                    "HUMAN_OAUTH_DELEGATION_SOURCE_IMPLEMENTED_C7W_REGISTRY_FILTERING_IMPLEMENTED_PARITY_PENDING",
		ProtocolVersion:           "2026-07-28",
		Transport:                 "stateless-streamable-http",
		ResourceServer:            "platform-api:/mcp",
		AuthorizationAuthority:    "self-hosted-keycloak-oidc-oauth",
		ProtectedResourceMetadata: "/.well-known/oauth-protected-resource",
		ClientRegistrationPolicy:  "trusted-client-metadata-or-explicit-admin-registration; dynamic-registration-disabled-by-default",
		TokenAudience:             "platform-mcp",
		TokenLifetimePolicy:       "short-lived-access-token; refresh/offline-access only when tenant policy and client capability allow",
		GrantAuthority:            "MCP_DELEGATION_GRANT_AUTHORITY_V1",
		GrantResourceScopes:       []string{"platform", "organization", "project"},
		EffectiveAuthorization: []string{
			"keycloak-authenticated-human-identity",
			"current-product-rbac-and-membership",
			"active-revocable-mcp-delegation-grant",
			"tool/action policy and resource scope",
			"domain capability, revision, maintenance-window and approval policy",
		},
		UserJourney: []string{
			"sign in with organization account",
			"select organization/project or platform administration context",
			"choose friendly access profile without OAuth scope or tool-name exposure",
			"describe intended change in natural language",
			"inspect product-generated impact preview and confirm",
			"follow durable job, audit and evidence result",
		},
		ToolFamilies: []string{
			"discover/read",
			"plan/preview",
			"request-change",
			"approval-as-separate-authorized-principal",
			"operation-status/evidence",
			"identity/administration-through-product-jobs",
		},
		ExternalInteropTargets:  []string{"chatgpt-custom-mcp", "claude-remote-mcp", "gemini-remote-mcp", "grok-custom-mcp"},
		ActionRegistryAuthority: "MCP_PRODUCT_ACTION_REGISTRY_V1",
		EffectiveToolFiltering:  "MCP_EFFECTIVE_TOOL_FILTERING_V1",
		PendingC7WBlockers: []string{
			"MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING",
		},
		ForbiddenDirectAuthorities: []string{
			"raw-user-password-or-session-cookie",
			"raw-secret-private-key-or-keycloak-admin-token",
			"arbitrary-ssh-shell-kubectl-or-sql",
			"direct-database-search-index-or-git-administration",
			"self-approval-bypass-for-high-impact-operations",
			"release-or-physical-certification-pass-override",
		},
		PasswordOrSecretToModel:     false,
		EveryWriteCreatesDurableJob: true,
	}
}

type Model struct {
	Authority               string                           `json:"authority"`
	Distributions           []VocabularyEntry                `json:"distributions"`
	ProvisioningModes       []VocabularyEntry                `json:"provisioningModes"`
	InfrastructureProviders []VocabularyEntry                `json:"infrastructureProviders"`
	LegacyDistributionMap   map[string]string                `json:"legacyDistributionMap"`
	LegacyAdapterMap        map[string]string                `json:"legacyAdapterMap"`
	ManagementPlane         Target                           `json:"managementPlane"`
	ManagementPlaneStorage  ManagementPlaneStorageDescriptor `json:"managementPlaneStorage"`
	CapabilityResolver      CapabilityResolverDescriptor     `json:"capabilityResolver"`
	ProgramRoadmap          ProgramRoadmap                   `json:"programRoadmap"`
	SearchProjection        SearchProjectionDescriptor       `json:"searchProjection"`
	MCPRemoteOAuth          MCPRemoteOAuthDescriptor         `json:"mcpRemoteOAuth"`
}

func ArchitectureModel() Model {
	return Model{
		Authority: AuthorityMethod,
		Distributions: []VocabularyEntry{
			{ID: DistributionKubernetes, Status: "SUPPORTED", ImportSupported: true, Description: "Upstream-conformant Kubernetes distribution identity. Installer history such as Kubespray is not part of this identity."},
			{ID: DistributionRKE2, Status: "SUPPORTED", ImportSupported: true, Description: "RKE2 distribution identity. The Factory management appliance is also RKE2 but remains a separate internal boundary."},
			{ID: DistributionOKD, Status: "SOURCE_MANAGED_INSTALL_RUNTIME_CERTIFICATION_PENDING", ImportSupported: true, ManagedInstallSupport: true, Description: "First-class OKD identity for existing-cluster import and source-implemented Compact-3 managed-install orchestration. Connected runtime and Exact-SHA Physical certification remain independently pending."},
			{ID: DistributionOpenShift, Status: "RECOGNIZED_NOT_YET_ADMITTED", Description: "Red Hat OpenShift identity detected from ClusterVersion authority. It is intentionally distinct from OKD and is not admitted by the current OKD target phases."},
		},
		ProvisioningModes: []VocabularyEntry{
			{ID: ProvisioningImportExisting, Status: "SUPPORTED", Description: "Connect an already-running Kubernetes target through the fleet enrollment workflow."},
			{ID: ProvisioningClusterAPI, Status: "SUPPORTED", Description: "Provision through the admitted Cluster API topology adapter; this is a provisioning method, not a distribution or infrastructure provider."},
			{ID: ProvisioningManagedInstall, Status: "SOURCE_SUPPORTED_TARGET_RUNTIME_CERTIFICATION_PENDING", ManagedInstallSupport: true, Description: "Used by the internal RKE2 management-appliance installer and the source-implemented Bare Metal OKD Compact-3 orchestration path. Exact connected target execution remains separately certification-gated."},
		},
		InfrastructureProviders: []VocabularyEntry{
			{ID: InfrastructureExisting, Status: "SUPPORTED_FOR_IMPORT", Description: "Infrastructure is pre-existing and remains outside Factory lifecycle ownership."},
			{ID: InfrastructureUnspecified, Status: "SUPPORTED_FOR_EXTERNAL_ADAPTER", Description: "Infrastructure identity is intentionally unknown because an external provisioning adapter owns that detail."},
			{ID: InfrastructureBareMetal, Status: "SOURCE_MANAGED_INSTALL_RUNTIME_CERTIFICATION_PENDING", ManagedInstallSupport: true, Description: "Product-owned Redfish BootMedia and durable Managed OKD orchestration are source-implemented for Bare Metal. Exact connected target execution and Physical certification remain pending."},
			{ID: InfrastructureVMware, Status: "SOURCE_IMPLEMENTED_RUNTIME_CERTIFICATION_PENDING", Description: "VMware vSphere infrastructure identity is source-admitted through Cluster API topology with HTTPS origin, external-secret references and CAPV template verification; connected vCenter execution and Physical certification remain pending."},
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
		ManagementPlaneStorage: ManagementPlaneStorageDescriptor{
			Authority:         "MANAGEMENT_PLANE_STORAGE_AUTHORITY_V1",
			Provider:          "longhorn",
			Version:           "v1.12.1",
			DataEngine:        "v1",
			ReplicaCount:      3,
			Scope:             "management-plane-rke2-production-ha-only",
			Status:            "SOURCE_LOCKED_RUNTIME_CERTIFICATION_PENDING",
			SourceLockID:      "replicated-storage-install-manifest",
			HostPrerequisites: []string{"iscsiadm", "iscsid"},
			TargetDefault:     false,
		},
		CapabilityResolver: CapabilityResolverModel(),
		ProgramRoadmap:     ProgramRoadmapModel(),
		MCPRemoteOAuth:     MCPRemoteOAuthModel(),
		SearchProjection: SearchProjectionDescriptor{
			Authority:             "SEARCH_PROJECTION_AUTHORITY_V2",
			Role:                  "derived-search-projection-not-source-of-truth",
			DefaultBackend:        "postgresql-bounded",
			OptionalBackends:      []string{"opensearch"},
			Status:                "DECIDED_OPTIONAL_OPENSEARCH_SCALE_PROJECTION",
			AuthoritativeStores:   []string{"postgresql-product-authority", "durable-evidence-object-storage", "metrics-authority"},
			ProjectionSources:     []string{"managed-clusters", "operations", "evidence-metadata", "scoped-audit-events"},
			RebuildAuthority:      "SEARCH_PROJECTION_REBUILD_CONTRACT_V1",
			RebuildRequired:       true,
			ObservabilityBoundary: "OpenSearch does not replace metrics authority and is not a second default log stack; raw logs/traces remain behind observability adapters until an explicit profile chooses a backend",
			MCPBoundary:           "AI clients use 4SO project-scoped search tools; direct unrestricted OpenSearch MCP administration is not product authority",
		},
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

// ManagedInstallSourceSupported reports only source-level product support for a
// managed target path. It deliberately does not imply runtime, integration or
// Physical certification. Production admission remains owned by the roadmap
// and exact-artifact/certification gates.
func ManagedInstallSourceSupported(distributionIdentity, infrastructureProvider string) bool {
	distribution := CanonicalDistribution(distributionIdentity)
	infrastructure := strings.ToLower(strings.TrimSpace(infrastructureProvider))
	return distribution == DistributionOKD && infrastructure == InfrastructureBareMetal
}

func SupportedDistribution(identity string) bool {
	switch CanonicalDistribution(identity) {
	case DistributionKubernetes, DistributionRKE2:
		return true
	default:
		return false
	}
}

func ImportedMutationSupportedDistribution(identity string) bool {
	switch CanonicalDistribution(identity) {
	case DistributionKubernetes, DistributionRKE2, DistributionOKD:
		return true
	default:
		return false
	}
}
