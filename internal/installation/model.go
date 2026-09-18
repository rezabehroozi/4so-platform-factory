package installation

import "time"

type ConnectivityMode string

const (
	ConnectivityConnected        ConnectivityMode = "connected"
	ConnectivityRestrictedEgress ConnectivityMode = "restricted-egress"
	ConnectivityDisconnected     ConnectivityMode = "disconnected"
)

type ServiceMode string

const (
	ServiceModeManaged  ServiceMode = "managed-internal"
	ServiceModeExternal ServiceMode = "external"
)

type ApplianceSizing struct {
	Authority            string `json:"authority"`
	Status               string `json:"status"`
	Scope                string `json:"scope"`
	MinimumVCPU          int    `json:"minimumVcpu"`
	MinimumMemoryGiB     int    `json:"minimumMemoryGiB"`
	MinimumDiskGiB       int    `json:"minimumDiskGiB"`
	MinimumFreeDiskGiB   int    `json:"minimumFreeDiskGiB"`
	RecommendedVCPU      int    `json:"recommendedVcpu"`
	RecommendedMemoryGiB int    `json:"recommendedMemoryGiB"`
	RecommendedDiskGiB   int    `json:"recommendedDiskGiB"`
}

type DeploymentProfile struct {
	ID                    string          `json:"id"`
	DisplayName           string          `json:"displayName"`
	Description           string          `json:"description"`
	Default               bool            `json:"default"`
	Production            bool            `json:"production"`
	HighAvailability      bool            `json:"highAvailability"`
	MinNodes              int             `json:"minNodes"`
	RecommendedNodes      int             `json:"recommendedNodes"`
	SupportedConnectivity []string        `json:"supportedConnectivity"`
	CustomerInputs        []string        `json:"customerInputs"`
	ManagedServices       []string        `json:"managedServices"`
	Sizing                ApplianceSizing `json:"sizing"`
}

type ServiceSpec struct {
	Mode          ServiceMode `json:"mode"`
	Provider      string      `json:"provider,omitempty"`
	URL           string      `json:"url,omitempty"`
	CredentialRef string      `json:"credentialRef,omitempty"`
	Bucket        string      `json:"bucket,omitempty"`
	Prefix        string      `json:"prefix,omitempty"`
	Region        string      `json:"region,omitempty"`
}

type GitSpec struct {
	ServiceSpec
	Organization string `json:"organization,omitempty"`
	Repository   string `json:"repository,omitempty"`
	WebhookMode  string `json:"webhookMode,omitempty"`
}

type IdentitySpec struct {
	ServiceSpec
	IssuerURL  string `json:"issuerUrl,omitempty"`
	ClientID   string `json:"clientId,omitempty"`
	AdminEmail string `json:"adminEmail,omitempty"`
}

type InfrastructureSpec struct {
	Provider             string   `json:"provider"`
	ExistingCluster      bool     `json:"existingCluster"`
	NodeAddresses        []string `json:"nodeAddresses,omitempty"`
	ClusterNodeAddresses []string `json:"clusterNodeAddresses,omitempty"`
	ClusterInterface     string   `json:"clusterInterface,omitempty"`
	CredentialRef        string   `json:"credentialRef,omitempty"`
	SSHUser              string   `json:"sshUser,omitempty"`
	StorageClass         string   `json:"storageClass,omitempty"`
	StorageDataDevices   []string `json:"storageDataDevices,omitempty"`
	StorageDeviceMode    string   `json:"storageDeviceMode,omitempty"`
	Region               string   `json:"region,omitempty"`
}

type NetworkSpec struct {
	PublicEndpoint string `json:"publicEndpoint"`
	DNSZone        string `json:"dnsZone,omitempty"`
	TLSMode        string `json:"tlsMode"`
	CertificateRef string `json:"certificateRef,omitempty"`
}

type ServicesSpec struct {
	Git           GitSpec      `json:"git"`
	Registry      ServiceSpec  `json:"registry"`
	Database      ServiceSpec  `json:"database"`
	ObjectStorage ServiceSpec  `json:"objectStorage"`
	Identity      IdentitySpec `json:"identity"`
}

type InstallRequest struct {
	ProfileID          string             `json:"profileId"`
	Connectivity       ConnectivityMode   `json:"connectivity"`
	Infrastructure     InfrastructureSpec `json:"infrastructure"`
	Network            NetworkSpec        `json:"network"`
	Services           ServicesSpec       `json:"services"`
	ExecutionMilestone string             `json:"executionMilestone,omitempty"`
	ExecutionStartStep string             `json:"executionStartStep,omitempty"`
	AcceptRisk         bool               `json:"acceptRisk"`
}

type ManagedDependency struct {
	Name                    string      `json:"name"`
	Role                    string      `json:"role"`
	Mode                    ServiceMode `json:"mode"`
	Provider                string      `json:"provider"`
	Replaceable             bool        `json:"replaceable"`
	CustomerInstallRequired bool        `json:"customerInstallRequired"`
	LifecycleContract       []string    `json:"lifecycleContract"`
}

type PlanStep struct {
	Order        int      `json:"order"`
	Stage        string   `json:"stage"`
	Key          string   `json:"key"`
	Title        string   `json:"title"`
	Executor     string   `json:"executor"`
	Risk         string   `json:"risk"`
	DependsOn    []string `json:"dependsOn,omitempty"`
	Verification []string `json:"verification"`
	Rollback     string   `json:"rollback"`
}

type InstallationPlan struct {
	ID                string              `json:"id"`
	SpecDigest        string              `json:"specDigest"`
	CreatedAt         time.Time           `json:"createdAt"`
	Profile           DeploymentProfile   `json:"profile"`
	EffectiveRequest  InstallRequest      `json:"effectiveRequest"`
	EffectiveServices ServicesSpec        `json:"effectiveServices"`
	Dependencies      []ManagedDependency `json:"dependencies"`
	Steps             []PlanStep          `json:"steps"`
	CustomerActions   []string            `json:"customerActions"`
	Warnings          []string            `json:"warnings"`
	Blockers          []string            `json:"blockers"`
	AuthorityGate     string              `json:"authorityGate"`
	Status            string              `json:"status"`
	Executable        bool                `json:"executable"`
}
