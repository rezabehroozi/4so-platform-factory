package domain

import "time"

type Blueprint struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   BlueprintMetadata `json:"metadata"`
	Spec       BlueprintSpec     `json:"spec"`
}

type BlueprintMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type KubernetesCompatibility struct {
	MinVersion string `json:"minVersion"`
	MaxVersion string `json:"maxVersion"`
}

type Compatibility struct {
	Kubernetes           KubernetesCompatibility `json:"kubernetes"`
	Architectures        []string                `json:"architectures"`
	DistributionProfiles []string                `json:"distributionProfiles"`
}

type Delivery struct {
	Mode         string `json:"mode"`
	Repository   string `json:"repository"`
	Revision     string `json:"revision"`
	RevisionType string `json:"revisionType"`
	OCIRegistry  string `json:"ociRegistry"`
}

type ComponentSelection struct {
	Name     string         `json:"name"`
	Enabled  bool           `json:"enabled"`
	Settings map[string]any `json:"settings,omitempty"`
}

type Tenancy struct {
	Mode           string   `json:"mode"`
	Plans          []string `json:"plans"`
	DeletionPolicy string   `json:"deletionPolicy"`
}

type Governance struct {
	ApprovalRequiredFor   []string `json:"approvalRequiredFor"`
	EnforceDigestImages   bool     `json:"enforceDigestImages"`
	AllowPlaintextSecrets bool     `json:"allowPlaintextSecrets"`
}

type Certification struct {
	RequiredLevel         string `json:"requiredLevel"`
	EvidenceRetentionDays int    `json:"evidenceRetentionDays"`
}

// FieldOwnershipRule defines who may change one exact JSON Pointer in a Blueprint.
// Paths without an explicit rule are BLUEPRINT_ONLY and cannot be changed by overlays.
type FieldOwnershipRule struct {
	Path   string `json:"path"`
	Policy string `json:"policy"`
}

type BlueprintSpec struct {
	Description    string               `json:"description"`
	Compatibility  Compatibility        `json:"compatibility"`
	Delivery       Delivery             `json:"delivery"`
	Components     []ComponentSelection `json:"components"`
	Tenancy        Tenancy              `json:"tenancy"`
	Governance     Governance           `json:"governance"`
	Certification  Certification        `json:"certification"`
	FieldOwnership []FieldOwnershipRule `json:"fieldOwnership,omitempty"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type ValidationResult struct {
	Valid    bool      `json:"valid"`
	Findings []Finding `json:"findings"`
}

type PlanStep struct {
	ID                    string   `json:"id"`
	Component             string   `json:"component"`
	ReleaseConstraint     string   `json:"releaseConstraint"`
	CertificationStatus   string   `json:"certificationStatus"`
	SourceResolved        bool     `json:"sourceResolved"`
	SourceLockDigest      string   `json:"sourceLockDigest,omitempty"`
	CertificationEvidence string   `json:"certificationEvidence,omitempty"`
	Wave                  int      `json:"wave"`
	Risk                  string   `json:"risk"`
	Dependencies          []string `json:"dependencies"`
	Provides              []string `json:"provides"`
	Readiness             []string `json:"readiness"`
	Rollback              string   `json:"rollback"`
	ApprovalRequired      bool     `json:"approvalRequired"`
}

type DeploymentPlan struct {
	ID               string         `json:"id"`
	Blueprint        string         `json:"blueprint"`
	BlueprintVersion string         `json:"blueprintVersion"`
	BlueprintDigest  string         `json:"blueprintDigest"`
	CatalogDigest    string         `json:"catalogDigest"`
	CreatedAt        time.Time      `json:"createdAt"`
	Status           string         `json:"status"`
	Executable       bool           `json:"executable"`
	Blockers         []Finding      `json:"blockers"`
	RiskSummary      map[string]int `json:"riskSummary"`
	Steps            []PlanStep     `json:"steps"`
	EvidenceRequired bool           `json:"evidenceRequired"`
}
