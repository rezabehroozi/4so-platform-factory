package resourceexplorer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	ResourceExplorerOwnerContinuationAuthority = "RESOURCE_EXPLORER_OWNER_CONTINUATION_V1"
	ProductOwnerBindingAuthority                = "RESOURCE_EXPLORER_PRODUCT_OWNER_BINDING_V1"
	PersonaTaskJourneyAuthority                 = "PERSONA_TASK_JOURNEY_AUTHORITY_V1"
)

type OwnerFamily string

const (
	OwnerFamilyClusterNode                   OwnerFamily = "cluster-node"
	OwnerFamilyVirtualCluster                OwnerFamily = "virtual-cluster"
	OwnerFamilyApplicationEnvironmentBinding OwnerFamily = "application-environment-binding"
)

type OwnerAction string

const (
	OwnerActionMaintainNode          OwnerAction = "MAINTAIN_NODE"
	OwnerActionSuspendVirtualCluster OwnerAction = "SUSPEND_VIRTUAL_CLUSTER"
	OwnerActionResumeVirtualCluster  OwnerAction = "RESUME_VIRTUAL_CLUSTER"
	OwnerActionDeleteVirtualCluster  OwnerAction = "DELETE_VIRTUAL_CLUSTER"
	OwnerActionPromoteApplication    OwnerAction = "PROMOTE_APPLICATION"
)

type ProductOwnerBinding struct {
	Authority              string      `json:"authority"`
	OrganizationID         string      `json:"organizationId"`
	ProjectID              string      `json:"projectId"`
	ClusterID              string      `json:"clusterId"`
	ResourceIdentityDigest string      `json:"resourceIdentityDigest"`
	ResourceEvidenceDigest string      `json:"resourceEvidenceDigest"`
	Family                 OwnerFamily `json:"family"`
	OwnerID                string      `json:"ownerId"`
	ParentID               string      `json:"parentId,omitempty"`
	Revision               int64       `json:"revision"`
	Digest                 string      `json:"digest"`
}

type OwnerContinuation struct {
	Authority             string            `json:"authority"`
	OwnerBindingDigest    string            `json:"ownerBindingDigest"`
	OwnerFamily           OwnerFamily       `json:"ownerFamily"`
	OwnerID               string            `json:"ownerId"`
	OwnerRevision         int64             `json:"ownerRevision"`
	Action                OwnerAction       `json:"action"`
	Task                  string            `json:"task"`
	Method                string            `json:"method"`
	PathTemplate          string            `json:"pathTemplate"`
	PathParams            map[string]string `json:"pathParams"`
	MutationDelegated     bool              `json:"mutationDelegated"`
	ImpactPreviewRequired bool              `json:"impactPreviewRequired"`
	ApprovalRequired      bool              `json:"approvalRequired"`
	ConfirmationRequired  bool              `json:"confirmationRequired"`
	ConfirmationHeader    string            `json:"confirmationHeader,omitempty"`
	ProgressOperation     bool              `json:"progressOperation"`
	EvidenceRequired      bool              `json:"evidenceRequired"`
	RawKubernetesMutation bool              `json:"rawKubernetesMutation"`
}

func BuildProductOwnerBinding(detail ResourceDetail, family OwnerFamily, ownerID, parentID string, revision int64) (ProductOwnerBinding, error) {
	if err := validateOwnerDetail(detail); err != nil {
		return ProductOwnerBinding{}, err
	}
	ownerID = strings.TrimSpace(ownerID)
	parentID = strings.TrimSpace(parentID)
	if ownerID == "" || revision <= 0 {
		return ProductOwnerBinding{}, errors.New("product owner identity and positive revision are required")
	}
	switch family {
	case OwnerFamilyClusterNode:
		if !strings.EqualFold(detail.Key.Kind, "Node") || detail.Key.Namespace != "" || ownerID != detail.Key.Name || parentID != "" {
			return ProductOwnerBinding{}, errors.New("cluster-node owner must bind the exact cluster-scoped Node identity")
		}
	case OwnerFamilyVirtualCluster:
		if parentID == "" {
			return ProductOwnerBinding{}, errors.New("virtual-cluster owner requires workspace parent identity")
		}
	case OwnerFamilyApplicationEnvironmentBinding:
		if parentID != "" {
			return ProductOwnerBinding{}, errors.New("application environment binding owner does not accept parent identity")
		}
	default:
		return ProductOwnerBinding{}, fmt.Errorf("unsupported product owner family %q", family)
	}
	binding := ProductOwnerBinding{
		Authority: ProductOwnerBindingAuthority,
		OrganizationID: strings.TrimSpace(detail.OrganizationID),
		ProjectID: strings.TrimSpace(detail.ProjectID),
		ClusterID: strings.TrimSpace(detail.ClusterID),
		ResourceIdentityDigest: resourceDetailIdentityDigest(detail),
		ResourceEvidenceDigest: strings.ToLower(strings.TrimSpace(detail.EvidenceDigest)),
		Family: family,
		OwnerID: ownerID,
		ParentID: parentID,
		Revision: revision,
	}
	binding.Digest = productOwnerBindingDigest(binding)
	return binding, nil
}

func ValidateProductOwnerBinding(binding ProductOwnerBinding) error {
	if binding.Authority != ProductOwnerBindingAuthority || strings.TrimSpace(binding.OrganizationID) == "" || strings.TrimSpace(binding.ProjectID) == "" || strings.TrimSpace(binding.ClusterID) == "" || strings.TrimSpace(binding.OwnerID) == "" || binding.Revision <= 0 {
		return errors.New("product owner binding authority/scope/identity is invalid")
	}
	if !validDigest(strings.ToLower(strings.TrimSpace(binding.ResourceIdentityDigest))) || !validDigest(strings.ToLower(strings.TrimSpace(binding.ResourceEvidenceDigest))) || !validDigest(strings.ToLower(strings.TrimSpace(binding.Digest))) {
		return errors.New("product owner binding digests are invalid")
	}
	switch binding.Family {
	case OwnerFamilyClusterNode:
		if binding.ParentID != "" { return errors.New("cluster-node binding must not carry parent identity") }
	case OwnerFamilyVirtualCluster:
		if strings.TrimSpace(binding.ParentID) == "" { return errors.New("virtual-cluster binding requires workspace parent identity") }
	case OwnerFamilyApplicationEnvironmentBinding:
		if binding.ParentID != "" { return errors.New("application environment binding must not carry parent identity") }
	default:
		return errors.New("product owner binding family is unsupported")
	}
	if productOwnerBindingDigest(binding) != strings.ToLower(strings.TrimSpace(binding.Digest)) {
		return errors.New("product owner binding content digest mismatch")
	}
	return nil
}

func BuildOwnerContinuation(detail ResourceDetail, binding ProductOwnerBinding, action OwnerAction) (OwnerContinuation, error) {
	if err := validateOwnerDetail(detail); err != nil {
		return OwnerContinuation{}, err
	}
	if err := ValidateProductOwnerBinding(binding); err != nil {
		return OwnerContinuation{}, err
	}
	if binding.OrganizationID != strings.TrimSpace(detail.OrganizationID) || binding.ProjectID != strings.TrimSpace(detail.ProjectID) || binding.ClusterID != strings.TrimSpace(detail.ClusterID) || binding.ResourceIdentityDigest != resourceDetailIdentityDigest(detail) || binding.ResourceEvidenceDigest != strings.ToLower(strings.TrimSpace(detail.EvidenceDigest)) {
		return OwnerContinuation{}, errors.New("product owner binding does not match exact explorer resource/evidence")
	}
	out := OwnerContinuation{
		Authority: ResourceExplorerOwnerContinuationAuthority,
		OwnerBindingDigest: binding.Digest,
		OwnerFamily: binding.Family,
		OwnerID: binding.OwnerID,
		OwnerRevision: binding.Revision,
		Action: action,
		Method: "POST",
		MutationDelegated: true,
		ImpactPreviewRequired: true,
		ProgressOperation: true,
		EvidenceRequired: true,
		RawKubernetesMutation: false,
		PathParams: map[string]string{},
	}
	switch binding.Family {
	case OwnerFamilyClusterNode:
		if action != OwnerActionMaintainNode {
			return OwnerContinuation{}, errors.New("cluster-node owner only admits typed maintenance continuation")
		}
		out.Task = "Plan node maintenance"
		out.PathTemplate = "/api/v1/clusters/{id}/maintenance-runs"
		out.PathParams["id"] = binding.ClusterID
		out.ApprovalRequired = true
	case OwnerFamilyVirtualCluster:
		out.PathParams["id"] = binding.ParentID
		out.PathParams["virtualClusterId"] = binding.OwnerID
		switch action {
		case OwnerActionSuspendVirtualCluster:
			out.Task = "Suspend virtual cluster"
			out.PathTemplate = "/api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/suspend"
		case OwnerActionResumeVirtualCluster:
			out.Task = "Resume virtual cluster"
			out.PathTemplate = "/api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/resume"
		case OwnerActionDeleteVirtualCluster:
			out.Task = "Delete virtual cluster"
			out.PathTemplate = "/api/v1/workspaces/{id}/virtual-clusters/{virtualClusterId}/delete"
			out.ConfirmationRequired = true
			out.ConfirmationHeader = "X-Confirm-Delete"
		default:
			return OwnerContinuation{}, errors.New("virtual-cluster owner action is not allow-listed")
		}
	case OwnerFamilyApplicationEnvironmentBinding:
		return OwnerContinuation{}, errors.New("application promotion continuation is gated until CP3 verified durable promotion owns the Product API path")
	default:
		return OwnerContinuation{}, errors.New("product owner family has no typed continuation")
	}
	return out, nil
}

func validateOwnerDetail(detail ResourceDetail) error {
	if detail.Authority != BoundedResourceExplorerAuthority || !detail.ReadOnly || len(detail.AllowedVerbs) != 0 || strings.TrimSpace(detail.OrganizationID) == "" || strings.TrimSpace(detail.ProjectID) == "" || strings.TrimSpace(detail.ClusterID) == "" || strings.TrimSpace(detail.Key.APIVersion) == "" || strings.TrimSpace(detail.Key.Kind) == "" || strings.TrimSpace(detail.Key.Name) == "" || !validTruthState(detail.State) || !validDigest(strings.ToLower(strings.TrimSpace(detail.EvidenceDigest))) {
		return errors.New("resource explorer detail is not a valid read-only owner handoff source")
	}
	if (detail.State == TruthFresh || detail.State == TruthStale) && strings.TrimSpace(detail.Key.UID) == "" {
		return errors.New("fresh/stale resource owner handoff requires exact UID")
	}
	return nil
}

func resourceDetailIdentityDigest(detail ResourceDetail) string {
	material := struct {
		OrganizationID string      `json:"organizationId"`
		ProjectID      string      `json:"projectId"`
		ClusterID      string      `json:"clusterId"`
		Key            ResourceKey `json:"key"`
	}{strings.TrimSpace(detail.OrganizationID), strings.TrimSpace(detail.ProjectID), strings.TrimSpace(detail.ClusterID), detail.Key}
	return continuationDigestMaterial(material)
}

func productOwnerBindingDigest(binding ProductOwnerBinding) string {
	copy := binding
	copy.Digest = ""
	return continuationDigestMaterial(copy)
}

func continuationDigestMaterial(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type Persona string

const (
	PersonaOperator         Persona = "operator"
	PersonaPlatformEngineer Persona = "platform-engineer"
	PersonaDeveloper        Persona = "developer"
)

type PersonaTaskJourney struct {
	Authority                 string   `json:"authority"`
	Persona                   Persona  `json:"persona"`
	Tasks                     []string `json:"tasks"`
	TaskLanguageFirst         bool     `json:"taskLanguageFirst"`
	AdvancedEvidenceByDefault bool     `json:"advancedEvidenceByDefault"`
	RawKubernetesMutation     bool     `json:"rawKubernetesMutation"`
}

func PersonaTaskJourneys() []PersonaTaskJourney {
	return []PersonaTaskJourney{
		{Authority: PersonaTaskJourneyAuthority, Persona: PersonaOperator, Tasks: []string{"Investigate resource health", "Open typed owner workflow", "Review impact and approval", "Follow operation and evidence"}, TaskLanguageFirst: true},
		{Authority: PersonaTaskJourneyAuthority, Persona: PersonaPlatformEngineer, Tasks: []string{"Inspect scoped resource state", "Plan platform change", "Open typed owner workflow", "Follow operation progress"}, TaskLanguageFirst: true},
		{Authority: PersonaTaskJourneyAuthority, Persona: PersonaDeveloper, Tasks: []string{"Inspect project workload state", "Open application or workspace workflow", "Follow deployment progress"}, TaskLanguageFirst: true},
	}
}
