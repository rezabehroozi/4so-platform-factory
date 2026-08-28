package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	bp "platform.4so.io/factory/internal/blueprint"
)

const blueprintAuthoringMethod = "BLUEPRINT_VISUAL_API_AUTHORING_PARITY_V1"

type blueprintAuthoringField struct {
	Path        string   `json:"path"`
	UIControlID string   `json:"uiControlId"`
	Mode        string   `json:"mode"`
	Options     []string `json:"options,omitempty"`
}

var blueprintAuthoringFields = []blueprintAuthoringField{
	{"apiVersion", "blueprint-api-version", "fixed", []string{"platform.4so.io/v1alpha1"}},
	{"kind", "blueprint-kind", "fixed", []string{"PlatformBlueprint"}},
	{"metadata.name", "blueprint-name", "editable", nil},
	{"metadata.version", "blueprint-version", "editable", nil},
	{"spec.description", "blueprint-description", "editable", nil},
	{"spec.compatibility.kubernetes.minVersion", "blueprint-k8s-min", "editable", []string{"1.34", "1.35"}},
	{"spec.compatibility.kubernetes.maxVersion", "blueprint-k8s-max", "editable", []string{"1.34", "1.35"}},
	{"spec.compatibility.architectures", "blueprint-architectures", "collection", []string{"amd64", "arm64"}},
	{"spec.compatibility.distributionProfiles", "blueprint-distribution-list", "collection", nil},
	{"spec.delivery.mode", "blueprint-delivery-mode", "editable", []string{"gitops"}},
	{"spec.delivery.repository", "blueprint-repository", "editable", nil},
	{"spec.delivery.revision", "blueprint-revision", "editable", nil},
	{"spec.delivery.revisionType", "blueprint-revision-type", "editable", []string{"commit", "tag", "branch"}},
	{"spec.delivery.ociRegistry", "blueprint-registry", "editable", nil},
	{"spec.components[].name", "blueprint-component-list", "collection", nil},
	{"spec.components[].enabled", "blueprint-component-list", "collection", []string{"true", "false"}},
	{"spec.components[].settings", "blueprint-component-list", "json-object", nil},
	{"spec.tenancy.mode", "blueprint-tenancy-mode", "editable", []string{"namespace"}},
	{"spec.tenancy.plans", "blueprint-tenant-plans", "collection", nil},
	{"spec.tenancy.deletionPolicy", "blueprint-deletion-policy", "editable", []string{"approval-and-backup-required"}},
	{"spec.governance.approvalRequiredFor", "blueprint-approval-risks", "collection", []string{"low", "medium", "high", "critical"}},
	{"spec.governance.enforceDigestImages", "blueprint-enforce-digest-images", "editable", []string{"true", "false"}},
	{"spec.governance.allowPlaintextSecrets", "blueprint-allow-plaintext-secrets", "editable", []string{"true", "false"}},
	{"spec.certification.requiredLevel", "blueprint-certification", "editable", []string{"render", "ephemeral-runtime", "target-runtime", "upgrade", "production"}},
	{"spec.certification.evidenceRetentionDays", "blueprint-evidence-days", "editable", nil},
	{"spec.fieldOwnership[].path", "blueprint-field-ownership", "collection", nil},
	{"spec.fieldOwnership[].policy", "blueprint-field-ownership", "collection", []string{"BLUEPRINT_ONLY", "PROVIDER_ONLY", "ENVIRONMENT_ONLY", "PROVIDER_THEN_ENVIRONMENT"}},
}

func (s *Server) blueprintAuthoringContract(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"method":              blueprintAuthoringMethod,
		"schemaVersion":       1,
		"strictUnknownFields": true,
		"fieldCount":          len(blueprintAuthoringFields),
		"fields":              blueprintAuthoringFields,
		"releaseEnvelope":     []string{"projectId", "catalogReleaseId", "providerOverlayId", "environmentOverlayId", "sourceReleaseId", "upgradeFromIds", "blueprint"},
	})
}

func (s *Server) blueprintAuthoringRoundTrip(w http.ResponseWriter, r *http.Request) {
	blueprint, err := decodeBlueprint(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BLUEPRINT", err.Error())
		return
	}
	raw, err := json.Marshal(blueprint)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "BLUEPRINT_CANONICALIZE_FAILED", err.Error())
		return
	}
	sum := sha256.Sum256(raw)
	validation := bp.Validate(blueprint, s.components)
	writeJSON(w, http.StatusOK, map[string]any{
		"method":        blueprintAuthoringMethod,
		"fieldCount":    len(blueprintAuthoringFields),
		"blueprint":     blueprint,
		"canonicalJson": string(raw),
		"digest":        "sha256:" + hex.EncodeToString(sum[:]),
		"validation":    validation,
	})
}
