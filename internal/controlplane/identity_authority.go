package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	OIDCGroupMappingMethod = "OIDC_GROUP_MAPPING_AUTHORITY_V1"
	SecurityAuditMethod    = "IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1"
)

type OIDCGroupMappingState string

const (
	OIDCGroupMappingActive  OIDCGroupMappingState = "ACTIVE"
	OIDCGroupMappingRevoked OIDCGroupMappingState = "REVOKED"
)

type OIDCGroupMapping struct {
	ResourceMeta
	Group            string                     `json:"group"`
	ProductRole      string                     `json:"productRole"`
	OrganizationID   string                     `json:"organizationId,omitempty"`
	OrganizationRole OrganizationMembershipRole `json:"organizationRole,omitempty"`
	ProjectID        string                     `json:"projectId,omitempty"`
	ProjectRole      string                     `json:"projectRole,omitempty"`
	State            OIDCGroupMappingState      `json:"state"`
	CreatedBy        string                     `json:"createdBy"`
	RevokedBy        string                     `json:"revokedBy,omitempty"`
	RevokedAt        *time.Time                 `json:"revokedAt,omitempty"`
}

type OIDCGroupResolution struct {
	Method            string            `json:"method"`
	MappingDigest     string            `json:"mappingDigest"`
	ProductRoles      []string          `json:"productRoles"`
	OrganizationRoles map[string]string `json:"organizationRoles,omitempty"`
	ProjectRoles      map[string]string `json:"projectRoles,omitempty"`
	MappingIDs        []string          `json:"mappingIds,omitempty"`
}

func validProductRole(role string) bool {
	switch strings.TrimSpace(role) {
	case "platform-admin", "platform-operator", "platform-viewer":
		return true
	default:
		return false
	}
}
func validProjectRole(role string) bool {
	switch strings.TrimSpace(role) {
	case "project-admin", "project-operator", "project-viewer", "":
		return true
	default:
		return false
	}
}
func ValidateOIDCGroupMapping(v OIDCGroupMapping) error {
	if strings.TrimSpace(v.Group) == "" || !validProductRole(v.ProductRole) {
		return fmt.Errorf("%w: group and a valid productRole are required", ErrValidation)
	}
	if v.OrganizationID == "" && v.OrganizationRole != "" {
		return fmt.Errorf("%w: organizationRole requires organizationId", ErrValidation)
	}
	if v.OrganizationID != "" && !validMembershipRoleLocal(v.OrganizationRole) {
		return fmt.Errorf("%w: organizationId requires a valid organizationRole", ErrValidation)
	}
	if v.ProjectID == "" && v.ProjectRole != "" {
		return fmt.Errorf("%w: projectRole requires projectId", ErrValidation)
	}
	if v.ProjectID != "" && !validProjectRole(v.ProjectRole) || (v.ProjectID != "" && v.ProjectRole == "") {
		return fmt.Errorf("%w: projectId requires a valid projectRole", ErrValidation)
	}
	return nil
}
func validMembershipRoleLocal(role OrganizationMembershipRole) bool {
	switch role {
	case OrganizationAdmin, OrganizationOperator, OrganizationViewer:
		return true
	default:
		return false
	}
}

func ResolveOIDCGroupMappings(mappings []OIDCGroupMapping, groups []string) OIDCGroupResolution {
	groupSet := map[string]bool{}
	for _, group := range groups {
		if g := strings.TrimSpace(group); g != "" {
			groupSet[g] = true
		}
	}
	matched := make([]OIDCGroupMapping, 0)
	for _, m := range mappings {
		if m.State == OIDCGroupMappingActive && groupSet[strings.TrimSpace(m.Group)] {
			matched = append(matched, m)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].ID < matched[j].ID })
	rolesSet := map[string]bool{}
	orgRoles := map[string]string{}
	projectRoles := map[string]string{}
	ids := make([]string, 0, len(matched))
	level := func(role string) int {
		switch role {
		case "platform-admin", "organization-admin", "project-admin":
			return 3
		case "platform-operator", "organization-operator", "project-operator":
			return 2
		case "platform-viewer", "organization-viewer", "project-viewer":
			return 1
		}
		return 0
	}
	for _, m := range matched {
		rolesSet[m.ProductRole] = true
		ids = append(ids, m.ID)
		if m.OrganizationID != "" && level(string(m.OrganizationRole)) > level(orgRoles[m.OrganizationID]) {
			orgRoles[m.OrganizationID] = string(m.OrganizationRole)
		}
		if m.ProjectID != "" && level(m.ProjectRole) > level(projectRoles[m.ProjectID]) {
			projectRoles[m.ProjectID] = m.ProjectRole
		}
	}
	roles := make([]string, 0, len(rolesSet))
	for r := range rolesSet {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	canonical := struct {
		Method  string            `json:"method"`
		IDs     []string          `json:"mappingIds"`
		Roles   []string          `json:"roles"`
		Org     map[string]string `json:"organizationRoles"`
		Project map[string]string `json:"projectRoles"`
	}{OIDCGroupMappingMethod, ids, roles, orgRoles, projectRoles}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return OIDCGroupResolution{Method: OIDCGroupMappingMethod, MappingDigest: "sha256:" + hex.EncodeToString(sum[:]), ProductRoles: roles, OrganizationRoles: orgRoles, ProjectRoles: projectRoles, MappingIDs: ids}
}

type SecurityAuditInput struct {
	Category       string `json:"category"`
	Decision       string `json:"decision"`
	ActorID        string `json:"actorId"`
	Authentication string `json:"authentication,omitempty"`
	Method         string `json:"method,omitempty"`
	Path           string `json:"path,omitempty"`
	StatusCode     int    `json:"statusCode,omitempty"`
	ReasonCode     string `json:"reasonCode,omitempty"`
	RequestID      string `json:"requestId,omitempty"`
	ScopeType      string `json:"scopeType,omitempty"`
	ScopeID        string `json:"scopeId,omitempty"`
	EffectiveRole  string `json:"effectiveRole,omitempty"`
	MappingDigest  string `json:"mappingDigest,omitempty"`
}

type SecurityAuditEvent struct {
	ID            string    `json:"id"`
	Sequence      int64     `json:"sequence"`
	OccurredAt    time.Time `json:"occurredAt"`
	MethodVersion string    `json:"methodVersion"`
	SecurityAuditInput
	PreviousDigest string `json:"previousDigest,omitempty"`
	Digest         string `json:"digest"`
}

func SecurityAuditEventDigest(v SecurityAuditEvent) string {
	v.Digest = ""
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func ValidateSecurityAuditChain(values []SecurityAuditEvent) error {
	var prev string
	for i, v := range values {
		if v.Sequence != int64(i+1) || v.MethodVersion != SecurityAuditMethod || v.PreviousDigest != prev || v.Digest == "" || SecurityAuditEventDigest(v) != v.Digest {
			return fmt.Errorf("%w: security audit chain invalid at sequence %d", ErrValidation, v.Sequence)
		}
		prev = v.Digest
	}
	return nil
}
