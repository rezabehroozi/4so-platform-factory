package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

var (
	errPlatformAdminRequired = errors.New("platform-admin role is required")
	errSeparationOfDuties    = errors.New("the requester cannot approve the same change")
)

func requestPrincipal(r *http.Request) (auth.Principal, bool) {
	return auth.PrincipalFromContext(r.Context())
}

func requestHasRole(r *http.Request, role string) bool {
	if principal, ok := requestPrincipal(r); ok {
		return auth.HasAnyRole(principal, role)
	}
	// Direct Server.Handler tests do not include the product authentication
	// middleware. Keep header fallback only for that isolated internal/test use.
	return strings.TrimSpace(r.Header.Get("X-Actor-Role")) == role
}

func requirePlatformAdmin(r *http.Request) error {
	if !requestHasRole(r, "platform-admin") {
		return errPlatformAdminRequired
	}
	return nil
}

func approvalActor(r *http.Request, requestedBy string) (string, error) {
	actor, err := actorID(r)
	if err != nil {
		return "", err
	}
	principal, authenticated := requestPrincipal(r)
	if authenticated && principal.Subject == "local-development" {
		return actor, nil
	}
	if err = requirePlatformAdmin(r); err != nil {
		return "", err
	}
	if strings.TrimSpace(requestedBy) != "" && strings.TrimSpace(requestedBy) == actor {
		return "", errSeparationOfDuties
	}
	return actor, nil
}

func writeApprovalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errPlatformAdminRequired):
		writeError(w, http.StatusForbidden, "APPROVAL_ROLE_REQUIRED", "approval requires an authenticated platform-admin")
	case errors.Is(err, errSeparationOfDuties):
		writeError(w, http.StatusForbidden, "SEPARATION_OF_DUTIES_REQUIRED", "a different platform-admin must approve this request")
	default:
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", fmt.Sprint(err))
	}
}

type organizationAccessLevel int

const (
	organizationRead organizationAccessLevel = iota + 1
	organizationWrite
	organizationAdminAccess
)

var errOrganizationAccessDenied = errors.New("organization access denied")

func globalPrincipalLevel(principal auth.Principal) organizationAccessLevel {
	if auth.HasAnyRole(principal, "platform-admin") {
		return organizationAdminAccess
	}
	if auth.HasAnyRole(principal, "platform-operator") {
		return organizationWrite
	}
	if auth.HasAnyRole(principal, "platform-viewer") {
		return organizationRead
	}
	return 0
}

func mcpHumanDelegationLevel(principal auth.Principal) organizationAccessLevel {
	switch strings.ToUpper(strings.TrimSpace(principal.DelegationAccessProfile)) {
	case "VIEW":
		return organizationRead
	case "OPERATE":
		return organizationWrite
	case "ADMINISTRATION":
		return organizationAdminAccess
	default:
		return 0
	}
}

func membershipLevel(role controlplane.OrganizationMembershipRole) organizationAccessLevel {
	switch role {
	case controlplane.OrganizationAdmin:
		return organizationAdminAccess
	case controlplane.OrganizationOperator:
		return organizationWrite
	case controlplane.OrganizationViewer:
		return organizationRead
	default:
		return 0
	}
}

func minAccessLevel(a, b organizationAccessLevel) organizationAccessLevel {
	if a < b {
		return a
	}
	return b
}

func accessLevelRole(level organizationAccessLevel, scope string) string {
	prefix := scope
	if prefix == "organization" {
		switch level {
		case organizationAdminAccess:
			return "organization-admin"
		case organizationWrite:
			return "organization-operator"
		case organizationRead:
			return "organization-viewer"
		}
	}
	if prefix == "project" {
		switch level {
		case organizationAdminAccess:
			return "project-admin"
		case organizationWrite:
			return "project-operator"
		case organizationRead:
			return "project-viewer"
		}
	}
	return ""
}
func projectRoleLevel(role string) organizationAccessLevel {
	switch strings.TrimSpace(role) {
	case "project-admin":
		return organizationAdminAccess
	case "project-operator":
		return organizationWrite
	case "project-viewer":
		return organizationRead
	default:
		return 0
	}
}
func (s *Server) recordScopeAuthorization(r *http.Request, decision, reason, scopeType, scopeID, effectiveRole string) error {
	principal, ok := requestPrincipal(r)
	if !ok {
		return nil
	}
	_, err := s.store.AppendSecurityAudit(r.Context(), controlplane.SecurityAuditInput{Category: "SCOPE_AUTHORIZATION", Decision: decision, ActorID: principal.Subject, Authentication: principal.Authentication, Method: r.Method, Path: r.URL.Path, StatusCode: map[bool]int{true: http.StatusOK, false: http.StatusForbidden}[decision == "ALLOW"], ReasonCode: reason, RequestID: r.Header.Get("X-Request-ID"), ScopeType: scopeType, ScopeID: scopeID, EffectiveRole: effectiveRole, MappingDigest: principal.MappingDigest})
	return err
}

func (s *Server) organizationAccess(r *http.Request, organizationID string) (organizationAccessLevel, error) {
	principal, authenticated := requestPrincipal(r)
	if !authenticated {
		// Direct internal Server.Handler tests intentionally omit the authentication middleware.
		return organizationAdminAccess, nil
	}
	global := globalPrincipalLevel(principal)
	if principal.Authentication == "mcp-human" {
		global = minAccessLevel(global, mcpHumanDelegationLevel(principal))
		grantOrg := strings.TrimSpace(principal.OrganizationID)
		if grantOrg != "" && grantOrg != strings.TrimSpace(organizationID) {
			return 0, errOrganizationAccessDenied
		}
		if grantOrg == "" && global == organizationAdminAccess {
			return organizationAdminAccess, nil
		}
	}
	if global == organizationAdminAccess {
		return organizationAdminAccess, nil
	}
	if principal.Authentication == "api-token" {
		if strings.TrimSpace(principal.OrganizationID) != strings.TrimSpace(organizationID) || global == 0 {
			return 0, errOrganizationAccessDenied
		}
		// Service accounts never gain organization-admin; their product role is the ceiling.
		return global, nil
	}
	if mapped := membershipLevel(controlplane.OrganizationMembershipRole(principal.OrganizationRoles[strings.TrimSpace(organizationID)])); mapped > 0 {
		if global == organizationRead {
			return organizationRead, nil
		}
		if global == organizationWrite {
			return mapped, nil
		}
	}
	if global == 0 {
		return 0, errOrganizationAccessDenied
	}
	membership, err := s.store.GetOrganizationMembership(r.Context(), strings.TrimSpace(organizationID), strings.TrimSpace(principal.Subject))
	if err != nil || membership.State != controlplane.OrganizationMembershipActive {
		return 0, errOrganizationAccessDenied
	}
	member := membershipLevel(membership.Role)
	if global == organizationRead {
		if member >= organizationRead {
			return organizationRead, nil
		}
		return 0, errOrganizationAccessDenied
	}
	if global == organizationWrite && member > 0 {
		return member, nil
	}
	return 0, errOrganizationAccessDenied
}

func (s *Server) requireOrganizationAccess(r *http.Request, organizationID string, required organizationAccessLevel) error {
	level, err := s.organizationAccess(r, organizationID)
	denied := err != nil || level < required
	if principal, ok := requestPrincipal(r); ok && (principal.Authentication == "api-token" || principal.Authentication == "mcp-human") && strings.TrimSpace(principal.ProjectID) != "" && required > organizationRead {
		denied = true
	}
	if denied {
		_ = s.recordScopeAuthorization(r, "DENY", "ORGANIZATION_ACCESS_DENIED", "organization", organizationID, accessLevelRole(level, "organization"))
		return errOrganizationAccessDenied
	}
	if auditErr := s.recordScopeAuthorization(r, "ALLOW", "ORGANIZATION_ACCESS_ALLOWED", "organization", organizationID, accessLevelRole(level, "organization")); auditErr != nil {
		return auditErr
	}
	return nil
}

func (s *Server) projectAccess(r *http.Request, projectID string) (controlplane.Project, organizationAccessLevel, error) {
	project, err := s.store.GetProject(r.Context(), strings.TrimSpace(projectID))
	if err != nil {
		return controlplane.Project{}, 0, err
	}
	level := organizationAccessLevel(0)
	var accessErr error
	if principal, ok := requestPrincipal(r); ok && principal.Authentication != "api-token" {
		if direct := projectRoleLevel(principal.ProjectRoles[project.ID]); direct > 0 {
			global := globalPrincipalLevel(principal)
			if principal.Authentication == "mcp-human" {
				global = minAccessLevel(global, mcpHumanDelegationLevel(principal))
			}
			if global == organizationRead {
				level = organizationRead
			} else if global >= organizationWrite {
				level = direct
			}
		}
	}
	if level == 0 {
		level, accessErr = s.organizationAccess(r, project.OrganizationID)
	}
	if principal, ok := requestPrincipal(r); ok && principal.Authentication == "mcp-human" && strings.TrimSpace(principal.OrganizationID) != "" && strings.TrimSpace(principal.OrganizationID) != project.OrganizationID {
		return project, 0, errOrganizationAccessDenied
	}
	if principal, ok := requestPrincipal(r); ok && (principal.Authentication == "api-token" || principal.Authentication == "mcp-human") && strings.TrimSpace(principal.ProjectID) != "" && strings.TrimSpace(principal.ProjectID) != project.ID {
		return project, 0, errOrganizationAccessDenied
	}
	if accessErr != nil || level == 0 {
		return project, level, errOrganizationAccessDenied
	}
	return project, level, nil
}

func (s *Server) requireProjectAccess(r *http.Request, projectID string, required organizationAccessLevel) (controlplane.Project, error) {
	project, level, accessErr := s.projectAccess(r, projectID)
	denied := accessErr != nil || level < required
	if denied {
		_ = s.recordScopeAuthorization(r, "DENY", "PROJECT_ACCESS_DENIED", "project", project.ID, accessLevelRole(level, "project"))
		return controlplane.Project{}, errOrganizationAccessDenied
	}
	if auditErr := s.recordScopeAuthorization(r, "ALLOW", "PROJECT_ACCESS_ALLOWED", "project", project.ID, accessLevelRole(level, "project")); auditErr != nil {
		return controlplane.Project{}, auditErr
	}
	return project, nil
}

type effectiveAccessContextSnapshot struct {
	OrganizationRoles map[string]string
	ProjectRoles      map[string]string
	Memberships       []controlplane.OrganizationMembership
}

func (s *Server) effectiveAccessContext(r *http.Request) (effectiveAccessContextSnapshot, error) {
	result := effectiveAccessContextSnapshot{
		OrganizationRoles: make(map[string]string),
		ProjectRoles:      make(map[string]string),
		Memberships:       []controlplane.OrganizationMembership{},
	}
	principal, authenticated := requestPrincipal(r)
	if !authenticated {
		return result, nil
	}
	global := globalPrincipalLevel(principal)
	if global == 0 || global == organizationAdminAccess {
		// Platform administrators already carry allOrganizations=true in the
		// access-context response. Publishing a duplicate map of every tenant and
		// project adds no authority information and scales payload/query cost with
		// the entire installation.
		return result, nil
	}
	if principal.Authentication == "api-token" {
		organizationID := strings.TrimSpace(principal.OrganizationID)
		projectID := strings.TrimSpace(principal.ProjectID)
		if organizationID != "" {
			if _, err := s.store.GetOrganization(r.Context(), organizationID); err == nil {
				level := global
				if projectID != "" && level > organizationRead {
					level = organizationRead
				}
				result.OrganizationRoles[organizationID] = accessLevelRole(level, "organization")
			} else if !errors.Is(err, controlplane.ErrNotFound) {
				return effectiveAccessContextSnapshot{}, err
			}
		}
		if projectID != "" {
			project, err := s.store.GetProject(r.Context(), projectID)
			if err == nil && project.OrganizationID == organizationID {
				result.ProjectRoles[projectID] = accessLevelRole(global, "project")
			} else if err != nil && !errors.Is(err, controlplane.ErrNotFound) {
				return effectiveAccessContextSnapshot{}, err
			}
		}
		return result, nil
	}

	memberships, err := s.store.ListSubjectOrganizationMemberships(r.Context(), principal.Subject)
	if err != nil {
		return effectiveAccessContextSnapshot{}, err
	}
	result.Memberships = memberships
	organizationLevels := make(map[string]organizationAccessLevel)
	directOrganizationRole := make(map[string]bool)
	for organizationID, role := range principal.OrganizationRoles {
		organizationID = strings.TrimSpace(organizationID)
		mapped := membershipLevel(controlplane.OrganizationMembershipRole(role))
		if organizationID == "" || mapped == 0 {
			continue
		}
		if _, lookupErr := s.store.GetOrganization(r.Context(), organizationID); lookupErr != nil {
			if errors.Is(lookupErr, controlplane.ErrNotFound) {
				continue
			}
			return effectiveAccessContextSnapshot{}, lookupErr
		}
		directOrganizationRole[organizationID] = true
		if global == organizationRead {
			mapped = organizationRead
		}
		organizationLevels[organizationID] = mapped
	}
	for _, membership := range memberships {
		if membership.State != controlplane.OrganizationMembershipActive || directOrganizationRole[membership.OrganizationID] {
			continue
		}
		level := membershipLevel(membership.Role)
		if level == 0 {
			continue
		}
		if global == organizationRead {
			level = organizationRead
		}
		organizationLevels[membership.OrganizationID] = level
	}
	for organizationID, level := range organizationLevels {
		result.OrganizationRoles[organizationID] = accessLevelRole(level, "organization")
	}

	directProjectRole := make(map[string]bool)
	for projectID, role := range principal.ProjectRoles {
		projectID = strings.TrimSpace(projectID)
		direct := projectRoleLevel(role)
		if projectID == "" || direct == 0 {
			continue
		}
		if _, lookupErr := s.store.GetProject(r.Context(), projectID); lookupErr != nil {
			if errors.Is(lookupErr, controlplane.ErrNotFound) {
				continue
			}
			return effectiveAccessContextSnapshot{}, lookupErr
		}
		if global == organizationRead {
			direct = organizationRead
		}
		directProjectRole[projectID] = true
		result.ProjectRoles[projectID] = accessLevelRole(direct, "project")
	}
	for organizationID, inherited := range organizationLevels {
		projects, listErr := s.store.ListProjects(r.Context(), organizationID)
		if listErr != nil {
			return effectiveAccessContextSnapshot{}, listErr
		}
		for _, project := range projects {
			if directProjectRole[project.ID] {
				continue
			}
			result.ProjectRoles[project.ID] = accessLevelRole(inherited, "project")
		}
	}
	return result, nil
}

func (s *Server) accessibleOrganizationSet(r *http.Request) (map[string]bool, bool, error) {
	principal, authenticated := requestPrincipal(r)
	if !authenticated || auth.HasAnyRole(principal, "platform-admin") {
		return nil, true, nil
	}
	if globalPrincipalLevel(principal) == 0 {
		return map[string]bool{}, false, nil
	}
	if principal.Authentication == "api-token" {
		if strings.TrimSpace(principal.OrganizationID) == "" {
			return map[string]bool{}, false, nil
		}
		return map[string]bool{strings.TrimSpace(principal.OrganizationID): true}, false, nil
	}
	memberships, err := s.store.ListSubjectOrganizationMemberships(r.Context(), principal.Subject)
	if err != nil {
		return nil, false, err
	}
	out := map[string]bool{}
	for id, role := range principal.OrganizationRoles {
		if membershipLevel(controlplane.OrganizationMembershipRole(role)) >= organizationRead {
			out[id] = true
		}
	}
	if len(principal.ProjectRoles) > 0 {
		for projectID, role := range principal.ProjectRoles {
			if projectRoleLevel(role) < organizationRead {
				continue
			}
			project, projectErr := s.store.GetProject(r.Context(), projectID)
			if projectErr != nil {
				if errors.Is(projectErr, controlplane.ErrNotFound) {
					continue
				}
				return nil, false, projectErr
			}
			out[project.OrganizationID] = true
		}
	}
	for _, membership := range memberships {
		if membership.State == controlplane.OrganizationMembershipActive && membershipLevel(membership.Role) >= organizationRead {
			out[membership.OrganizationID] = true
		}
	}
	return out, false, nil
}

// resourceOrganizationSet returns organizations for which the principal has
// actual organization-level read authority. This is intentionally narrower
// than accessibleOrganizationSet: a direct project grant may reveal its parent
// organization for hierarchy/navigation without granting visibility into
// organization-wide resources, audit history or summary counters.
func (s *Server) resourceOrganizationSet(r *http.Request) (map[string]bool, bool, error) {
	principal, authenticated := requestPrincipal(r)
	if !authenticated || auth.HasAnyRole(principal, "platform-admin") {
		return nil, true, nil
	}
	if globalPrincipalLevel(principal) == 0 {
		return map[string]bool{}, false, nil
	}
	if principal.Authentication == "api-token" {
		if strings.TrimSpace(principal.ProjectID) != "" {
			return map[string]bool{}, false, nil
		}
		organizationID := strings.TrimSpace(principal.OrganizationID)
		if organizationID == "" {
			return map[string]bool{}, false, nil
		}
		return map[string]bool{organizationID: true}, false, nil
	}
	effective, err := s.effectiveAccessContext(r)
	if err != nil {
		return nil, false, err
	}
	out := make(map[string]bool, len(effective.OrganizationRoles))
	for organizationID := range effective.OrganizationRoles {
		out[organizationID] = true
	}
	return out, false, nil
}

func (s *Server) accessibleProjectSet(r *http.Request) (map[string]bool, bool, error) {
	principal, authenticated := requestPrincipal(r)
	if !authenticated || auth.HasAnyRole(principal, "platform-admin") {
		return nil, true, nil
	}
	if globalPrincipalLevel(principal) == 0 {
		return map[string]bool{}, false, nil
	}
	if principal.Authentication == "api-token" {
		if projectID := strings.TrimSpace(principal.ProjectID); projectID != "" {
			// Project-scoped service credentials are already bound to a single
			// immutable project authority. Do not scan sibling projects merely to
			// rediscover that binding.
			return map[string]bool{projectID: true}, false, nil
		}
		organizationID := strings.TrimSpace(principal.OrganizationID)
		if organizationID == "" {
			return map[string]bool{}, false, nil
		}
		projects, err := s.store.ListProjects(r.Context(), organizationID)
		if err != nil {
			return nil, false, err
		}
		out := make(map[string]bool, len(projects))
		for _, project := range projects {
			out[project.ID] = true
		}
		return out, false, nil
	}

	// Do not derive project authority from accessibleOrganizationSet. That set
	// intentionally includes the parent organization of a direct project role so
	// the user can identify the parent tenant. Expanding that visibility back to
	// every sibling project would turn one direct project grant into organization-
	// wide read access. effectiveAccessContext keeps organization inheritance and
	// direct project grants distinct, so its project-role map is the canonical
	// enumerable project authority for scoped interactive principals.
	effective, err := s.effectiveAccessContext(r)
	if err != nil {
		return nil, false, err
	}
	out := make(map[string]bool, len(effective.ProjectRoles))
	for projectID := range effective.ProjectRoles {
		out[projectID] = true
	}
	return out, false, nil
}
func writeScopeError(w http.ResponseWriter, err error) {
	if errors.Is(err, controlplane.ErrNotFound) {
		writeStoreError(w, err)
		return
	}
	writeError(w, http.StatusForbidden, "ORGANIZATION_ACCESS_DENIED", "the authenticated subject does not have sufficient access to this organization")
}

func isProjectScopedAPIToken(r *http.Request) bool {
	principal, ok := requestPrincipal(r)
	return ok && principal.Authentication == "api-token" && strings.TrimSpace(principal.ProjectID) != ""
}

func filterProjectScoped[T any](items []T, allowed map[string]bool, all bool, projectID func(T) string) []T {
	if all {
		return items
	}
	out := make([]T, 0, len(items))
	for _, item := range items {
		if allowed[projectID(item)] {
			out = append(out, item)
		}
	}
	return out
}

type scopeIndex struct {
	organizations map[string]bool
	projects      map[string]bool
	resources     map[string]bool
	operations    map[string]bool
}

func buildScopeIndex(snapshot controlplane.Snapshot, organizations, projects map[string]bool) scopeIndex {
	index := scopeIndex{organizations: organizations, projects: projects, resources: map[string]bool{}, operations: map[string]bool{}}
	for id := range organizations {
		index.resources[id] = true
	}
	for id := range projects {
		index.resources[id] = true
	}
	for _, v := range snapshot.OrganizationMemberships {
		if organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.OIDCGroupMappings {
		if (v.ProjectID != "" && projects[v.ProjectID]) || (v.ProjectID == "" && v.OrganizationID != "" && organizations[v.OrganizationID]) {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ServiceAccounts {
		if organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.APITokens {
		if organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.BlueprintOverlays {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.Revisions {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.BlueprintReleases {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.CatalogTrustKeys {
		if v.OrganizationID != "" && organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.CatalogRevisions {
		if v.OrganizationID != "" && organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.CatalogReleases {
		if v.OrganizationID != "" && organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.Assignments {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.Operations {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
			index.operations[v.ID] = true
		}
	}
	for _, v := range snapshot.Steps {
		if index.operations[v.OperationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.StepTraces {
		if index.operations[v.OperationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.CompensationSteps {
		if index.operations[v.OperationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.Evidence {
		if index.operations[v.OperationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.NotificationDestinations {
		if organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.NotificationRoutes {
		if (v.ProjectID != "" && projects[v.ProjectID]) || (v.ProjectID == "" && organizations[v.OrganizationID]) {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.NotificationEvents {
		if (v.ProjectID != "" && projects[v.ProjectID]) || (v.ProjectID == "" && organizations[v.OrganizationID]) {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.NotificationDeliveries {
		if index.resources[v.EventID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.NotificationAttempts {
		if index.resources[v.DeliveryID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ClusterImports {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ManagedClusters {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ClusterInventories {
		if index.resources[v.ClusterID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ClusterMaintenanceProfiles {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ClusterMaintenanceWindows {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ClusterMaintenanceRuns {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.AgentCertificates {
		if index.resources[v.ClusterID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.BaselineDeployments {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.RuntimeVerifications {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.RuntimeCertifications {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.RecoveryCheckpoints {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.FleetGroups {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.DriftScans {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.UpgradeCampaigns {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.Entitlements {
		if organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.OEMProfiles {
		if organizations[v.OrganizationID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.Tenants {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ProviderProfiles {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.ProviderClusters {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.MarketplaceRecommendations {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	for _, v := range snapshot.RuntimeClosureCampaigns {
		if projects[v.ProjectID] {
			index.resources[v.ID] = true
		}
	}
	return index
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func auditVisible(event controlplane.AuditEvent, index scopeIndex) bool {
	if index.resources[event.ResourceID] {
		return true
	}
	if organizationID := metadataString(event.Metadata, "organizationId"); organizationID != "" && index.organizations[organizationID] {
		return true
	}
	if projectID := metadataString(event.Metadata, "projectId"); projectID != "" && index.projects[projectID] {
		return true
	}
	return false
}
