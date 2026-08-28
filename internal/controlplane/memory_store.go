package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type MemoryStore struct {
	mu  sync.RWMutex
	now func() time.Time
	id  func(string) string

	organizations                map[string]Organization
	organizationMemberships      map[string]OrganizationMembership
	oidcGroupMappings            map[string]OIDCGroupMapping
	securityAudit                []SecurityAuditEvent
	serviceAccounts              map[string]ServiceAccount
	apiTokens                    map[string]APIToken
	projects                     map[string]Project
	blueprintOverlays            map[string]BlueprintOverlay
	revisions                    map[string]BlueprintRevision
	blueprintReleases            map[string]BlueprintRelease
	catalogTrustKeys             map[string]CatalogTrustKey
	catalogRevisions             map[string]CatalogRevision
	catalogReleases              map[string]CatalogRelease
	assignments                  map[string]Assignment
	operations                   map[string]Operation
	steps                        map[string]OperationStep
	stepTraces                   map[string]OperationStepTrace
	compensationSteps            map[string]OperationCompensationStep
	outbox                       map[string]OutboxEvent
	notificationDestinations     map[string]NotificationDestination
	notificationRoutes           map[string]NotificationRoute
	notificationEvents           map[string]NotificationEvent
	notificationDeliveries       map[string]NotificationDelivery
	notificationAttempts         map[string]NotificationDeliveryAttempt
	notificationHealthLeaseBy    string
	notificationHealthLeaseUntil *time.Time
	audit                        []AuditEvent
	evidence                     map[string]EvidenceMetadata
	evidencePayloads             map[string][]byte
	idempotency                  map[string]string
	clusterImports               map[string]ClusterImport
	managedClusters              map[string]ManagedCluster
	clusterMaintenanceProfiles   map[string]ClusterMaintenanceProfile
	clusterMaintenanceWindows    map[string]ClusterMaintenanceWindow
	clusterMaintenanceRuns       map[string]ClusterMaintenanceRun
	agentCertificates            map[string]AgentCertificate
	clusterInventories           map[string]ClusterInventory
	baselineDeployments          map[string]BaselineDeployment
	runtimeVerifications         map[string]RuntimeVerification
	runtimeCertifications        map[string]RuntimeCertificationRun
	recoveryCheckpoints          map[string]RecoveryCheckpoint
	fleetGroups                  map[string]FleetGroup
	gitCredentials               map[string]GitCredential
	gitProviders                 map[string]GitProvider
	gitPullRequests              map[string]GitPullRequest
	managedGitRevisions          map[string]ManagedGitRevision
	driftScans                   map[string]DriftScan
	upgradeCampaigns             map[string]UpgradeCampaign
	entitlements                 map[string]Entitlement
	oemProfiles                  map[string]OEMProfile
	tenants                      map[string]TenantEnvironment
	providerProfiles             map[string]ProviderProfile
	providerClusters             map[string]ProviderCluster
	aiRuns                       map[string]AIRun
	marketplaceRecommendations   map[string]MarketplaceRecommendation
	runtimeClosureCampaigns      map[string]RuntimeClosureCampaign
}

func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWith(time.Now, randomID)
}

func NewMemoryStoreWith(now func() time.Time, id func(string) string) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	if id == nil {
		id = randomID
	}
	return &MemoryStore{
		now: now, id: id,
		organizations: map[string]Organization{}, organizationMemberships: map[string]OrganizationMembership{}, oidcGroupMappings: map[string]OIDCGroupMapping{}, securityAudit: []SecurityAuditEvent{}, serviceAccounts: map[string]ServiceAccount{}, apiTokens: map[string]APIToken{}, projects: map[string]Project{}, blueprintOverlays: map[string]BlueprintOverlay{},
		revisions: map[string]BlueprintRevision{}, blueprintReleases: map[string]BlueprintRelease{}, catalogTrustKeys: map[string]CatalogTrustKey{}, catalogRevisions: map[string]CatalogRevision{}, catalogReleases: map[string]CatalogRelease{}, assignments: map[string]Assignment{},
		operations: map[string]Operation{}, steps: map[string]OperationStep{}, stepTraces: map[string]OperationStepTrace{}, compensationSteps: map[string]OperationCompensationStep{}, outbox: map[string]OutboxEvent{}, notificationDestinations: map[string]NotificationDestination{}, notificationRoutes: map[string]NotificationRoute{}, notificationEvents: map[string]NotificationEvent{}, notificationDeliveries: map[string]NotificationDelivery{}, notificationAttempts: map[string]NotificationDeliveryAttempt{},
		evidence: map[string]EvidenceMetadata{}, evidencePayloads: map[string][]byte{}, idempotency: map[string]string{},
		clusterImports: map[string]ClusterImport{}, managedClusters: map[string]ManagedCluster{}, clusterMaintenanceProfiles: map[string]ClusterMaintenanceProfile{}, clusterMaintenanceWindows: map[string]ClusterMaintenanceWindow{}, clusterMaintenanceRuns: map[string]ClusterMaintenanceRun{}, agentCertificates: map[string]AgentCertificate{}, clusterInventories: map[string]ClusterInventory{}, baselineDeployments: map[string]BaselineDeployment{}, runtimeVerifications: map[string]RuntimeVerification{}, runtimeCertifications: map[string]RuntimeCertificationRun{}, recoveryCheckpoints: map[string]RecoveryCheckpoint{}, fleetGroups: map[string]FleetGroup{}, gitCredentials: map[string]GitCredential{}, gitProviders: map[string]GitProvider{}, gitPullRequests: map[string]GitPullRequest{}, managedGitRevisions: map[string]ManagedGitRevision{}, driftScans: map[string]DriftScan{}, upgradeCampaigns: map[string]UpgradeCampaign{},
		entitlements: map[string]Entitlement{}, oemProfiles: map[string]OEMProfile{}, tenants: map[string]TenantEnvironment{}, providerProfiles: map[string]ProviderProfile{}, providerClusters: map[string]ProviderCluster{}, aiRuns: map[string]AIRun{}, marketplaceRecommendations: map[string]MarketplaceRecommendation{}, runtimeClosureCampaigns: map[string]RuntimeClosureCampaign{},
	}
}

func randomID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func normalizeName(s string) string       { return strings.ToLower(strings.TrimSpace(s)) }
func nowUTC(f func() time.Time) time.Time { return f().UTC().Truncate(time.Microsecond) }

func (s *MemoryStore) appendAuditLocked(actor, action, resourceType, resourceID string, revision int64, metadata map[string]any) {
	s.audit = append(s.audit, AuditEvent{ID: s.id("aud"), OccurredAt: nowUTC(s.now), ActorID: actor, Action: action, ResourceType: resourceType, ResourceID: resourceID, Revision: revision, Metadata: cloneMap(metadata)})
}

func (s *MemoryStore) appendOutboxLocked(aggregateType, aggregateID, eventType string, payload any) {
	raw, _ := json.Marshal(payload)
	now := nowUTC(s.now)
	e := OutboxEvent{ResourceMeta: ResourceMeta{ID: s.id("evt"), Revision: 1, CreatedAt: now, UpdatedAt: now}, AggregateType: aggregateType, AggregateID: aggregateID, EventType: eventType, Payload: raw, AvailableAt: now}
	s.outbox[e.ID] = e
}

func (s *MemoryStore) CreateOrganization(_ context.Context, org Organization, actor string) (Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if normalizeName(org.Name) == "" || strings.TrimSpace(org.DisplayName) == "" {
		return Organization{}, fmt.Errorf("%w: organization name and displayName are required", ErrValidation)
	}
	for _, existing := range s.organizations {
		if normalizeName(existing.Name) == normalizeName(org.Name) {
			return Organization{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	org.ResourceMeta = ResourceMeta{ID: s.id("org"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	org.Name = normalizeName(org.Name)
	s.organizations[org.ID] = org
	if strings.TrimSpace(actor) != "" {
		membership := OrganizationMembership{
			ResourceMeta:   ResourceMeta{ID: s.id("mem"), Revision: 1, CreatedAt: now, UpdatedAt: now},
			OrganizationID: org.ID, Subject: strings.TrimSpace(actor), Role: OrganizationAdmin, State: OrganizationMembershipActive, GrantedBy: strings.TrimSpace(actor),
		}
		s.organizationMemberships[membership.ID] = membership
		s.appendAuditLocked(actor, "organization_membership.granted", "organizationMembership", membership.ID, membership.Revision, map[string]any{"organizationId": org.ID, "subject": membership.Subject, "role": membership.Role})
		s.appendOutboxLocked("organizationMembership", membership.ID, "organization_membership.granted", membership)
	}
	s.appendAuditLocked(actor, "organization.created", "organization", org.ID, org.Revision, nil)
	s.appendOutboxLocked("organization", org.ID, "organization.created", org)
	return org, nil
}

func (s *MemoryStore) UpdateOrganization(_ context.Context, id string, expected int64, displayName, name, actor string) (Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	org, ok := s.organizations[id]
	if !ok {
		return Organization{}, ErrNotFound
	}
	if org.Revision != expected {
		return Organization{}, ErrConflict
	}
	if name != "" {
		nn := normalizeName(name)
		if nn == "" {
			return Organization{}, fmt.Errorf("%w: name is empty", ErrValidation)
		}
		for oid, o := range s.organizations {
			if oid != id && normalizeName(o.Name) == nn {
				return Organization{}, ErrDuplicateName
			}
		}
		org.Name = nn
	}
	if displayName != "" {
		org.DisplayName = strings.TrimSpace(displayName)
	}
	org.Revision++
	org.UpdatedAt = nowUTC(s.now)
	s.organizations[id] = org
	s.appendAuditLocked(actor, "organization.updated", "organization", id, org.Revision, nil)
	s.appendOutboxLocked("organization", id, "organization.updated", org)
	return org, nil
}
func (s *MemoryStore) GetOrganization(_ context.Context, id string) (Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.organizations[id]
	if !ok {
		return Organization{}, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) ListOrganizations(_ context.Context) ([]Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Organization, 0, len(s.organizations))
	for _, v := range s.organizations {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *MemoryStore) CreateProject(_ context.Context, p Project, actor string) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.organizations[p.OrganizationID]; !ok {
		return Project{}, ErrNotFound
	}
	if normalizeName(p.Name) == "" || strings.TrimSpace(p.DisplayName) == "" {
		return Project{}, fmt.Errorf("%w: project name and displayName are required", ErrValidation)
	}
	for _, x := range s.projects {
		if x.OrganizationID == p.OrganizationID && normalizeName(x.Name) == normalizeName(p.Name) {
			return Project{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	p.ResourceMeta = ResourceMeta{ID: s.id("prj"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	p.Name = normalizeName(p.Name)
	s.projects[p.ID] = p
	s.appendAuditLocked(actor, "project.created", "project", p.ID, p.Revision, map[string]any{"organizationId": p.OrganizationID})
	s.appendOutboxLocked("project", p.ID, "project.created", p)
	return p, nil
}
func (s *MemoryStore) GetProject(_ context.Context, id string) (Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.projects[id]
	if !ok {
		return Project{}, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) ListProjects(_ context.Context, orgID string) ([]Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Project{}
	for _, v := range s.projects {
		if orgID == "" || v.OrganizationID == orgID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OrganizationID == out[j].OrganizationID {
			return out[i].Name < out[j].Name
		}
		return out[i].OrganizationID < out[j].OrganizationID
	})
	return out, nil
}

func validOrganizationMembershipRole(role OrganizationMembershipRole) bool {
	switch role {
	case OrganizationAdmin, OrganizationOperator, OrganizationViewer:
		return true
	default:
		return false
	}
}

func (s *MemoryStore) UpsertOrganizationMembership(_ context.Context, membership OrganizationMembership, expected int64, actor string) (OrganizationMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	membership.OrganizationID = strings.TrimSpace(membership.OrganizationID)
	membership.Subject = strings.TrimSpace(membership.Subject)
	if _, ok := s.organizations[membership.OrganizationID]; !ok {
		return OrganizationMembership{}, ErrNotFound
	}
	if membership.Subject == "" || !validOrganizationMembershipRole(membership.Role) {
		return OrganizationMembership{}, fmt.Errorf("%w: organization membership subject and valid role are required", ErrValidation)
	}
	now := nowUTC(s.now)
	for id, existing := range s.organizationMemberships {
		if existing.OrganizationID == membership.OrganizationID && existing.Subject == membership.Subject {
			if expected <= 0 || existing.Revision != expected {
				return OrganizationMembership{}, ErrConflict
			}
			existing.Role = membership.Role
			existing.State = OrganizationMembershipActive
			existing.GrantedBy = strings.TrimSpace(actor)
			existing.RevokedAt = nil
			existing.RevokedBy = ""
			existing.Revision++
			existing.UpdatedAt = now
			s.organizationMemberships[id] = existing
			s.appendAuditLocked(actor, "organization_membership.granted", "organizationMembership", id, existing.Revision, map[string]any{"organizationId": existing.OrganizationID, "subject": existing.Subject, "role": existing.Role})
			s.appendOutboxLocked("organizationMembership", id, "organization_membership.granted", existing)
			return existing, nil
		}
	}
	if expected != 0 {
		return OrganizationMembership{}, ErrConflict
	}
	membership.ResourceMeta = ResourceMeta{ID: s.id("mem"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	membership.State = OrganizationMembershipActive
	membership.GrantedBy = strings.TrimSpace(actor)
	membership.RevokedAt = nil
	membership.RevokedBy = ""
	s.organizationMemberships[membership.ID] = membership
	s.appendAuditLocked(actor, "organization_membership.granted", "organizationMembership", membership.ID, membership.Revision, map[string]any{"organizationId": membership.OrganizationID, "subject": membership.Subject, "role": membership.Role})
	s.appendOutboxLocked("organizationMembership", membership.ID, "organization_membership.granted", membership)
	return membership, nil
}

func (s *MemoryStore) GetOrganizationMembership(_ context.Context, organizationID, subject string) (OrganizationMembership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, membership := range s.organizationMemberships {
		if membership.OrganizationID == strings.TrimSpace(organizationID) && membership.Subject == strings.TrimSpace(subject) {
			return membership, nil
		}
	}
	return OrganizationMembership{}, ErrNotFound
}

func (s *MemoryStore) ListOrganizationMemberships(_ context.Context, organizationID string) ([]OrganizationMembership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organizationID = strings.TrimSpace(organizationID)
	out := []OrganizationMembership{}
	for _, membership := range s.organizationMemberships {
		if organizationID == "" || membership.OrganizationID == organizationID {
			out = append(out, membership)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OrganizationID == out[j].OrganizationID {
			return out[i].Subject < out[j].Subject
		}
		return out[i].OrganizationID < out[j].OrganizationID
	})
	return out, nil
}

func (s *MemoryStore) ListSubjectOrganizationMemberships(_ context.Context, subject string) ([]OrganizationMembership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	subject = strings.TrimSpace(subject)
	out := []OrganizationMembership{}
	for _, membership := range s.organizationMemberships {
		if membership.Subject == subject && membership.State == OrganizationMembershipActive {
			out = append(out, membership)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OrganizationID < out[j].OrganizationID })
	return out, nil
}

func (s *MemoryStore) RevokeOrganizationMembership(_ context.Context, organizationID, subject string, expected int64, actor string) (OrganizationMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	organizationID, subject = strings.TrimSpace(organizationID), strings.TrimSpace(subject)
	var id string
	var current OrganizationMembership
	for candidateID, membership := range s.organizationMemberships {
		if membership.OrganizationID == organizationID && membership.Subject == subject {
			id, current = candidateID, membership
			break
		}
	}
	if id == "" {
		return OrganizationMembership{}, ErrNotFound
	}
	if current.Revision != expected {
		return OrganizationMembership{}, ErrConflict
	}
	if current.State == OrganizationMembershipRevoked {
		return current, nil
	}
	if current.Role == OrganizationAdmin {
		admins := 0
		for _, membership := range s.organizationMemberships {
			if membership.OrganizationID == organizationID && membership.State == OrganizationMembershipActive && membership.Role == OrganizationAdmin {
				admins++
			}
		}
		if admins <= 1 {
			return OrganizationMembership{}, fmt.Errorf("%w: the last active organization-admin cannot be revoked", ErrValidation)
		}
	}
	now := nowUTC(s.now)
	current.State = OrganizationMembershipRevoked
	current.RevokedBy = strings.TrimSpace(actor)
	current.RevokedAt = &now
	current.Revision++
	current.UpdatedAt = now
	s.organizationMemberships[id] = current
	s.appendAuditLocked(actor, "organization_membership.revoked", "organizationMembership", id, current.Revision, map[string]any{"organizationId": organizationID, "subject": subject})
	s.appendOutboxLocked("organizationMembership", id, "organization_membership.revoked", current)
	return current, nil
}

func (s *MemoryStore) CreateBlueprintOverlay(_ context.Context, overlay BlueprintOverlay, actor string) (BlueprintOverlay, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[overlay.ProjectID]; !ok {
		return BlueprintOverlay{}, ErrNotFound
	}
	var err error
	overlay, err = NormalizeBlueprintOverlay(overlay)
	if err != nil {
		return BlueprintOverlay{}, err
	}
	for _, existing := range s.blueprintOverlays {
		if existing.ProjectID == overlay.ProjectID && existing.Name == overlay.Name && existing.Version == overlay.Version {
			return BlueprintOverlay{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	overlay.ResourceMeta = ResourceMeta{ID: s.id("bpo"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	overlay.CreatedBy = strings.TrimSpace(actor)
	overlay = cloneOverlay(overlay)
	s.blueprintOverlays[overlay.ID] = overlay
	s.appendAuditLocked(actor, "blueprint_overlay.created", "blueprintOverlay", overlay.ID, overlay.Revision, map[string]any{"projectId": overlay.ProjectID, "scope": overlay.Scope, "scopeKey": overlay.ScopeKey, "digest": overlay.Digest})
	s.appendOutboxLocked("blueprintOverlay", overlay.ID, "blueprint_overlay.created", overlay)
	return cloneOverlay(overlay), nil
}

func (s *MemoryStore) GetBlueprintOverlay(_ context.Context, id string) (BlueprintOverlay, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.blueprintOverlays[id]
	if !ok {
		return BlueprintOverlay{}, ErrNotFound
	}
	return cloneOverlay(v), nil
}

func (s *MemoryStore) ListBlueprintOverlays(_ context.Context, projectID string, scope BlueprintOverlayScope) ([]BlueprintOverlay, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []BlueprintOverlay{}
	for _, v := range s.blueprintOverlays {
		if (projectID == "" || v.ProjectID == projectID) && (scope == "" || v.Scope == scope) {
			out = append(out, cloneOverlay(v))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			if out[i].Version == out[j].Version {
				return out[i].ID < out[j].ID
			}
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (s *MemoryStore) prepareBlueprintRevisionLocked(r BlueprintRevision) (BlueprintRevision, bool, error) {
	r = NormalizeBlueprintRevisionResolution(r)
	if _, ok := s.projects[r.ProjectID]; !ok {
		return BlueprintRevision{}, false, ErrNotFound
	}
	if !strings.HasPrefix(r.BlueprintDigest, "sha256:") || !strings.HasPrefix(r.CatalogDigest, "sha256:") || !strings.HasPrefix(r.BaseBlueprintDigest, "sha256:") || !strings.HasPrefix(r.OverlayDigest, "sha256:") || !strings.HasPrefix(r.OwnershipDigest, "sha256:") || len(r.Payload) == 0 || !json.Valid(r.Payload) || len(r.BasePayload) == 0 || !json.Valid(r.BasePayload) || len(r.ResolutionPayload) == 0 || !json.Valid(r.ResolutionPayload) {
		return BlueprintRevision{}, false, fmt.Errorf("%w: immutable base/resolved Blueprint payloads and sha256 resolution digests are required", ErrValidation)
	}
	if r.ProviderOverlayID != "" {
		overlay, ok := s.blueprintOverlays[r.ProviderOverlayID]
		if !ok {
			return BlueprintRevision{}, false, ErrNotFound
		}
		if overlay.ProjectID != r.ProjectID || overlay.Scope != BlueprintOverlayProvider {
			return BlueprintRevision{}, false, fmt.Errorf("%w: provider overlay must belong to the same project and have PROVIDER scope", ErrValidation)
		}
	}
	if r.EnvironmentOverlayID != "" {
		overlay, ok := s.blueprintOverlays[r.EnvironmentOverlayID]
		if !ok {
			return BlueprintRevision{}, false, ErrNotFound
		}
		if overlay.ProjectID != r.ProjectID || overlay.Scope != BlueprintOverlayEnvironment {
			return BlueprintRevision{}, false, fmt.Errorf("%w: environment overlay must belong to the same project and have ENVIRONMENT scope", ErrValidation)
		}
	}
	for _, x := range s.revisions {
		if x.ProjectID == r.ProjectID && x.BlueprintDigest == r.BlueprintDigest && x.CatalogDigest == r.CatalogDigest && x.BaseBlueprintDigest == r.BaseBlueprintDigest && x.OverlayDigest == r.OverlayDigest && x.OwnershipDigest == r.OwnershipDigest {
			x.Payload = append([]byte(nil), x.Payload...)
			x.BasePayload = append([]byte(nil), x.BasePayload...)
			x.ResolutionPayload = append([]byte(nil), x.ResolutionPayload...)
			return x, true, nil
		}
	}
	now := nowUTC(s.now)
	r.ResourceMeta = ResourceMeta{ID: s.id("bpr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	r.Payload = append([]byte(nil), r.Payload...)
	r.BasePayload = append([]byte(nil), r.BasePayload...)
	r.ResolutionPayload = append([]byte(nil), r.ResolutionPayload...)
	return r, false, nil
}

func (s *MemoryStore) commitBlueprintRevisionLocked(r BlueprintRevision, actor string) {
	s.revisions[r.ID] = r
	s.appendAuditLocked(actor, "blueprint_revision.created", "blueprintRevision", r.ID, r.Revision, map[string]any{"projectId": r.ProjectID})
	s.appendOutboxLocked("blueprintRevision", r.ID, "blueprint_revision.created", r)
}

func (s *MemoryStore) CreateBlueprintRevision(_ context.Context, r BlueprintRevision, actor string) (BlueprintRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prepared, existing, err := s.prepareBlueprintRevisionLocked(r)
	if err != nil {
		return BlueprintRevision{}, err
	}
	if !existing {
		s.commitBlueprintRevisionLocked(prepared, actor)
	}
	return prepared, nil
}
func (s *MemoryStore) GetBlueprintRevision(_ context.Context, id string) (BlueprintRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.revisions[id]
	if !ok {
		return BlueprintRevision{}, ErrNotFound
	}
	v.Payload = append([]byte(nil), v.Payload...)
	v.BasePayload = append([]byte(nil), v.BasePayload...)
	v.ResolutionPayload = append([]byte(nil), v.ResolutionPayload...)
	return v, nil
}

func cloneBlueprintRelease(v BlueprintRelease) BlueprintRelease {
	v.UpgradeFromIDs = append([]string(nil), v.UpgradeFromIDs...)
	return v
}

func validBlueprintTransition(from, to BlueprintLifecycleState) bool {
	switch from {
	case BlueprintDraft:
		return to == BlueprintReview
	case BlueprintReview:
		return to == BlueprintDraft || to == BlueprintPublished
	case BlueprintPublished:
		return to == BlueprintDeprecated || to == BlueprintRevoked
	case BlueprintDeprecated:
		return to == BlueprintRevoked
	default:
		return false
	}
}

func (s *MemoryStore) prepareBlueprintReleaseLocked(release BlueprintRelease, revision BlueprintRevision, actor string) (BlueprintRelease, error) {
	if _, ok := s.projects[release.ProjectID]; !ok {
		return BlueprintRelease{}, ErrNotFound
	}
	if revision.ProjectID != release.ProjectID || revision.BlueprintName != release.BlueprintName || revision.BlueprintVersion != release.BlueprintVersion || revision.BlueprintDigest != release.CurrentBlueprintDigest || revision.CatalogDigest != release.CatalogDigest {
		return BlueprintRelease{}, fmt.Errorf("%w: current revision does not match release identity", ErrValidation)
	}
	if strings.TrimSpace(release.CatalogReleaseID) != "" {
		catalogRelease, ok := s.catalogReleases[strings.TrimSpace(release.CatalogReleaseID)]
		if !ok {
			return BlueprintRelease{}, ErrNotFound
		}
		project := s.projects[release.ProjectID]
		if catalogRelease.State != CatalogPublished || catalogRelease.ManifestDigest != release.CatalogDigest || (catalogRelease.Visibility == CatalogVisibilityPrivate && catalogRelease.OrganizationID != project.OrganizationID) {
			return BlueprintRelease{}, fmt.Errorf("%w: blueprint catalog release must be published, trusted, digest-matched and visible to the project", ErrValidation)
		}
		key, ok := s.catalogTrustKeys[catalogRelease.SigningKeyID]
		if !ok {
			return BlueprintRelease{}, ErrNotFound
		}
		if err := VerifyCatalogReleaseSignature(catalogRelease, key); err != nil {
			return BlueprintRelease{}, err
		}
	}
	if normalizeName(release.BlueprintName) == "" || strings.TrimSpace(release.BlueprintVersion) == "" {
		return BlueprintRelease{}, fmt.Errorf("%w: blueprint name and version are required", ErrValidation)
	}
	for _, existing := range s.blueprintReleases {
		if existing.ProjectID == release.ProjectID && normalizeName(existing.BlueprintName) == normalizeName(release.BlueprintName) && existing.BlueprintVersion == release.BlueprintVersion {
			return BlueprintRelease{}, ErrDuplicateName
		}
	}
	seen := map[string]bool{}
	for _, sourceID := range release.UpgradeFromIDs {
		if sourceID == "" || seen[sourceID] {
			return BlueprintRelease{}, fmt.Errorf("%w: upgradeFromIds must contain unique release IDs", ErrValidation)
		}
		source, ok := s.blueprintReleases[sourceID]
		if !ok || source.ProjectID != release.ProjectID || normalizeName(source.BlueprintName) != normalizeName(release.BlueprintName) || (source.State != BlueprintPublished && source.State != BlueprintDeprecated) {
			return BlueprintRelease{}, fmt.Errorf("%w: upgrade source must be a published or deprecated release of the same blueprint", ErrValidation)
		}
		seen[sourceID] = true
	}
	now := nowUTC(s.now)
	release.ResourceMeta = ResourceMeta{ID: s.id("bpl"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	release.State = BlueprintDraft
	release.BlueprintName = normalizeName(release.BlueprintName)
	release.RequestedBy = strings.TrimSpace(actor)
	release.UpgradeFromIDs = append([]string(nil), release.UpgradeFromIDs...)
	sort.Strings(release.UpgradeFromIDs)
	return release, nil
}

func (s *MemoryStore) commitBlueprintReleaseLocked(release BlueprintRelease, actor string) {
	s.blueprintReleases[release.ID] = release
	s.appendAuditLocked(actor, "blueprint_release.created", "blueprintRelease", release.ID, release.Revision, map[string]any{"projectId": release.ProjectID, "blueprintName": release.BlueprintName, "blueprintVersion": release.BlueprintVersion})
	s.appendOutboxLocked("blueprintRelease", release.ID, "blueprint_release.created", release)
}

func (s *MemoryStore) CreateBlueprintRelease(_ context.Context, release BlueprintRelease, actor string) (BlueprintRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	revision, ok := s.revisions[release.CurrentRevisionID]
	if !ok {
		return BlueprintRelease{}, ErrNotFound
	}
	prepared, err := s.prepareBlueprintReleaseLocked(release, revision, actor)
	if err != nil {
		return BlueprintRelease{}, err
	}
	s.commitBlueprintReleaseLocked(prepared, actor)
	return cloneBlueprintRelease(prepared), nil
}

func (s *MemoryStore) CreateBlueprintReleaseWithRevision(_ context.Context, revision BlueprintRevision, release BlueprintRelease, actor string) (BlueprintRevision, BlueprintRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	preparedRevision, existing, err := s.prepareBlueprintRevisionLocked(revision)
	if err != nil {
		return BlueprintRevision{}, BlueprintRelease{}, err
	}
	release.ProjectID = preparedRevision.ProjectID
	release.BlueprintName = preparedRevision.BlueprintName
	release.BlueprintVersion = preparedRevision.BlueprintVersion
	release.CurrentRevisionID = preparedRevision.ID
	release.CurrentBlueprintDigest = preparedRevision.BlueprintDigest
	release.CatalogDigest = preparedRevision.CatalogDigest
	preparedRelease, err := s.prepareBlueprintReleaseLocked(release, preparedRevision, actor)
	if err != nil {
		return BlueprintRevision{}, BlueprintRelease{}, err
	}
	if !existing {
		s.commitBlueprintRevisionLocked(preparedRevision, actor)
	}
	s.commitBlueprintReleaseLocked(preparedRelease, actor)
	return preparedRevision, cloneBlueprintRelease(preparedRelease), nil
}

func (s *MemoryStore) GetBlueprintRelease(_ context.Context, id string) (BlueprintRelease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.blueprintReleases[id]
	if !ok {
		return BlueprintRelease{}, ErrNotFound
	}
	return cloneBlueprintRelease(v), nil
}

func (s *MemoryStore) ListBlueprintReleases(_ context.Context, projectID string) ([]BlueprintRelease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]BlueprintRelease, 0)
	for _, v := range s.blueprintReleases {
		if projectID == "" || v.ProjectID == projectID {
			out = append(out, cloneBlueprintRelease(v))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BlueprintName == out[j].BlueprintName {
			if out[i].BlueprintVersion == out[j].BlueprintVersion {
				return out[i].ID < out[j].ID
			}
			return out[i].BlueprintVersion < out[j].BlueprintVersion
		}
		return out[i].BlueprintName < out[j].BlueprintName
	})
	return out, nil
}

func (s *MemoryStore) prepareBlueprintDraftUpdateLocked(id string, expected int64, revision BlueprintRevision, executionReady bool, planStatus string, upgradeFromIDs []string) (BlueprintRelease, error) {
	current, ok := s.blueprintReleases[id]
	if !ok {
		return BlueprintRelease{}, ErrNotFound
	}
	if current.Revision != expected {
		return BlueprintRelease{}, ErrConflict
	}
	if current.State != BlueprintDraft {
		return BlueprintRelease{}, ErrImmutable
	}
	if revision.ProjectID != current.ProjectID || revision.BlueprintName != current.BlueprintName || revision.BlueprintVersion != current.BlueprintVersion {
		return BlueprintRelease{}, fmt.Errorf("%w: draft revision does not match release identity", ErrValidation)
	}
	seen := map[string]bool{}
	for _, sourceID := range upgradeFromIDs {
		if sourceID == id || sourceID == "" || seen[sourceID] {
			return BlueprintRelease{}, fmt.Errorf("%w: invalid or duplicate upgrade source", ErrValidation)
		}
		source, ok := s.blueprintReleases[sourceID]
		if !ok || source.ProjectID != current.ProjectID || source.BlueprintName != current.BlueprintName || (source.State != BlueprintPublished && source.State != BlueprintDeprecated) {
			return BlueprintRelease{}, fmt.Errorf("%w: upgrade source must be a published or deprecated release of the same blueprint", ErrValidation)
		}
		seen[sourceID] = true
	}
	current.CurrentRevisionID = revision.ID
	current.CurrentBlueprintDigest = revision.BlueprintDigest
	current.CatalogDigest = revision.CatalogDigest
	current.ExecutionReady = executionReady
	current.PlanStatus = strings.TrimSpace(planStatus)
	current.UpgradeFromIDs = append([]string(nil), upgradeFromIDs...)
	sort.Strings(current.UpgradeFromIDs)
	current.Revision++
	current.UpdatedAt = nowUTC(s.now)
	return current, nil
}

func (s *MemoryStore) commitBlueprintDraftUpdateLocked(current BlueprintRelease, actor string) {
	s.blueprintReleases[current.ID] = current
	s.appendAuditLocked(actor, "blueprint_release.draft_updated", "blueprintRelease", current.ID, current.Revision, map[string]any{"revisionId": current.CurrentRevisionID, "blueprintDigest": current.CurrentBlueprintDigest})
	s.appendOutboxLocked("blueprintRelease", current.ID, "blueprint_release.draft_updated", current)
}

func (s *MemoryStore) UpdateBlueprintReleaseDraft(_ context.Context, id string, expected int64, revisionID, blueprintDigest, catalogDigest string, executionReady bool, planStatus string, upgradeFromIDs []string, actor string) (BlueprintRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	revision, ok := s.revisions[revisionID]
	if !ok {
		return BlueprintRelease{}, ErrNotFound
	}
	if revision.BlueprintDigest != blueprintDigest || revision.CatalogDigest != catalogDigest {
		return BlueprintRelease{}, fmt.Errorf("%w: draft revision does not match requested digests", ErrValidation)
	}
	updated, err := s.prepareBlueprintDraftUpdateLocked(id, expected, revision, executionReady, planStatus, upgradeFromIDs)
	if err != nil {
		return BlueprintRelease{}, err
	}
	s.commitBlueprintDraftUpdateLocked(updated, actor)
	return cloneBlueprintRelease(updated), nil
}

func (s *MemoryStore) UpdateBlueprintReleaseDraftWithRevision(_ context.Context, id string, expected int64, revision BlueprintRevision, executionReady bool, planStatus string, upgradeFromIDs []string, actor string) (BlueprintRevision, BlueprintRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.blueprintReleases[id]
	if !ok {
		return BlueprintRevision{}, BlueprintRelease{}, ErrNotFound
	}
	if current.Revision != expected {
		return BlueprintRevision{}, BlueprintRelease{}, ErrConflict
	}
	if current.State != BlueprintDraft {
		return BlueprintRevision{}, BlueprintRelease{}, ErrImmutable
	}
	preparedRevision, existing, err := s.prepareBlueprintRevisionLocked(revision)
	if err != nil {
		return BlueprintRevision{}, BlueprintRelease{}, err
	}
	updated, err := s.prepareBlueprintDraftUpdateLocked(id, expected, preparedRevision, executionReady, planStatus, upgradeFromIDs)
	if err != nil {
		return BlueprintRevision{}, BlueprintRelease{}, err
	}
	if !existing {
		s.commitBlueprintRevisionLocked(preparedRevision, actor)
	}
	s.commitBlueprintDraftUpdateLocked(updated, actor)
	return preparedRevision, cloneBlueprintRelease(updated), nil
}

func (s *MemoryStore) TransitionBlueprintRelease(_ context.Context, id string, expected int64, to BlueprintLifecycleState, actor string) (BlueprintRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.blueprintReleases[id]
	if !ok {
		return BlueprintRelease{}, ErrNotFound
	}
	if current.Revision != expected {
		return BlueprintRelease{}, ErrConflict
	}
	if !validBlueprintTransition(current.State, to) {
		return BlueprintRelease{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	from := current.State
	if to == BlueprintPublished {
		if strings.TrimSpace(actor) == "" {
			return BlueprintRelease{}, fmt.Errorf("%w: publish approver is required", ErrValidation)
		}
		if strings.TrimSpace(current.CatalogReleaseID) != "" {
			catalogRelease, ok := s.catalogReleases[current.CatalogReleaseID]
			project := s.projects[current.ProjectID]
			if !ok || catalogRelease.State != CatalogPublished || catalogRelease.ManifestDigest != current.CatalogDigest || (catalogRelease.Visibility == CatalogVisibilityPrivate && catalogRelease.OrganizationID != project.OrganizationID) {
				return BlueprintRelease{}, fmt.Errorf("%w: linked catalog release is not publishable for this project", ErrValidation)
			}
			key, ok := s.catalogTrustKeys[catalogRelease.SigningKeyID]
			if !ok {
				return BlueprintRelease{}, ErrNotFound
			}
			if err := VerifyCatalogReleaseSignature(catalogRelease, key); err != nil {
				return BlueprintRelease{}, err
			}
		}
		for _, sourceID := range current.UpgradeFromIDs {
			source, ok := s.blueprintReleases[sourceID]
			if !ok || (source.State != BlueprintPublished && source.State != BlueprintDeprecated) {
				return BlueprintRelease{}, fmt.Errorf("%w: upgrade source is no longer publishable", ErrValidation)
			}
		}
		current.PublishedBy, current.PublishedAt = actor, &now
	}
	if to == BlueprintReview {
		current.RequestedBy = actor
		current.ReviewRequestedAt = &now
	}
	if from == BlueprintReview && to == BlueprintDraft {
		current.ReviewRequestedAt = nil
	}
	if to == BlueprintDeprecated {
		current.DeprecatedBy, current.DeprecatedAt = actor, &now
	}
	if to == BlueprintRevoked {
		current.RevokedBy, current.RevokedAt = actor, &now
	}
	current.State = to
	current.Revision++
	current.UpdatedAt = now
	s.blueprintReleases[id] = current
	action := "blueprint_release." + strings.ToLower(string(to))
	s.appendAuditLocked(actor, action, "blueprintRelease", id, current.Revision, map[string]any{"from": from, "to": to})
	s.appendOutboxLocked("blueprintRelease", id, action, current)
	return cloneBlueprintRelease(current), nil
}

func (s *MemoryStore) CreateAssignment(_ context.Context, a Assignment, actor string) (Assignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[a.ProjectID]; !ok {
		return Assignment{}, ErrNotFound
	}
	if _, ok := s.revisions[a.BlueprintRevisionID]; !ok {
		return Assignment{}, ErrNotFound
	}
	if strings.TrimSpace(a.TargetRef) == "" {
		return Assignment{}, fmt.Errorf("%w: targetRef is required", ErrValidation)
	}
	for _, x := range s.assignments {
		if x.ProjectID == a.ProjectID && x.TargetRef == a.TargetRef {
			return Assignment{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	a.ResourceMeta = ResourceMeta{ID: s.id("asn"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	a.DesiredGeneration = 1
	s.assignments[a.ID] = a
	s.appendAuditLocked(actor, "assignment.created", "assignment", a.ID, a.Revision, nil)
	s.appendOutboxLocked("assignment", a.ID, "assignment.created", a)
	return a, nil
}
func (s *MemoryStore) UpdateAssignment(_ context.Context, id string, expected int64, revisionID string, generation int64, actor string) (Assignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assignments[id]
	if !ok {
		return Assignment{}, ErrNotFound
	}
	if a.Revision != expected {
		return Assignment{}, ErrConflict
	}
	if _, ok := s.revisions[revisionID]; !ok {
		return Assignment{}, ErrNotFound
	}
	if generation <= a.DesiredGeneration {
		return Assignment{}, fmt.Errorf("%w: desired generation must increase", ErrValidation)
	}
	a.BlueprintRevisionID = revisionID
	a.DesiredGeneration = generation
	a.Revision++
	a.UpdatedAt = nowUTC(s.now)
	s.assignments[id] = a
	s.appendAuditLocked(actor, "assignment.updated", "assignment", id, a.Revision, map[string]any{"desiredGeneration": generation})
	s.appendOutboxLocked("assignment", id, "assignment.updated", a)
	return a, nil
}
func (s *MemoryStore) GetAssignment(_ context.Context, id string) (Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.assignments[id]
	if !ok {
		return Assignment{}, ErrNotFound
	}
	return v, nil
}

func operationDigest(r OperationRequest) string {
	raw, _ := json.Marshal(r)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (s *MemoryStore) createOperationLocked(r OperationRequest, key, actor, requestID string) (Operation, bool, error) {
	if strings.TrimSpace(key) == "" || len(key) > 200 {
		return Operation{}, false, fmt.Errorf("%w: a bounded idempotency key is required", ErrValidation)
	}
	if strings.TrimSpace(actor) == "" {
		return Operation{}, false, fmt.Errorf("%w: actor is required", ErrValidation)
	}
	if r.Risk != "low" && r.Risk != "medium" && r.Risk != "high" && r.Risk != "critical" {
		return Operation{}, false, fmt.Errorf("%w: invalid operation risk", ErrValidation)
	}
	class, classErr := NormalizeOperationClass(r.Class)
	if classErr != nil {
		return Operation{}, false, classErr
	}
	r.Class = class
	if _, ok := s.projects[r.ProjectID]; !ok {
		return Operation{}, false, ErrNotFound
	}
	if r.Kind == "" || r.TargetRef == "" || r.DesiredRevision == "" {
		return Operation{}, false, fmt.Errorf("%w: kind, targetRef and desiredRevision are required", ErrValidation)
	}
	digest := operationDigest(r)
	scope := r.ProjectID + ":" + key
	if id, ok := s.idempotency[scope]; ok {
		op := s.operations[id]
		if op.RequestDigest != digest {
			return Operation{}, false, ErrIdempotencyConflict
		}
		return op, true, nil
	}
	now := nowUTC(s.now)
	op := Operation{ResourceMeta: ResourceMeta{ID: s.id("op"), Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: r.ProjectID, Kind: r.Kind, TargetRef: r.TargetRef, DesiredRevision: r.DesiredRevision, State: OperationDraft, Risk: r.Risk, Class: class, RetryPolicy: RetryPolicyForOperationClass(class), RecoveryCheckpointID: strings.TrimSpace(r.RecoveryCheckpointID), IdempotencyKey: key, RequestDigest: digest, ActorID: actor}
	if class == OperationClassDestructive {
		checkpoint, ok := s.recoveryCheckpoints[op.RecoveryCheckpointID]
		if !ok {
			return Operation{}, false, fmt.Errorf("%w: destructive operation requires a verified recovery checkpoint", ErrPrerequisite)
		}
		op.RecoveryEvidenceDigest = checkpoint.EvidenceDigest
		op.RecoveryInventoryDigest = checkpoint.InventoryDigest
		if err := s.validateDestructiveRecoveryLocked(op, now); err != nil {
			return Operation{}, false, err
		}
	}
	s.operations[op.ID] = op
	s.idempotency[scope] = op.ID
	s.appendAuditLocked(actor, "operation.created", "operation", op.ID, op.Revision, map[string]any{"requestId": requestID, "state": op.State})
	s.appendOutboxLocked("operation", op.ID, "operation.created", op)
	return op, false, nil
}

func (s *MemoryStore) CreateOperation(_ context.Context, r OperationRequest, key, actor, requestID string) (Operation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createOperationLocked(r, key, actor, requestID)
}

func (s *MemoryStore) GetOperation(_ context.Context, id string) (Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) ListOperations(_ context.Context, projectID string) ([]Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Operation{}
	for _, v := range s.operations {
		if projectID == "" || v.ProjectID == projectID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}
func (s *MemoryStore) transitionOperationLocked(id string, expected int64, to OperationState, lastError, actor string) (Operation, error) {
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if op.Revision != expected {
		return Operation{}, ErrConflict
	}
	if !CanTransition(op.State, to) {
		return Operation{}, ErrInvalidTransition
	}
	if to == OperationRollingBack {
		return Operation{}, fmt.Errorf("%w: ROLLING_BACK is compensation-authority controlled; use BeginOperationCompensation", ErrPrerequisite)
	}
	if op.State == OperationFailed && to == OperationQueued && op.Attempt > 0 {
		return Operation{}, fmt.Errorf("%w: bounded retry budget cannot be bypassed; create a new idempotent operation or recover explicitly", ErrPrerequisite)
	}
	op.State = to
	op.LastError = lastError
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	if IsTerminal(to) {
		op.LeaseOwner = ""
		op.LeaseExpiresAt = nil
	}
	s.operations[id] = op
	s.appendAuditLocked(actor, "operation.transitioned", "operation", id, op.Revision, map[string]any{"state": to})
	s.appendOutboxLocked("operation", id, "operation.transitioned", op)
	return op, nil
}

func (s *MemoryStore) TransitionOperation(_ context.Context, id string, expected int64, to OperationState, lastError, actor string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitionOperationLocked(id, expected, to, lastError, actor)
}

func (s *MemoryStore) ClaimOperation(_ context.Context, id, worker string, ttl time.Duration, at time.Time) (ClaimResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return ClaimResult{}, ErrNotFound
	}
	at = at.UTC()
	if op.State == OperationRetryWait {
		if op.NextAttemptAt == nil || op.NextAttemptAt.After(at) {
			return ClaimResult{}, ErrNotClaimable
		}
		op.State = OperationQueued
		op.NextAttemptAt = nil
		op.Revision++
		op.UpdatedAt = nowUTC(s.now)
		s.operations[id] = op
		s.appendAuditLocked(worker, "operation.retry_due_queued", "operation", id, op.Revision, map[string]any{"attempt": op.Attempt + 1})
		s.appendOutboxLocked("operation", id, "operation.retry_due_queued", op)
	}
	if op.State != OperationQueued && op.State != OperationRunning && op.State != OperationVerifying && op.State != OperationRollingBack && op.State != OperationCancelRequested {
		return ClaimResult{}, ErrNotClaimable
	}
	if worker == "" || ttl <= 0 {
		return ClaimResult{}, fmt.Errorf("%w: worker and positive ttl are required", ErrValidation)
	}
	if op.LeaseExpiresAt != nil && op.LeaseExpiresAt.After(at) && op.LeaseOwner != worker {
		return ClaimResult{}, ErrLeaseHeld
	}
	expires := at.Add(ttl)
	op.FenceToken++
	op.LeaseOwner = worker
	op.LeaseExpiresAt = &expires
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.operations[id] = op
	s.appendAuditLocked(worker, "operation.claimed", "operation", id, op.Revision, map[string]any{"fenceToken": op.FenceToken})
	return ClaimResult{OperationID: id, LeaseOwner: worker, LeaseExpiresAt: expires, FenceToken: op.FenceToken}, nil
}
func (s *MemoryStore) RenewOperationLease(_ context.Context, id, worker string, fence int64, ttl time.Duration, at time.Time) (ClaimResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return ClaimResult{}, ErrNotFound
	}
	if op.FenceToken != fence || op.LeaseOwner != worker {
		return ClaimResult{}, ErrStaleFence
	}
	if ttl <= 0 {
		return ClaimResult{}, fmt.Errorf("%w: positive lease ttl is required", ErrValidation)
	}
	if op.LeaseExpiresAt == nil || !op.LeaseExpiresAt.After(at.UTC()) {
		return ClaimResult{}, ErrLeaseHeld
	}
	expires := at.UTC().Add(ttl)
	op.LeaseExpiresAt = &expires
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.operations[id] = op
	return ClaimResult{OperationID: id, LeaseOwner: worker, LeaseExpiresAt: expires, FenceToken: fence}, nil
}
func (s *MemoryStore) ReleaseOperationLease(_ context.Context, id, worker string, fence int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return ErrNotFound
	}
	if op.FenceToken != fence || op.LeaseOwner != worker {
		return ErrStaleFence
	}
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	op.Revision++
	op.UpdatedAt = nowUTC(s.now)
	s.operations[id] = op
	return nil
}

func (s *MemoryStore) AppendOperationStep(_ context.Context, step OperationStep, actor string) (OperationStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[step.OperationID]
	if !ok {
		return OperationStep{}, ErrNotFound
	}
	if step.FenceToken != op.FenceToken {
		return OperationStep{}, ErrStaleFence
	}
	if step.StepKey == "" {
		return OperationStep{}, fmt.Errorf("%w: stepKey is required", ErrValidation)
	}
	if op.Attempt < 1 {
		return OperationStep{}, fmt.Errorf("%w: operation attempt has not started", ErrPrerequisite)
	}
	step.Attempt = op.Attempt
	key := fmt.Sprintf("%s:%d:%s", step.OperationID, step.Attempt, step.StepKey)
	if existing, ok := s.steps[key]; ok {
		return existing, nil
	}
	now := nowUTC(s.now)
	step.ResourceMeta = ResourceMeta{ID: s.id("stp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	s.steps[key] = step
	s.appendAuditLocked(actor, "operation_step.appended", "operationStep", step.ID, step.Revision, map[string]any{"operationId": step.OperationID, "stepKey": step.StepKey})
	s.appendOutboxLocked("operationStep", step.ID, "operation_step.appended", step)
	return step, nil
}
func (s *MemoryStore) ListOperationSteps(_ context.Context, operationID string) ([]OperationStep, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []OperationStep{}
	for _, v := range s.steps {
		if v.OperationID == operationID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StepKey < out[j].StepKey })
	return out, nil
}

func (s *MemoryStore) ClaimOutbox(_ context.Context, worker string, limit int, ttl time.Duration, at time.Time) ([]OutboxEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if worker == "" || limit <= 0 || ttl <= 0 {
		return nil, fmt.Errorf("%w: invalid outbox claim", ErrValidation)
	}
	ids := make([]string, 0, len(s.outbox))
	for id := range s.outbox {
		ids = append(ids, id)
	}
	// Match the PostgreSQL authority scheduler: eligible outbox work is
	// selected by availability time first, with ID as a deterministic tie-break.
	// Random resource IDs must never decide queue age or allow newer events to
	// jump ahead of older available work in Memory/FileStore.
	sort.Slice(ids, func(i, j int) bool {
		left, right := s.outbox[ids[i]], s.outbox[ids[j]]
		if left.AvailableAt.Equal(right.AvailableAt) {
			return left.ID < right.ID
		}
		return left.AvailableAt.Before(right.AvailableAt)
	})
	out := []OutboxEvent{}
	for _, id := range ids {
		if len(out) >= limit {
			break
		}
		e := s.outbox[id]
		if e.PublishedAt != nil || e.AvailableAt.After(at.UTC()) {
			continue
		}
		if e.ClaimedUntil != nil && e.ClaimedUntil.After(at.UTC()) {
			continue
		}
		until := at.UTC().Add(ttl)
		e.ClaimedBy = worker
		e.ClaimedUntil = &until
		e.Attempt++
		e.Revision++
		e.UpdatedAt = nowUTC(s.now)
		s.outbox[id] = e
		out = append(out, e)
	}
	return out, nil
}
func (s *MemoryStore) MarkOutboxPublished(_ context.Context, id, worker string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.outbox[id]
	if !ok {
		return ErrNotFound
	}
	if e.ClaimedBy != worker || e.ClaimedUntil == nil || !e.ClaimedUntil.After(at.UTC()) {
		return ErrStaleFence
	}
	published := at.UTC()
	e.PublishedAt = &published
	e.ClaimedBy = ""
	e.ClaimedUntil = nil
	e.Revision++
	e.UpdatedAt = nowUTC(s.now)
	s.outbox[id] = e
	return nil
}

func (s *MemoryStore) AppendEvidence(_ context.Context, e EvidenceMetadata, actor string) (EvidenceMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.operations[e.OperationID]; !ok {
		return EvidenceMetadata{}, ErrNotFound
	}
	if !strings.HasPrefix(e.Digest, "sha256:") || e.Location == "" || e.MediaType == "" || e.Size < 0 {
		return EvidenceMetadata{}, fmt.Errorf("%w: evidence sha256 digest, location, mediaType and non-negative size are required", ErrValidation)
	}
	for _, x := range s.evidence {
		if x.OperationID == e.OperationID && x.Digest == e.Digest {
			return x, nil
		}
	}
	now := nowUTC(s.now)
	e.ResourceMeta = ResourceMeta{ID: s.id("evd"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	e.Sealed = true
	s.evidence[e.ID] = e
	s.appendAuditLocked(actor, "evidence.sealed", "evidence", e.ID, e.Revision, map[string]any{"operationId": e.OperationID, "digest": e.Digest})
	s.appendOutboxLocked("evidence", e.ID, "evidence.sealed", e)
	return e, nil
}
func (s *MemoryStore) ListEvidence(_ context.Context, operationID string) ([]EvidenceMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []EvidenceMetadata{}
	for _, v := range s.evidence {
		if operationID == "" || v.OperationID == operationID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *MemoryStore) ListAudit(_ context.Context, limit int) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	out := append([]AuditEvent(nil), s.audit...)
	auditNewestFirst(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) Health(_ context.Context) error { return nil }
func (s *MemoryStore) Backend() string                { return "memory" }
func (s *MemoryStore) ReadinessCounts(_ context.Context) (int, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.organizations), len(s.operations), nil
}

func (s *MemoryStore) Snapshot(_ context.Context) (Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{}
	for _, v := range s.organizations {
		snap.Organizations = append(snap.Organizations, v)
	}
	for _, v := range s.organizationMemberships {
		snap.OrganizationMemberships = append(snap.OrganizationMemberships, v)
	}
	for _, v := range s.oidcGroupMappings {
		snap.OIDCGroupMappings = append(snap.OIDCGroupMappings, v)
	}
	snap.SecurityAudit = append([]SecurityAuditEvent(nil), s.securityAudit...)
	for _, v := range s.serviceAccounts {
		snap.ServiceAccounts = append(snap.ServiceAccounts, v)
	}
	for _, v := range s.apiTokens {
		v.Permissions = append([]string(nil), v.Permissions...)
		snap.APITokens = append(snap.APITokens, v)
	}
	for _, v := range s.projects {
		snap.Projects = append(snap.Projects, v)
	}
	for _, v := range s.blueprintOverlays {
		snap.BlueprintOverlays = append(snap.BlueprintOverlays, cloneOverlay(v))
	}
	for _, v := range s.revisions {
		v.Payload = append([]byte(nil), v.Payload...)
		v.BasePayload = append([]byte(nil), v.BasePayload...)
		v.ResolutionPayload = append([]byte(nil), v.ResolutionPayload...)
		snap.Revisions = append(snap.Revisions, v)
	}
	for _, v := range s.blueprintReleases {
		snap.BlueprintReleases = append(snap.BlueprintReleases, cloneBlueprintRelease(v))
	}
	for _, v := range s.catalogTrustKeys {
		snap.CatalogTrustKeys = append(snap.CatalogTrustKeys, v)
	}
	for _, v := range s.catalogRevisions {
		v.Payload = append([]byte(nil), v.Payload...)
		snap.CatalogRevisions = append(snap.CatalogRevisions, v)
	}
	for _, v := range s.catalogReleases {
		snap.CatalogReleases = append(snap.CatalogReleases, v)
	}
	for _, v := range s.assignments {
		snap.Assignments = append(snap.Assignments, v)
	}
	for _, v := range s.operations {
		snap.Operations = append(snap.Operations, v)
	}
	for _, v := range s.steps {
		snap.Steps = append(snap.Steps, v)
	}
	for _, v := range s.stepTraces {
		snap.StepTraces = append(snap.StepTraces, v)
	}
	for _, v := range s.compensationSteps {
		snap.CompensationSteps = append(snap.CompensationSteps, v)
	}
	for _, v := range s.outbox {
		v.Payload = append([]byte(nil), v.Payload...)
		snap.Outbox = append(snap.Outbox, v)
	}
	for _, v := range s.notificationDestinations {
		snap.NotificationDestinations = append(snap.NotificationDestinations, v)
	}
	for _, v := range s.notificationRoutes {
		v.EventPatterns = append([]string(nil), v.EventPatterns...)
		v.DestinationIDs = append([]string(nil), v.DestinationIDs...)
		snap.NotificationRoutes = append(snap.NotificationRoutes, v)
	}
	for _, v := range s.notificationEvents {
		v.Payload = append([]byte(nil), v.Payload...)
		snap.NotificationEvents = append(snap.NotificationEvents, v)
	}
	for _, v := range s.notificationDeliveries {
		snap.NotificationDeliveries = append(snap.NotificationDeliveries, v)
	}
	for _, v := range s.notificationAttempts {
		snap.NotificationAttempts = append(snap.NotificationAttempts, v)
	}
	snap.Audit = append([]AuditEvent(nil), s.audit...)
	for _, v := range s.evidence {
		snap.Evidence = append(snap.Evidence, v)
	}
	for id, payload := range s.evidencePayloads {
		snap.EvidencePayloads = append(snap.EvidencePayloads, EvidencePayload{EvidenceID: id, Payload: append([]byte(nil), payload...)})
	}
	for _, v := range s.clusterImports {
		snap.ClusterImports = append(snap.ClusterImports, v)
		snap.ClusterImportCredentials = append(snap.ClusterImportCredentials, ClusterImportCredentialSnapshot{ImportID: v.ID, TokenDigest: v.TokenDigest, AgentTokenDigest: v.AgentTokenDigest})
	}
	for _, v := range s.managedClusters {
		snap.ManagedClusters = append(snap.ManagedClusters, cloneManagedCluster(v))
	}
	for _, v := range s.clusterMaintenanceProfiles {
		snap.ClusterMaintenanceProfiles = append(snap.ClusterMaintenanceProfiles, v)
	}
	for _, v := range s.clusterMaintenanceWindows {
		snap.ClusterMaintenanceWindows = append(snap.ClusterMaintenanceWindows, v)
	}
	for _, v := range s.clusterMaintenanceRuns {
		snap.ClusterMaintenanceRuns = append(snap.ClusterMaintenanceRuns, cloneClusterMaintenanceRun(v))
	}
	for _, v := range s.agentCertificates {
		snap.AgentCertificates = append(snap.AgentCertificates, v)
	}
	for _, v := range s.clusterInventories {
		snap.ClusterInventories = append(snap.ClusterInventories, cloneClusterInventory(v))
	}
	for _, v := range s.baselineDeployments {
		v.Plan = append([]BaselinePlanChange(nil), v.Plan...)
		snap.BaselineDeployments = append(snap.BaselineDeployments, v)
	}
	for _, v := range s.runtimeVerifications {
		v.Checks = append([]RuntimeCheck(nil), v.Checks...)
		snap.RuntimeVerifications = append(snap.RuntimeVerifications, v)
	}
	for _, v := range s.runtimeCertifications {
		snap.RuntimeCertifications = append(snap.RuntimeCertifications, cloneRuntimeCertification(v))
	}
	for _, v := range s.recoveryCheckpoints {
		snap.RecoveryCheckpoints = append(snap.RecoveryCheckpoints, v)
	}
	for _, v := range s.fleetGroups {
		snap.FleetGroups = append(snap.FleetGroups, cloneFleetGroup(v))
	}
	for _, v := range s.gitCredentials {
		snap.GitCredentials = append(snap.GitCredentials, v)
	}
	for _, v := range s.gitProviders {
		snap.GitProviders = append(snap.GitProviders, v)
	}
	for _, v := range s.gitPullRequests {
		snap.GitPullRequests = append(snap.GitPullRequests, v)
	}
	for _, v := range s.managedGitRevisions {
		snap.ManagedGitRevisions = append(snap.ManagedGitRevisions, v)
	}
	for _, v := range s.driftScans {
		snap.DriftScans = append(snap.DriftScans, cloneDriftScan(v))
	}
	for _, v := range s.upgradeCampaigns {
		snap.UpgradeCampaigns = append(snap.UpgradeCampaigns, cloneUpgradeCampaign(v))
	}
	for _, v := range s.entitlements {
		v.Features = append([]string(nil), v.Features...)
		snap.Entitlements = append(snap.Entitlements, v)
	}
	for _, v := range s.oemProfiles {
		snap.OEMProfiles = append(snap.OEMProfiles, v)
	}
	for _, v := range s.tenants {
		v.Quota = cloneStringMap(v.Quota)
		snap.Tenants = append(snap.Tenants, v)
	}
	for _, v := range s.providerProfiles {
		v.KubernetesSeries = append([]string(nil), v.KubernetesSeries...)
		snap.ProviderProfiles = append(snap.ProviderProfiles, v)
	}
	for _, v := range s.providerClusters {
		snap.ProviderClusters = append(snap.ProviderClusters, v)
	}
	for _, v := range s.aiRuns {
		snap.AIRuns = append(snap.AIRuns, cloneAIRun(v))
	}
	for _, v := range s.marketplaceRecommendations {
		v.Items = append([]MarketplaceRecommendationItem(nil), v.Items...)
		snap.MarketplaceRecommendations = append(snap.MarketplaceRecommendations, v)
	}
	for _, v := range s.runtimeClosureCampaigns {
		snap.RuntimeClosureCampaigns = append(snap.RuntimeClosureCampaigns, v)
	}
	CanonicalizeSnapshot(&snap)
	return snap, nil
}

// CanonicalizeSnapshot normalizes snapshot collection ordering so semantically
// identical authoritative state has one stable representation across Memory,
// File and PostgreSQL backends. Append-only audit chains intentionally retain
// their sequence/chronological order and are not resorted here.
func CanonicalizeSnapshot(s *Snapshot) {
	sort.Slice(s.Organizations, func(i, j int) bool { return s.Organizations[i].ID < s.Organizations[j].ID })
	sort.Slice(s.OrganizationMemberships, func(i, j int) bool { return s.OrganizationMemberships[i].ID < s.OrganizationMemberships[j].ID })
	sort.Slice(s.OIDCGroupMappings, func(i, j int) bool { return s.OIDCGroupMappings[i].ID < s.OIDCGroupMappings[j].ID })
	sort.Slice(s.ServiceAccounts, func(i, j int) bool { return s.ServiceAccounts[i].ID < s.ServiceAccounts[j].ID })
	sort.Slice(s.APITokens, func(i, j int) bool { return s.APITokens[i].ID < s.APITokens[j].ID })
	sort.Slice(s.Projects, func(i, j int) bool { return s.Projects[i].ID < s.Projects[j].ID })
	sort.Slice(s.BlueprintOverlays, func(i, j int) bool { return s.BlueprintOverlays[i].ID < s.BlueprintOverlays[j].ID })
	sort.Slice(s.Revisions, func(i, j int) bool { return s.Revisions[i].ID < s.Revisions[j].ID })
	sort.Slice(s.BlueprintReleases, func(i, j int) bool { return s.BlueprintReleases[i].ID < s.BlueprintReleases[j].ID })
	sort.Slice(s.CatalogTrustKeys, func(i, j int) bool { return s.CatalogTrustKeys[i].ID < s.CatalogTrustKeys[j].ID })
	sort.Slice(s.CatalogRevisions, func(i, j int) bool { return s.CatalogRevisions[i].ID < s.CatalogRevisions[j].ID })
	sort.Slice(s.CatalogReleases, func(i, j int) bool { return s.CatalogReleases[i].ID < s.CatalogReleases[j].ID })
	sort.Slice(s.Assignments, func(i, j int) bool { return s.Assignments[i].ID < s.Assignments[j].ID })
	sort.Slice(s.Operations, func(i, j int) bool { return s.Operations[i].ID < s.Operations[j].ID })
	sort.Slice(s.Steps, func(i, j int) bool { return s.Steps[i].ID < s.Steps[j].ID })
	sort.Slice(s.StepTraces, func(i, j int) bool { return s.StepTraces[i].ID < s.StepTraces[j].ID })
	sort.Slice(s.CompensationSteps, func(i, j int) bool {
		if s.CompensationSteps[i].OperationID != s.CompensationSteps[j].OperationID {
			return s.CompensationSteps[i].OperationID < s.CompensationSteps[j].OperationID
		}
		if s.CompensationSteps[i].ForwardOrder != s.CompensationSteps[j].ForwardOrder {
			return s.CompensationSteps[i].ForwardOrder < s.CompensationSteps[j].ForwardOrder
		}
		return s.CompensationSteps[i].ID < s.CompensationSteps[j].ID
	})
	sort.Slice(s.Outbox, func(i, j int) bool { return s.Outbox[i].ID < s.Outbox[j].ID })
	sort.Slice(s.NotificationDestinations, func(i, j int) bool { return s.NotificationDestinations[i].ID < s.NotificationDestinations[j].ID })
	sort.Slice(s.NotificationRoutes, func(i, j int) bool { return s.NotificationRoutes[i].ID < s.NotificationRoutes[j].ID })
	sort.Slice(s.NotificationEvents, func(i, j int) bool { return s.NotificationEvents[i].ID < s.NotificationEvents[j].ID })
	sort.Slice(s.NotificationDeliveries, func(i, j int) bool { return s.NotificationDeliveries[i].ID < s.NotificationDeliveries[j].ID })
	sort.Slice(s.NotificationAttempts, func(i, j int) bool { return s.NotificationAttempts[i].ID < s.NotificationAttempts[j].ID })
	sort.Slice(s.Evidence, func(i, j int) bool { return s.Evidence[i].ID < s.Evidence[j].ID })
	sort.Slice(s.EvidencePayloads, func(i, j int) bool { return s.EvidencePayloads[i].EvidenceID < s.EvidencePayloads[j].EvidenceID })
	sort.Slice(s.ClusterImports, func(i, j int) bool { return s.ClusterImports[i].ID < s.ClusterImports[j].ID })
	sort.Slice(s.ClusterImportCredentials, func(i, j int) bool {
		return s.ClusterImportCredentials[i].ImportID < s.ClusterImportCredentials[j].ImportID
	})
	sort.Slice(s.ManagedClusters, func(i, j int) bool { return s.ManagedClusters[i].ID < s.ManagedClusters[j].ID })
	sort.Slice(s.ClusterMaintenanceProfiles, func(i, j int) bool {
		return s.ClusterMaintenanceProfiles[i].ClusterID < s.ClusterMaintenanceProfiles[j].ClusterID
	})
	sort.Slice(s.ClusterMaintenanceWindows, func(i, j int) bool { return s.ClusterMaintenanceWindows[i].ID < s.ClusterMaintenanceWindows[j].ID })
	sort.Slice(s.ClusterMaintenanceRuns, func(i, j int) bool { return s.ClusterMaintenanceRuns[i].ID < s.ClusterMaintenanceRuns[j].ID })
	sort.Slice(s.AgentCertificates, func(i, j int) bool { return s.AgentCertificates[i].ID < s.AgentCertificates[j].ID })
	sort.Slice(s.ClusterInventories, func(i, j int) bool { return s.ClusterInventories[i].ID < s.ClusterInventories[j].ID })
	sort.Slice(s.BaselineDeployments, func(i, j int) bool { return s.BaselineDeployments[i].ID < s.BaselineDeployments[j].ID })
	sort.Slice(s.RuntimeVerifications, func(i, j int) bool { return s.RuntimeVerifications[i].ID < s.RuntimeVerifications[j].ID })
	sort.Slice(s.RuntimeCertifications, func(i, j int) bool { return s.RuntimeCertifications[i].ID < s.RuntimeCertifications[j].ID })
	sort.Slice(s.RecoveryCheckpoints, func(i, j int) bool { return s.RecoveryCheckpoints[i].ID < s.RecoveryCheckpoints[j].ID })
	sort.Slice(s.FleetGroups, func(i, j int) bool { return s.FleetGroups[i].ID < s.FleetGroups[j].ID })
	sort.Slice(s.GitCredentials, func(i, j int) bool { return s.GitCredentials[i].ID < s.GitCredentials[j].ID })
	sort.Slice(s.GitProviders, func(i, j int) bool { return s.GitProviders[i].ID < s.GitProviders[j].ID })
	sort.Slice(s.GitPullRequests, func(i, j int) bool { return s.GitPullRequests[i].ID < s.GitPullRequests[j].ID })
	sort.Slice(s.ManagedGitRevisions, func(i, j int) bool { return s.ManagedGitRevisions[i].ID < s.ManagedGitRevisions[j].ID })
	sort.Slice(s.DriftScans, func(i, j int) bool { return s.DriftScans[i].ID < s.DriftScans[j].ID })
	sort.Slice(s.UpgradeCampaigns, func(i, j int) bool { return s.UpgradeCampaigns[i].ID < s.UpgradeCampaigns[j].ID })
	sort.Slice(s.Entitlements, func(i, j int) bool { return s.Entitlements[i].OrganizationID < s.Entitlements[j].OrganizationID })
	sort.Slice(s.OEMProfiles, func(i, j int) bool { return s.OEMProfiles[i].OrganizationID < s.OEMProfiles[j].OrganizationID })
	sort.Slice(s.Tenants, func(i, j int) bool { return s.Tenants[i].ID < s.Tenants[j].ID })
	sort.Slice(s.ProviderProfiles, func(i, j int) bool { return s.ProviderProfiles[i].ID < s.ProviderProfiles[j].ID })
	sort.Slice(s.ProviderClusters, func(i, j int) bool { return s.ProviderClusters[i].ID < s.ProviderClusters[j].ID })
	sort.Slice(s.AIRuns, func(i, j int) bool { return s.AIRuns[i].ID < s.AIRuns[j].ID })
	sort.Slice(s.MarketplaceRecommendations, func(i, j int) bool { return s.MarketplaceRecommendations[i].ID < s.MarketplaceRecommendations[j].ID })
	sort.Slice(s.RuntimeClosureCampaigns, func(i, j int) bool { return s.RuntimeClosureCampaigns[i].ID < s.RuntimeClosureCampaigns[j].ID })
}
func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeRestoredManagedClusterAuthority(clusters []ManagedCluster, audit []AuditEvent) []ManagedCluster {
	out := make([]ManagedCluster, len(clusters))
	index := make(map[string]int, len(clusters))
	for i, cluster := range clusters {
		out[i] = cloneManagedCluster(cluster)
		index[cluster.ID] = i
	}
	for _, event := range audit {
		i, ok := index[event.ResourceID]
		if !ok || event.ResourceType != "managedCluster" {
			continue
		}
		switch event.Action {
		case "cluster.mutation_rbac_activation.authorized":
			out[i].Capabilities = dedupeSortedStrings(append(out[i].Capabilities, TargetMutationRBACEverIssuedCapability))
		case "managed_cluster.target_rbac_revocation_acknowledged":
			digest, _ := event.Metadata["fenceDigest"].(string)
			if strings.HasPrefix(strings.TrimSpace(digest), "sha256:") {
				at := event.OccurredAt.UTC()
				out[i].TargetRBACRevocationAcknowledgedDigest = strings.TrimSpace(digest)
				out[i].TargetRBACRevocationAcknowledgedAt = &at
				out[i].TargetRBACRevocationAcknowledgedBy = strings.TrimSpace(event.ActorID)
			}
		}
	}
	// Repair legacy unsafe ordering: a successor created before digest-bound
	// acknowledgement existed must not retain mutation authority while any
	// revoked predecessor for the same physical UID remains unacknowledged.
	for i := range out {
		if out[i].ConnectionState == "REVOKED" || strings.TrimSpace(out[i].ExternalUID) == "" {
			continue
		}
		blocked := false
		for j := range out {
			if i == j || out[j].ConnectionState != "REVOKED" || !secureEqual(strings.TrimSpace(out[i].ExternalUID), strings.TrimSpace(out[j].ExternalUID)) {
				continue
			}
			if !ClusterTargetRBACRevocationAcknowledged(out[j]) {
				blocked = true
				break
			}
		}
		if blocked {
			out[i].Capabilities = removeClusterCapability(out[i].Capabilities, TargetMutationRBACActiveCapability)
			out[i].Capabilities = removeClusterCapability(out[i].Capabilities, TargetMutationRBACActivationIssuedCapability)
			out[i].Capabilities = dedupeSortedStrings(append(out[i].Capabilities, TargetReadOnlyAdmissionCapability))
			out[i].MutationRBACIssuedForDigest = ""
		}
	}
	return out
}

func (s *MemoryStore) Restore(snapshot Snapshot) error {
	// Validate every fallible snapshot invariant before replacing live authority.
	// Restore is used by FileStore rollback after a failed durable write, so an
	// invalid input must never turn an error return into partial/empty state.
	if err := ValidateSecurityAuditChain(snapshot.SecurityAudit); err != nil && len(snapshot.SecurityAudit) > 0 {
		return err
	}
	normalizedManagedClusters := normalizeRestoredManagedClusterAuthority(snapshot.ManagedClusters, snapshot.Audit)
	projectsByID := make(map[string]Project, len(snapshot.Projects))
	for _, project := range snapshot.Projects {
		projectsByID[project.ID] = project
	}
	operationsByID := make(map[string]Operation, len(snapshot.Operations))
	for _, operation := range snapshot.Operations {
		operationsByID[operation.ID] = operation
	}
	clustersByID := make(map[string]ManagedCluster, len(normalizedManagedClusters))
	for _, cluster := range normalizedManagedClusters {
		clustersByID[cluster.ID] = cluster
	}
	for i := range snapshot.AIRuns {
		run := cloneAIRun(snapshot.AIRuns[i])
		if err := ValidateAIRun(&run); err != nil {
			return err
		}
		if _, ok := projectsByID[run.ProjectID]; !ok {
			return fmt.Errorf("%w: AI run project %q does not exist", ErrValidation, run.ProjectID)
		}
		switch run.LinkedResourceType {
		case "operation":
			linked, ok := operationsByID[run.LinkedResourceID]
			if !ok || linked.ProjectID != run.ProjectID {
				return fmt.Errorf("%w: AI run operation link is outside project authority", ErrValidation)
			}
		case "managedCluster":
			linked, ok := clustersByID[run.LinkedResourceID]
			if !ok || linked.ProjectID != run.ProjectID {
				return fmt.Errorf("%w: AI run managed-cluster link is outside project authority", ErrValidation)
			}
		}
	}
	activeClusterUIDs := map[string]string{}
	for _, cluster := range normalizedManagedClusters {
		uid := strings.TrimSpace(cluster.ExternalUID)
		if cluster.ConnectionState == "REVOKED" || uid == "" {
			continue
		}
		if existingID, ok := activeClusterUIDs[uid]; ok && existingID != cluster.ID {
			return fmt.Errorf("%w: physical cluster UID %q has multiple active managed-cluster authorities", ErrValidation, uid)
		}
		activeClusterUIDs[uid] = cluster.ID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.organizations = map[string]Organization{}
	s.organizationMemberships = map[string]OrganizationMembership{}
	s.oidcGroupMappings = map[string]OIDCGroupMapping{}
	s.securityAudit = nil
	s.serviceAccounts = map[string]ServiceAccount{}
	s.apiTokens = map[string]APIToken{}
	s.projects = map[string]Project{}
	s.blueprintOverlays = map[string]BlueprintOverlay{}
	s.revisions = map[string]BlueprintRevision{}
	s.blueprintReleases = map[string]BlueprintRelease{}
	s.catalogTrustKeys = map[string]CatalogTrustKey{}
	s.catalogRevisions = map[string]CatalogRevision{}
	s.catalogReleases = map[string]CatalogRelease{}
	s.assignments = map[string]Assignment{}
	s.operations = map[string]Operation{}
	s.steps = map[string]OperationStep{}
	s.stepTraces = map[string]OperationStepTrace{}
	s.compensationSteps = map[string]OperationCompensationStep{}
	s.outbox = map[string]OutboxEvent{}
	s.notificationDestinations = map[string]NotificationDestination{}
	s.notificationRoutes = map[string]NotificationRoute{}
	s.notificationEvents = map[string]NotificationEvent{}
	s.notificationDeliveries = map[string]NotificationDelivery{}
	s.notificationAttempts = map[string]NotificationDeliveryAttempt{}
	s.evidence = map[string]EvidenceMetadata{}
	s.evidencePayloads = map[string][]byte{}
	s.idempotency = map[string]string{}
	s.clusterImports = map[string]ClusterImport{}
	s.managedClusters = map[string]ManagedCluster{}
	s.agentCertificates = map[string]AgentCertificate{}
	s.clusterInventories = map[string]ClusterInventory{}
	s.baselineDeployments = map[string]BaselineDeployment{}
	s.runtimeVerifications = map[string]RuntimeVerification{}
	s.runtimeCertifications = map[string]RuntimeCertificationRun{}
	s.fleetGroups = map[string]FleetGroup{}
	s.gitCredentials = map[string]GitCredential{}
	s.gitProviders = map[string]GitProvider{}
	s.gitPullRequests = map[string]GitPullRequest{}
	s.managedGitRevisions = map[string]ManagedGitRevision{}
	s.driftScans = map[string]DriftScan{}
	s.upgradeCampaigns = map[string]UpgradeCampaign{}
	s.entitlements = map[string]Entitlement{}
	s.oemProfiles = map[string]OEMProfile{}
	s.tenants = map[string]TenantEnvironment{}
	s.providerProfiles = map[string]ProviderProfile{}
	s.providerClusters = map[string]ProviderCluster{}
	s.aiRuns = map[string]AIRun{}
	s.marketplaceRecommendations = map[string]MarketplaceRecommendation{}
	s.runtimeClosureCampaigns = map[string]RuntimeClosureCampaign{}
	for _, v := range snapshot.Organizations {
		s.organizations[v.ID] = v
	}
	for _, v := range snapshot.OrganizationMemberships {
		s.organizationMemberships[v.ID] = v
	}
	for _, v := range snapshot.OIDCGroupMappings {
		s.oidcGroupMappings[v.ID] = v
	}
	s.securityAudit = append([]SecurityAuditEvent(nil), snapshot.SecurityAudit...)
	for _, v := range snapshot.ServiceAccounts {
		s.serviceAccounts[v.ID] = v
	}
	for _, v := range snapshot.APITokens {
		v.Permissions = append([]string(nil), v.Permissions...)
		s.apiTokens[v.ID] = v
	}
	for _, v := range snapshot.Projects {
		s.projects[v.ID] = v
	}
	for _, v := range snapshot.BlueprintOverlays {
		s.blueprintOverlays[v.ID] = cloneOverlay(v)
	}
	for _, v := range snapshot.Revisions {
		v = NormalizeBlueprintRevisionResolution(v)
		v.Payload = append([]byte(nil), v.Payload...)
		v.BasePayload = append([]byte(nil), v.BasePayload...)
		v.ResolutionPayload = append([]byte(nil), v.ResolutionPayload...)
		s.revisions[v.ID] = v
	}
	for _, v := range snapshot.BlueprintReleases {
		s.blueprintReleases[v.ID] = cloneBlueprintRelease(v)
	}
	for _, v := range snapshot.CatalogTrustKeys {
		s.catalogTrustKeys[v.ID] = v
	}
	for _, v := range snapshot.CatalogRevisions {
		v.Payload = append([]byte(nil), v.Payload...)
		s.catalogRevisions[v.ID] = v
	}
	for _, v := range snapshot.CatalogReleases {
		s.catalogReleases[v.ID] = v
	}
	for _, v := range snapshot.Assignments {
		s.assignments[v.ID] = v
	}
	for _, v := range snapshot.Operations {
		if v.Class == "" {
			v.Class = OperationClassMutating
		}
		if v.RetryPolicy.MaxAttempts <= 0 {
			v.RetryPolicy = RetryPolicyForOperationClass(v.Class)
		}
		s.operations[v.ID] = v
		s.idempotency[v.ProjectID+":"+v.IdempotencyKey] = v.ID
	}
	for _, v := range snapshot.Steps {
		if v.Attempt < 1 {
			v.Attempt = 1
		}
		s.steps[fmt.Sprintf("%s:%d:%s", v.OperationID, v.Attempt, v.StepKey)] = v
	}
	for _, v := range snapshot.StepTraces {
		s.stepTraces[v.OperationID+":"+string(v.Phase)+":"+v.StepKey+":"+fmt.Sprint(v.Attempt)+":"+v.TraceKey] = v
	}
	for _, v := range snapshot.CompensationSteps {
		if v.MaxAttempts < 1 {
			v.MaxAttempts = 3
		}
		if v.State == "" {
			v.State = CompensationStepPending
		}
		s.compensationSteps[v.OperationID+":"+v.StepKey] = v
	}
	for _, v := range snapshot.Outbox {
		s.outbox[v.ID] = v
	}
	for _, v := range snapshot.NotificationDestinations {
		s.notificationDestinations[v.ID] = v
	}
	for _, v := range snapshot.NotificationRoutes {
		v.EventPatterns = append([]string(nil), v.EventPatterns...)
		v.DestinationIDs = append([]string(nil), v.DestinationIDs...)
		s.notificationRoutes[v.ID] = v
	}
	for _, v := range snapshot.NotificationEvents {
		v.Payload = append([]byte(nil), v.Payload...)
		s.notificationEvents[v.ID] = v
	}
	for _, v := range snapshot.NotificationDeliveries {
		s.notificationDeliveries[v.ID] = v
	}
	for _, v := range snapshot.NotificationAttempts {
		s.notificationAttempts[v.ID] = v
	}
	s.audit = append([]AuditEvent(nil), snapshot.Audit...)
	for _, v := range snapshot.Evidence {
		s.evidence[v.ID] = v
	}
	for _, v := range snapshot.EvidencePayloads {
		s.evidencePayloads[v.EvidenceID] = append([]byte(nil), v.Payload...)
	}
	for _, v := range snapshot.ClusterImports {
		s.clusterImports[v.ID] = v
	}
	for _, credential := range snapshot.ClusterImportCredentials {
		v, ok := s.clusterImports[credential.ImportID]
		if !ok {
			continue
		}
		v.TokenDigest = credential.TokenDigest
		v.AgentTokenDigest = credential.AgentTokenDigest
		s.clusterImports[v.ID] = v
	}
	for _, v := range normalizedManagedClusters {
		s.managedClusters[v.ID] = cloneManagedCluster(v)
	}
	for _, v := range snapshot.ClusterMaintenanceProfiles {
		s.clusterMaintenanceProfiles[v.ClusterID] = v
	}
	for _, v := range snapshot.ClusterMaintenanceWindows {
		s.clusterMaintenanceWindows[v.ID] = v
	}
	for _, v := range snapshot.ClusterMaintenanceRuns {
		s.clusterMaintenanceRuns[v.ID] = cloneClusterMaintenanceRun(v)
	}
	for _, v := range snapshot.AgentCertificates {
		s.agentCertificates[v.ID] = v
	}
	for _, v := range snapshot.ClusterInventories {
		s.clusterInventories[v.ClusterID] = cloneClusterInventory(v)
	}
	for _, v := range snapshot.BaselineDeployments {
		v.Plan = append([]BaselinePlanChange(nil), v.Plan...)
		s.baselineDeployments[v.ID] = v
	}
	for _, v := range snapshot.RuntimeVerifications {
		v.Checks = append([]RuntimeCheck(nil), v.Checks...)
		s.runtimeVerifications[v.ID] = v
	}
	for _, v := range snapshot.RuntimeCertifications {
		s.runtimeCertifications[v.ID] = cloneRuntimeCertification(v)
	}
	for _, v := range snapshot.RecoveryCheckpoints {
		s.recoveryCheckpoints[v.ID] = v
	}
	for _, v := range snapshot.FleetGroups {
		s.fleetGroups[v.ID] = cloneFleetGroup(v)
	}
	for _, v := range snapshot.GitCredentials {
		s.gitCredentials[v.ID] = v
	}
	for _, v := range snapshot.GitProviders {
		s.gitProviders[v.ID] = v
	}
	for _, v := range snapshot.GitPullRequests {
		s.gitPullRequests[v.ID] = v
	}
	for _, v := range snapshot.ManagedGitRevisions {
		s.managedGitRevisions[v.ID] = v
	}
	for _, v := range snapshot.DriftScans {
		s.driftScans[v.ID] = cloneDriftScan(v)
	}
	for _, v := range snapshot.UpgradeCampaigns {
		s.upgradeCampaigns[v.ID] = cloneUpgradeCampaign(v)
	}
	for _, v := range snapshot.Entitlements {
		v.Features = append([]string(nil), v.Features...)
		s.entitlements[v.OrganizationID] = v
	}
	for _, v := range snapshot.OEMProfiles {
		s.oemProfiles[v.OrganizationID] = v
	}
	for _, v := range snapshot.Tenants {
		v.Quota = cloneStringMap(v.Quota)
		s.tenants[v.ID] = v
	}
	for _, v := range snapshot.ProviderProfiles {
		v.KubernetesSeries = append([]string(nil), v.KubernetesSeries...)
		s.providerProfiles[v.ID] = v
	}
	for _, v := range snapshot.ProviderClusters {
		s.providerClusters[v.ID] = v
	}
	for _, v := range snapshot.AIRuns {
		s.aiRuns[v.ID] = cloneAIRun(v)
	}
	for _, v := range snapshot.MarketplaceRecommendations {
		v.Items = append([]MarketplaceRecommendationItem(nil), v.Items...)
		s.marketplaceRecommendations[v.ID] = v
	}
	for _, v := range snapshot.RuntimeClosureCampaigns {
		s.runtimeClosureCampaigns[v.ID] = v
	}
	return nil
}
