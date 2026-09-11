package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"platform.4so.io/factory/internal/targetmodel"
	"sort"
	"strings"
	"time"
)

const (
	DistributionEvidenceKubeletV1                = "KUBELET_VERSION_V1"
	DistributionEvidenceOKDClusterV1             = "OKD_CLUSTERVERSION_V1"
	DistributionEvidenceOpenShiftClusterV1       = "OPENSHIFT_CLUSTERVERSION_V1"
	TargetReadOnlyAdmissionCapability            = "target-read-only-admission"
	TargetMutationRBACActiveCapability           = "target-mutation-rbac-active"
	TargetMutationRBACActivationIssuedCapability = "target-mutation-rbac-activation-issued"
	TargetMutationRBACEverIssuedCapability       = "target-mutation-rbac-ever-issued"
	TargetIdentityContinuityCapability           = "target-cluster-uid-attested"
	TargetEnrollmentPrincipalIsolatedCapability  = "target-enrollment-principal-isolated"
)

func FleetAgentServiceAccountName(importID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(importID)))
	return fmt.Sprintf("4so-platform-agent-%x", sum[:8])
}

var previewMutationCapabilities = map[string]struct{}{
	"controlled-baseline-deployment":             {},
	TenantDeleteObservedCapability:               {},
	ClusterMaintenanceFencedReportCapability:     {},
	"strict-schema-dry-run":                      {},
	TargetMutationRBACActiveCapability:           {},
	TargetMutationRBACActivationIssuedCapability: {},
	TargetMutationRBACEverIssuedCapability:       {},
}

const (
	ClusterInventoryAuthorityFreshness    = 3 * time.Minute
	ClusterInventoryObservationFutureSkew = ClusterInventoryAuthorityFreshness
)

func ClusterMutationRBACActivationCurrent(c ManagedCluster) bool {
	return clusterHasCapability(c, TargetMutationRBACActivationIssuedCapability) &&
		strings.HasPrefix(strings.TrimSpace(c.MutationRBACBasisDigest), "sha256:") &&
		secureEqual(strings.TrimSpace(c.MutationRBACBasisDigest), strings.TrimSpace(c.MutationRBACIssuedForDigest))
}

func ClusterTaskAdmitted(c ManagedCluster) bool {
	return c.ConnectionState == "CONNECTED" &&
		ClusterMutationAdmissionEligible(c) &&
		c.InventoryDigest != "" && c.InventoryUpdatedAt != nil && c.LastSeenAt != nil &&
		c.InventoryUpdatedAt.Equal(*c.LastSeenAt) &&
		clusterHasCapability(c, TargetMutationRBACActiveCapability) &&
		ClusterMutationRBACActivationCurrent(c)
}

func ClusterInventoryAuthorityFreshAt(c ManagedCluster, now time.Time) bool {
	if c.ConnectionState != "CONNECTED" || c.InventoryDigest == "" || c.InventoryUpdatedAt == nil || c.InventoryObservedAt == nil || c.LastSeenAt == nil || !c.InventoryUpdatedAt.Equal(*c.LastSeenAt) {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	receiptAge := now.Sub(c.LastSeenAt.UTC())
	observationAge := now.Sub(c.InventoryObservedAt.UTC())
	return receiptAge >= 0 && receiptAge <= ClusterInventoryAuthorityFreshness &&
		observationAge >= -ClusterInventoryObservationFutureSkew && observationAge <= ClusterInventoryAuthorityFreshness
}

func ValidateClusterInventoryObservationEpoch(c ManagedCluster, observedAt, now time.Time) error {
	if observedAt.IsZero() {
		return fmt.Errorf("%w: inventory observation timestamp is required", ErrValidation)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	observedAt = observedAt.UTC()
	now = now.UTC()
	if observedAt.After(now.Add(ClusterInventoryObservationFutureSkew)) {
		return fmt.Errorf("%w: inventory observation timestamp is too far in the future", ErrPrerequisite)
	}
	if now.Sub(observedAt) > ClusterInventoryAuthorityFreshness {
		return fmt.Errorf("%w: inventory observation is stale", ErrPrerequisite)
	}
	if c.InventoryObservedAt != nil && observedAt.Before(c.InventoryObservedAt.UTC()) {
		return fmt.Errorf("%w: inventory observation timestamp moved backwards", ErrConflict)
	}
	return nil
}

func ClusterTaskClaimAdmittedAt(c ManagedCluster, now time.Time) bool {
	return ClusterTaskAdmitted(c) && ClusterInventoryAuthorityFreshAt(c, now)
}

func NormalizeClusterInventoryReadOnly(inv ClusterInventory) ClusterInventory {
	filtered := make([]string, 0, len(inv.Capabilities)+1)
	for _, capability := range inv.Capabilities {
		if _, mutating := previewMutationCapabilities[capability]; !mutating {
			filtered = append(filtered, capability)
		}
	}
	filtered = append(filtered, TargetReadOnlyAdmissionCapability)
	inv.Capabilities = dedupeSortedStrings(filtered)
	return inv
}

func NormalizeClusterInventoryIdentityAuthority(inv ClusterInventory, verified bool) ClusterInventory {
	filtered := make([]string, 0, len(inv.Capabilities)+1)
	for _, capability := range inv.Capabilities {
		if strings.TrimSpace(capability) != TargetIdentityContinuityCapability {
			filtered = append(filtered, capability)
		}
	}
	inv.Capabilities = filtered
	if verified {
		inv.Capabilities = dedupeSortedStrings(append(inv.Capabilities, TargetIdentityContinuityCapability))
		return inv
	}
	return NormalizeClusterInventoryReadOnly(inv)
}

func NormalizeClusterInventoryForAdmission(inv ClusterInventory) ClusterInventory {
	inv.Distribution = targetmodel.CanonicalDistribution(inv.Distribution)
	if inv.Distribution == targetmodel.DistributionOKD {
		inv = NormalizeOKDInventoryAuthority(inv)
	}
	if ClusterInventoryMutationEligible(inv) {
		return inv
	}
	return NormalizeClusterInventoryReadOnly(inv)
}

// ClusterInventoryMutationBasisDigest binds mutation authorization only to
// stable target-identity facts that define who the imported Kubernetes target
// is. Discovery catalog churn (for example an unrelated OLM Operator adding a
// CRD/API) and runtime telemetry are intentionally excluded; task/plan safety
// continues to bind to the full authenticated inventory digest separately.
func ClusterInventoryMutationBasisDigest(inv ClusterInventory) string {
	authority := struct {
		Distribution                string `json:"distribution"`
		DistributionEvidenceMethod  string `json:"distributionEvidenceMethod,omitempty"`
		DistributionEvidenceUID     string `json:"distributionEvidenceUid,omitempty"`
		DistributionEvidenceVersion string `json:"distributionEvidenceVersion,omitempty"`
		KubernetesVersion           string `json:"kubernetesVersion"`
		IdentityContinuityVerified  bool   `json:"identityContinuityVerified"`
		EnrollmentPrincipalIsolated bool   `json:"enrollmentPrincipalIsolated"`
	}{
		Distribution:                targetmodel.CanonicalDistribution(inv.Distribution),
		DistributionEvidenceMethod:  strings.TrimSpace(inv.DistributionEvidenceMethod),
		DistributionEvidenceUID:     strings.TrimSpace(inv.DistributionEvidenceUID),
		DistributionEvidenceVersion: strings.TrimSpace(inv.DistributionEvidenceVersion),
		KubernetesVersion:           strings.TrimSpace(inv.KubernetesVersion),
		IdentityContinuityVerified:  clusterHasCapability(ManagedCluster{Capabilities: inv.Capabilities}, TargetIdentityContinuityCapability),
		EnrollmentPrincipalIsolated: clusterHasCapability(ManagedCluster{Capabilities: inv.Capabilities}, TargetEnrollmentPrincipalIsolatedCapability),
	}
	raw, _ := json.Marshal(authority)
	return digestBytes(raw)
}

// ClusterMayHaveTargetMutationRBAC is deliberately sticky/mixed-version safe.
// Revocation must fence target-local mutation bindings whenever the Hub has
// evidence that activation was ever issued or proven, even if later authority
// drift removed the current active/issued capabilities.
func ClusterMayHaveTargetMutationRBAC(c ManagedCluster) bool {
	return clusterHasCapability(c, TargetMutationRBACEverIssuedCapability) ||
		clusterHasCapability(c, TargetMutationRBACActivationIssuedCapability) ||
		clusterHasCapability(c, TargetMutationRBACActiveCapability)
}

func ClusterTargetRBACRevocationFenceDigest(c ManagedCluster) string {
	authorityDigest := strings.TrimSpace(c.InventoryDigest)
	if authorityDigest == "" {
		authorityDigest = strings.TrimSpace(c.MutationRBACBasisDigest)
	}
	raw, _ := json.Marshal(struct {
		ClusterID        string `json:"clusterId"`
		ExternalUID      string `json:"externalUid"`
		AuthorityDigest  string `json:"authorityDigest"`
		MutationMayExist bool   `json:"mutationMayExist"`
	}{strings.TrimSpace(c.ID), strings.TrimSpace(c.ExternalUID), authorityDigest, ClusterMayHaveTargetMutationRBAC(c)})
	return digestBytes(raw)
}

func ClusterTargetRBACRevocationAcknowledged(c ManagedCluster) bool {
	expected := ClusterTargetRBACRevocationFenceDigest(c)
	return c.ConnectionState == "REVOKED" && c.TargetRBACRevocationAcknowledgedAt != nil &&
		strings.HasPrefix(strings.TrimSpace(c.TargetRBACRevocationAcknowledgedDigest), "sha256:") &&
		secureEqual(strings.TrimSpace(c.TargetRBACRevocationAcknowledgedDigest), expected)
}

func ClusterHasCapability(c ManagedCluster, capability string) bool {
	return clusterHasCapability(c, capability)
}
func DedupeClusterCapabilities(values []string) []string { return dedupeSortedStrings(values) }

func dedupeSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func removeClusterCapability(values []string, unwanted string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != unwanted {
			out = append(out, value)
		}
	}
	return dedupeSortedStrings(out)
}

func NormalizeClusterInventoryMutationAuthority(inv ClusterInventory, current ManagedCluster, imp ClusterImport, identityVerified bool, basisDigest string) ClusterInventory {
	reportedActive := clusterHasCapability(ManagedCluster{Capabilities: inv.Capabilities}, TargetMutationRBACActiveCapability)
	principalAttested := clusterHasCapability(ManagedCluster{Capabilities: inv.Capabilities}, TargetEnrollmentPrincipalIsolatedCapability)
	issued := clusterHasCapability(current, TargetMutationRBACActivationIssuedCapability) &&
		secureEqual(strings.TrimSpace(current.MutationRBACIssuedForDigest), strings.TrimSpace(basisDigest))

	// Server-owned issuance can never be asserted by an agent inventory, and an
	// issuance is valid only for the exact non-mutation inventory basis that was
	// authorized. Semantic drift therefore fails closed until re-issued.
	inv.Capabilities = removeClusterCapability(inv.Capabilities, TargetMutationRBACActivationIssuedCapability)
	inv.Capabilities = removeClusterCapability(inv.Capabilities, TargetMutationRBACEverIssuedCapability)
	allowActive := issued && identityVerified && ClusterInventoryMutationEligible(inv) && reportedActive
	if strings.TrimSpace(imp.AgentServiceAccount) != "" && !principalAttested {
		allowActive = false
	}
	if !allowActive {
		inv = NormalizeClusterInventoryReadOnly(inv)
	}
	return inv
}

func ClusterCapabilitiesWithServerMutationAuthority(inv ClusterInventory, previous ManagedCluster, identityVerified bool, basisDigest string) []string {
	values := append([]string(nil), inv.Capabilities...)
	// Historical issuance is server-owned and sticky so a later authority drift
	// cannot erase the fact that target-local mutation RoleBindings may still
	// exist and therefore must be fenced during revocation.
	if ClusterMayHaveTargetMutationRBAC(previous) {
		values = append(values, TargetMutationRBACEverIssuedCapability)
	}
	if clusterHasCapability(previous, TargetMutationRBACActivationIssuedCapability) &&
		identityVerified && ClusterInventoryMutationEligible(inv) &&
		secureEqual(strings.TrimSpace(previous.MutationRBACIssuedForDigest), strings.TrimSpace(basisDigest)) {
		values = append(values, TargetMutationRBACActivationIssuedCapability)
	}
	return dedupeSortedStrings(values)
}

func (s *MemoryStore) requireClusterTaskAdmissionLocked(clusterID, tokenDigest string) (ManagedCluster, error) {
	c, ok := s.managedClusters[clusterID]
	if !ok {
		return ManagedCluster{}, ErrNotFound
	}
	imp, ok := s.clusterImports[c.ImportID]
	if !ok || !secureEqual(imp.AgentTokenDigest, tokenDigest) {
		return ManagedCluster{}, ErrValidation
	}
	if !ClusterTaskAdmitted(c) {
		return ManagedCluster{}, ErrPrerequisite
	}
	return c, nil
}

func (s *MemoryStore) requireFreshClusterTaskAdmissionLocked(clusterID, tokenDigest string) (ManagedCluster, error) {
	c, err := s.requireClusterTaskAdmissionLocked(clusterID, tokenDigest)
	if err != nil {
		return ManagedCluster{}, err
	}
	if !ClusterTaskClaimAdmittedAt(c, nowUTC(s.now)) {
		return ManagedCluster{}, ErrPrerequisite
	}
	return c, nil
}

func cloneManagedCluster(v ManagedCluster) ManagedCluster {
	v.Labels = cloneStringMap(v.Labels)
	v.Capabilities = append([]string(nil), v.Capabilities...)
	return v
}
func cloneClusterInventory(v ClusterInventory) ClusterInventory {
	v.Nodes = append([]ClusterNode(nil), v.Nodes...)
	for i := range v.Nodes {
		v.Nodes[i].Roles = append([]string(nil), v.Nodes[i].Roles...)
	}
	v.AddOns = append([]ClusterAddOn(nil), v.AddOns...)
	v.StorageClasses = append([]ClusterStorageClass(nil), v.StorageClasses...)
	v.Certificates = append([]ClusterCertificateObservation(nil), v.Certificates...)
	v.Networking.IngressControllers = append([]string(nil), v.Networking.IngressControllers...)
	v.WorkloadExplorer.Workloads = append([]ClusterWorkloadObservation(nil), v.WorkloadExplorer.Workloads...)
	for i := range v.WorkloadExplorer.Workloads {
		v.WorkloadExplorer.Workloads[i].Images = append([]string(nil), v.WorkloadExplorer.Workloads[i].Images...)
	}
	v.WorkloadExplorer.Services = append([]ClusterServiceObservation(nil), v.WorkloadExplorer.Services...)
	for i := range v.WorkloadExplorer.Services {
		v.WorkloadExplorer.Services[i].ExternalIPs = append([]string(nil), v.WorkloadExplorer.Services[i].ExternalIPs...)
		v.WorkloadExplorer.Services[i].Ports = append([]ClusterServicePortObservation(nil), v.WorkloadExplorer.Services[i].Ports...)
	}
	v.WorkloadExplorer.Ingresses = append([]ClusterIngressObservation(nil), v.WorkloadExplorer.Ingresses...)
	for i := range v.WorkloadExplorer.Ingresses {
		v.WorkloadExplorer.Ingresses[i].Hosts = append([]string(nil), v.WorkloadExplorer.Ingresses[i].Hosts...)
		v.WorkloadExplorer.Ingresses[i].TLSHosts = append([]string(nil), v.WorkloadExplorer.Ingresses[i].TLSHosts...)
	}
	v.WorkloadExplorer.PVCs = append([]ClusterPVCObservation(nil), v.WorkloadExplorer.PVCs...)
	v.WorkloadExplorer.Events = append([]ClusterEventObservation(nil), v.WorkloadExplorer.Events...)
	v.APIResources = append([]ClusterAPIResourceObservation(nil), v.APIResources...)
	for i := range v.APIResources {
		v.APIResources[i].Verbs = append([]string(nil), v.APIResources[i].Verbs...)
	}
	v.CRDs = append([]ClusterCRDObservation(nil), v.CRDs...)
	for i := range v.CRDs {
		v.CRDs[i].Versions = append([]ClusterCRDVersionObservation(nil), v.CRDs[i].Versions...)
	}
	v.Capabilities = append([]string(nil), v.Capabilities...)
	return v
}
func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func secureEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func clusterImportEffectivelyExpired(v ClusterImport, now time.Time) bool {
	return (v.State == ClusterImportPendingApproval || v.State == ClusterImportApproved) && !v.ExpiresAt.After(now)
}

func effectiveClusterImport(v ClusterImport, now time.Time) ClusterImport {
	if clusterImportEffectivelyExpired(v, now) {
		v.State = ClusterImportExpired
	}
	return v
}

func (s *MemoryStore) expireClusterImportLocked(v ClusterImport, now time.Time) ClusterImport {
	if !clusterImportEffectivelyExpired(v, now) {
		return v
	}
	v.State = ClusterImportExpired
	v.TokenDigest = "sha256:expired"
	v.Revision++
	v.UpdatedAt = now
	s.clusterImports[v.ID] = v
	s.appendAuditLocked("system", "cluster_import.expired", "clusterImport", v.ID, v.Revision, map[string]any{"projectId": v.ProjectID})
	s.appendOutboxLocked("clusterImport", v.ID, "cluster_import.expired", v)
	return v
}

func (s *MemoryStore) CreateClusterImport(_ context.Context, v ClusterImport, actor string) (ClusterImport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[v.ProjectID]; !ok {
		return ClusterImport{}, ErrNotFound
	}
	v.Name = normalizeName(v.Name)
	v.DisplayName = strings.TrimSpace(v.DisplayName)
	now := nowUTC(s.now)
	if v.Name == "" || v.DisplayName == "" || !strings.HasPrefix(v.TokenDigest, "sha256:") || v.ExpiresAt.IsZero() || !v.ExpiresAt.After(now) {
		return ClusterImport{}, fmt.Errorf("%w: projectId, name, displayName, token digest and future expiry are required", ErrValidation)
	}
	for _, x := range s.clusterImports {
		if x.ProjectID != v.ProjectID || x.Name != v.Name {
			continue
		}
		x = s.expireClusterImportLocked(x, now)
		if x.State != ClusterImportRevoked && x.State != ClusterImportExpired {
			return ClusterImport{}, ErrDuplicateName
		}
	}
	v.ResourceMeta = ResourceMeta{ID: s.id("imp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.AgentServiceAccount = FleetAgentServiceAccountName(v.ID)
	v.State = ClusterImportPendingApproval
	v.RequestedBy = actor
	s.clusterImports[v.ID] = v
	s.appendAuditLocked(actor, "cluster_import.created", "clusterImport", v.ID, v.Revision, map[string]any{"projectId": v.ProjectID})
	s.appendOutboxLocked("clusterImport", v.ID, "cluster_import.created", v)
	return v, nil
}
func (s *MemoryStore) ApproveClusterImport(_ context.Context, id string, expected int64, actor string) (ClusterImport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.clusterImports[id]
	if !ok {
		return ClusterImport{}, ErrNotFound
	}
	if v.Revision != expected {
		return ClusterImport{}, ErrConflict
	}
	if v.State != ClusterImportPendingApproval {
		return ClusterImport{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	if clusterImportEffectivelyExpired(v, now) {
		return ClusterImport{}, ErrInvalidTransition
	}
	v.State = ClusterImportApproved
	v.ApprovedAt = &now
	v.ApprovedBy = actor
	v.Revision++
	v.UpdatedAt = now
	s.clusterImports[id] = v
	s.appendAuditLocked(actor, "cluster_import.approved", "clusterImport", id, v.Revision, nil)
	s.appendOutboxLocked("clusterImport", id, "cluster_import.approved", v)
	return v, nil
}
func (s *MemoryStore) RevokeClusterImport(_ context.Context, id string, expected int64, actor string) (ClusterImport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.clusterImports[id]
	if !ok {
		return ClusterImport{}, ErrNotFound
	}
	if v.Revision != expected {
		return ClusterImport{}, ErrConflict
	}
	if v.State != ClusterImportPendingApproval && v.State != ClusterImportApproved {
		return ClusterImport{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	if clusterImportEffectivelyExpired(v, now) {
		return ClusterImport{}, ErrInvalidTransition
	}
	v.State = ClusterImportRevoked
	v.TokenDigest = "sha256:revoked"
	v.Revision++
	v.UpdatedAt = now
	s.clusterImports[id] = v
	s.appendAuditLocked(actor, "cluster_import.revoked", "clusterImport", id, v.Revision, map[string]any{"projectId": v.ProjectID})
	s.appendOutboxLocked("clusterImport", id, "cluster_import.revoked", v)
	return v, nil
}

func (s *MemoryStore) GetClusterImport(_ context.Context, id string) (ClusterImport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.clusterImports[id]
	if !ok {
		return ClusterImport{}, ErrNotFound
	}
	return effectiveClusterImport(v, nowUTC(s.now)), nil
}
func (s *MemoryStore) ListClusterImports(_ context.Context, projectID string) ([]ClusterImport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := nowUTC(s.now)
	out := []ClusterImport{}
	for _, v := range s.clusterImports {
		if projectID == "" || v.ProjectID == projectID {
			out = append(out, effectiveClusterImport(v, now))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) hasUnacknowledgedRevokedClusterForUIDLocked(externalUID, exceptClusterID string) bool {
	uid := strings.TrimSpace(externalUID)
	if uid == "" {
		return false
	}
	for _, existing := range s.managedClusters {
		if existing.ID == exceptClusterID || existing.ConnectionState != "REVOKED" || !secureEqual(strings.TrimSpace(existing.ExternalUID), uid) {
			continue
		}
		if !ClusterTargetRBACRevocationAcknowledged(existing) {
			return true
		}
	}
	return false
}
func (s *MemoryStore) ClaimClusterImport(_ context.Context, id, tokenDigest, agentTokenDigest, externalUID, agentVersion string) (ClusterImport, ManagedCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.clusterImports[id]
	if !ok {
		return ClusterImport{}, ManagedCluster{}, ErrNotFound
	}
	normalizedExternalUID := strings.TrimSpace(externalUID)
	now := nowUTC(s.now)
	if v.State == ClusterImportExpired || v.State == ClusterImportRevoked || clusterImportEffectivelyExpired(v, now) {
		return ClusterImport{}, ManagedCluster{}, ErrInvalidTransition
	}
	if !secureEqual(v.TokenDigest, tokenDigest) {
		return ClusterImport{}, ManagedCluster{}, ErrValidation
	}
	if v.State == ClusterImportClaimed {
		c, ok := s.managedClusters[v.ClusterID]
		if ok && secureEqual(strings.TrimSpace(c.ExternalUID), normalizedExternalUID) && secureEqual(v.AgentTokenDigest, agentTokenDigest) {
			return v, cloneManagedCluster(c), nil
		}
		return ClusterImport{}, ManagedCluster{}, ErrInvalidTransition
	}
	if v.State != ClusterImportApproved {
		return ClusterImport{}, ManagedCluster{}, ErrInvalidTransition
	}
	if normalizedExternalUID == "" || !strings.HasPrefix(agentTokenDigest, "sha256:") {
		return ClusterImport{}, ManagedCluster{}, ErrValidation
	}
	for _, existing := range s.managedClusters {
		if existing.ConnectionState != "REVOKED" && secureEqual(strings.TrimSpace(existing.ExternalUID), normalizedExternalUID) {
			return ClusterImport{}, ManagedCluster{}, fmt.Errorf("%w: physical cluster UID already has an active managed-cluster authority", ErrDuplicateName)
		}
	}
	if s.hasUnacknowledgedRevokedClusterForUIDLocked(normalizedExternalUID, "") {
		return ClusterImport{}, ManagedCluster{}, fmt.Errorf("%w: target-side RBAC revocation fence must be acknowledged before physical cluster re-enrollment", ErrPrerequisite)
	}
	c := ManagedCluster{ResourceMeta: ResourceMeta{ID: s.id("clu"), Revision: 1, CreatedAt: now, UpdatedAt: now}, ProjectID: v.ProjectID, ImportID: v.ID, Name: v.Name, DisplayName: v.DisplayName, ExternalUID: normalizedExternalUID, ConnectionState: "CONNECTED", AgentVersion: strings.TrimSpace(agentVersion), LastSeenAt: &now, Labels: map[string]string{}}
	v.State = ClusterImportClaimed
	v.AgentTokenDigest = agentTokenDigest
	v.ClusterID = c.ID
	v.ClaimedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.clusterImports[id] = v
	s.managedClusters[c.ID] = c
	s.appendAuditLocked("cluster-agent", "cluster_import.claimed", "clusterImport", id, v.Revision, map[string]any{"clusterId": c.ID})
	s.appendOutboxLocked("managedCluster", c.ID, "managed_cluster.connected", c)
	return v, cloneManagedCluster(c), nil
}
func (s *MemoryStore) UpsertClusterInventory(_ context.Context, clusterID, agentTokenDigest, externalUID string, inv ClusterInventory) (ManagedCluster, ClusterInventory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.managedClusters[clusterID]
	if !ok {
		return ManagedCluster{}, ClusterInventory{}, ErrNotFound
	}
	imp := s.clusterImports[c.ImportID]
	if !secureEqual(imp.AgentTokenDigest, agentTokenDigest) {
		return ManagedCluster{}, ClusterInventory{}, ErrValidation
	}
	observedExternalUID := strings.TrimSpace(externalUID)
	identityContinuityVerified := observedExternalUID != "" && secureEqual(strings.TrimSpace(c.ExternalUID), observedExternalUID)
	if observedExternalUID != "" && !identityContinuityVerified {
		return ManagedCluster{}, ClusterInventory{}, ErrValidation
	}
	inv = NormalizeClusterInventoryIdentityAuthority(inv, identityContinuityVerified)
	now := nowUTC(s.now)
	if err := ValidateClusterInventoryObservationEpoch(c, inv.ObservedAt, now); err != nil {
		return ManagedCluster{}, ClusterInventory{}, err
	}
	if err := ValidateClusterInventoryAPISurface(inv); err != nil {
		return ManagedCluster{}, ClusterInventory{}, err
	}
	inv = NormalizeClusterInventoryForAdmission(inv)
	basisDigest := ClusterInventoryMutationBasisDigest(inv)
	inv = NormalizeClusterInventoryMutationAuthority(inv, c, imp, identityContinuityVerified, basisDigest)
	inv.Digest = ClusterInventoryDigest(inv)
	inv.ObservedAt = inv.ObservedAt.UTC()
	inv.ResourceMeta = ResourceMeta{ID: s.id("inv"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	inv.ClusterID = clusterID
	c.Distribution = strings.TrimSpace(inv.Distribution)
	c.KubernetesVersion = strings.TrimSpace(inv.KubernetesVersion)
	issuedForCurrentBasis := clusterHasCapability(c, TargetMutationRBACActivationIssuedCapability) && secureEqual(strings.TrimSpace(c.MutationRBACIssuedForDigest), basisDigest)
	c.Capabilities = ClusterCapabilitiesWithServerMutationAuthority(inv, c, identityContinuityVerified, basisDigest)
	if !issuedForCurrentBasis {
		c.MutationRBACIssuedForDigest = ""
	}
	c.MutationRBACBasisDigest = basisDigest
	c.InventoryDigest = inv.Digest
	c.ConnectionState = "CONNECTED"
	c.LastSeenAt = &now
	c.InventoryUpdatedAt = &now
	observedAt := inv.ObservedAt
	c.InventoryObservedAt = &observedAt
	c.Revision++
	c.UpdatedAt = now
	s.managedClusters[clusterID] = cloneManagedCluster(c)
	s.clusterInventories[clusterID] = cloneClusterInventory(inv)
	s.appendAuditLocked("cluster-agent", "cluster.inventory.updated", "managedCluster", clusterID, c.Revision, map[string]any{"digest": inv.Digest, "nodes": len(inv.Nodes)})
	return cloneManagedCluster(c), cloneClusterInventory(inv), nil
}
func (s *MemoryStore) AuthorizeClusterMutationRBACActivation(_ context.Context, clusterID, actor string) (ManagedCluster, ClusterImport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.managedClusters[clusterID]
	if !ok {
		return ManagedCluster{}, ClusterImport{}, ErrNotFound
	}
	imp, ok := s.clusterImports[c.ImportID]
	if !ok {
		return ManagedCluster{}, ClusterImport{}, ErrNotFound
	}
	if !ClusterMutationAdmissionEligible(c) || !ClusterInventoryAuthorityFreshAt(c, nowUTC(s.now)) || !clusterHasCapability(c, TargetIdentityContinuityCapability) {
		return ManagedCluster{}, ClusterImport{}, ErrPrerequisite
	}
	if s.hasUnacknowledgedRevokedClusterForUIDLocked(c.ExternalUID, c.ID) {
		return ManagedCluster{}, ClusterImport{}, fmt.Errorf("%w: predecessor target-side RBAC revocation fence is not acknowledged", ErrPrerequisite)
	}
	if strings.TrimSpace(imp.AgentServiceAccount) != "" {
		if imp.AgentServiceAccount != FleetAgentServiceAccountName(imp.ID) || !clusterHasCapability(c, TargetEnrollmentPrincipalIsolatedCapability) {
			return ManagedCluster{}, ClusterImport{}, ErrPrerequisite
		}
	}
	if strings.TrimSpace(c.MutationRBACBasisDigest) == "" || !strings.HasPrefix(c.MutationRBACBasisDigest, "sha256:") {
		return ManagedCluster{}, ClusterImport{}, ErrPrerequisite
	}
	if ClusterMutationRBACActivationCurrent(c) {
		return cloneManagedCluster(c), imp, nil
	}
	now := nowUTC(s.now)
	c.Capabilities = dedupeSortedStrings(append(c.Capabilities, TargetMutationRBACActivationIssuedCapability, TargetMutationRBACEverIssuedCapability))
	c.MutationRBACIssuedForDigest = c.MutationRBACBasisDigest
	c.Revision++
	c.UpdatedAt = now
	s.managedClusters[clusterID] = cloneManagedCluster(c)
	s.appendAuditLocked(actor, "cluster.mutation_rbac_activation.authorized", "managedCluster", clusterID, c.Revision, map[string]any{"inventoryDigest": c.InventoryDigest, "importId": imp.ID})
	s.appendOutboxLocked("managedCluster", clusterID, "managed_cluster.mutation_rbac_activation_authorized", c)
	return cloneManagedCluster(c), imp, nil
}

func (s *MemoryStore) HeartbeatCluster(_ context.Context, clusterID, agentTokenDigest, externalUID, agentVersion string) (ManagedCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.managedClusters[clusterID]
	if !ok {
		return ManagedCluster{}, ErrNotFound
	}
	imp := s.clusterImports[c.ImportID]
	if !secureEqual(imp.AgentTokenDigest, agentTokenDigest) {
		return ManagedCluster{}, ErrValidation
	}
	observedExternalUID := strings.TrimSpace(externalUID)
	if observedExternalUID == "" {
		return cloneManagedCluster(c), nil
	}
	if !secureEqual(strings.TrimSpace(c.ExternalUID), observedExternalUID) {
		return ManagedCluster{}, ErrValidation
	}
	now := nowUTC(s.now)
	c.ConnectionState = "CONNECTED"
	c.AgentVersion = strings.TrimSpace(agentVersion)
	c.LastSeenAt = &now
	c.Revision++
	c.UpdatedAt = now
	s.managedClusters[clusterID] = cloneManagedCluster(c)
	return cloneManagedCluster(c), nil
}
func (s *MemoryStore) RevokeManagedCluster(_ context.Context, clusterID string, expected int64, actor string) (ManagedCluster, ClusterImport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.managedClusters[clusterID]
	if !ok {
		return ManagedCluster{}, ClusterImport{}, ErrNotFound
	}
	if c.Revision != expected {
		return ManagedCluster{}, ClusterImport{}, ErrConflict
	}
	imp, ok := s.clusterImports[c.ImportID]
	if !ok {
		return ManagedCluster{}, ClusterImport{}, ErrNotFound
	}
	if imp.State == ClusterImportRevoked || c.ConnectionState == "REVOKED" {
		return ManagedCluster{}, ClusterImport{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	if ClusterMayHaveTargetMutationRBAC(c) {
		c.Capabilities = dedupeSortedStrings(append(c.Capabilities, TargetMutationRBACEverIssuedCapability))
	}
	// A new revocation generation always requires a fresh target-side fence
	// acknowledgement; a previous acknowledgement cannot carry across revoke.
	c.TargetRBACRevocationAcknowledgedDigest = ""
	c.TargetRBACRevocationAcknowledgedAt = nil
	c.TargetRBACRevocationAcknowledgedBy = ""
	imp.State = ClusterImportRevoked
	imp.AgentTokenDigest = ""
	imp.Revision++
	imp.UpdatedAt = now
	c.ConnectionState = "REVOKED"
	c.Revision++
	c.UpdatedAt = now
	s.clusterImports[imp.ID] = imp
	s.managedClusters[c.ID] = c
	s.revokeAgentCertificatesLocked(c.ID, actor)
	s.appendAuditLocked(actor, "managed_cluster.revoked", "managedCluster", c.ID, c.Revision, map[string]any{"importId": imp.ID})
	s.appendOutboxLocked("managedCluster", c.ID, "managed_cluster.revoked", c)
	return cloneManagedCluster(c), imp, nil
}

func (s *MemoryStore) AcknowledgeManagedClusterTargetRBACRevocation(_ context.Context, clusterID string, expected int64, fenceDigest, actor string) (ManagedCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.managedClusters[clusterID]
	if !ok {
		return ManagedCluster{}, ErrNotFound
	}
	if c.Revision != expected {
		return ManagedCluster{}, ErrConflict
	}
	if c.ConnectionState != "REVOKED" {
		return ManagedCluster{}, ErrInvalidTransition
	}
	expectedDigest := ClusterTargetRBACRevocationFenceDigest(c)
	if !strings.HasPrefix(strings.TrimSpace(fenceDigest), "sha256:") || !secureEqual(strings.TrimSpace(fenceDigest), expectedDigest) {
		return ManagedCluster{}, ErrValidation
	}
	if ClusterTargetRBACRevocationAcknowledged(c) {
		return cloneManagedCluster(c), nil
	}
	now := nowUTC(s.now)
	c.TargetRBACRevocationAcknowledgedDigest = expectedDigest
	c.TargetRBACRevocationAcknowledgedAt = &now
	c.TargetRBACRevocationAcknowledgedBy = strings.TrimSpace(actor)
	c.Revision++
	c.UpdatedAt = now
	s.managedClusters[c.ID] = cloneManagedCluster(c)
	s.appendAuditLocked(actor, "managed_cluster.target_rbac_revocation_acknowledged", "managedCluster", c.ID, c.Revision, map[string]any{"fenceDigest": expectedDigest, "externalUid": c.ExternalUID})
	s.appendOutboxLocked("managedCluster", c.ID, "managed_cluster.target_rbac_revocation_acknowledged", c)
	return cloneManagedCluster(c), nil
}

func (s *MemoryStore) GetManagedCluster(_ context.Context, id string) (ManagedCluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.managedClusters[id]
	if !ok {
		return ManagedCluster{}, ErrNotFound
	}
	return cloneManagedCluster(v), nil
}
func (s *MemoryStore) ListManagedClusters(_ context.Context, projectID string) ([]ManagedCluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ManagedCluster{}
	for _, v := range s.managedClusters {
		if projectID == "" || v.ProjectID == projectID {
			out = append(out, cloneManagedCluster(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (s *MemoryStore) GetLatestClusterInventory(_ context.Context, clusterID string) (ClusterInventory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.clusterInventories[clusterID]
	if !ok {
		return ClusterInventory{}, ErrNotFound
	}
	return cloneClusterInventory(v), nil
}

func ClusterInventoryDigest(v ClusterInventory) string {
	raw, _ := json.Marshal(struct {
		Distribution                string                          `json:"distribution"`
		DistributionEvidenceMethod  string                          `json:"distributionEvidenceMethod,omitempty"`
		DistributionEvidenceUID     string                          `json:"distributionEvidenceUid,omitempty"`
		DistributionEvidenceVersion string                          `json:"distributionEvidenceVersion,omitempty"`
		KubernetesVersion           string                          `json:"kubernetesVersion"`
		Nodes                       []ClusterNode                   `json:"nodes"`
		AddOns                      []ClusterAddOn                  `json:"addOns"`
		StorageClasses              []ClusterStorageClass           `json:"storageClasses"`
		Capacity                    ClusterCapacity                 `json:"capacity"`
		Certificates                []ClusterCertificateObservation `json:"certificates"`
		Networking                  ClusterNetworking               `json:"networking"`
		WorkloadExplorer            ClusterWorkloadExplorer         `json:"workloadExplorer"`
		APIResources                []ClusterAPIResourceObservation `json:"apiResources"`
		CRDs                        []ClusterCRDObservation         `json:"crds"`
		APIDiscoveryComplete        bool                            `json:"apiDiscoveryComplete"`
		CRDDiscoveryComplete        bool                            `json:"crdDiscoveryComplete"`
		SchemaDiscoveryVersion      string                          `json:"schemaDiscoveryVersion"`
		SchemaDiscoveryDigest       string                          `json:"schemaDiscoveryDigest"`
		SchemaDiscoveryComplete     bool                            `json:"schemaDiscoveryComplete"`
		Capabilities                []string                        `json:"capabilities"`
	}{v.Distribution, v.DistributionEvidenceMethod, v.DistributionEvidenceUID, v.DistributionEvidenceVersion, v.KubernetesVersion, v.Nodes, v.AddOns, v.StorageClasses, v.Capacity, v.Certificates, v.Networking, v.WorkloadExplorer, v.APIResources, v.CRDs, v.APIDiscoveryComplete, v.CRDDiscoveryComplete, v.SchemaDiscoveryVersion, v.SchemaDiscoveryDigest, v.SchemaDiscoveryComplete, v.Capabilities})
	return digestBytes(raw)
}
func digestBytes(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256Sum(raw)) }
func sha256Sum(raw []byte) [32]byte { return sha256.Sum256(raw) }

var _ = time.Second

func ValidateClusterInventoryAPISurface(inv ClusterInventory) error {
	distribution := targetmodel.CanonicalDistribution(inv.Distribution)
	if distribution == "" {
		return fmt.Errorf("%w: distribution identity is required", ErrValidation)
	}
	foundNativeClusterVersion := false
	for _, r := range inv.APIResources {
		if r.APIVersion == "config.openshift.io/v1" && r.Resource == "clusterversions" && r.Kind == "ClusterVersion" {
			foundNativeClusterVersion = true
			break
		}
	}
	if foundNativeClusterVersion && distribution != targetmodel.DistributionOKD && distribution != targetmodel.DistributionOpenShift {
		return fmt.Errorf("%w: native ClusterVersion API contradicts distribution identity %q", ErrValidation, distribution)
	}
	if distribution == targetmodel.DistributionOKD || distribution == targetmodel.DistributionOpenShift {
		expectedMethod := DistributionEvidenceOKDClusterV1
		label := "OKD"
		if distribution == targetmodel.DistributionOpenShift {
			expectedMethod = DistributionEvidenceOpenShiftClusterV1
			label = "OpenShift"
		}
		if inv.DistributionEvidenceMethod != expectedMethod || strings.TrimSpace(inv.DistributionEvidenceUID) == "" || strings.TrimSpace(inv.DistributionEvidenceVersion) == "" {
			return fmt.Errorf("%w: %s identity requires ClusterVersion/version UID and version evidence", ErrValidation, label)
		}
		versionLooksOKD := strings.Contains(strings.ToLower(strings.TrimSpace(inv.DistributionEvidenceVersion)), "okd")
		if distribution == targetmodel.DistributionOKD && !versionLooksOKD {
			return fmt.Errorf("%w: OKD identity requires an OKD ClusterVersion release version", ErrValidation)
		}
		if distribution == targetmodel.DistributionOpenShift && versionLooksOKD {
			return fmt.Errorf("%w: OpenShift identity cannot claim an OKD ClusterVersion release version", ErrValidation)
		}
		if !inv.APIDiscoveryComplete || !inv.CRDDiscoveryComplete {
			return fmt.Errorf("%w: %s identity requires complete API and CRD discovery", ErrValidation, label)
		}
		if !foundNativeClusterVersion {
			return fmt.Errorf("%w: %s ClusterVersion API authority was not discovered", ErrValidation, label)
		}
		for _, crd := range inv.CRDs {
			if strings.EqualFold(strings.TrimSpace(crd.Name), "clusterversions.config.openshift.io") {
				return fmt.Errorf("%w: %s identity cannot be derived from a CRD-defined ClusterVersion", ErrValidation, label)
			}
		}
	} else if inv.DistributionEvidenceMethod == DistributionEvidenceOKDClusterV1 || inv.DistributionEvidenceMethod == DistributionEvidenceOpenShiftClusterV1 {
		return fmt.Errorf("%w: ClusterVersion evidence disagrees with distribution identity", ErrValidation)
	}
	if inv.SchemaDiscoveryComplete {
		if inv.SchemaDiscoveryVersion != "OPENAPI_V3" && inv.SchemaDiscoveryVersion != "OPENAPI_V2" {
			return fmt.Errorf("%w: schemaDiscoveryComplete requires OPENAPI_V3 or OPENAPI_V2", ErrValidation)
		}
		if !strings.HasPrefix(inv.SchemaDiscoveryDigest, "sha256:") || len(inv.SchemaDiscoveryDigest) != 71 {
			return fmt.Errorf("%w: schemaDiscoveryComplete requires SHA256 schema discovery digest", ErrValidation)
		}
	} else if strings.TrimSpace(inv.SchemaDiscoveryVersion) != "" || strings.TrimSpace(inv.SchemaDiscoveryDigest) != "" {
		return fmt.Errorf("%w: incomplete schema discovery must not publish version/digest", ErrValidation)
	}
	if inv.APIDiscoveryComplete && len(inv.APIResources) == 0 {
		return fmt.Errorf("%w: apiDiscoveryComplete requires at least one discovered API resource", ErrValidation)
	}
	seen := map[string]struct{}{}
	for _, r := range inv.APIResources {
		if strings.TrimSpace(r.APIVersion) == "" || strings.TrimSpace(r.Version) == "" || strings.TrimSpace(r.Kind) == "" || strings.TrimSpace(r.Resource) == "" {
			return fmt.Errorf("%w: discovered API resources require apiVersion, version, kind and resource", ErrValidation)
		}
		key := r.APIVersion + "|" + r.Kind + "|" + r.Resource
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate discovered API resource %s", ErrValidation, key)
		}
		seen[key] = struct{}{}
	}
	for _, crd := range inv.CRDs {
		if strings.TrimSpace(crd.Name) == "" || strings.TrimSpace(crd.Group) == "" || strings.TrimSpace(crd.Kind) == "" || strings.TrimSpace(crd.Plural) == "" || len(crd.Versions) == 0 {
			return fmt.Errorf("%w: CRD inventory entries require identity and versions", ErrValidation)
		}
		served := false
		for _, v := range crd.Versions {
			if strings.TrimSpace(v.Name) == "" {
				return fmt.Errorf("%w: CRD version name is required", ErrValidation)
			}
			served = served || v.Served
		}
		if !served {
			return fmt.Errorf("%w: CRD %s has no served version", ErrValidation, crd.Name)
		}
	}
	return nil
}
