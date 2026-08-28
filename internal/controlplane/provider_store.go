package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/targetmodel"
)

const clusterAPIAdapter = "cluster-api-topology-v1beta2"
const providerSystemNamespace = "4so-provider-system"

func ProviderClusterDesiredDigest(profileID, name string, spec ProviderClusterSpec) string {
	payload := struct {
		ProviderProfileID string              `json:"providerProfileId"`
		Name              string              `json:"name"`
		Spec              ProviderClusterSpec `json:"spec"`
	}{
		ProviderProfileID: strings.TrimSpace(profileID),
		Name:              normalizeName(name),
		Spec:              spec,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	dnsLabelPattern    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	kubeVersionPattern = regexp.MustCompile(`^v1\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	kubeSeriesPattern  = regexp.MustCompile(`^v1\.[0-9]+$`)
)

func cloneProviderProfile(v ProviderProfile) ProviderProfile {
	v.KubernetesSeries = append([]string(nil), v.KubernetesSeries...)
	v.Architectures = append([]string(nil), v.Architectures...)
	v.DistributionProfiles = targetmodel.CanonicalDistributionSet(v.DistributionProfiles)
	v.DistributionIdentities = append([]string(nil), v.DistributionProfiles...)
	v.ProvisioningMode = targetmodel.ProvisioningModeFromAdapter(v.Adapter)
	if v.InfrastructureProvider == "" {
		v.InfrastructureProvider = targetmodel.InfrastructureUnspecified
	}
	return v
}

func providerResourceName(name, id string) string {
	clean := normalizeName(name)
	var b strings.Builder
	for _, r := range clean {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	clean = strings.Trim(b.String(), "-")
	if clean == "" {
		clean = "cluster"
	}
	suffix := id
	if len(suffix) > 6 {
		suffix = suffix[len(suffix)-6:]
	}
	maxName := 63 - len("pf--") - len(suffix)
	if len(clean) > maxName {
		clean = strings.Trim(clean[:maxName], "-")
	}
	return "pf-" + clean + "-" + suffix
}

func normalizeKubeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func kubeSeries(v string) string {
	parts := strings.Split(strings.TrimPrefix(normalizeKubeVersion(v), "v"), ".")
	if len(parts) < 2 {
		return ""
	}
	return "v" + parts[0] + "." + parts[1]
}

func validateProviderProfile(v *ProviderProfile) error {
	v.Name = normalizeName(v.Name)
	v.DisplayName = strings.TrimSpace(v.DisplayName)
	v.Adapter = strings.TrimSpace(v.Adapter)
	v.Namespace = strings.TrimSpace(v.Namespace)
	v.ClusterClassName = normalizeName(v.ClusterClassName)
	v.WorkerClassName = normalizeName(v.WorkerClassName)
	v.DefaultKubernetesVersion = normalizeKubeVersion(v.DefaultKubernetesVersion)
	if v.Name == "" || len(v.Name) > 63 || !dnsLabelPattern.MatchString(v.Name) || v.DisplayName == "" {
		return fmt.Errorf("%w: provider profile name and displayName are required", ErrValidation)
	}
	if v.Adapter != clusterAPIAdapter {
		return fmt.Errorf("%w: only %s is supported", ErrValidation, clusterAPIAdapter)
	}
	if v.Namespace != providerSystemNamespace {
		return fmt.Errorf("%w: provider namespace must be %s", ErrValidation, providerSystemNamespace)
	}
	if v.ClusterClassName == "" || len(v.ClusterClassName) > 63 || !dnsLabelPattern.MatchString(v.ClusterClassName) || v.WorkerClassName == "" || len(v.WorkerClassName) > 63 || !dnsLabelPattern.MatchString(v.WorkerClassName) {
		return fmt.Errorf("%w: ClusterClass and worker class names must be DNS labels", ErrValidation)
	}
	if !kubeVersionPattern.MatchString(v.DefaultKubernetesVersion) {
		return fmt.Errorf("%w: default Kubernetes version must be an exact v1.x.y version", ErrValidation)
	}
	seen := map[string]bool{}
	series := make([]string, 0, len(v.KubernetesSeries)+1)
	for _, item := range append(v.KubernetesSeries, kubeSeries(v.DefaultKubernetesVersion)) {
		item = normalizeKubeVersion(item)
		if !kubeSeriesPattern.MatchString(item) {
			return fmt.Errorf("%w: Kubernetes series must use v1.x", ErrValidation)
		}
		if !seen[item] {
			seen[item] = true
			series = append(series, item)
		}
	}
	sort.Strings(series)
	v.KubernetesSeries = series
	dummy := ProviderClusterSpec{}
	NormalizeProviderCompatibility(v, &dummy)
	if len(v.Architectures) == 0 || len(v.DistributionProfiles) == 0 {
		return fmt.Errorf("%w: provider compatibility architecture/distribution is required", ErrValidation)
	}
	for _, arch := range v.Architectures {
		if arch != "amd64" && arch != "arm64" {
			return fmt.Errorf("%w: unsupported provider architecture %s", ErrValidation, arch)
		}
	}
	for _, dist := range v.DistributionProfiles {
		if !targetmodel.SupportedDistribution(dist) {
			return fmt.Errorf("%w: unsupported provider distribution identity %s", ErrValidation, dist)
		}
	}
	v.DistributionIdentities = append([]string(nil), v.DistributionProfiles...)
	v.ProvisioningMode = targetmodel.ProvisioningModeFromAdapter(v.Adapter)
	v.InfrastructureProvider = targetmodel.InfrastructureUnspecified
	if v.MaxWorkerReplicas < 1 || v.MaxWorkerReplicas > 500 {
		return fmt.Errorf("%w: maxWorkerReplicas must be between 1 and 500", ErrValidation)
	}
	if strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") || !strings.HasPrefix(v.DesiredDigest, "sha256:") {
		return fmt.Errorf("%w: provider profile idempotency and digests are required", ErrValidation)
	}
	return nil
}

func providerSpecAllowed(profile ProviderProfile, spec *ProviderClusterSpec) error {
	legacyIdentity := targetmodel.CanonicalDistribution(spec.Distribution)
	explicitIdentity := targetmodel.CanonicalDistribution(spec.DistributionIdentity)
	if legacyIdentity != "" && explicitIdentity != "" && legacyIdentity != explicitIdentity {
		return fmt.Errorf("%w: distribution and distributionIdentity disagree", ErrValidation)
	}
	NormalizeProviderCompatibility(&profile, spec)
	if !targetmodel.SupportedDistribution(spec.DistributionIdentity) {
		return fmt.Errorf("%w: unsupported distribution identity %s", ErrValidation, spec.DistributionIdentity)
	}
	if spec.ProvisioningMode != targetmodel.ProvisioningClusterAPI {
		return fmt.Errorf("%w: provider clusters require provisioningMode %s", ErrValidation, targetmodel.ProvisioningClusterAPI)
	}
	spec.KubernetesVersion = normalizeKubeVersion(spec.KubernetesVersion)
	if !kubeVersionPattern.MatchString(spec.KubernetesVersion) {
		return fmt.Errorf("%w: Kubernetes version must be an exact v1.x.y version", ErrValidation)
	}
	if spec.ControlPlaneReplicas != 1 && spec.ControlPlaneReplicas != 3 {
		return fmt.Errorf("%w: controlPlaneReplicas must be 1 or 3", ErrValidation)
	}
	if spec.WorkerReplicas < 1 || spec.WorkerReplicas > profile.MaxWorkerReplicas {
		return fmt.Errorf("%w: workerReplicas is outside the provider profile limit", ErrValidation)
	}
	decision := ProviderCompatibilityDecision(profile, *spec)
	if decision.Status != "PASS" {
		return fmt.Errorf("%w: target is outside provider compatibility matrix: %s", ErrValidation, strings.Join(decision.Blockers, "; "))
	}
	return nil
}

func (s *MemoryStore) validateProviderAgentLocked(clusterID, digest string) error {
	_, err := s.requireClusterTaskAdmissionLocked(clusterID, digest)
	return err
}

func (s *MemoryStore) validateFreshProviderAgentLocked(clusterID, digest string) error {
	_, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, digest)
	return err
}

func (s *MemoryStore) CreateProviderProfile(_ context.Context, v ProviderProfile, actor string) (ProviderProfile, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	project, ok := s.projects[v.ProjectID]
	if !ok {
		return ProviderProfile{}, false, ErrNotFound
	}
	cluster, ok := s.managedClusters[v.ManagementClusterID]
	if !ok || cluster.ProjectID != project.ID {
		return ProviderProfile{}, false, ErrNotFound
	}
	if err := validateProviderProfile(&v); err != nil {
		return ProviderProfile{}, false, err
	}
	for _, existing := range s.providerProfiles {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return ProviderProfile{}, false, ErrIdempotencyConflict
			}
			return cloneProviderProfile(existing), true, nil
		}
		if existing.ProjectID == v.ProjectID && normalizeName(existing.Name) == v.Name {
			return ProviderProfile{}, false, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("prv"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = ProviderProfileVerifyQueued
	v.RequestedBy = actor
	s.providerProfiles[v.ID] = cloneProviderProfile(v)
	s.appendAuditLocked(actor, "provider_profile.created", "providerProfile", v.ID, v.Revision, map[string]any{"managementClusterId": v.ManagementClusterID, "clusterClass": v.ClusterClassName})
	s.appendOutboxLocked("providerProfile", v.ID, "provider_profile.verify.queued", v)
	return cloneProviderProfile(v), false, nil
}

func (s *MemoryStore) GetProviderProfile(_ context.Context, id string) (ProviderProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.providerProfiles[id]
	if !ok {
		return ProviderProfile{}, ErrNotFound
	}
	return cloneProviderProfile(v), nil
}

func (s *MemoryStore) ListProviderProfiles(_ context.Context, projectID, managementClusterID string) ([]ProviderProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ProviderProfile{}
	for _, v := range s.providerProfiles {
		if (projectID == "" || v.ProjectID == projectID) && (managementClusterID == "" || v.ManagementClusterID == managementClusterID) {
			out = append(out, cloneProviderProfile(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return resourceCreatedBefore(out[i].ResourceMeta, out[j].ResourceMeta) })
	return out, nil
}

func (s *MemoryStore) RetryProviderProfile(_ context.Context, id string, expected int64, actor string) (ProviderProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.providerProfiles[id]
	if !ok {
		return ProviderProfile{}, ErrNotFound
	}
	if v.Revision != expected {
		return ProviderProfile{}, ErrConflict
	}
	if v.State != ProviderProfileFailed {
		return ProviderProfile{}, ErrInvalidTransition
	}
	v.State = ProviderProfileVerifyQueued
	v.LastError = ""
	v.Revision++
	v.UpdatedAt = nowUTC(s.now)
	s.providerProfiles[id] = cloneProviderProfile(v)
	s.appendAuditLocked(actor, "provider_profile.retry.queued", "providerProfile", id, v.Revision, nil)
	s.appendOutboxLocked("providerProfile", id, "provider_profile.verify.queued", v)
	return cloneProviderProfile(v), nil
}

func (s *MemoryStore) NextProviderProfileTask(_ context.Context, clusterID, tokenDigest string) (ProviderProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateFreshProviderAgentLocked(clusterID, tokenDigest); err != nil {
		return ProviderProfile{}, err
	}
	now := nowUTC(s.now)
	ids := []string{}
	for id, v := range s.providerProfiles {
		if v.ManagementClusterID != clusterID {
			continue
		}
		if v.State == ProviderProfileVerifyQueued || (v.State == ProviderProfileVerifying && !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now)) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return ProviderProfile{}, ErrNotFound
	}
	sort.Slice(ids, func(i, j int) bool {
		return resourceCreatedBefore(s.providerProfiles[ids[i]].ResourceMeta, s.providerProfiles[ids[j]].ResourceMeta)
	})
	v := s.providerProfiles[ids[0]]
	lease := now.Add(AgentTaskLeaseDuration)
	v.State = ProviderProfileVerifying
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseExpiresAt = &lease
	v.Revision++
	v.UpdatedAt = now
	s.providerProfiles[v.ID] = cloneProviderProfile(v)
	return cloneProviderProfile(v), nil
}

func (s *MemoryStore) ReportProviderProfileTask(_ context.Context, clusterID, tokenDigest string, expected int64, result ProviderProfileTaskResult) (ProviderProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateProviderAgentLocked(clusterID, tokenDigest); err != nil {
		return ProviderProfile{}, err
	}
	v, ok := s.providerProfiles[result.ProfileID]
	if !ok || v.ManagementClusterID != clusterID {
		return ProviderProfile{}, ErrNotFound
	}
	now := nowUTC(s.now)
	if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		return ProviderProfile{}, ErrConflict
	}
	if v.State != ProviderProfileVerifying {
		return ProviderProfile{}, ErrInvalidTransition
	}
	if result.Success && strings.HasPrefix(result.ObservedDigest, "sha256:") {
		v.State = ProviderProfileReady
		v.ObservedDigest = result.ObservedDigest
		v.LastError = ""
	} else {
		v.State = ProviderProfileFailed
		v.LastError = strings.TrimSpace(result.Error)
		if v.LastError == "" {
			v.LastError = "provider profile verification failed"
		}
	}
	v.TaskLeaseExpiresAt = nil
	v.Revision++
	v.UpdatedAt = now
	s.providerProfiles[v.ID] = cloneProviderProfile(v)
	s.appendAuditLocked("cluster-agent", "provider_profile.verify.reported", "providerProfile", v.ID, v.Revision, map[string]any{"success": result.Success, "taskFenceToken": result.TaskFenceToken})
	s.appendOutboxLocked("providerProfile", v.ID, "provider_profile.state.changed", v)
	return cloneProviderProfile(v), nil
}

func (s *MemoryStore) CreateProviderCluster(_ context.Context, v ProviderCluster, actor string) (ProviderCluster, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.providerProfiles[v.ProviderProfileID]
	if !ok || profile.ProjectID != v.ProjectID || profile.State != ProviderProfileReady {
		return ProviderCluster{}, false, fmt.Errorf("%w: a READY provider profile is required", ErrValidation)
	}
	if _, ok = s.projects[v.ProjectID]; !ok {
		return ProviderCluster{}, false, ErrNotFound
	}
	v.Name = normalizeName(v.Name)
	v.DisplayName = strings.TrimSpace(v.DisplayName)
	v.Desired.KubernetesVersion = normalizeKubeVersion(v.Desired.KubernetesVersion)
	NormalizeProviderCompatibility(&profile, &v.Desired)
	v.DesiredDigest = ProviderClusterDesiredDigest(v.ProviderProfileID, v.Name, v.Desired)
	if v.Name == "" || len(v.Name) > 63 || !dnsLabelPattern.MatchString(v.Name) || v.DisplayName == "" || strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") || !strings.HasPrefix(v.DesiredDigest, "sha256:") {
		return ProviderCluster{}, false, fmt.Errorf("%w: provider cluster identity, idempotency and digests are required", ErrValidation)
	}
	if err := providerSpecAllowed(profile, &v.Desired); err != nil {
		return ProviderCluster{}, false, err
	}
	for _, existing := range s.providerClusters {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return ProviderCluster{}, false, ErrIdempotencyConflict
			}
			return existing, true, nil
		}
		if existing.ProjectID == v.ProjectID && normalizeName(existing.Name) == v.Name && existing.State != ProviderClusterDeleted {
			return ProviderCluster{}, false, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("pcl"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.Compatibility = ProviderCompatibilityDecision(profile, v.Desired)
	v.ManagementClusterID = profile.ManagementClusterID
	v.Namespace = profile.Namespace
	v.ResourceName = providerResourceName(v.Name, v.ID)
	v.State = ProviderClusterAwaitingApproval
	v.PendingAction = "PROVISION"
	v.RequestedBy = actor
	s.providerClusters[v.ID] = v
	s.appendAuditLocked(actor, "provider_cluster.created", "providerCluster", v.ID, v.Revision, map[string]any{"providerProfileId": profile.ID, "resourceName": v.ResourceName})
	s.appendOutboxLocked("providerCluster", v.ID, "provider_cluster.approval.requested", v)
	return v, false, nil
}

func (s *MemoryStore) GetProviderCluster(_ context.Context, id string) (ProviderCluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.providerClusters[id]
	if !ok {
		return ProviderCluster{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListProviderClusters(_ context.Context, projectID, profileID string) ([]ProviderCluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ProviderCluster{}
	for _, v := range s.providerClusters {
		if (projectID == "" || v.ProjectID == projectID) && (profileID == "" || v.ProviderProfileID == profileID) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return resourceCreatedBefore(out[i].ResourceMeta, out[j].ResourceMeta) })
	return out, nil
}

func (s *MemoryStore) QueueProviderClusterChange(_ context.Context, id string, expected int64, action string, desired ProviderClusterSpec, desiredDigest, actor, requestDigest, recoveryCheckpointID string) (ProviderCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.providerClusters[id]
	if !ok {
		return ProviderCluster{}, ErrNotFound
	}
	if v.Revision != expected {
		return ProviderCluster{}, ErrConflict
	}
	action = strings.ToUpper(strings.TrimSpace(action))
	if action == "DELETE" {
		if v.State != ProviderClusterActive && v.State != ProviderClusterFailed && v.State != ProviderClusterDeleteApproval && v.State != ProviderClusterDeleteQueued {
			return ProviderCluster{}, ErrInvalidTransition
		}
		if v.State == ProviderClusterDeleteApproval || v.State == ProviderClusterDeleteQueued {
			if err := s.cancelOwnerDestructiveOperationLocked(v.DestructiveOperationID, actor, "recovery checkpoint superseded before provider cluster delete claim"); err != nil {
				return ProviderCluster{}, err
			}
		}
		op, err := s.createOwnerDestructiveOperationLocked(v.ProjectID, v.ManagementClusterID, OwnerOperationProviderClusterDelete, v.ID, v.Revision, v.DesiredDigest, recoveryCheckpointID, actor, requestDigest, true)
		if err != nil {
			return ProviderCluster{}, err
		}
		v.State = ProviderClusterDeleteApproval
		v.PendingAction = action
		v.DestructiveOperationID = op.ID
	} else {
		if v.State != ProviderClusterActive {
			return ProviderCluster{}, ErrInvalidTransition
		}
		profile := s.providerProfiles[v.ProviderProfileID]
		desired.KubernetesVersion = normalizeKubeVersion(desired.KubernetesVersion)
		if err := providerSpecAllowed(profile, &desired); err != nil {
			return ProviderCluster{}, err
		}
		switch action {
		case "SCALE":
			if desired.KubernetesVersion != v.Desired.KubernetesVersion || desired.ControlPlaneReplicas == v.Desired.ControlPlaneReplicas && desired.WorkerReplicas == v.Desired.WorkerReplicas {
				return ProviderCluster{}, fmt.Errorf("%w: scale changes replicas only", ErrValidation)
			}
		case "UPGRADE":
			if desired.KubernetesVersion == v.Desired.KubernetesVersion || desired.ControlPlaneReplicas != v.Desired.ControlPlaneReplicas || desired.WorkerReplicas != v.Desired.WorkerReplicas {
				return ProviderCluster{}, fmt.Errorf("%w: upgrade changes Kubernetes version only", ErrValidation)
			}
		default:
			return ProviderCluster{}, fmt.Errorf("%w: unsupported provider cluster action", ErrValidation)
		}
		if !strings.HasPrefix(requestDigest, "sha256:") {
			return ProviderCluster{}, fmt.Errorf("%w: change request digest is required", ErrValidation)
		}
		_ = desiredDigest // caller hint only; authority recomputes after normalization/defaulting.
		v.Desired = desired
		v.Compatibility = ProviderCompatibilityDecision(profile, desired)
		v.DesiredDigest = ProviderClusterDesiredDigest(v.ProviderProfileID, v.Name, desired)
		v.RequestDigest = requestDigest
		v.State = ProviderClusterAwaitingApproval
		v.PendingAction = action
	}
	v.RequestedBy = actor
	v.ApprovedBy = ""
	v.ApprovedAt = nil
	v.LastError = ""
	v.Revision++
	v.UpdatedAt = nowUTC(s.now)
	s.providerClusters[id] = v
	s.appendAuditLocked(actor, "provider_cluster."+strings.ToLower(action)+".approval_requested", "providerCluster", id, v.Revision, nil)
	s.appendOutboxLocked("providerCluster", id, "provider_cluster.approval.requested", v)
	return v, nil
}

func (s *MemoryStore) ApproveProviderCluster(_ context.Context, id string, expected int64, actor string) (ProviderCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.providerClusters[id]
	if !ok {
		return ProviderCluster{}, ErrNotFound
	}
	if v.Revision != expected {
		return ProviderCluster{}, ErrConflict
	}
	switch v.State {
	case ProviderClusterAwaitingApproval:
		v.State = ProviderClusterQueued
	case ProviderClusterDeleteApproval:
		if _, err := s.approveOwnerDestructiveOperationLocked(v.DestructiveOperationID, v.ProjectID, v.ManagementClusterID, actor); err != nil {
			return ProviderCluster{}, err
		}
		v.State = ProviderClusterDeleteQueued
	default:
		return ProviderCluster{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	v.ApprovedBy = actor
	v.ApprovedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.providerClusters[id] = v
	s.appendAuditLocked(actor, "provider_cluster.approved", "providerCluster", id, v.Revision, map[string]any{"action": v.PendingAction})
	s.appendOutboxLocked("providerCluster", id, "provider_cluster.execution.queued", v)
	return v, nil
}

func (s *MemoryStore) RetryProviderCluster(_ context.Context, id string, expected int64, actor string) (ProviderCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.providerClusters[id]
	if !ok {
		return ProviderCluster{}, ErrNotFound
	}
	if v.Revision != expected {
		return ProviderCluster{}, ErrConflict
	}
	if v.State != ProviderClusterFailed {
		return ProviderCluster{}, ErrInvalidTransition
	}
	if v.PendingAction == "DELETE" {
		return ProviderCluster{}, ownerDestructiveRetryRequiresFreshRequest(v.DestructiveOperationID)
	} else if v.PendingAction == "PROVISION" || v.PendingAction == "SCALE" || v.PendingAction == "UPGRADE" {
		v.State = ProviderClusterQueued
	} else {
		return ProviderCluster{}, fmt.Errorf("%w: failed provider cluster has no retryable action", ErrValidation)
	}
	v.LastError = ""
	v.Revision++
	v.UpdatedAt = nowUTC(s.now)
	s.providerClusters[id] = v
	s.appendAuditLocked(actor, "provider_cluster.retry.queued", "providerCluster", id, v.Revision, map[string]any{"action": v.PendingAction})
	s.appendOutboxLocked("providerCluster", id, "provider_cluster.execution.queued", v)
	return v, nil
}

func (s *MemoryStore) NextProviderClusterTask(_ context.Context, clusterID, tokenDigest string) (ProviderCluster, ProviderProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateFreshProviderAgentLocked(clusterID, tokenDigest); err != nil {
		return ProviderCluster{}, ProviderProfile{}, err
	}
	now := nowUTC(s.now)
	ids := []string{}
	for id, v := range s.providerClusters {
		if v.ManagementClusterID != clusterID {
			continue
		}
		switch v.State {
		case ProviderClusterQueued, ProviderClusterDeleteQueued:
			ids = append(ids, id)
		case ProviderClusterApplying, ProviderClusterReconciling, ProviderClusterDeleting:
			if !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return ProviderCluster{}, ProviderProfile{}, ErrNotFound
	}
	sort.Slice(ids, func(i, j int) bool {
		return resourceUpdatedBefore(s.providerClusters[ids[i]].ResourceMeta, s.providerClusters[ids[j]].ResourceMeta)
	})
	v := s.providerClusters[ids[0]]
	if v.State == ProviderClusterDeleting && v.TaskLeaseExpiresAt != nil {
		message := "provider cluster destructive task lease expired; explicit recovery-bound retry is required"
		if _, err := s.finishOwnerDestructiveOperationLocked(v.DestructiveOperationID, false, message, "cluster-agent"); err != nil {
			return ProviderCluster{}, ProviderProfile{}, err
		}
		v.State, v.LastError, v.TaskLeaseExpiresAt = ProviderClusterFailed, message, nil
		v.Revision++
		v.UpdatedAt = now
		s.providerClusters[v.ID] = v
		s.appendAuditLocked("cluster-agent", "provider_cluster.task.lease_expired", "providerCluster", v.ID, v.Revision, map[string]any{"action": "DELETE", "taskFenceToken": v.TaskFenceToken})
		s.appendOutboxLocked("providerCluster", v.ID, "provider_cluster.state.changed", v)
		return ProviderCluster{}, ProviderProfile{}, ErrNotFound
	}
	switch v.State {
	case ProviderClusterQueued:
		v.State = ProviderClusterApplying
	case ProviderClusterDeleteQueued:
		if _, err := s.startOwnerDestructiveOperationLocked(v.DestructiveOperationID, v.ProjectID, v.ManagementClusterID, "cluster-agent"); err != nil {
			return ProviderCluster{}, ProviderProfile{}, err
		}
		v.State = ProviderClusterDeleting
	}
	lease := now.Add(AgentTaskLeaseDuration)
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseExpiresAt = &lease
	v.Revision++
	v.UpdatedAt = now
	s.providerClusters[v.ID] = v
	profile, ok := s.providerProfiles[v.ProviderProfileID]
	if !ok || profile.State != ProviderProfileReady {
		return ProviderCluster{}, ProviderProfile{}, fmt.Errorf("%w: provider profile is not ready", ErrValidation)
	}
	return v, cloneProviderProfile(profile), nil
}

func (s *MemoryStore) ReportProviderClusterTask(_ context.Context, clusterID, tokenDigest string, expected int64, result ProviderClusterTaskResult) (ProviderCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateProviderAgentLocked(clusterID, tokenDigest); err != nil {
		return ProviderCluster{}, err
	}
	v, ok := s.providerClusters[result.ProviderClusterID]
	if !ok || v.ManagementClusterID != clusterID {
		return ProviderCluster{}, ErrNotFound
	}
	now := nowUTC(s.now)
	if v.Revision != expected {
		return ProviderCluster{}, ErrConflict
	}
	action := strings.ToUpper(strings.TrimSpace(result.Action))
	wasDelete := action == "DELETE" || action == "INSPECT_DELETE"
	switch action {
	case "APPLY":
		if v.State != ProviderClusterApplying {
			return ProviderCluster{}, ErrInvalidTransition
		}
	case "INSPECT":
		if v.State != ProviderClusterReconciling {
			return ProviderCluster{}, ErrInvalidTransition
		}
	case "DELETE", "INSPECT_DELETE":
		if v.State != ProviderClusterDeleting {
			return ProviderCluster{}, ErrInvalidTransition
		}
	default:
		return ProviderCluster{}, fmt.Errorf("%w: provider task action is unsupported", ErrValidation)
	}
	if result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		return ProviderCluster{}, ErrConflict
	}
	if !result.Success {
		v.State = ProviderClusterFailed
		v.LastError = strings.TrimSpace(result.Error)
		if v.LastError == "" {
			v.LastError = "provider cluster task failed"
		}
	} else {
		switch action {
		case "APPLY":
			if result.ObservedDigest != v.DesiredDigest {
				v.State = ProviderClusterFailed
				v.LastError = "provider cluster desired/observed digest mismatch"
			} else {
				v.State = ProviderClusterReconciling
				v.ObservedDigest = result.ObservedDigest
				v.Phase = strings.TrimSpace(result.Phase)
				v.LastError = ""
			}
		case "INSPECT":
			v.ObservedDigest = result.ObservedDigest
			v.Phase = strings.TrimSpace(result.Phase)
			if result.Ready {
				if result.ObservedDigest != v.DesiredDigest {
					v.State = ProviderClusterFailed
					v.LastError = "provider cluster ready with a different desired digest"
				} else {
					v.State = ProviderClusterActive
					v.Applied = v.Desired
					v.PendingAction = ""
					v.LastError = ""
				}
			}
		case "DELETE", "INSPECT_DELETE":
			v.Phase = strings.TrimSpace(result.Phase)
			if result.Deleted {
				v.State = ProviderClusterDeleted
				v.PendingAction = ""
				v.ObservedDigest = ""
				v.LastError = ""
			}
		}
	}
	if wasDelete && (!result.Success || result.Deleted) {
		if _, err := s.finishOwnerDestructiveOperationLocked(v.DestructiveOperationID, result.Success, v.LastError, "cluster-agent"); err != nil {
			return ProviderCluster{}, err
		}
	}
	v.TaskLeaseExpiresAt = nil
	v.Revision++
	v.UpdatedAt = now
	s.providerClusters[v.ID] = v
	s.appendAuditLocked("cluster-agent", "provider_cluster.task.reported", "providerCluster", v.ID, v.Revision, map[string]any{"action": result.Action, "success": result.Success, "ready": result.Ready, "deleted": result.Deleted, "taskFenceToken": result.TaskFenceToken})
	s.appendOutboxLocked("providerCluster", v.ID, "provider_cluster.state.changed", v)
	return v, nil
}
