package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const RuntimeCertificationValidity = 30 * 24 * time.Hour

var observabilityRuntimeCertificationCapabilities = []string{"cert.metrics", "cert.logs", "cert.alerts"}

var targetRuntimeCertificationCapabilities = []string{
	"cert.dns", "cert.tls", "cert.network", "cert.tenant-isolation", "cert.pvc", "cert.snapshot", "cert.backup", "cert.restore", "cert.metrics", "cert.logs", "cert.alerts",
}

func RuntimeCertificationRequiredCapabilities(profile RuntimeCertificationProfile) []string {
	switch profile {
	case RuntimeCertificationObservabilityV1:
		return append([]string(nil), observabilityRuntimeCertificationCapabilities...)
	case RuntimeCertificationTargetV1:
		return append([]string(nil), targetRuntimeCertificationCapabilities...)
	default:
		return nil
	}
}

func RuntimeEnvironmentFingerprint(inv ClusterInventory) string {
	storage := make([]string, 0, len(inv.StorageClasses))
	for _, item := range inv.StorageClasses {
		storage = append(storage, item.Name)
	}
	sort.Strings(storage)
	caps := append([]string(nil), inv.Capabilities...)
	sort.Strings(caps)
	raw, _ := json.Marshal(struct {
		InventoryDigest   string   `json:"inventoryDigest"`
		Distribution      string   `json:"distribution"`
		KubernetesVersion string   `json:"kubernetesVersion"`
		CNI               string   `json:"cni"`
		GatewayAPI        bool     `json:"gatewayApi"`
		StorageClasses    []string `json:"storageClasses"`
		Capabilities      []string `json:"capabilities"`
	}{inv.Digest, inv.Distribution, inv.KubernetesVersion, inv.Networking.CNI, inv.Networking.GatewayAPI, storage, caps})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cloneRuntimeCertification(v RuntimeCertificationRun) RuntimeCertificationRun {
	v.Checks = append([]RuntimeCheck(nil), v.Checks...)
	v.CleanupGenerations = append([]RuntimeCertificationCleanupGeneration(nil), v.CleanupGenerations...)
	return v
}

func RuntimeCertificationCleanupToken(runID string, attempt int, fenceToken int64) string {
	raw := fmt.Sprintf("%s:%d:%d", strings.TrimSpace(runID), attempt, fenceToken)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

func certificationContextValid(v RuntimeCertificationRun) bool {
	return validSHA256(v.InventoryDigest) && validSHA256(v.EnvironmentFingerprint) && validSHA256(v.ManifestDigest) && validSHA256(v.SourceLockDigest) && validSHA256(v.RenderedDigest) && v.ResourceCount > 0
}

func RuntimeCertificationCheckpointDigest(v RuntimeCertificationRun, checks []RuntimeCheck) string {
	raw, _ := json.Marshal(struct {
		RunID         string         `json:"runId"`
		Inventory     string         `json:"inventoryDigest"`
		Environment   string         `json:"environmentFingerprint"`
		Catalog       string         `json:"catalogReleaseId"`
		Manifest      string         `json:"manifestDigest"`
		SourceLock    string         `json:"sourceLockDigest"`
		Rendered      string         `json:"renderedDigest"`
		Namespace     string         `json:"namespace"`
		InstallChecks []RuntimeCheck `json:"installChecks"`
	}{v.ID, v.InventoryDigest, v.EnvironmentFingerprint, v.CatalogReleaseID, v.ManifestDigest, v.SourceLockDigest, v.RenderedDigest, v.Namespace, checks})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func RuntimeCertificationEvidenceDigest(v RuntimeCertificationRun) string {
	raw, _ := json.Marshal(struct {
		Schema        string                      `json:"schema"`
		RunID         string                      `json:"runId"`
		Profile       RuntimeCertificationProfile `json:"profile"`
		Inventory     string                      `json:"inventoryDigest"`
		Environment   string                      `json:"environmentFingerprint"`
		Catalog       string                      `json:"catalogReleaseId"`
		Revision      string                      `json:"catalogRevisionId"`
		Manifest      string                      `json:"manifestDigest"`
		SourceLock    string                      `json:"sourceLockDigest"`
		Rendered      string                      `json:"renderedDigest"`
		Namespace     string                      `json:"namespace"`
		ResourceCount int                         `json:"resourceCount"`
		Checkpoint    string                      `json:"installCheckpointDigest"`
		Checks        []RuntimeCheck              `json:"checks"`
	}{"platform.4so.io/runtime-certification-evidence/v1", v.ID, v.Profile, v.InventoryDigest, v.EnvironmentFingerprint, v.CatalogReleaseID, v.CatalogRevisionID, v.ManifestDigest, v.SourceLockDigest, v.RenderedDigest, v.Namespace, v.ResourceCount, v.InstallCheckpointDigest, v.Checks})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ValidateRuntimeCertificationEvidence revalidates a completed certification
// record before it is used as an authority. This protects durable restore and
// downstream admission from treating a state label plus a digest-shaped string
// as proof when the stored checkpoints/checks no longer reconstruct the exact
// evidence digest originally produced by the certification state machine.
func ValidateRuntimeCertificationEvidence(v RuntimeCertificationRun) error {
	if v.State != RuntimeCertificationSucceeded && v.State != RuntimeCertificationRevoked {
		return fmt.Errorf("%w: runtime certification evidence requires SUCCEEDED or REVOKED state", ErrInvalidTransition)
	}
	if v.Profile != RuntimeCertificationFoundationV1 && v.Profile != RuntimeCertificationObservabilityV1 && v.Profile != RuntimeCertificationTargetV1 {
		return fmt.Errorf("%w: unsupported runtime certification evidence profile", ErrValidation)
	}
	if !certificationContextValid(v) || v.InstallCheckpointAt == nil || v.FinishedAt == nil || v.ExpiresAt == nil {
		return fmt.Errorf("%w: runtime certification evidence context/timestamps are incomplete", ErrValidation)
	}
	if v.FinishedAt.Before(*v.InstallCheckpointAt) || !v.ExpiresAt.After(*v.FinishedAt) {
		return fmt.Errorf("%w: runtime certification evidence timestamps are inconsistent", ErrValidation)
	}
	installCount := v.ResourceCount + 1 // fresh-install-target + one apply/* per rendered resource.
	if installCount <= 1 || len(v.Checks) <= installCount {
		return fmt.Errorf("%w: runtime certification evidence checks are incomplete", ErrValidation)
	}
	installChecks := append([]RuntimeCheck(nil), v.Checks[:installCount]...)
	verifyChecks := append([]RuntimeCheck(nil), v.Checks[installCount:]...)
	installView := v
	installView.Phase = RuntimeCertificationPhaseInstall
	if err := ValidateRuntimeCertificationResultShape(installView, RuntimeCertificationResult{Phase: RuntimeCertificationPhaseInstall, Success: true, Checks: installChecks}); err != nil {
		return err
	}
	verifyView := v
	verifyView.Phase = RuntimeCertificationPhaseVerify
	if err := ValidateRuntimeCertificationResultShape(verifyView, RuntimeCertificationResult{Phase: RuntimeCertificationPhaseVerify, Success: true, Checks: verifyChecks}); err != nil {
		return err
	}
	for _, check := range v.Checks {
		if check.Status != "PASS" {
			return fmt.Errorf("%w: runtime certification evidence contains a non-PASS check", ErrValidation)
		}
	}
	if !validSHA256(v.InstallCheckpointDigest) || v.InstallCheckpointDigest != RuntimeCertificationCheckpointDigest(v, installChecks) {
		return fmt.Errorf("%w: runtime certification install checkpoint digest mismatch", ErrValidation)
	}
	if !validSHA256(v.EvidenceDigest) || v.EvidenceDigest != RuntimeCertificationEvidenceDigest(v) {
		return fmt.Errorf("%w: runtime certification evidence digest mismatch", ErrValidation)
	}
	return nil
}

func missingRuntimeCertificationCapabilities(profile RuntimeCertificationProfile, inv ClusterInventory) []string {
	required := RuntimeCertificationRequiredCapabilities(profile)
	if len(required) == 0 {
		return nil
	}
	have := map[string]bool{}
	for _, item := range inv.Capabilities {
		have[strings.TrimSpace(item)] = true
	}
	missing := []string{}
	for _, item := range required {
		if !have[item] {
			missing = append(missing, item)
		}
	}
	return missing
}

func (s *MemoryStore) CreateRuntimeCertification(_ context.Context, v RuntimeCertificationRun, actor string) (RuntimeCertificationRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v.ProjectID, v.ClusterID, v.CatalogReleaseID, v.Namespace = strings.TrimSpace(v.ProjectID), strings.TrimSpace(v.ClusterID), strings.TrimSpace(v.CatalogReleaseID), strings.TrimSpace(v.Namespace)
	if v.Profile != RuntimeCertificationFoundationV1 && v.Profile != RuntimeCertificationObservabilityV1 && v.Profile != RuntimeCertificationTargetV1 {
		return RuntimeCertificationRun{}, false, fmt.Errorf("%w: unsupported runtime certification profile", ErrValidation)
	}
	if v.ProjectID == "" || v.ClusterID == "" || v.CatalogReleaseID == "" || v.Namespace == "" || strings.TrimSpace(actor) == "" || strings.TrimSpace(v.IdempotencyKey) == "" || !validSHA256(v.RequestDigest) {
		return RuntimeCertificationRun{}, false, fmt.Errorf("%w: certification project, cluster, catalog release, namespace, idempotency key, request digest and actor are required", ErrValidation)
	}
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || cluster.ProjectID != v.ProjectID {
		return RuntimeCertificationRun{}, false, ErrNotFound
	}
	inv, ok := s.clusterInventories[v.ClusterID]
	if !ok || !validSHA256(inv.Digest) || inv.Digest != cluster.InventoryDigest {
		return RuntimeCertificationRun{}, false, fmt.Errorf("%w: fresh digest-bearing cluster inventory is required", ErrInvalidTransition)
	}
	release, ok := s.catalogReleases[v.CatalogReleaseID]
	if !ok || release.State != CatalogPublished || (release.Channel != CatalogChannelRender && release.Channel != CatalogChannelRuntime && release.Channel != CatalogChannelProduction) {
		return RuntimeCertificationRun{}, false, fmt.Errorf("%w: published renderable catalog release is required", ErrInvalidTransition)
	}
	key, ok := s.catalogTrustKeys[release.SigningKeyID]
	if !ok || VerifyCatalogReleaseSignature(release, key) != nil {
		return RuntimeCertificationRun{}, false, fmt.Errorf("%w: active trusted catalog signature is required", ErrInvalidTransition)
	}
	if release.CurrentRevisionID != v.CatalogRevisionID || release.ManifestDigest != v.ManifestDigest {
		return RuntimeCertificationRun{}, false, fmt.Errorf("%w: catalog revision binding mismatch", ErrValidation)
	}
	if v.InventoryDigest != inv.Digest || v.EnvironmentFingerprint != RuntimeEnvironmentFingerprint(inv) || !certificationContextValid(v) {
		return RuntimeCertificationRun{}, false, fmt.Errorf("%w: certification context digest mismatch", ErrValidation)
	}
	for _, existing := range s.runtimeCertifications {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return RuntimeCertificationRun{}, false, ErrIdempotencyConflict
			}
			return cloneRuntimeCertification(existing), true, nil
		}
		if existing.ClusterID == v.ClusterID && existing.Namespace == v.Namespace && (existing.State == RuntimeCertificationQueued || existing.State == RuntimeCertificationInstalling || existing.State == RuntimeCertificationVerifying) {
			return RuntimeCertificationRun{}, false, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("rtc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = RuntimeCertificationQueued
	v.Phase = RuntimeCertificationPhaseInstall
	v.RequestedBy = actor
	v.Checks = nil
	if missing := missingRuntimeCertificationCapabilities(v.Profile, inv); len(missing) > 0 {
		v.State = RuntimeCertificationBlocked
		v.LastError = "required runtime certification capabilities are not reported by current cluster inventory: " + strings.Join(missing, ", ")
		v.FinishedAt = &now
		for _, capability := range missing {
			v.Checks = append(v.Checks, RuntimeCheck{Key: "capability/" + capability, Status: "BLOCKED", Detail: "capability is absent from the authoritative cluster inventory"})
		}
	}
	s.runtimeCertifications[v.ID] = cloneRuntimeCertification(v)
	action := "runtime_certification.queued"
	if v.State == RuntimeCertificationBlocked {
		action = "runtime_certification.blocked"
	}
	s.appendAuditLocked(actor, action, "runtimeCertification", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "catalogReleaseId": v.CatalogReleaseID, "profile": v.Profile})
	s.appendOutboxLocked("runtimeCertification", v.ID, action, v)
	return cloneRuntimeCertification(v), false, nil
}

func (s *MemoryStore) GetRuntimeCertification(_ context.Context, id string) (RuntimeCertificationRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.runtimeCertifications[id]
	if !ok {
		return RuntimeCertificationRun{}, ErrNotFound
	}
	return cloneRuntimeCertification(v), nil
}

func (s *MemoryStore) ListRuntimeCertifications(_ context.Context, projectID, clusterID string) ([]RuntimeCertificationRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []RuntimeCertificationRun{}
	for _, v := range s.runtimeCertifications {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) {
			out = append(out, cloneRuntimeCertification(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return resourceCreatedBefore(out[i].ResourceMeta, out[j].ResourceMeta) })
	return out, nil
}

func (s *MemoryStore) validateRuntimeCertificationAgentLocked(clusterID, tokenDigest string) error {
	_, err := s.requireClusterTaskAdmissionLocked(clusterID, tokenDigest)
	return err
}

func (s *MemoryStore) validateFreshRuntimeCertificationAgentLocked(clusterID, tokenDigest string) error {
	_, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, tokenDigest)
	return err
}

func (s *MemoryStore) NextRuntimeCertificationTask(_ context.Context, clusterID, tokenDigest string) (RuntimeCertificationRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateFreshRuntimeCertificationAgentLocked(clusterID, tokenDigest); err != nil {
		return RuntimeCertificationRun{}, err
	}
	now := nowUTC(s.now)
	var selected *RuntimeCertificationRun
	for _, candidate := range s.runtimeCertifications {
		if candidate.ClusterID != clusterID {
			continue
		}
		runnable := candidate.State == RuntimeCertificationQueued || ((candidate.State == RuntimeCertificationInstalling || candidate.State == RuntimeCertificationVerifying) && !AgentTaskLeaseActive(candidate.TaskLeaseExpiresAt, now))
		if !runnable {
			continue
		}
		if selected == nil || resourceCreatedBefore(candidate.ResourceMeta, selected.ResourceMeta) {
			copy := candidate
			selected = &copy
		}
	}
	if selected == nil {
		return RuntimeCertificationRun{}, ErrNotFound
	}
	v := *selected
	cluster := s.managedClusters[clusterID]
	inv, ok := s.clusterInventories[clusterID]
	if !ok || cluster.InventoryDigest != v.InventoryDigest || inv.Digest != v.InventoryDigest || RuntimeEnvironmentFingerprint(inv) != v.EnvironmentFingerprint {
		v.State = RuntimeCertificationFailed
		v.LastError = "cluster inventory changed after certification was queued; create a new certification run"
		v.FinishedAt = &now
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		s.runtimeCertifications[v.ID] = cloneRuntimeCertification(v)
		s.appendAuditLocked("cluster-agent", "runtime_certification.context_stale", "runtimeCertification", v.ID, v.Revision, map[string]any{"inventoryDigest": cluster.InventoryDigest})
		s.appendOutboxLocked("runtimeCertification", v.ID, "runtime_certification.failed", v)
		return cloneRuntimeCertification(v), nil
	}
	if v.State == RuntimeCertificationQueued {
		v.State = RuntimeCertificationInstalling
		v.Phase = RuntimeCertificationPhaseInstall
		v.StartedAt = &now
	} else if v.State == RuntimeCertificationVerifying {
		v.Phase = RuntimeCertificationPhaseVerify
	}
	lease := now.Add(AgentTaskLeaseDuration)
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseExpiresAt = &lease
	v.CleanupGenerations = append(v.CleanupGenerations, RuntimeCertificationCleanupGeneration{TaskAttempt: v.TaskAttempt, Phase: v.Phase, Token: RuntimeCertificationCleanupToken(v.ID, v.TaskAttempt, v.TaskFenceToken)})
	v.Revision++
	v.UpdatedAt = now
	s.runtimeCertifications[v.ID] = cloneRuntimeCertification(v)
	s.appendAuditLocked("cluster-agent", "runtime_certification.task_claimed", "runtimeCertification", v.ID, v.Revision, map[string]any{"phase": v.Phase, "attempt": v.TaskAttempt, "taskFenceToken": v.TaskFenceToken, "leaseExpiresAt": lease})
	return cloneRuntimeCertification(v), nil
}

func ValidateRuntimeCertificationResultShape(v RuntimeCertificationRun, result RuntimeCertificationResult) error {
	seen := map[string]bool{}
	applyCount, verifyCount := 0, 0
	for _, item := range result.Checks {
		key := strings.TrimSpace(item.Key)
		if key == "" || seen[key] {
			return fmt.Errorf("%w: runtime certification check keys must be non-empty and unique", ErrValidation)
		}
		seen[key] = true
		if strings.HasPrefix(key, "apply/") {
			applyCount++
		}
		if strings.HasPrefix(key, "verify/") {
			verifyCount++
		}
	}
	if !result.Success {
		return nil
	}
	require := func(key string) error {
		if !seen[key] {
			return fmt.Errorf("%w: required runtime certification check %s is missing", ErrValidation, key)
		}
		return nil
	}
	switch result.Phase {
	case RuntimeCertificationPhaseInstall:
		if err := require("fresh-install-target"); err != nil {
			return err
		}
		if applyCount != v.ResourceCount {
			return fmt.Errorf("%w: install certification requires exactly %d apply checks, got %d", ErrValidation, v.ResourceCount, applyCount)
		}
	case RuntimeCertificationPhaseVerify:
		for _, key := range []string{"durable-install-checkpoint", "nodes-ready", "cluster-dns-service", "kubernetes-api-tls"} {
			if err := require(key); err != nil {
				return err
			}
		}
		if verifyCount != v.ResourceCount {
			return fmt.Errorf("%w: verify certification requires exactly %d resource persistence checks, got %d", ErrValidation, v.ResourceCount, verifyCount)
		}
		if v.Profile == RuntimeCertificationObservabilityV1 || v.Profile == RuntimeCertificationTargetV1 {
			for _, key := range []string{"target-runtime/metrics-query", "target-runtime/logs-push", "target-runtime/logs-query", "target-runtime/alert-fire", "target-runtime/alert-query"} {
				if err := require(key); err != nil {
					return err
				}
			}
		}
		if v.Profile == RuntimeCertificationTargetV1 {
			for _, key := range []string{"target-runtime/network-namespaces", "target-runtime/network-default-deny", "target-runtime/network-dns-tenant-a", "target-runtime/network-dns-tenant-b", "target-runtime/network-intra-tenant-allow", "target-runtime/network-cross-tenant-deny", "target-runtime/network-cross-tenant-explicit-allow", "target-runtime/pvc-bind", "target-runtime/pvc-io", "target-runtime/snapshot-create", "target-runtime/snapshot-restore-pvc", "target-runtime/snapshot-restore-io", "target-runtime/backup-create", "target-runtime/restore-validate"} {
				if err := require(key); err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("%w: unsupported runtime certification result phase", ErrValidation)
	}
	return nil
}

func allRuntimeChecksPass(checks []RuntimeCheck) bool {
	if len(checks) == 0 {
		return false
	}
	for _, check := range checks {
		if check.Status != "PASS" {
			return false
		}
	}
	return true
}

func (s *MemoryStore) ReportRuntimeCertificationTask(_ context.Context, clusterID, tokenDigest string, expected int64, result RuntimeCertificationResult) (RuntimeCertificationRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateRuntimeCertificationAgentLocked(clusterID, tokenDigest); err != nil {
		return RuntimeCertificationRun{}, err
	}
	v, ok := s.runtimeCertifications[result.RunID]
	if !ok || v.ClusterID != clusterID {
		return RuntimeCertificationRun{}, ErrNotFound
	}
	now := nowUTC(s.now)
	if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		return RuntimeCertificationRun{}, ErrConflict
	}
	if result.InventoryDigest != v.InventoryDigest || result.RenderedDigest != v.RenderedDigest || result.Phase != v.Phase {
		return RuntimeCertificationRun{}, fmt.Errorf("%w: certification task result context mismatch", ErrValidation)
	}
	if (v.Phase == RuntimeCertificationPhaseInstall && v.State != RuntimeCertificationInstalling) || (v.Phase == RuntimeCertificationPhaseVerify && v.State != RuntimeCertificationVerifying) {
		return RuntimeCertificationRun{}, ErrInvalidTransition
	}
	if err := ValidateRuntimeCertificationResultShape(v, result); err != nil {
		return RuntimeCertificationRun{}, err
	}
	if !result.Success || !allRuntimeChecksPass(result.Checks) {
		v.Checks = append(v.Checks, result.Checks...)
		if result.Blocked {
			v.State = RuntimeCertificationBlocked
		} else {
			v.State = RuntimeCertificationFailed
		}
		v.LastError = strings.TrimSpace(result.Error)
		if v.LastError == "" {
			v.LastError = "runtime certification checks failed"
		}
		v.FinishedAt = &now
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		s.runtimeCertifications[v.ID] = cloneRuntimeCertification(v)
		action := "runtime_certification." + strings.ToLower(string(v.State))
		s.appendAuditLocked("cluster-agent", action, "runtimeCertification", v.ID, v.Revision, map[string]any{"phase": v.Phase})
		s.appendOutboxLocked("runtimeCertification", v.ID, action, v)
		return cloneRuntimeCertification(v), nil
	}
	v.Checks = append(v.Checks, result.Checks...)
	if v.Phase == RuntimeCertificationPhaseInstall {
		v.InstallCheckpointDigest = RuntimeCertificationCheckpointDigest(v, result.Checks)
		v.InstallCheckpointAt = &now
		v.State = RuntimeCertificationVerifying
		v.Phase = RuntimeCertificationPhaseVerify
		v.LastError = ""
	} else {
		if !validSHA256(v.InstallCheckpointDigest) || v.InstallCheckpointAt == nil {
			return RuntimeCertificationRun{}, fmt.Errorf("%w: durable install checkpoint is required before verify completion", ErrInvalidTransition)
		}
		v.State = RuntimeCertificationSucceeded
		v.LastError = ""
		v.FinishedAt = &now
		expires := now.Add(RuntimeCertificationValidity)
		v.ExpiresAt = &expires
		v.EvidenceDigest = RuntimeCertificationEvidenceDigest(v)
	}
	v.TaskLeaseExpiresAt = nil
	v.Revision++
	v.UpdatedAt = now
	s.runtimeCertifications[v.ID] = cloneRuntimeCertification(v)
	action := "runtime_certification.install_checkpointed"
	if v.State == RuntimeCertificationSucceeded {
		action = "runtime_certification.succeeded"
	}
	s.appendAuditLocked("cluster-agent", action, "runtimeCertification", v.ID, v.Revision, map[string]any{"phase": result.Phase, "evidenceDigest": v.EvidenceDigest, "taskFenceToken": result.TaskFenceToken})
	s.appendOutboxLocked("runtimeCertification", v.ID, action, v)
	return cloneRuntimeCertification(v), nil
}

func (s *MemoryStore) RevokeRuntimeCertification(_ context.Context, id string, expected int64, actor string) (RuntimeCertificationRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.runtimeCertifications[id]
	if !ok {
		return RuntimeCertificationRun{}, ErrNotFound
	}
	if v.Revision != expected {
		return RuntimeCertificationRun{}, ErrConflict
	}
	if v.State != RuntimeCertificationSucceeded {
		return RuntimeCertificationRun{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	v.State = RuntimeCertificationRevoked
	v.RevokedBy = actor
	v.RevokedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.runtimeCertifications[id] = cloneRuntimeCertification(v)
	s.appendAuditLocked(actor, "runtime_certification.revoked", "runtimeCertification", v.ID, v.Revision, map[string]any{"evidenceDigest": v.EvidenceDigest})
	s.appendOutboxLocked("runtimeCertification", v.ID, "runtime_certification.revoked", v)
	return cloneRuntimeCertification(v), nil
}
