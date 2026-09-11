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

const DataProtectionAgentCapability = "target-data-protection-v1"

func cloneBackupPolicy(v BackupPolicy) BackupPolicy {
	v.IncludedNamespaces = append([]string(nil), v.IncludedNamespaces...)
	return v
}

func cloneDataProtectionRun(v DataProtectionRun) DataProtectionRun {
	v.Checks = append([]RuntimeCheck(nil), v.Checks...)
	return v
}

func backupPolicyDigest(v BackupPolicy) string {
	raw, _ := json.Marshal(struct {
		ProjectID             string   `json:"projectId"`
		ClusterID             string   `json:"clusterId"`
		Name                  string   `json:"name"`
		Provider              string   `json:"provider"`
		BackupStorageLocation string   `json:"backupStorageLocation"`
		CredentialRef         string   `json:"credentialRef"`
		Schedule              string   `json:"schedule"`
		Retention             string   `json:"retention"`
		IncludedNamespaces    []string `json:"includedNamespaces"`
	}{v.ProjectID, v.ClusterID, v.Name, v.Provider, v.BackupStorageLocation, v.CredentialRef, v.Schedule, v.Retention, v.IncludedNamespaces})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func DataProtectionEvidenceDigest(v DataProtectionRun, result DataProtectionTaskResult) string {
	// Evidence identity must be restart/retry deterministic. RuntimeCheck.DurationMillis
	// and observed RPO/RTO are telemetry measurements: they remain persisted on the run
	// but are deliberately excluded from the canonical semantic digest because a resumed
	// observation of the same already-completed Velero object can legitimately measure a
	// different local wall-clock duration.
	checks := make([]RuntimeCheck, 0, len(result.Checks))
	for _, check := range result.Checks {
		check.DurationMillis = 0
		checks = append(checks, check)
	}
	raw, _ := json.Marshal(struct {
		Schema          string                `json:"schema"`
		RunID           string                `json:"runId"`
		Kind            DataProtectionRunKind `json:"kind"`
		ProjectID       string                `json:"projectId"`
		ClusterID       string                `json:"clusterId"`
		PolicyID        string                `json:"policyId"`
		BackupRunID     string                `json:"backupRunId,omitempty"`
		InventoryDigest string                `json:"inventoryDigest"`
		PolicyDigest    string                `json:"policyDigest"`
		VeleroName      string                `json:"veleroName"`
		SourceBackup    string                `json:"sourceBackupName,omitempty"`
		TargetNamespace string                `json:"targetNamespace,omitempty"`
		Reference       string                `json:"reference"`
		Checks          []RuntimeCheck        `json:"checks"`
	}{"platform.4so.io/data-protection-evidence/v2", v.ID, v.Kind, v.ProjectID, v.ClusterID, v.PolicyID, v.BackupRunID, v.InventoryDigest, v.PolicyDigest, v.VeleroName, v.SourceBackupName, v.TargetNamespace, result.Reference, checks})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ValidateDataProtectionSuccessfulResult(v DataProtectionRun, result DataProtectionTaskResult) error {
	if !result.Success {
		return nil
	}
	required := []string{"data-protection/bsl"}
	var referencePrefix string
	switch v.Kind {
	case DataProtectionBackup:
		required = append(required, "data-protection/backup")
		referencePrefix = "velero://" + v.ClusterID + "/backup/"
	case DataProtectionRestore:
		required = append(required, "data-protection/restore", "data-protection/restore-progress")
		referencePrefix = "velero://" + v.ClusterID + "/restore/"
	case DataProtectionRestoreDrill:
		required = append(required, "data-protection/restore_drill", "data-protection/restore-progress", "data-protection/restore-drill-cleanup")
		referencePrefix = "velero://" + v.ClusterID + "/restore-drill/"
	default:
		return fmt.Errorf("%w: unsupported data protection run kind", ErrValidation)
	}
	seen := map[string]bool{}
	for _, check := range result.Checks {
		key := strings.TrimSpace(check.Key)
		if key == "" || check.Status != "PASS" {
			return fmt.Errorf("%w: successful data protection evidence contains a non-PASS check", ErrValidation)
		}
		seen[key] = true
	}
	for _, key := range required {
		if !seen[key] {
			return fmt.Errorf("%w: successful data protection evidence is missing required check %s", ErrValidation, key)
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(result.Reference), referencePrefix) {
		return fmt.Errorf("%w: successful data protection reference does not match run kind/cluster", ErrValidation)
	}
	if result.RPOSeconds < 0 || result.RTOSeconds < 0 {
		return fmt.Errorf("%w: RPO/RTO evidence cannot be negative", ErrValidation)
	}
	return nil
}

func normalizeNamespaceList(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" || len(v) > 63 || strings.ContainsAny(v, " /\\\n\r\t") || strings.HasPrefix(v, "-") || strings.HasSuffix(v, "-") {
			return nil, fmt.Errorf("%w: included namespace is invalid", ErrValidation)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) == 0 || len(out) > 32 {
		return nil, fmt.Errorf("%w: one to 32 included namespaces are required", ErrValidation)
	}
	sort.Strings(out)
	return out, nil
}

func ValidateBackupPolicy(v *BackupPolicy, cluster ManagedCluster) error {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	v.Name = normalizeName(v.Name)
	v.Provider = strings.ToLower(strings.TrimSpace(v.Provider))
	v.BackupStorageLocation = strings.TrimSpace(v.BackupStorageLocation)
	v.CredentialRef = strings.TrimSpace(v.CredentialRef)
	v.Schedule = strings.Join(strings.Fields(v.Schedule), " ")
	v.Retention = strings.TrimSpace(v.Retention)
	if v.ProjectID == "" || v.ClusterID == "" || v.Name == "" || cluster.ID != v.ClusterID || cluster.ProjectID != v.ProjectID {
		return ErrNotFound
	}
	if v.Provider != "velero" || v.BackupStorageLocation == "" || len(v.BackupStorageLocation) > 63 {
		return fmt.Errorf("%w: V1 data protection requires an explicit Velero backup storage location", ErrValidation)
	}
	if !strings.HasPrefix(v.CredentialRef, "k8s-secret://velero/") || len(v.CredentialRef) > 256 || strings.ContainsAny(v.CredentialRef, "\n\r\t") {
		return fmt.Errorf("%w: credentialRef must be an opaque k8s-secret://velero/<name> reference; secret material is forbidden", ErrValidation)
	}
	if _, err := BackupScheduleMatchesUTC(v.Schedule, time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		return fmt.Errorf("%w: schedule must be a valid five-field UTC cron expression: %v", ErrValidation, err)
	}
	retention, err := time.ParseDuration(v.Retention)
	if err != nil || retention < time.Hour || retention > 365*24*time.Hour {
		return fmt.Errorf("%w: retention must be a duration between 1h and 8760h", ErrValidation)
	}
	ns, err := normalizeNamespaceList(v.IncludedNamespaces)
	if err != nil {
		return err
	}
	v.IncludedNamespaces = ns
	v.DesiredDigest = backupPolicyDigest(*v)
	return nil
}

func (s *MemoryStore) UpsertBackupPolicy(_ context.Context, v BackupPolicy, expected int64, actor string) (BackupPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok {
		return BackupPolicy{}, ErrNotFound
	}
	if err := ValidateBackupPolicy(&v, cluster); err != nil {
		return BackupPolicy{}, err
	}
	now := nowUTC(s.now)
	if v.ID == "" {
		for _, current := range s.backupPolicies {
			if current.ProjectID == v.ProjectID && current.ClusterID == v.ClusterID && normalizeName(current.Name) == v.Name {
				return BackupPolicy{}, ErrDuplicateName
			}
		}
		v.ResourceMeta = ResourceMeta{ID: s.id("bkp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
		v.State = BackupPolicyActive
		v.RequestedBy = strings.TrimSpace(actor)
		s.backupPolicies[v.ID] = cloneBackupPolicy(v)
		s.appendAuditLocked(actor, "backup_policy.created", "backupPolicy", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "desiredDigest": v.DesiredDigest})
		s.appendOutboxLocked("backupPolicy", v.ID, "backup_policy.created", v)
		return cloneBackupPolicy(v), nil
	}
	current, ok := s.backupPolicies[v.ID]
	if !ok {
		return BackupPolicy{}, ErrNotFound
	}
	if current.Revision != expected || current.ProjectID != v.ProjectID || current.ClusterID != v.ClusterID {
		return BackupPolicy{}, ErrConflict
	}
	v.ResourceMeta = current.ResourceMeta
	v.Revision++
	v.UpdatedAt = now
	v.State = current.State
	v.RequestedBy = current.RequestedBy
	s.backupPolicies[v.ID] = cloneBackupPolicy(v)
	s.appendAuditLocked(actor, "backup_policy.updated", "backupPolicy", v.ID, v.Revision, map[string]any{"desiredDigest": v.DesiredDigest})
	s.appendOutboxLocked("backupPolicy", v.ID, "backup_policy.updated", v)
	return cloneBackupPolicy(v), nil
}

func (s *MemoryStore) SetBackupPolicyState(_ context.Context, id string, expected int64, state BackupPolicyState, actor string) (BackupPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.backupPolicies[strings.TrimSpace(id)]
	if !ok {
		return BackupPolicy{}, ErrNotFound
	}
	if v.Revision != expected {
		return BackupPolicy{}, ErrConflict
	}
	if state != BackupPolicyActive && state != BackupPolicyDisabled {
		return BackupPolicy{}, ErrValidation
	}
	if v.State == state {
		return cloneBackupPolicy(v), nil
	}
	now := nowUTC(s.now)
	v.State = state
	v.Revision++
	v.UpdatedAt = now
	s.backupPolicies[v.ID] = cloneBackupPolicy(v)
	action := "backup_policy.enabled"
	if state == BackupPolicyDisabled {
		action = "backup_policy.disabled"
	}
	s.appendAuditLocked(actor, action, "backupPolicy", v.ID, v.Revision, map[string]any{"state": state})
	s.appendOutboxLocked("backupPolicy", v.ID, action, v)
	return cloneBackupPolicy(v), nil
}

func (s *MemoryStore) GetBackupPolicy(_ context.Context, id string) (BackupPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.backupPolicies[id]
	if !ok {
		return BackupPolicy{}, ErrNotFound
	}
	return cloneBackupPolicy(v), nil
}

func (s *MemoryStore) ListBackupPolicies(_ context.Context, projectID, clusterID string) ([]BackupPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []BackupPolicy{}
	for _, v := range s.backupPolicies {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) {
			out = append(out, cloneBackupPolicy(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateDataProtectionRun(_ context.Context, v DataProtectionRun, actor string) (DataProtectionRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.backupPolicies[strings.TrimSpace(v.PolicyID)]
	if !ok || policy.State != BackupPolicyActive {
		return DataProtectionRun{}, false, ErrPrerequisite
	}
	cluster, ok := s.managedClusters[policy.ClusterID]
	if !ok || !ClusterTaskAdmitted(cluster) || !clusterHasCapability(cluster, DataProtectionAgentCapability) {
		return DataProtectionRun{}, false, fmt.Errorf("%w: cluster data-protection mutation authority is not active", ErrPrerequisite)
	}
	if !validSHA256(cluster.InventoryDigest) || v.ProjectID != policy.ProjectID || v.ClusterID != policy.ClusterID {
		return DataProtectionRun{}, false, ErrPrerequisite
	}
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	v.RequestDigest = strings.TrimSpace(v.RequestDigest)
	if v.IdempotencyKey == "" || !validSHA256(v.RequestDigest) {
		return DataProtectionRun{}, false, fmt.Errorf("%w: idempotency key and request digest are required", ErrValidation)
	}
	key := "dataProtectionRun:" + v.ProjectID + ":" + v.IdempotencyKey
	if id, ok := s.idempotency[key]; ok {
		current := s.dataProtectionRuns[id]
		if current.RequestDigest != v.RequestDigest {
			return DataProtectionRun{}, false, ErrConflict
		}
		return cloneDataProtectionRun(current), true, nil
	}
	if v.Kind != DataProtectionBackup && v.Kind != DataProtectionRestore && v.Kind != DataProtectionRestoreDrill {
		return DataProtectionRun{}, false, fmt.Errorf("%w: unsupported data protection run kind", ErrValidation)
	}
	if v.Kind != DataProtectionBackup {
		backup, ok := s.dataProtectionRuns[strings.TrimSpace(v.BackupRunID)]
		if !ok || backup.Kind != DataProtectionBackup || backup.State != DataProtectionSucceeded || backup.ClusterID != v.ClusterID || backup.PolicyID != v.PolicyID || backup.RecoveryCheckpointID == "" {
			return DataProtectionRun{}, false, fmt.Errorf("%w: restore requires a successful backup run with recovery checkpoint", ErrPrerequisite)
		}
		cp, ok := s.recoveryCheckpoints[backup.RecoveryCheckpointID]
		if !ok || cp.State != RecoveryCheckpointVerified || !cp.ExpiresAt.After(nowUTC(s.now)) || cp.InventoryDigest != backup.InventoryDigest {
			return DataProtectionRun{}, false, fmt.Errorf("%w: source backup recovery checkpoint is unavailable or stale", ErrPrerequisite)
		}
		v.SourceBackupName = backup.VeleroName
		v.RecoveryCheckpointID = cp.ID
		if v.Kind == DataProtectionRestoreDrill && len(policy.IncludedNamespaces) != 1 {
			return DataProtectionRun{}, false, fmt.Errorf("%w: V1 restore drill requires exactly one included namespace", ErrPrerequisite)
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("dpr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.InventoryDigest = cluster.InventoryDigest
	v.PolicyDigest = policy.DesiredDigest
	v.RequestedBy = strings.TrimSpace(actor)
	v.VeleroName = strings.ToLower(string(v.Kind)) + "-" + strings.TrimPrefix(v.ID, "dpr_")
	if len(v.VeleroName) > 63 {
		v.VeleroName = v.VeleroName[:63]
	}
	if v.Kind == DataProtectionRestoreDrill {
		v.TargetNamespace = "restore-drill-" + strings.TrimPrefix(v.ID, "dpr_")
		if len(v.TargetNamespace) > 63 {
			v.TargetNamespace = v.TargetNamespace[:63]
		}
	}
	if v.Kind == DataProtectionRestore {
		v.State = DataProtectionAwaitingApproval
	} else {
		v.State = DataProtectionQueued
	}
	s.dataProtectionRuns[v.ID] = cloneDataProtectionRun(v)
	s.idempotency[key] = v.ID
	s.appendAuditLocked(actor, "data_protection_run.created", "dataProtectionRun", v.ID, v.Revision, map[string]any{"kind": v.Kind, "clusterId": v.ClusterID, "policyId": v.PolicyID})
	s.appendOutboxLocked("dataProtectionRun", v.ID, "data_protection_run.created", v)
	return cloneDataProtectionRun(v), false, nil
}

func (s *MemoryStore) GetDataProtectionRun(_ context.Context, id string) (DataProtectionRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.dataProtectionRuns[id]
	if !ok {
		return DataProtectionRun{}, ErrNotFound
	}
	return cloneDataProtectionRun(v), nil
}

func (s *MemoryStore) ListDataProtectionRuns(_ context.Context, projectID, clusterID string, kind DataProtectionRunKind) ([]DataProtectionRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []DataProtectionRun{}
	for _, v := range s.dataProtectionRuns {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) && (kind == "" || v.Kind == kind) {
			out = append(out, cloneDataProtectionRun(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) ApproveDataProtectionRun(_ context.Context, id string, expected int64, actor string) (DataProtectionRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.dataProtectionRuns[id]
	if !ok {
		return DataProtectionRun{}, ErrNotFound
	}
	if v.Revision != expected {
		return DataProtectionRun{}, ErrConflict
	}
	actor = strings.TrimSpace(actor)
	if v.Kind != DataProtectionRestore || v.State != DataProtectionAwaitingApproval || actor == "" || actor == v.RequestedBy {
		return DataProtectionRun{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	v.State = DataProtectionQueued
	v.ApprovedBy = actor
	v.ApprovedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.dataProtectionRuns[id] = v
	s.appendAuditLocked(actor, "data_protection_run.approved", "dataProtectionRun", id, v.Revision, map[string]any{"kind": v.Kind})
	s.appendOutboxLocked("dataProtectionRun", id, "data_protection_run.approved", v)
	return cloneDataProtectionRun(v), nil
}

func (s *MemoryStore) NextDataProtectionTask(_ context.Context, clusterID, tokenDigest string) (DataProtectionRun, BackupPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, tokenDigest)
	if err != nil {
		return DataProtectionRun{}, BackupPolicy{}, err
	}
	now := nowUTC(s.now)
	var chosen *DataProtectionRun
	for id, current := range s.dataProtectionRuns {
		if current.ClusterID != clusterID || (current.State != DataProtectionQueued && !(current.State == DataProtectionRunning && !AgentTaskLeaseActive(current.TaskLeaseExpiresAt, now))) {
			continue
		}
		if chosen == nil || current.CreatedAt.Before(chosen.CreatedAt) {
			v := current
			v.ID = id
			chosen = &v
		}
	}
	if chosen == nil {
		return DataProtectionRun{}, BackupPolicy{}, ErrNotFound
	}
	v := *chosen
	policy, ok := s.backupPolicies[v.PolicyID]
	if !ok || policy.State != BackupPolicyActive || policy.DesiredDigest != v.PolicyDigest || cluster.InventoryDigest != v.InventoryDigest || !clusterHasCapability(cluster, DataProtectionAgentCapability) {
		v.State = DataProtectionFailed
		v.LastError = "data-protection context changed after run was queued"
		v.FinishedAt = &now
		v.TaskLeaseExpiresAt = nil
		v.Revision++
		v.UpdatedAt = now
		s.dataProtectionRuns[v.ID] = v
		s.appendAuditLocked("system", "data_protection_run.context_invalidated", "dataProtectionRun", v.ID, v.Revision, map[string]any{"kind": v.Kind})
		s.appendOutboxLocked("dataProtectionRun", v.ID, "data_protection_run.failed", v)
		return cloneDataProtectionRun(v), BackupPolicy{}, nil
	}
	if v.State == DataProtectionQueued {
		v.State = DataProtectionRunning
		v.StartedAt = &now
	}
	lease := now.Add(AgentTaskLeaseDuration)
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseExpiresAt = &lease
	v.Revision++
	v.UpdatedAt = now
	s.dataProtectionRuns[v.ID] = v
	s.appendAuditLocked("cluster-agent", "data_protection_run.task_claimed", "dataProtectionRun", v.ID, v.Revision, map[string]any{"kind": v.Kind, "attempt": v.TaskAttempt, "taskFenceToken": v.TaskFenceToken})
	return cloneDataProtectionRun(v), cloneBackupPolicy(policy), nil
}

func (s *MemoryStore) ReportDataProtectionTask(_ context.Context, clusterID, tokenDigest string, expected int64, result DataProtectionTaskResult) (DataProtectionRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requireClusterTaskAdmissionLocked(clusterID, tokenDigest); err != nil {
		return DataProtectionRun{}, err
	}
	v, ok := s.dataProtectionRuns[result.RunID]
	if !ok || v.ClusterID != clusterID {
		return DataProtectionRun{}, ErrNotFound
	}
	now := nowUTC(s.now)
	if v.Revision != expected || v.State != DataProtectionRunning || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		return DataProtectionRun{}, ErrConflict
	}
	if len(result.Checks) == 0 {
		return DataProtectionRun{}, fmt.Errorf("%w: data protection result requires checks", ErrValidation)
	}
	allPass := result.Success
	for _, check := range result.Checks {
		if strings.TrimSpace(check.Key) == "" || check.Status != "PASS" {
			allPass = false
		}
	}
	v.Checks = append([]RuntimeCheck(nil), result.Checks...)
	v.Reference = strings.TrimSpace(result.Reference)
	v.RPOSeconds = result.RPOSeconds
	v.RTOSeconds = result.RTOSeconds
	if !allPass {
		v.State = DataProtectionFailed
		v.LastError = strings.TrimSpace(result.Error)
		if v.LastError == "" {
			v.LastError = "data protection task checks failed"
		}
	} else {
		if err := ValidateDataProtectionSuccessfulResult(v, result); err != nil {
			return DataProtectionRun{}, err
		}
		expectedEvidence := DataProtectionEvidenceDigest(v, result)
		if strings.TrimSpace(result.EvidenceDigest) != expectedEvidence || v.Reference == "" {
			return DataProtectionRun{}, fmt.Errorf("%w: evidence digest/reference mismatch", ErrValidation)
		}
		v.State = DataProtectionSucceeded
		v.EvidenceDigest = expectedEvidence
		v.LastError = ""
		if v.Kind == DataProtectionBackup || v.Kind == DataProtectionRestoreDrill {
			policy := s.backupPolicies[v.PolicyID]
			retention, _ := time.ParseDuration(policy.Retention)
			cp := RecoveryCheckpoint{ProjectID: v.ProjectID, ClusterID: v.ClusterID, Provider: "velero", Reference: v.Reference, EvidenceDigest: v.EvidenceDigest, InventoryDigest: v.InventoryDigest, CompletedAt: now, ExpiresAt: now.Add(retention), State: RecoveryCheckpointVerified, RequestedBy: "cluster-agent"}
			cp.ResourceMeta = ResourceMeta{ID: s.id("rcp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
			s.recoveryCheckpoints[cp.ID] = cp
			v.RecoveryCheckpointID = cp.ID
			s.appendAuditLocked("cluster-agent", "recovery_checkpoint.produced", "recoveryCheckpoint", cp.ID, cp.Revision, map[string]any{"dataProtectionRunId": v.ID, "kind": v.Kind, "evidenceDigest": cp.EvidenceDigest})
			s.appendOutboxLocked("recoveryCheckpoint", cp.ID, "recovery_checkpoint.verified", cp)
		}
	}
	v.FinishedAt = &now
	v.TaskLeaseExpiresAt = nil
	v.Revision++
	v.UpdatedAt = now
	s.dataProtectionRuns[v.ID] = cloneDataProtectionRun(v)
	action := "data_protection_run.failed"
	if v.State == DataProtectionSucceeded {
		action = "data_protection_run.succeeded"
	}
	s.appendAuditLocked("cluster-agent", action, "dataProtectionRun", v.ID, v.Revision, map[string]any{"kind": v.Kind, "evidenceDigest": v.EvidenceDigest, "taskFenceToken": result.TaskFenceToken})
	s.appendOutboxLocked("dataProtectionRun", v.ID, action, v)
	return cloneDataProtectionRun(v), nil
}
