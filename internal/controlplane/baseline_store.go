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

const ExecutionPlanTTL = 30 * time.Minute

func ExecutionPlanContextDigest(desiredDigest, observedDigest, inventoryDigest, impactDigest string) string {
	raw, _ := json.Marshal(struct {
		Desired   string `json:"desired"`
		Observed  string `json:"observed"`
		Inventory string `json:"inventory"`
		Impact    string `json:"impact"`
	}{strings.TrimSpace(desiredDigest), strings.TrimSpace(observedDigest), strings.TrimSpace(inventoryDigest), strings.TrimSpace(impactDigest)})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func BaselineCompletionEvidenceReady(v BaselineDeployment, now time.Time) bool {
	if v.State != BaselineDeploymentSucceeded || v.DesiredDigest == "" || v.DesiredDigest != v.ObservedDigest {
		return false
	}
	if !strings.HasPrefix(v.EvidenceDigest, "sha256:") || len(v.Evidence) == 0 || v.EvidenceDigest != BaselineEvidenceSetDigest(v.Evidence) {
		return false
	}
	if err := ValidateEvidenceCollectionPlan(v.PlanImpact.Evidence); err != nil {
		return false
	}
	if err := ValidateCollectedBaselineEvidence(v.PlanImpact.Evidence, v.ID, v.Evidence); err != nil {
		return false
	}
	for _, item := range v.Evidence {
		if !item.Required || item.CollectedAt == nil || item.RetainUntil == nil || !item.RetainUntil.After(*item.CollectedAt) || !now.Before(*item.RetainUntil) {
			return false
		}
	}
	return true
}

func BaselinePlanFresh(v BaselineDeployment, cluster ManagedCluster, now time.Time) bool {
	if v.PlanCreatedAt == nil || v.PlanExpiresAt == nil || !now.Before(*v.PlanExpiresAt) {
		return false
	}
	if strings.TrimSpace(v.PlanInventoryDigest) == "" || strings.TrimSpace(cluster.InventoryDigest) == "" || v.PlanInventoryDigest != cluster.InventoryDigest {
		return false
	}
	return strings.HasPrefix(v.PlanImpactDigest, "sha256:") && v.PlanImpact.Digest == v.PlanImpactDigest && v.PlanImpact.ApprovalReady && v.PlanImpact.Capability.Status == "PASS" && ValidateCapabilityPreflight(v.PlanImpact.Capability) == nil && PlanningImpactSchemaReady(v.PlanImpact) && ValidateEvidenceCollectionPlan(v.PlanImpact.Evidence) == nil && v.PlanContextDigest == ExecutionPlanContextDigest(v.DesiredDigest, v.ObservedDigest, v.PlanInventoryDigest, v.PlanImpactDigest)
}

func resetBaselineForReplan(v *BaselineDeployment, now time.Time, reason string) {
	v.State = BaselineDeploymentPlanning
	v.PendingAction = "PLAN"
	v.ApprovedBy = ""
	v.ApprovedAt = nil
	v.Plan = nil
	v.PlanCreatedAt = nil
	v.PlanExpiresAt = nil
	v.PlanInventoryDigest = ""
	v.PlanImpact = BaselinePlanImpact{}
	v.PlanImpactDigest = ""
	v.PlanContextDigest = ""
	v.Evidence = nil
	v.EvidenceDigest = ""
	v.PlanRevalidationCount++
	v.LastError = strings.TrimSpace(reason)
	v.FinishedAt = nil
	v.Revision++
	v.UpdatedAt = now
}

func cloneBaselineDeployment(v BaselineDeployment) BaselineDeployment {
	v.Plan = append([]BaselinePlanChange(nil), v.Plan...)
	v.PlanImpact.Capability.Checks = append([]PlanCapabilityCheck(nil), v.PlanImpact.Capability.Checks...)
	for i := range v.PlanImpact.Capability.Checks {
		v.PlanImpact.Capability.Checks[i].Evidence = append([]string(nil), v.PlanImpact.Capability.Checks[i].Evidence...)
	}
	v.PlanImpact.Capability.Blockers = append([]string(nil), v.PlanImpact.Capability.Blockers...)
	v.PlanImpact.Capability.Warnings = append([]string(nil), v.PlanImpact.Capability.Warnings...)
	v.PlanImpact.API = append([]PlanAPIImpact(nil), v.PlanImpact.API...)
	for i := range v.PlanImpact.API {
		v.PlanImpact.API[i].Schema.Warnings = append([]string(nil), v.PlanImpact.API[i].Schema.Warnings...)
	}
	v.PlanImpact.Blockers = append([]string(nil), v.PlanImpact.Blockers...)
	v.PlanImpact.Warnings = append([]string(nil), v.PlanImpact.Warnings...)
	v.PlanImpact.Capacity.UnknownReasons = append([]string(nil), v.PlanImpact.Capacity.UnknownReasons...)
	v.PlanImpact.Capacity.QuotaImpacts = append([]PlanQuotaImpact(nil), v.PlanImpact.Capacity.QuotaImpacts...)
	for i := range v.PlanImpact.Capacity.QuotaImpacts {
		v.PlanImpact.Capacity.QuotaImpacts[i].Current = cloneStringMap(v.PlanImpact.Capacity.QuotaImpacts[i].Current)
		v.PlanImpact.Capacity.QuotaImpacts[i].Desired = cloneStringMap(v.PlanImpact.Capacity.QuotaImpacts[i].Desired)
	}
	v.PlanImpact.Disruption.Reasons = append([]string(nil), v.PlanImpact.Disruption.Reasons...)
	v.PlanImpact.Disruption.AffectedResources = append([]string(nil), v.PlanImpact.Disruption.AffectedResources...)
	v.PlanImpact.Rollback.Resources = append([]PlanRollbackResource(nil), v.PlanImpact.Rollback.Resources...)
	for i := range v.PlanImpact.Rollback.Resources {
		v.PlanImpact.Rollback.Resources[i].Warnings = append([]string(nil), v.PlanImpact.Rollback.Resources[i].Warnings...)
		v.PlanImpact.Rollback.Resources[i].RestoreObject = cloneAnyMap(v.PlanImpact.Rollback.Resources[i].RestoreObject)
	}
	v.PlanImpact.Rollback.Blockers = append([]string(nil), v.PlanImpact.Rollback.Blockers...)
	v.PlanImpact.Rollback.Warnings = append([]string(nil), v.PlanImpact.Rollback.Warnings...)
	v.PlanImpact.Evidence.Artifacts = append([]PlanEvidenceArtifact(nil), v.PlanImpact.Evidence.Artifacts...)
	v.PlanImpact.Evidence.Blockers = append([]string(nil), v.PlanImpact.Evidence.Blockers...)
	v.PlanImpact.Evidence.Warnings = append([]string(nil), v.PlanImpact.Evidence.Warnings...)
	v.Evidence = append([]BaselineEvidenceArtifact(nil), v.Evidence...)
	for i := range v.Evidence {
		v.Evidence[i].Payload = cloneAnyMap(v.Evidence[i].Payload)
	}
	return v
}

func cloneAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	raw, _ := json.Marshal(in)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func ValidateBaselineDeploymentCreate(v *BaselineDeployment) error {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	v.BaselineID = strings.TrimSpace(v.BaselineID)
	v.BaselineVersion = strings.TrimSpace(v.BaselineVersion)
	v.TargetNamespace = strings.TrimSpace(v.TargetNamespace)
	v.Risk = strings.ToLower(strings.TrimSpace(v.Risk))
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	v.SourceType = strings.ToLower(strings.TrimSpace(v.SourceType))
	v.SourceID = strings.TrimSpace(v.SourceID)
	v.SourceVersion = strings.TrimSpace(v.SourceVersion)
	if v.ProjectID == "" || v.ClusterID == "" || v.BaselineID == "" || v.BaselineVersion == "" || v.TargetNamespace == "" || !strings.HasPrefix(v.DesiredDigest, "sha256:") || !strings.HasPrefix(v.RequestDigest, "sha256:") || v.IdempotencyKey == "" {
		return fmt.Errorf("%w: project, cluster, baseline, namespace, digests and idempotency key are required", ErrValidation)
	}
	if v.SourceType == "" && v.SourceID == "" && v.SourceVersion == "" {
		return nil
	}
	if v.SourceType != BaselineSourceMarketplace || v.SourceID == "" || v.SourceVersion == "" {
		return fmt.Errorf("%w: source identity must be empty or a complete marketplace offer identity", ErrValidation)
	}
	return nil
}

func (s *MemoryStore) CreateBaselineDeployment(_ context.Context, v BaselineDeployment, actor string) (BaselineDeployment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[v.ProjectID]; !ok {
		return BaselineDeployment{}, false, ErrNotFound
	}
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || cluster.ProjectID != v.ProjectID {
		return BaselineDeployment{}, false, ErrNotFound
	}
	if err := ValidateBaselineDeploymentCreate(&v); err != nil {
		return BaselineDeployment{}, false, err
	}
	for _, existing := range s.baselineDeployments {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return BaselineDeployment{}, false, ErrIdempotencyConflict
			}
			return cloneBaselineDeployment(existing), true, nil
		}
		if existing.ClusterID == v.ClusterID && existing.BaselineID == v.BaselineID {
			switch existing.State {
			case BaselineDeploymentPlanning, BaselineDeploymentAwaitingApproval, BaselineDeploymentQueued, BaselineDeploymentApplying, BaselineDeploymentRollbackQueued, BaselineDeploymentRollingBack:
				return BaselineDeployment{}, false, ErrDuplicateName
			}
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("bld"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = BaselineDeploymentPlanning
	v.PendingAction = "PLAN"
	v.RequestedBy = actor
	v.Plan = nil
	s.baselineDeployments[v.ID] = cloneBaselineDeployment(v)
	s.appendAuditLocked(actor, "baseline_deployment.created", "baselineDeployment", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "baselineId": v.BaselineID})
	s.appendOutboxLocked("baselineDeployment", v.ID, "baseline_deployment.planning_requested", v)
	return cloneBaselineDeployment(v), false, nil
}

func (s *MemoryStore) GetBaselineDeployment(_ context.Context, id string) (BaselineDeployment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.baselineDeployments[id]
	if !ok {
		return BaselineDeployment{}, ErrNotFound
	}
	return cloneBaselineDeployment(v), nil
}

func (s *MemoryStore) ListBaselineDeployments(_ context.Context, projectID, clusterID string) ([]BaselineDeployment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []BaselineDeployment{}
	for _, v := range s.baselineDeployments {
		if (projectID == "" || v.ProjectID == projectID) && (clusterID == "" || v.ClusterID == clusterID) {
			out = append(out, cloneBaselineDeployment(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return resourceCreatedBefore(out[i].ResourceMeta, out[j].ResourceMeta) })
	return out, nil
}

func (s *MemoryStore) ApproveBaselineDeployment(_ context.Context, id string, expected int64, actor string) (BaselineDeployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.baselineDeployments[id]
	if !ok {
		return BaselineDeployment{}, ErrNotFound
	}
	if v.Revision != expected {
		return BaselineDeployment{}, ErrConflict
	}
	if v.State != BaselineDeploymentAwaitingApproval {
		return BaselineDeployment{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || !BaselinePlanFresh(v, cluster, now) {
		if ok && v.PlanImpact.Digest != "" && !v.PlanImpact.ApprovalReady {
			return BaselineDeployment{}, fmt.Errorf("%w: plan impact has approval blockers", ErrPrerequisite)
		}
		return BaselineDeployment{}, ErrPlanStale
	}
	v.State = BaselineDeploymentQueued
	v.PendingAction = "APPLY"
	v.ApprovedBy = actor
	v.ApprovedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.baselineDeployments[id] = cloneBaselineDeployment(v)
	s.appendAuditLocked(actor, "baseline_deployment.approved", "baselineDeployment", id, v.Revision, map[string]any{"desiredDigest": v.DesiredDigest})
	s.appendOutboxLocked("baselineDeployment", id, "baseline_deployment.queued", v)
	return cloneBaselineDeployment(v), nil
}

func (s *MemoryStore) RevalidateBaselineDeployment(_ context.Context, id string, expected int64, actor string) (BaselineDeployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.baselineDeployments[id]
	if !ok {
		return BaselineDeployment{}, ErrNotFound
	}
	if v.Revision != expected {
		return BaselineDeployment{}, ErrConflict
	}
	if v.State != BaselineDeploymentAwaitingApproval && v.State != BaselineDeploymentQueued {
		return BaselineDeployment{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	resetBaselineForReplan(&v, now, "plan revalidation requested")
	s.baselineDeployments[id] = cloneBaselineDeployment(v)
	s.appendAuditLocked(actor, "baseline_deployment.revalidation_requested", "baselineDeployment", id, v.Revision, map[string]any{"revalidationCount": v.PlanRevalidationCount})
	s.appendOutboxLocked("baselineDeployment", id, "baseline_deployment.planning_requested", v)
	return cloneBaselineDeployment(v), nil
}

func (s *MemoryStore) RetryBaselineDeployment(_ context.Context, id string, expected int64, actor string) (BaselineDeployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.baselineDeployments[id]
	if !ok {
		return BaselineDeployment{}, ErrNotFound
	}
	if v.Revision != expected {
		return BaselineDeployment{}, ErrConflict
	}
	if v.State != BaselineDeploymentFailed {
		return BaselineDeployment{}, ErrInvalidTransition
	}
	switch v.PendingAction {
	case "PLAN":
		v.State = BaselineDeploymentPlanning
	case "APPLY":
		v.State = BaselineDeploymentQueued
	case "ROLLBACK":
		return BaselineDeployment{}, ownerDestructiveRetryRequiresFreshRequest(v.DestructiveOperationID)
	default:
		return BaselineDeployment{}, fmt.Errorf("%w: failed baseline has no resumable action", ErrValidation)
	}
	v.LastError = ""
	v.FinishedAt = nil
	v.Revision++
	v.UpdatedAt = nowUTC(s.now)
	s.baselineDeployments[id] = cloneBaselineDeployment(v)
	s.appendAuditLocked(actor, "baseline_deployment.retry_queued", "baselineDeployment", id, v.Revision, map[string]any{"action": v.PendingAction})
	s.appendOutboxLocked("baselineDeployment", id, "baseline_deployment.retry_queued", v)
	return cloneBaselineDeployment(v), nil
}

func (s *MemoryStore) QueueBaselineRollback(_ context.Context, id string, expected int64, actor, recoveryCheckpointID, requestDigest string) (BaselineDeployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.baselineDeployments[id]
	if !ok {
		return BaselineDeployment{}, ErrNotFound
	}
	if v.Revision != expected {
		return BaselineDeployment{}, ErrConflict
	}
	if v.State != BaselineDeploymentSucceeded && v.State != BaselineDeploymentFailed && v.State != BaselineDeploymentRollbackQueued {
		return BaselineDeployment{}, ErrInvalidTransition
	}
	if v.State == BaselineDeploymentRollbackQueued {
		if err := s.cancelOwnerDestructiveOperationLocked(v.DestructiveOperationID, actor, "recovery checkpoint superseded before rollback claim"); err != nil {
			return BaselineDeployment{}, err
		}
	}
	op, err := s.createOwnerDestructiveOperationLocked(v.ProjectID, v.ClusterID, OwnerOperationBaselineRollback, v.ID, v.Revision, v.DesiredDigest, recoveryCheckpointID, actor, requestDigest, false)
	if err != nil {
		return BaselineDeployment{}, err
	}
	now := nowUTC(s.now)
	v.State = BaselineDeploymentRollbackQueued
	v.DestructiveOperationID = op.ID
	v.PendingAction = "ROLLBACK"
	v.LastError = ""
	v.FinishedAt = nil
	v.Revision++
	v.UpdatedAt = now
	s.baselineDeployments[id] = cloneBaselineDeployment(v)
	s.appendAuditLocked(actor, "baseline_deployment.rollback_queued", "baselineDeployment", id, v.Revision, nil)
	s.appendOutboxLocked("baselineDeployment", id, "baseline_deployment.rollback_queued", v)
	return cloneBaselineDeployment(v), nil
}

func (s *MemoryStore) NextBaselineTask(_ context.Context, clusterID, agentTokenDigest string) (BaselineDeployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, agentTokenDigest)
	if err != nil {
		return BaselineDeployment{}, err
	}
	now := nowUTC(s.now)
	ids := make([]string, 0)
	for id, v := range s.baselineDeployments {
		if v.ClusterID != clusterID {
			continue
		}
		switch v.State {
		case BaselineDeploymentPlanning:
			if !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
				ids = append(ids, id)
			}
		case BaselineDeploymentQueued, BaselineDeploymentRollbackQueued:
			ids = append(ids, id)
		case BaselineDeploymentApplying, BaselineDeploymentRollingBack:
			if !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return BaselineDeployment{}, ErrNotFound
	}
	sort.Slice(ids, func(i, j int) bool {
		return resourceCreatedBefore(s.baselineDeployments[ids[i]].ResourceMeta, s.baselineDeployments[ids[j]].ResourceMeta)
	})
	v := s.baselineDeployments[ids[0]]
	if v.State == BaselineDeploymentRollingBack && v.TaskLeaseExpiresAt != nil {
		message := "baseline rollback task lease expired; explicit recovery-bound retry is required"
		if _, err := s.finishOwnerDestructiveOperationLocked(v.DestructiveOperationID, false, message, "cluster-agent"); err != nil {
			return BaselineDeployment{}, err
		}
		v.State, v.LastError, v.TaskLeaseExpiresAt = BaselineDeploymentFailed, message, nil
		v.FinishedAt = &now
		v.Revision++
		v.UpdatedAt = now
		s.baselineDeployments[v.ID] = cloneBaselineDeployment(v)
		s.appendAuditLocked("cluster-agent", "baseline_deployment.task.lease_expired", "baselineDeployment", v.ID, v.Revision, map[string]any{"action": "ROLLBACK", "taskFenceToken": v.TaskFenceToken})
		s.appendOutboxLocked("baselineDeployment", v.ID, "baseline_deployment.failed", v)
		return BaselineDeployment{}, ErrNotFound
	}
	if v.State == BaselineDeploymentQueued && !BaselinePlanFresh(v, cluster, now) {
		resetBaselineForReplan(&v, now, "approved plan became stale before apply; a fresh read-only plan is required")
		s.baselineDeployments[v.ID] = cloneBaselineDeployment(v)
		s.appendAuditLocked("cluster-agent", "baseline_deployment.plan_stale", "baselineDeployment", v.ID, v.Revision, map[string]any{"inventoryDigest": cluster.InventoryDigest})
		s.appendOutboxLocked("baselineDeployment", v.ID, "baseline_deployment.planning_requested", v)
	}
	action := "PLAN"
	switch v.State {
	case BaselineDeploymentQueued:
		action = "APPLY"
		v.State = BaselineDeploymentApplying
		if v.StartedAt == nil {
			v.StartedAt = &now
		}
	case BaselineDeploymentApplying:
		action = "APPLY"
	case BaselineDeploymentRollbackQueued:
		action = "ROLLBACK"
		if _, err := s.startOwnerDestructiveOperationLocked(v.DestructiveOperationID, v.ProjectID, v.ClusterID, "cluster-agent"); err != nil {
			return BaselineDeployment{}, err
		}
		v.State = BaselineDeploymentRollingBack
		if v.StartedAt == nil {
			v.StartedAt = &now
		}
	case BaselineDeploymentRollingBack:
		action = "ROLLBACK"
	}
	lease := now.Add(AgentTaskLeaseDuration)
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseExpiresAt = &lease
	v.Revision++
	v.UpdatedAt = now
	s.baselineDeployments[v.ID] = cloneBaselineDeployment(v)
	s.appendAuditLocked("cluster-agent", "baseline_deployment.task_claimed", "baselineDeployment", v.ID, v.Revision, map[string]any{"action": action, "attempt": v.TaskAttempt, "taskFenceToken": v.TaskFenceToken, "leaseExpiresAt": lease})
	return cloneBaselineDeployment(v), nil
}

func (s *MemoryStore) ReportBaselineTask(_ context.Context, clusterID, agentTokenDigest string, expected int64, result BaselineTaskResult) (BaselineDeployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, err := s.requireClusterTaskAdmissionLocked(clusterID, agentTokenDigest)
	if err != nil {
		return BaselineDeployment{}, err
	}
	v, ok := s.baselineDeployments[result.DeploymentID]
	if !ok || v.ClusterID != clusterID {
		return BaselineDeployment{}, ErrNotFound
	}
	now := nowUTC(s.now)
	if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken || !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		return BaselineDeployment{}, ErrConflict
	}
	switch strings.ToUpper(result.Action) {
	case "PLAN":
		if v.State != BaselineDeploymentPlanning {
			return BaselineDeployment{}, ErrInvalidTransition
		}
		if !result.Success {
			v.State = BaselineDeploymentFailed
			v.LastError = strings.TrimSpace(result.Error)
			v.FinishedAt = &now
		} else {
			if strings.TrimSpace(cluster.InventoryDigest) == "" || !strings.HasPrefix(cluster.InventoryDigest, "sha256:") {
				return BaselineDeployment{}, fmt.Errorf("%w: cluster inventory is required before a plan can be approved", ErrPrerequisite)
			}
			if err := ValidatePlanningImpact(result.Impact, cluster.InventoryDigest, result.Changes); err != nil {
				return BaselineDeployment{}, err
			}
			v.Plan = append([]BaselinePlanChange(nil), result.Changes...)
			v.PlanImpact = result.Impact
			v.PlanImpactDigest = result.Impact.Digest
			v.PreviousDigest = result.ObservedDigest
			v.ObservedDigest = result.ObservedDigest
			v.PlanCreatedAt = &now
			expires := now.Add(ExecutionPlanTTL)
			v.PlanExpiresAt = &expires
			v.PlanInventoryDigest = cluster.InventoryDigest
			v.PlanContextDigest = ExecutionPlanContextDigest(v.DesiredDigest, v.ObservedDigest, v.PlanInventoryDigest, v.PlanImpactDigest)
			v.State = BaselineDeploymentAwaitingApproval
			v.PendingAction = ""
			v.LastError = ""
		}
	case "APPLY":
		if v.State != BaselineDeploymentApplying {
			return BaselineDeployment{}, ErrInvalidTransition
		}
		if !result.Success || result.ObservedDigest != v.DesiredDigest {
			v.State = BaselineDeploymentFailed
			v.LastError = strings.TrimSpace(result.Error)
			if v.LastError == "" {
				v.LastError = "observed digest does not match desired digest"
			}
		} else {
			sealed, evidenceDigest, evidenceErr := SealBaselineEvidence(v.PlanImpact.Evidence, v.ID, result.Evidence, now)
			if evidenceErr != nil {
				return BaselineDeployment{}, fmt.Errorf("%w: baseline completion evidence invalid: %v", ErrValidation, evidenceErr)
			}
			v.State = BaselineDeploymentSucceeded
			v.PendingAction = ""
			v.ObservedDigest = result.ObservedDigest
			v.Evidence = sealed
			v.EvidenceDigest = evidenceDigest
			v.LastError = ""
		}
		v.FinishedAt = &now
	case "ROLLBACK":
		if v.State != BaselineDeploymentRollingBack {
			return BaselineDeployment{}, ErrInvalidTransition
		}
		if !result.Success {
			v.State = BaselineDeploymentFailed
			v.LastError = strings.TrimSpace(result.Error)
		} else {
			v.State = BaselineDeploymentRolledBack
			v.PendingAction = ""
			v.ObservedDigest = result.ObservedDigest
			v.LastError = ""
		}
		if _, err := s.finishOwnerDestructiveOperationLocked(v.DestructiveOperationID, result.Success, v.LastError, "cluster-agent"); err != nil {
			return BaselineDeployment{}, err
		}
		v.FinishedAt = &now
	default:
		return BaselineDeployment{}, ErrValidation
	}
	v.Revision++
	v.UpdatedAt = now
	s.baselineDeployments[v.ID] = cloneBaselineDeployment(v)
	action := "baseline_deployment." + strings.ToLower(string(v.State))
	auditPayload := map[string]any{"observedDigest": result.ObservedDigest, "taskFenceToken": result.TaskFenceToken}
	if strings.EqualFold(result.Action, "PLAN") && result.Success {
		auditPayload["planImpactDigest"] = v.PlanImpactDigest
		auditPayload["approvalReady"] = v.PlanImpact.ApprovalReady
		auditPayload["disruption"] = v.PlanImpact.Disruption.Level
		auditPayload["maintenance"] = v.PlanImpact.Disruption.MaintenanceRecommendation
		auditPayload["apiImpactCount"] = len(v.PlanImpact.API)
		auditPayload["capacityCeilingCheck"] = v.PlanImpact.Capacity.CeilingCheck
	}
	s.appendAuditLocked("cluster-agent", action, "baselineDeployment", v.ID, v.Revision, auditPayload)
	s.appendOutboxLocked("baselineDeployment", v.ID, action, v)
	return cloneBaselineDeployment(v), nil
}
