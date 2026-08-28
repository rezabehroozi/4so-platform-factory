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

func cloneFleetGroup(v FleetGroup) FleetGroup {
	v.ClusterIDs = append([]string(nil), v.ClusterIDs...)
	return v
}

func cloneDriftScan(v DriftScan) DriftScan {
	v.Targets = append([]DriftScanTarget(nil), v.Targets...)
	for i := range v.Targets {
		v.Targets[i].Changes = append([]BaselinePlanChange(nil), v.Targets[i].Changes...)
		v.Targets[i].Findings = append([]DriftFinding(nil), v.Targets[i].Findings...)
		if v.Targets[i].Comparison != nil {
			c := *v.Targets[i].Comparison
			v.Targets[i].Comparison = &c
		}
		if v.Targets[i].Git != nil {
			g := *v.Targets[i].Git
			g.ChangedFiles = append([]string(nil), g.ChangedFiles...)
			v.Targets[i].Git = &g
		}
	}
	return v
}

func cloneUpgradeCampaign(v UpgradeCampaign) UpgradeCampaign {
	v.Targets = append([]UpgradeCampaignTarget(nil), v.Targets...)
	v.RecoveryCheckpointIDs = append([]string(nil), v.RecoveryCheckpointIDs...)
	if v.TargetInventoryDigests != nil {
		original := v.TargetInventoryDigests
		v.TargetInventoryDigests = make(map[string]string, len(original))
		for k, value := range original {
			v.TargetInventoryDigests[k] = value
		}
	}
	return v
}

func UpgradeCampaignContextDigest(v UpgradeCampaign) string {
	type target struct {
		ClusterID            string `json:"clusterId"`
		PreviousDeploymentID string `json:"previousDeploymentId"`
		PreviousVersion      string `json:"previousVersion"`
		PreviousDigest       string `json:"previousDigest"`
		InventoryDigest      string `json:"inventoryDigest"`
	}
	targets := make([]target, 0, len(v.Targets))
	for _, item := range v.Targets {
		targets = append(targets, target{item.ClusterID, item.PreviousBaselineDeploymentID, item.PreviousVersion, item.PreviousDigest, v.TargetInventoryDigests[item.ClusterID]})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ClusterID < targets[j].ClusterID })
	checkpoints := append([]string(nil), v.RecoveryCheckpointIDs...)
	sort.Strings(checkpoints)
	raw, _ := json.Marshal(struct {
		BaselineID    string    `json:"baselineId"`
		TargetVersion string    `json:"targetVersion"`
		WindowStart   time.Time `json:"windowStart"`
		WindowEnd     time.Time `json:"windowEnd"`
		Targets       []target  `json:"targets"`
		Checkpoints   []string  `json:"checkpoints"`
	}{v.BaselineID, v.TargetVersion, v.MaintenanceWindowStart.UTC(), v.MaintenanceWindowEnd.UTC(), targets, checkpoints})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *MemoryStore) prepareUpgradeSafetyLocked(v *UpgradeCampaign, checkpointIDs []string, now time.Time) error {
	if v.MaintenanceWindowStart.IsZero() || v.MaintenanceWindowEnd.IsZero() || !v.MaintenanceWindowEnd.After(v.MaintenanceWindowStart) || !v.MaintenanceWindowEnd.After(now) || v.MaintenanceWindowEnd.Sub(v.MaintenanceWindowStart) > 24*time.Hour {
		return fmt.Errorf("%w: maintenance window must end in the future, be ordered, and be at most 24 hours", ErrValidation)
	}
	ids, ok := uniqueStrings(checkpointIDs)
	if !ok || len(ids) != len(v.Targets) {
		return fmt.Errorf("%w: exactly one recovery checkpoint is required for every target cluster", ErrPrerequisite)
	}
	checkpointByCluster := map[string]RecoveryCheckpoint{}
	for _, id := range ids {
		cp, exists := s.recoveryCheckpoints[id]
		if !exists || cp.ProjectID != v.ProjectID {
			return fmt.Errorf("%w: recovery checkpoint %s is unavailable", ErrPrerequisite, id)
		}
		if _, exists := checkpointByCluster[cp.ClusterID]; exists {
			return fmt.Errorf("%w: duplicate recovery checkpoint cluster", ErrPrerequisite)
		}
		checkpointByCluster[cp.ClusterID] = cp
	}
	inventory := map[string]string{}
	for clusterID, digest := range v.TargetInventoryDigests {
		inventory[clusterID] = digest
	}
	for _, t := range v.Targets {
		// Completed/rollback-completed targets no longer require a new recovery snapshot.
		if t.State != UpgradeTargetPending {
			continue
		}
		cluster, exists := s.managedClusters[t.ClusterID]
		if !exists || cluster.ProjectID != v.ProjectID || strings.TrimSpace(cluster.InventoryDigest) == "" {
			return fmt.Errorf("%w: target cluster %s requires fresh inventory", ErrPrerequisite, t.ClusterID)
		}
		cp, exists := checkpointByCluster[t.ClusterID]
		if !exists || cp.State != RecoveryCheckpointVerified || !cp.ExpiresAt.After(v.MaintenanceWindowEnd) || cp.InventoryDigest != cluster.InventoryDigest {
			return fmt.Errorf("%w: target cluster %s requires a verified recovery checkpoint captured against current inventory and valid through the maintenance window", ErrPrerequisite, t.ClusterID)
		}
		latestID := ""
		var latestAt time.Time
		for _, dep := range s.baselineDeployments {
			if dep.ProjectID == v.ProjectID && dep.ClusterID == t.ClusterID && dep.BaselineID == v.BaselineID && BaselineCompletionEvidenceReady(dep, now) && (latestID == "" || dep.CreatedAt.After(latestAt)) {
				latestID, latestAt = dep.ID, dep.CreatedAt
			}
		}
		if latestID == "" || latestID != t.PreviousBaselineDeploymentID {
			return fmt.Errorf("%w: source baseline changed for cluster %s; create a new campaign", ErrPlanStale, t.ClusterID)
		}
		inventory[t.ClusterID] = cluster.InventoryDigest
	}
	v.TargetInventoryDigests = inventory
	v.RecoveryCheckpointIDs = ids
	v.PlanCreatedAt = &now
	expires := now.Add(ExecutionPlanTTL)
	v.PlanExpiresAt = &expires
	v.PlanContextDigest = UpgradeCampaignContextDigest(*v)
	return nil
}

func (s *MemoryStore) validateUpgradeSafetyLocked(v UpgradeCampaign, now time.Time, requireOpenWindow bool) error {
	if v.PlanCreatedAt == nil || v.PlanExpiresAt == nil || !now.Before(*v.PlanExpiresAt) {
		return ErrPlanStale
	}
	if requireOpenWindow && (now.Before(v.MaintenanceWindowStart) || !now.Before(v.MaintenanceWindowEnd)) {
		return ErrMaintenanceWindow
	}
	copy := cloneUpgradeCampaign(v)
	if err := s.prepareUpgradeSafetyLocked(&copy, v.RecoveryCheckpointIDs, now); err != nil {
		return err
	}
	// prepareUpgradeSafetyLocked refreshes timestamps; compare only context inputs.
	if copy.PlanContextDigest != v.PlanContextDigest {
		return ErrPlanStale
	}
	return nil
}

func uniqueStrings(values []string) ([]string, bool) {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return nil, false
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out, true
}

func (s *MemoryStore) CreateFleetGroup(_ context.Context, v FleetGroup, actor string) (FleetGroup, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[v.ProjectID]; !ok {
		return FleetGroup{}, false, ErrNotFound
	}
	clusters, ok := uniqueStrings(v.ClusterIDs)
	if !ok || len(clusters) == 0 || normalizeName(v.Name) == "" || strings.TrimSpace(v.DisplayName) == "" || strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") {
		return FleetGroup{}, false, fmt.Errorf("%w: project, unique clusters, name, idempotency key and request digest are required", ErrValidation)
	}
	for _, id := range clusters {
		cluster, exists := s.managedClusters[id]
		if !exists || cluster.ProjectID != v.ProjectID {
			return FleetGroup{}, false, ErrNotFound
		}
	}
	for _, existing := range s.fleetGroups {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return FleetGroup{}, false, ErrIdempotencyConflict
			}
			return cloneFleetGroup(existing), true, nil
		}
		if existing.ProjectID == v.ProjectID && normalizeName(existing.Name) == normalizeName(v.Name) {
			return FleetGroup{}, false, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("flg"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.Name = normalizeName(v.Name)
	v.ClusterIDs = clusters
	v.RequestedBy = actor
	s.fleetGroups[v.ID] = cloneFleetGroup(v)
	s.appendAuditLocked(actor, "fleet_group.created", "fleetGroup", v.ID, v.Revision, map[string]any{"clusters": len(clusters)})
	s.appendOutboxLocked("fleetGroup", v.ID, "fleet_group.created", v)
	return cloneFleetGroup(v), false, nil
}

func (s *MemoryStore) GetFleetGroup(_ context.Context, id string) (FleetGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.fleetGroups[id]
	if !ok {
		return FleetGroup{}, ErrNotFound
	}
	return cloneFleetGroup(v), nil
}

func (s *MemoryStore) ListFleetGroups(_ context.Context, projectID string) ([]FleetGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []FleetGroup{}
	for _, v := range s.fleetGroups {
		if projectID == "" || v.ProjectID == projectID {
			out = append(out, cloneFleetGroup(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *MemoryStore) CreateDriftScan(_ context.Context, v DriftScan, actor string) (DriftScan, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[v.ProjectID]; !ok {
		return DriftScan{}, false, ErrNotFound
	}
	if len(v.Targets) == 0 || strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") {
		return DriftScan{}, false, fmt.Errorf("%w: targets, idempotency key and request digest are required", ErrValidation)
	}
	for _, existing := range s.driftScans {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return DriftScan{}, false, ErrIdempotencyConflict
			}
			return cloneDriftScan(existing), true, nil
		}
	}
	seen := map[string]bool{}
	for i := range v.Targets {
		t := &v.Targets[i]
		cluster, ok := s.managedClusters[t.ClusterID]
		if !ok || cluster.ProjectID != v.ProjectID || seen[t.ClusterID] {
			return DriftScan{}, false, ErrValidation
		}
		seen[t.ClusterID] = true
		deployment, ok := s.baselineDeployments[t.BaselineDeploymentID]
		if !ok || deployment.ClusterID != t.ClusterID || !BaselineCompletionEvidenceReady(deployment, nowUTC(s.now)) || deployment.DesiredDigest != t.DesiredDigest {
			return DriftScan{}, false, ErrValidation
		}
		t.State = DriftTargetPending
		t.Changes = nil
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("drf"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = DriftScanQueued
	v.RequestedBy = actor
	s.driftScans[v.ID] = cloneDriftScan(v)
	s.appendAuditLocked(actor, "drift_scan.created", "driftScan", v.ID, v.Revision, map[string]any{"targets": len(v.Targets)})
	s.appendOutboxLocked("driftScan", v.ID, "drift_scan.queued", v)
	return cloneDriftScan(v), false, nil
}

func (s *MemoryStore) GetDriftScan(_ context.Context, id string) (DriftScan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.driftScans[id]
	if !ok {
		return DriftScan{}, ErrNotFound
	}
	return cloneDriftScan(v), nil
}

func (s *MemoryStore) ListDriftScans(_ context.Context, projectID, groupID string) ([]DriftScan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []DriftScan{}
	for _, v := range s.driftScans {
		if (projectID == "" || v.ProjectID == projectID) && (groupID == "" || v.FleetGroupID == groupID) {
			out = append(out, cloneDriftScan(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return resourceCreatedBefore(out[i].ResourceMeta, out[j].ResourceMeta) })
	return out, nil
}

func (s *MemoryStore) NextDriftTask(_ context.Context, clusterID, agentTokenDigest string) (DriftScan, DriftScanTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, agentTokenDigest); err != nil {
		return DriftScan{}, DriftScanTarget{}, err
	}
	ids := make([]string, 0)
	for id, scan := range s.driftScans {
		for _, target := range scan.Targets {
			if target.ClusterID == clusterID && (target.State == DriftTargetPending || target.State == DriftTargetRunning) {
				ids = append(ids, id)
				break
			}
		}
	}
	if len(ids) == 0 {
		return DriftScan{}, DriftScanTarget{}, ErrNotFound
	}
	sort.Slice(ids, func(i, j int) bool {
		return resourceCreatedBefore(s.driftScans[ids[i]].ResourceMeta, s.driftScans[ids[j]].ResourceMeta)
	})
	scan := s.driftScans[ids[0]]
	now := nowUTC(s.now)
	for i := range scan.Targets {
		if scan.Targets[i].ClusterID != clusterID {
			continue
		}
		if scan.Targets[i].State == DriftTargetPending {
			scan.Targets[i].State = DriftTargetRunning
			scan.Targets[i].Attempt++
			scan.Targets[i].StartedAt = &now
			if scan.StartedAt == nil {
				scan.StartedAt = &now
			}
			scan.State = DriftScanRunning
			scan.Revision++
			scan.UpdatedAt = now
			s.driftScans[scan.ID] = cloneDriftScan(scan)
		}
		return cloneDriftScan(scan), scan.Targets[i], nil
	}
	return DriftScan{}, DriftScanTarget{}, ErrNotFound
}

func (s *MemoryStore) ReportDriftTask(_ context.Context, clusterID, agentTokenDigest string, expected int64, result DriftTaskResult) (DriftScan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requireClusterTaskAdmissionLocked(clusterID, agentTokenDigest); err != nil {
		return DriftScan{}, err
	}
	scan, ok := s.driftScans[result.ScanID]
	if !ok || scan.Revision != expected {
		if !ok {
			return DriftScan{}, ErrNotFound
		}
		return DriftScan{}, ErrConflict
	}
	now := nowUTC(s.now)
	prior := make([]DriftScan, 0, len(s.driftScans))
	for id, previous := range s.driftScans {
		if id != scan.ID && previous.ProjectID == scan.ProjectID {
			prior = append(prior, cloneDriftScan(previous))
		}
	}
	found := false
	for i := range scan.Targets {
		t := &scan.Targets[i]
		if t.ClusterID != clusterID || t.State != DriftTargetRunning {
			continue
		}
		found = true
		t.ObservedDigest = result.ObservedDigest
		t.Changes = append([]BaselinePlanChange(nil), result.Changes...)
		if t.Git != nil {
			t.Git = ClassifyGitDrift(t.Git, result.GitObservedDigest)
		}
		t.Comparison, t.Findings = RuntimeDriftFindings(*t, result, prior, now)
		t.FinishedAt = &now
		if !result.Success {
			t.State = DriftTargetFailed
			t.LastError = strings.TrimSpace(result.Error)
		} else {
			drifted := result.ObservedDigest != t.DesiredDigest
			if t.Git != nil && t.Git.Classification != GitDriftInSync && t.Git.Classification != GitDriftNotRequested {
				drifted = true
			}
			for _, change := range result.Changes {
				if strings.ToUpper(change.Action) != "NOOP" {
					drifted = true
				}
			}
			if drifted {
				t.State = DriftTargetDrifted
			} else {
				t.State = DriftTargetInSync
			}
			t.LastError = ""
		}
		break
	}
	if !found {
		return DriftScan{}, ErrInvalidTransition
	}
	allDone, failed, drifted := true, false, false
	for _, t := range scan.Targets {
		switch t.State {
		case DriftTargetPending, DriftTargetRunning:
			allDone = false
		case DriftTargetFailed:
			failed = true
		case DriftTargetDrifted:
			drifted = true
		}
	}
	if allDone {
		scan.FinishedAt = &now
		switch {
		case failed:
			scan.State, scan.Summary = DriftScanFailed, "one or more cluster drift checks failed"
		case drifted:
			scan.State, scan.Summary = DriftScanDrifted, "managed baseline drift was detected"
		default:
			scan.State, scan.Summary = DriftScanInSync, "all managed baseline resources are in sync"
		}
	}
	scan.Revision++
	scan.UpdatedAt = now
	s.driftScans[scan.ID] = cloneDriftScan(scan)
	action := "drift_scan." + strings.ToLower(string(scan.State))
	s.appendAuditLocked("cluster-agent", action, "driftScan", scan.ID, scan.Revision, map[string]any{"clusterId": clusterID})
	s.appendOutboxLocked("driftScan", scan.ID, action, scan)
	return cloneDriftScan(scan), nil
}

func (s *MemoryStore) CreateUpgradeCampaign(_ context.Context, v UpgradeCampaign, actor string) (UpgradeCampaign, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[v.ProjectID]; !ok {
		return UpgradeCampaign{}, false, ErrNotFound
	}
	group, ok := s.fleetGroups[v.FleetGroupID]
	if !ok || group.ProjectID != v.ProjectID || len(v.Targets) == 0 || v.CanaryCount < 1 || v.WaveSize < 1 || v.HaltAfterFailures < 1 || strings.TrimSpace(v.TargetVersion) == "" || strings.TrimSpace(v.IdempotencyKey) == "" || !strings.HasPrefix(v.RequestDigest, "sha256:") {
		return UpgradeCampaign{}, false, ErrValidation
	}
	for _, existing := range s.upgradeCampaigns {
		if existing.ProjectID == v.ProjectID && existing.IdempotencyKey == v.IdempotencyKey {
			if existing.RequestDigest != v.RequestDigest {
				return UpgradeCampaign{}, false, ErrIdempotencyConflict
			}
			return cloneUpgradeCampaign(existing), true, nil
		}
	}
	now := nowUTC(s.now)
	if err := s.prepareUpgradeSafetyLocked(&v, v.RecoveryCheckpointIDs, now); err != nil {
		return UpgradeCampaign{}, false, err
	}
	v.ResourceMeta = ResourceMeta{ID: s.id("upg"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = UpgradeCampaignAwaitingApproval
	v.RequestedBy = actor
	v.CurrentWave = 0
	s.upgradeCampaigns[v.ID] = cloneUpgradeCampaign(v)
	s.appendAuditLocked(actor, "upgrade_campaign.created", "upgradeCampaign", v.ID, v.Revision, map[string]any{"targets": len(v.Targets), "targetVersion": v.TargetVersion})
	s.appendOutboxLocked("upgradeCampaign", v.ID, "upgrade_campaign.awaiting_approval", v)
	return cloneUpgradeCampaign(v), false, nil
}

func (s *MemoryStore) GetUpgradeCampaign(_ context.Context, id string) (UpgradeCampaign, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.upgradeCampaigns[id]
	if !ok {
		return UpgradeCampaign{}, ErrNotFound
	}
	return cloneUpgradeCampaign(v), nil
}

func (s *MemoryStore) ListUpgradeCampaigns(_ context.Context, projectID, groupID string) ([]UpgradeCampaign, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []UpgradeCampaign{}
	for _, v := range s.upgradeCampaigns {
		if (projectID == "" || v.ProjectID == projectID) && (groupID == "" || v.FleetGroupID == groupID) {
			out = append(out, cloneUpgradeCampaign(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return resourceCreatedBefore(out[i].ResourceMeta, out[j].ResourceMeta) })
	return out, nil
}

func (s *MemoryStore) ApproveUpgradeCampaign(_ context.Context, id string, expected int64, actor string) (UpgradeCampaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.upgradeCampaigns[id]
	if !ok {
		return UpgradeCampaign{}, ErrNotFound
	}
	if v.Revision != expected {
		return UpgradeCampaign{}, ErrConflict
	}
	if v.State != UpgradeCampaignAwaitingApproval {
		return UpgradeCampaign{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	if err := s.validateUpgradeSafetyLocked(v, now, false); err != nil {
		return UpgradeCampaign{}, err
	}
	v.State = UpgradeCampaignQueued
	v.ApprovedBy = actor
	v.ApprovedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.upgradeCampaigns[id] = cloneUpgradeCampaign(v)
	s.appendAuditLocked(actor, "upgrade_campaign.approved", "upgradeCampaign", id, v.Revision, map[string]any{"targetVersion": v.TargetVersion})
	s.appendOutboxLocked("upgradeCampaign", id, "upgrade_campaign.queued", v)
	return cloneUpgradeCampaign(v), nil
}

func upgradeCampaignHasActiveTarget(v UpgradeCampaign) bool {
	for _, target := range v.Targets {
		switch target.State {
		case UpgradeTargetPlanning, UpgradeTargetApplying, UpgradeTargetVerifying, UpgradeTargetRollingBack:
			return true
		}
	}
	return false
}

func (s *MemoryStore) PauseUpgradeCampaign(_ context.Context, id string, expected int64, actor, reason string) (UpgradeCampaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.upgradeCampaigns[id]
	if !ok {
		return UpgradeCampaign{}, ErrNotFound
	}
	if v.Revision != expected {
		return UpgradeCampaign{}, ErrConflict
	}
	if v.State != UpgradeCampaignRunning {
		return UpgradeCampaign{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "operator requested pause"
	}
	v.PausedBy = actor
	v.ControlReason = reason
	v.PauseCount++
	if upgradeCampaignHasActiveTarget(v) {
		v.State = UpgradeCampaignPauseRequested
		v.PausedAt = nil
	} else {
		v.State = UpgradeCampaignPaused
		v.PausedAt = &now
	}
	v.Revision++
	v.UpdatedAt = now
	s.upgradeCampaigns[id] = cloneUpgradeCampaign(v)
	action := "upgrade_campaign.pause_requested"
	if v.State == UpgradeCampaignPaused {
		action = "upgrade_campaign.paused"
	}
	s.appendAuditLocked(actor, action, "upgradeCampaign", id, v.Revision, map[string]any{"wave": v.CurrentWave, "reason": reason})
	s.appendOutboxLocked("upgradeCampaign", id, action, v)
	return cloneUpgradeCampaign(v), nil
}

func (s *MemoryStore) ResumeUpgradeCampaign(_ context.Context, id string, expected int64, actor string) (UpgradeCampaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.upgradeCampaigns[id]
	if !ok {
		return UpgradeCampaign{}, ErrNotFound
	}
	if v.Revision != expected {
		return UpgradeCampaign{}, ErrConflict
	}
	if v.State != UpgradeCampaignPaused {
		return UpgradeCampaign{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	if err := s.validateUpgradeSafetyLocked(v, now, true); err != nil {
		return UpgradeCampaign{}, err
	}
	v.State = UpgradeCampaignQueued
	v.PausedAt = nil
	v.ControlReason = ""
	v.Revision++
	v.UpdatedAt = now
	s.upgradeCampaigns[id] = cloneUpgradeCampaign(v)
	s.appendAuditLocked(actor, "upgrade_campaign.resumed", "upgradeCampaign", id, v.Revision, map[string]any{"wave": v.CurrentWave, "startedAtPreserved": v.StartedAt != nil})
	s.appendOutboxLocked("upgradeCampaign", id, "upgrade_campaign.queued", v)
	return cloneUpgradeCampaign(v), nil
}

func (s *MemoryStore) CancelUpgradeCampaign(_ context.Context, id string, expected int64, actor, reason string) (UpgradeCampaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.upgradeCampaigns[id]
	if !ok {
		return UpgradeCampaign{}, ErrNotFound
	}
	if v.Revision != expected {
		return UpgradeCampaign{}, ErrConflict
	}
	switch v.State {
	case UpgradeCampaignSucceeded, UpgradeCampaignFailed, UpgradeCampaignCancelled, UpgradeCampaignCancelRequested:
		return UpgradeCampaign{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "operator requested cancel"
	}
	v.CancelRequestedBy = actor
	v.CancelRequestedAt = &now
	v.ControlReason = reason
	if upgradeCampaignHasActiveTarget(v) {
		if v.State != UpgradeCampaignRunning && v.State != UpgradeCampaignPauseRequested && v.State != UpgradeCampaignCancelRequested && v.State != UpgradeCampaignHalted {
			return UpgradeCampaign{}, ErrInvalidTransition
		}
		v.State = UpgradeCampaignCancelRequested
	} else {
		v.State = UpgradeCampaignCancelled
		v.CancelledBy = actor
		v.CancelledAt = &now
		v.FinishedAt = &now
	}
	v.Revision++
	v.UpdatedAt = now
	s.upgradeCampaigns[id] = cloneUpgradeCampaign(v)
	action := "upgrade_campaign.cancel_requested"
	if v.State == UpgradeCampaignCancelled {
		action = "upgrade_campaign.cancelled"
	}
	s.appendAuditLocked(actor, action, "upgradeCampaign", id, v.Revision, map[string]any{"wave": v.CurrentWave, "reason": reason})
	s.appendOutboxLocked("upgradeCampaign", id, action, v)
	return cloneUpgradeCampaign(v), nil
}

func (s *MemoryStore) RevalidateUpgradeCampaign(_ context.Context, id string, expected int64, input UpgradeCampaignRevalidation, actor string) (UpgradeCampaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.upgradeCampaigns[id]
	if !ok {
		return UpgradeCampaign{}, ErrNotFound
	}
	if v.Revision != expected {
		return UpgradeCampaign{}, ErrConflict
	}
	if v.State != UpgradeCampaignAwaitingApproval && v.State != UpgradeCampaignQueued && v.State != UpgradeCampaignRunning && v.State != UpgradeCampaignPaused {
		return UpgradeCampaign{}, ErrInvalidTransition
	}
	if v.State == UpgradeCampaignRunning {
		for _, target := range v.Targets {
			if target.State == UpgradeTargetPlanning || target.State == UpgradeTargetApplying || target.State == UpgradeTargetVerifying || target.State == UpgradeTargetRollingBack {
				return UpgradeCampaign{}, fmt.Errorf("%w: running campaign can only be revalidated between waves", ErrInvalidTransition)
			}
		}
	}
	checkpointIDs := input.RecoveryCheckpointIDs
	if len(checkpointIDs) == 0 {
		checkpointIDs = v.RecoveryCheckpointIDs
	}
	if !input.MaintenanceWindowStart.IsZero() {
		v.MaintenanceWindowStart = input.MaintenanceWindowStart
	}
	if !input.MaintenanceWindowEnd.IsZero() {
		v.MaintenanceWindowEnd = input.MaintenanceWindowEnd
	}
	now := nowUTC(s.now)
	if err := s.prepareUpgradeSafetyLocked(&v, checkpointIDs, now); err != nil {
		return UpgradeCampaign{}, err
	}
	v.State = UpgradeCampaignAwaitingApproval
	v.ApprovedBy, v.ApprovedAt = "", nil
	v.ControlReason = ""
	v.PlanRevalidationCount++
	v.Revision++
	v.UpdatedAt = now
	s.upgradeCampaigns[id] = cloneUpgradeCampaign(v)
	s.appendAuditLocked(actor, "upgrade_campaign.revalidated", "upgradeCampaign", id, v.Revision, map[string]any{"planContextDigest": v.PlanContextDigest, "revalidationCount": v.PlanRevalidationCount})
	s.appendOutboxLocked("upgradeCampaign", id, "upgrade_campaign.awaiting_approval", v)
	return cloneUpgradeCampaign(v), nil
}

func (s *MemoryStore) validateUpgradeTargetStartsLocked(current, next UpgradeCampaign, now time.Time) error {
	starts := map[string]bool{}
	for i, before := range current.Targets {
		if i < len(next.Targets) && before.State == UpgradeTargetPending && next.Targets[i].State != UpgradeTargetPending {
			starts[before.ClusterID] = true
		}
	}
	if len(starts) == 0 {
		return nil
	}
	if now.Before(current.MaintenanceWindowStart) || !now.Before(current.MaintenanceWindowEnd) {
		return ErrMaintenanceWindow
	}
	checkpointByCluster := map[string]RecoveryCheckpoint{}
	for _, id := range current.RecoveryCheckpointIDs {
		if cp, ok := s.recoveryCheckpoints[id]; ok {
			checkpointByCluster[cp.ClusterID] = cp
		}
	}
	for _, target := range current.Targets {
		if !starts[target.ClusterID] {
			continue
		}
		cluster, ok := s.managedClusters[target.ClusterID]
		cp, cpOK := checkpointByCluster[target.ClusterID]
		if !ok || cluster.ProjectID != current.ProjectID || strings.TrimSpace(cluster.InventoryDigest) == "" || !cpOK || cp.ProjectID != current.ProjectID || cp.State != RecoveryCheckpointVerified || !cp.ExpiresAt.After(current.MaintenanceWindowEnd) || cp.InventoryDigest != cluster.InventoryDigest || current.TargetInventoryDigests[target.ClusterID] != cluster.InventoryDigest {
			return fmt.Errorf("%w: target cluster %s requires campaign revalidation with current recovery evidence", ErrPrerequisite, target.ClusterID)
		}
		latestID := ""
		var latestAt time.Time
		for _, dep := range s.baselineDeployments {
			if dep.ProjectID == current.ProjectID && dep.ClusterID == target.ClusterID && dep.BaselineID == current.BaselineID && BaselineCompletionEvidenceReady(dep, now) && (latestID == "" || dep.CreatedAt.After(latestAt)) {
				latestID, latestAt = dep.ID, dep.CreatedAt
			}
		}
		if latestID != target.PreviousBaselineDeploymentID {
			return fmt.Errorf("%w: source baseline changed for cluster %s", ErrPlanStale, target.ClusterID)
		}
	}
	return nil
}

func (s *MemoryStore) UpdateUpgradeCampaign(_ context.Context, next UpgradeCampaign, expected int64, actor string) (UpgradeCampaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.upgradeCampaigns[next.ID]
	if !ok {
		return UpgradeCampaign{}, ErrNotFound
	}
	if current.Revision != expected {
		return UpgradeCampaign{}, ErrConflict
	}
	if next.ProjectID != current.ProjectID || next.FleetGroupID != current.FleetGroupID || next.BaselineID != current.BaselineID || next.TargetVersion != current.TargetVersion || next.IdempotencyKey != current.IdempotencyKey || next.RequestDigest != current.RequestDigest || next.PlanContextDigest != current.PlanContextDigest || !next.MaintenanceWindowStart.Equal(current.MaintenanceWindowStart) || !next.MaintenanceWindowEnd.Equal(current.MaintenanceWindowEnd) {
		return UpgradeCampaign{}, ErrValidation
	}
	now := nowUTC(s.now)
	if current.State == UpgradeCampaignQueued && next.State == UpgradeCampaignRunning {
		if err := s.validateUpgradeSafetyLocked(current, now, true); err != nil {
			return UpgradeCampaign{}, err
		}
	}
	if err := s.validateUpgradeTargetStartsLocked(current, next, now); err != nil {
		return UpgradeCampaign{}, err
	}
	next.ResourceMeta = current.ResourceMeta
	next.Revision = current.Revision + 1
	next.UpdatedAt = now
	s.upgradeCampaigns[next.ID] = cloneUpgradeCampaign(next)
	s.appendAuditLocked(actor, "upgrade_campaign.progressed", "upgradeCampaign", next.ID, next.Revision, map[string]any{"state": next.State, "wave": next.CurrentWave})
	s.appendOutboxLocked("upgradeCampaign", next.ID, "upgrade_campaign.progressed", next)
	return cloneUpgradeCampaign(next), nil
}
