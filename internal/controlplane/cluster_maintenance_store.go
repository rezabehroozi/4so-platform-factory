package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

func normalizeClusterEnvironment(v ClusterEnvironment) (ClusterEnvironment, bool) {
	switch ClusterEnvironment(strings.ToUpper(strings.TrimSpace(string(v)))) {
	case ClusterEnvironmentDevelopment:
		return ClusterEnvironmentDevelopment, true
	case ClusterEnvironmentStaging:
		return ClusterEnvironmentStaging, true
	case ClusterEnvironmentProduction:
		return ClusterEnvironmentProduction, true
	default:
		return "", false
	}
}

func cloneClusterMaintenanceRun(v ClusterMaintenanceRun) ClusterMaintenanceRun {
	v.NodeNames = append([]string(nil), v.NodeNames...)
	if v.NodeUIDs != nil {
		nodeUIDs := make(map[string]string, len(v.NodeUIDs))
		for name, uid := range v.NodeUIDs {
			nodeUIDs[name] = uid
		}
		v.NodeUIDs = nodeUIDs
	}
	v.Results = append([]NodeMaintenanceResult(nil), v.Results...)
	for i := range v.Results {
		v.Results[i].EvictedPods = append([]string(nil), v.Results[i].EvictedPods...)
		v.Results[i].SkippedPods = append([]string(nil), v.Results[i].SkippedPods...)
		v.Results[i].PDBBlockedPods = append([]string(nil), v.Results[i].PDBBlockedPods...)
	}
	return v
}

func validateDrainTimeout(seconds int) bool { return seconds >= 30 && seconds <= 3600 }

const defaultHostActionTimeoutSeconds = 3600

func normalizeMaintenanceAction(action TargetNodeLifecycleAction) (TargetNodeLifecycleAction, bool) {
	action = TargetNodeLifecycleAction(strings.ToUpper(strings.TrimSpace(string(action))))
	if action == "" {
		action = TargetNodeActionDrain
	}
	switch action {
	case TargetNodeActionDrain, TargetNodeActionOSPatch:
		return action, true
	default:
		return action, false
	}
}

func clusterMaintenanceLeaseDuration(v ClusterMaintenanceRun) time.Duration {
	nodes := len(v.NodeNames)
	if nodes < 1 {
		nodes = 1
	}
	secondsPerNode := int64(v.DrainTimeoutSeconds)
	if v.Action == TargetNodeActionOSPatch {
		host := v.HostActionTimeoutSeconds
		if host <= 0 {
			host = defaultHostActionTimeoutSeconds
		}
		secondsPerNode += int64(host)
	}
	seconds := int64(nodes) * secondsPerNode
	if seconds < 30 {
		seconds = 30
	}
	return time.Duration(seconds)*time.Second + 2*time.Minute
}

func (s *MemoryStore) failStaleRunningMaintenanceLocked(v ClusterMaintenanceRun, op Operation, now time.Time, message string) {
	v.State = ClusterMaintenanceNeedsOperator
	v.LastError = message
	v.FinishedAt = &now
	v.Revision++
	v.UpdatedAt = now
	op.State = OperationNeedsOperator
	op.LastError = message
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	op.Revision++
	op.UpdatedAt = now
	s.clusterMaintenanceRuns[v.ID] = cloneClusterMaintenanceRun(v)
	s.operations[op.ID] = op
	s.appendAuditLocked("cluster-agent", "cluster_maintenance.run_lease_expired", "clusterMaintenanceRun", v.ID, v.Revision, map[string]any{"operationId": op.ID, "error": message})
	s.appendOutboxLocked("clusterMaintenanceRun", v.ID, "cluster_maintenance.needs_operator", v)
	s.appendOutboxLocked("operation", op.ID, "operation.needs_operator", op)
}

func (s *MemoryStore) expireStaleRunningMaintenanceLocked(clusterID string, now time.Time) {
	owner := "cluster-maintenance-agent:" + clusterID
	for _, v := range s.clusterMaintenanceRuns {
		if v.ClusterID != clusterID || v.State != ClusterMaintenanceRunning {
			continue
		}
		op, ok := s.operations[v.OperationID]
		if !ok {
			continue
		}
		if op.State == OperationRunning && op.LeaseOwner == owner && op.LeaseExpiresAt != nil && op.LeaseExpiresAt.After(now) {
			continue
		}
		s.failStaleRunningMaintenanceLocked(v, op, now, "maintenance agent lease expired or ownership changed before task completion; operator recovery is required")
	}
}

func (s *MemoryStore) UpsertClusterMaintenanceProfile(_ context.Context, v ClusterMaintenanceProfile, expected int64, actor string) (ClusterMaintenanceProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || (strings.TrimSpace(v.ProjectID) != "" && cluster.ProjectID != strings.TrimSpace(v.ProjectID)) {
		return ClusterMaintenanceProfile{}, ErrNotFound
	}
	env, ok := normalizeClusterEnvironment(v.Environment)
	if !ok || !validateDrainTimeout(v.DefaultDrainTimeoutSeconds) {
		return ClusterMaintenanceProfile{}, fmt.Errorf("%w: environment and drain timeout (30..3600 seconds) are required", ErrValidation)
	}
	now := nowUTC(s.now)
	existing, exists := s.clusterMaintenanceProfiles[v.ClusterID]
	if exists {
		if expected == 0 || existing.Revision != expected {
			return ClusterMaintenanceProfile{}, ErrConflict
		}
		v.ResourceMeta = existing.ResourceMeta
		v.Revision++
		v.UpdatedAt = now
	} else {
		if expected != 0 {
			return ClusterMaintenanceProfile{}, ErrConflict
		}
		v.ResourceMeta = ResourceMeta{ID: s.id("cmp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	}
	v.ProjectID = cluster.ProjectID
	v.Environment = env
	v.UpdatedBy = strings.TrimSpace(actor)
	s.clusterMaintenanceProfiles[v.ClusterID] = v
	s.appendAuditLocked(actor, "cluster_maintenance.profile_upserted", "clusterMaintenanceProfile", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "environment": v.Environment, "method": ClusterMaintenanceAuthorityMethod})
	s.appendOutboxLocked("clusterMaintenanceProfile", v.ID, "cluster_maintenance.profile_upserted", v)
	return v, nil
}

func (s *MemoryStore) GetClusterMaintenanceProfile(_ context.Context, clusterID string) (ClusterMaintenanceProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.clusterMaintenanceProfiles[clusterID]
	if !ok {
		return ClusterMaintenanceProfile{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) CreateClusterMaintenanceWindow(_ context.Context, v ClusterMaintenanceWindow, actor string) (ClusterMaintenanceWindow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || (strings.TrimSpace(v.ProjectID) != "" && cluster.ProjectID != strings.TrimSpace(v.ProjectID)) {
		return ClusterMaintenanceWindow{}, ErrNotFound
	}
	if _, ok := s.clusterMaintenanceProfiles[v.ClusterID]; !ok {
		return ClusterMaintenanceWindow{}, fmt.Errorf("%w: cluster maintenance profile must be configured first", ErrPrerequisite)
	}
	v.Name = strings.TrimSpace(v.Name)
	v.StartsAt = v.StartsAt.UTC().Truncate(time.Microsecond)
	v.EndsAt = v.EndsAt.UTC().Truncate(time.Microsecond)
	if v.Name == "" || v.StartsAt.IsZero() || !v.EndsAt.After(v.StartsAt) || !v.EndsAt.After(nowUTC(s.now)) {
		return ClusterMaintenanceWindow{}, fmt.Errorf("%w: a future maintenance window with startsAt < endsAt is required", ErrValidation)
	}
	if v.MaxUnavailable == 0 {
		v.MaxUnavailable = 1
	}
	if v.MaxUnavailable != 1 {
		return ClusterMaintenanceWindow{}, fmt.Errorf("%w: this runtime intentionally enforces maxUnavailable=1 for disruption-safe node maintenance", ErrValidation)
	}
	if !validateDrainTimeout(v.DrainTimeoutSeconds) {
		return ClusterMaintenanceWindow{}, fmt.Errorf("%w: drainTimeoutSeconds must be 30..3600", ErrValidation)
	}
	for _, existing := range s.clusterMaintenanceWindows {
		if existing.ClusterID == v.ClusterID && existing.State == ClusterMaintenanceWindowActive && normalizeName(existing.Name) == normalizeName(v.Name) && existing.StartsAt.Equal(v.StartsAt) && existing.EndsAt.Equal(v.EndsAt) {
			return ClusterMaintenanceWindow{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("cmw"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.ProjectID = cluster.ProjectID
	v.State = ClusterMaintenanceWindowActive
	v.CreatedBy = strings.TrimSpace(actor)
	s.clusterMaintenanceWindows[v.ID] = v
	s.appendAuditLocked(actor, "cluster_maintenance.window_created", "clusterMaintenanceWindow", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "startsAt": v.StartsAt, "endsAt": v.EndsAt, "maxUnavailable": v.MaxUnavailable})
	s.appendOutboxLocked("clusterMaintenanceWindow", v.ID, "cluster_maintenance.window_created", v)
	return v, nil
}

func (s *MemoryStore) GetClusterMaintenanceWindow(_ context.Context, id string) (ClusterMaintenanceWindow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.clusterMaintenanceWindows[id]
	if !ok {
		return ClusterMaintenanceWindow{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListClusterMaintenanceWindows(_ context.Context, clusterID string) ([]ClusterMaintenanceWindow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ClusterMaintenanceWindow{}
	for _, v := range s.clusterMaintenanceWindows {
		if clusterID == "" || v.ClusterID == clusterID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartsAt.Equal(out[j].StartsAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].StartsAt.Before(out[j].StartsAt)
	})
	return out, nil
}

func (s *MemoryStore) CancelClusterMaintenanceWindow(_ context.Context, id string, expected int64, actor string) (ClusterMaintenanceWindow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.clusterMaintenanceWindows[id]
	if !ok {
		return ClusterMaintenanceWindow{}, ErrNotFound
	}
	if v.Revision != expected {
		return ClusterMaintenanceWindow{}, ErrConflict
	}
	if v.State != ClusterMaintenanceWindowActive {
		return ClusterMaintenanceWindow{}, ErrInvalidTransition
	}
	for _, run := range s.clusterMaintenanceRuns {
		if run.WindowID == id && (run.State == ClusterMaintenanceAwaitingApproval || run.State == ClusterMaintenanceQueued || run.State == ClusterMaintenanceRunning || run.State == ClusterMaintenanceRestoring) {
			return ClusterMaintenanceWindow{}, fmt.Errorf("%w: active maintenance run is bound to this window", ErrPrerequisite)
		}
	}
	now := nowUTC(s.now)
	v.State = ClusterMaintenanceWindowCancelled
	v.CancelledBy = strings.TrimSpace(actor)
	v.CancelledAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.clusterMaintenanceWindows[id] = v
	s.appendAuditLocked(actor, "cluster_maintenance.window_cancelled", "clusterMaintenanceWindow", id, v.Revision, map[string]any{"clusterId": v.ClusterID})
	s.appendOutboxLocked("clusterMaintenanceWindow", id, "cluster_maintenance.window_cancelled", v)
	return v, nil
}

func validateMaintenanceNodeSelection(inv ClusterInventory, names []string) ([]string, map[string]string, error) {
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("%w: at least one node is required", ErrValidation)
	}
	nodes := map[string]ClusterNode{}
	for _, n := range inv.Nodes {
		nodes[n.Name] = n
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(names))
	uids := make(map[string]string, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" || seen[name] {
			return nil, nil, fmt.Errorf("%w: node names must be non-empty and unique", ErrValidation)
		}
		node, ok := nodes[name]
		if !ok {
			return nil, nil, fmt.Errorf("%w: node %s is not present in current inventory", ErrValidation, name)
		}
		if !node.Ready {
			return nil, nil, fmt.Errorf("%w: node %s is not Ready", ErrPrerequisite, name)
		}
		uid := strings.TrimSpace(node.UID)
		if uid == "" {
			return nil, nil, fmt.Errorf("%w: node %s is missing a stable UID", ErrPrerequisite, name)
		}
		seen[name] = true
		out = append(out, name)
		uids[name] = uid
	}
	return out, uids, nil
}

func maintenanceNodeIdentityMatches(inv ClusterInventory, names []string, expected map[string]string) error {
	_, current, err := validateMaintenanceNodeSelection(inv, names)
	if err != nil {
		return err
	}
	if len(expected) != len(current) {
		return fmt.Errorf("%w: approved maintenance node identity is incomplete", ErrPrerequisite)
	}
	for name, uid := range current {
		if strings.TrimSpace(expected[name]) != uid {
			return fmt.Errorf("%w: node %s identity changed after maintenance request", ErrPrerequisite, name)
		}
	}
	return nil
}

func (s *MemoryStore) prepareClusterMaintenanceRunLocked(v ClusterMaintenanceRun, actor string) (ClusterMaintenanceRun, error) {
	cluster, ok := s.managedClusters[v.ClusterID]
	if !ok || cluster.ProjectID != v.ProjectID {
		return ClusterMaintenanceRun{}, ErrNotFound
	}
	if strings.TrimSpace(v.IdempotencyKey) == "" || len(v.IdempotencyKey) > 200 || !strings.HasPrefix(v.RequestDigest, "sha256:") {
		return ClusterMaintenanceRun{}, fmt.Errorf("%w: idempotencyKey and requestDigest are required", ErrValidation)
	}
	window, ok := s.clusterMaintenanceWindows[v.WindowID]
	if !ok || window.ClusterID != v.ClusterID || window.State != ClusterMaintenanceWindowActive {
		return ClusterMaintenanceRun{}, fmt.Errorf("%w: active maintenance window for this cluster is required", ErrPrerequisite)
	}
	if !window.EndsAt.After(nowUTC(s.now)) {
		return ClusterMaintenanceRun{}, ErrMaintenanceWindow
	}
	inv, ok := s.clusterInventories[v.ClusterID]
	if !ok || inv.Digest == "" || cluster.InventoryDigest != inv.Digest {
		return ClusterMaintenanceRun{}, fmt.Errorf("%w: current cluster inventory is required", ErrPrerequisite)
	}
	nodes, nodeUIDs, err := validateMaintenanceNodeSelection(inv, v.NodeNames)
	if err != nil {
		return ClusterMaintenanceRun{}, err
	}
	v.NodeNames = nodes
	v.NodeUIDs = nodeUIDs
	v.InventoryDigest = inv.Digest
	v.MaxUnavailable = window.MaxUnavailable
	v.DrainTimeoutSeconds = window.DrainTimeoutSeconds
	action, validAction := normalizeMaintenanceAction(v.Action)
	if !validAction {
		return ClusterMaintenanceRun{}, fmt.Errorf("%w: maintenance action %q is not executable through the cluster maintenance authority", ErrValidation, v.Action)
	}
	v.Action = action
	if action == TargetNodeActionOSPatch {
		descriptor := lifecycleDescriptor(action, inv, false)
		if !descriptor.Executable {
			blockers := append([]string(nil), descriptor.Blockers...)
			for _, missing := range descriptor.MissingCapabilities {
				blockers = append(blockers, "TARGET_CAPABILITY_MISSING:"+missing)
			}
			return ClusterMaintenanceRun{}, fmt.Errorf("%w: OS patch executor is not admitted: %s", ErrPrerequisite, strings.Join(blockers, "; "))
		}
		v.HostActionTimeoutSeconds = defaultHostActionTimeoutSeconds
	} else {
		v.HostActionTimeoutSeconds = 0
	}
	v.RequestedBy = strings.TrimSpace(actor)
	if err := ValidateDay2CampaignContract(Day2ContractForMaintenance(v, window)); err != nil {
		return ClusterMaintenanceRun{}, err
	}
	return v, nil
}

func (s *MemoryStore) createPreparedClusterMaintenanceRunLocked(v ClusterMaintenanceRun, actor string) (ClusterMaintenanceRun, error) {
	op, ok := s.operations[v.OperationID]
	if !ok || op.ProjectID != v.ProjectID || op.Kind != "CLUSTER_MAINTENANCE" || op.TargetRef != "cluster/"+v.ClusterID || op.State != OperationAwaitingApproval {
		return ClusterMaintenanceRun{}, fmt.Errorf("%w: linked maintenance operation must be awaiting approval", ErrPrerequisite)
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("cmr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = ClusterMaintenanceAwaitingApproval
	s.clusterMaintenanceRuns[v.ID] = cloneClusterMaintenanceRun(v)
	s.idempotency["cluster-maintenance:"+v.ProjectID+":"+v.IdempotencyKey] = v.ID
	s.appendAuditLocked(actor, "cluster_maintenance.run_requested", "clusterMaintenanceRun", v.ID, v.Revision, map[string]any{"clusterId": v.ClusterID, "windowId": v.WindowID, "operationId": v.OperationID, "action": v.Action, "nodes": v.NodeNames, "inventoryDigest": v.InventoryDigest})
	s.appendOutboxLocked("clusterMaintenanceRun", v.ID, "cluster_maintenance.run_requested", v)
	return cloneClusterMaintenanceRun(v), nil
}

func (s *MemoryStore) CreateClusterMaintenanceRun(_ context.Context, v ClusterMaintenanceRun, actor string) (ClusterMaintenanceRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scope := "cluster-maintenance:" + v.ProjectID + ":" + v.IdempotencyKey
	if id, ok := s.idempotency[scope]; ok {
		existing := s.clusterMaintenanceRuns[id]
		if existing.RequestDigest != v.RequestDigest {
			return ClusterMaintenanceRun{}, false, ErrIdempotencyConflict
		}
		return cloneClusterMaintenanceRun(existing), true, nil
	}
	prepared, err := s.prepareClusterMaintenanceRunLocked(v, actor)
	if err != nil {
		return ClusterMaintenanceRun{}, false, err
	}
	created, err := s.createPreparedClusterMaintenanceRunLocked(prepared, actor)
	if err != nil {
		return ClusterMaintenanceRun{}, false, err
	}
	return created, false, nil
}

// CreateClusterMaintenanceRunRequest atomically validates the maintenance request,
// creates/reuses its durable operation, advances that operation to independent
// approval, and records the maintenance run. Invalid requests therefore cannot
// leave orphan operations or poisoned partial workflow state.
func (s *MemoryStore) CreateClusterMaintenanceRunRequest(_ context.Context, v ClusterMaintenanceRun, opRequest OperationRequest, opKey, actor, requestID string) (ClusterMaintenanceRun, Operation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scope := "cluster-maintenance:" + v.ProjectID + ":" + v.IdempotencyKey
	if id, ok := s.idempotency[scope]; ok {
		existing := s.clusterMaintenanceRuns[id]
		if existing.RequestDigest != v.RequestDigest {
			return ClusterMaintenanceRun{}, Operation{}, false, ErrIdempotencyConflict
		}
		op, ok := s.operations[existing.OperationID]
		if !ok {
			return ClusterMaintenanceRun{}, Operation{}, false, fmt.Errorf("%w: linked maintenance operation is missing", ErrPrerequisite)
		}
		return cloneClusterMaintenanceRun(existing), op, true, nil
	}

	prepared, err := s.prepareClusterMaintenanceRunLocked(v, actor)
	if err != nil {
		return ClusterMaintenanceRun{}, Operation{}, false, err
	}
	op, opReplay, err := s.createOperationLocked(opRequest, opKey, actor, requestID)
	if err != nil {
		return ClusterMaintenanceRun{}, Operation{}, false, err
	}
	if opReplay {
		if op.ProjectID != prepared.ProjectID || op.Kind != "CLUSTER_MAINTENANCE" || op.TargetRef != "cluster/"+prepared.ClusterID {
			return ClusterMaintenanceRun{}, Operation{}, false, ErrIdempotencyConflict
		}
	}
	if op.State == OperationDraft {
		op, err = s.transitionOperationLocked(op.ID, op.Revision, OperationPlanning, "", actor)
		if err != nil {
			return ClusterMaintenanceRun{}, Operation{}, false, err
		}
	}
	if op.State == OperationPlanning {
		op, err = s.transitionOperationLocked(op.ID, op.Revision, OperationAwaitingApproval, "", actor)
		if err != nil {
			return ClusterMaintenanceRun{}, Operation{}, false, err
		}
	}
	if op.State != OperationAwaitingApproval {
		return ClusterMaintenanceRun{}, Operation{}, false, fmt.Errorf("%w: linked maintenance operation is not awaiting approval", ErrPrerequisite)
	}
	prepared.OperationID = op.ID
	created, err := s.createPreparedClusterMaintenanceRunLocked(prepared, actor)
	if err != nil {
		return ClusterMaintenanceRun{}, Operation{}, false, err
	}
	return created, op, false, nil
}

func (s *MemoryStore) GetClusterMaintenanceRun(_ context.Context, id string) (ClusterMaintenanceRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.clusterMaintenanceRuns[id]
	if !ok {
		return ClusterMaintenanceRun{}, ErrNotFound
	}
	return cloneClusterMaintenanceRun(v), nil
}

func (s *MemoryStore) ListClusterMaintenanceRuns(_ context.Context, clusterID string) ([]ClusterMaintenanceRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ClusterMaintenanceRun{}
	for _, v := range s.clusterMaintenanceRuns {
		if clusterID == "" || v.ClusterID == clusterID {
			out = append(out, cloneClusterMaintenanceRun(v))
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

func (s *MemoryStore) ApproveClusterMaintenanceRun(_ context.Context, id string, expected int64, actor string) (ClusterMaintenanceRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.clusterMaintenanceRuns[id]
	if !ok {
		return ClusterMaintenanceRun{}, ErrNotFound
	}
	if v.Revision != expected {
		return ClusterMaintenanceRun{}, ErrConflict
	}
	if v.State != ClusterMaintenanceAwaitingApproval {
		return ClusterMaintenanceRun{}, ErrInvalidTransition
	}
	if err := ValidateDay2IndependentApproval(v.RequestedBy, actor); err != nil {
		return ClusterMaintenanceRun{}, err
	}
	window, ok := s.clusterMaintenanceWindows[v.WindowID]
	if !ok || window.State != ClusterMaintenanceWindowActive || !window.EndsAt.After(nowUTC(s.now)) {
		return ClusterMaintenanceRun{}, ErrMaintenanceWindow
	}
	inv, ok := s.clusterInventories[v.ClusterID]
	if !ok || inv.Digest != v.InventoryDigest {
		return ClusterMaintenanceRun{}, fmt.Errorf("%w: cluster inventory changed after maintenance request; submit a new request", ErrPrerequisite)
	}
	if err := maintenanceNodeIdentityMatches(inv, v.NodeNames, v.NodeUIDs); err != nil {
		return ClusterMaintenanceRun{}, err
	}
	op, ok := s.operations[v.OperationID]
	if !ok || op.State != OperationAwaitingApproval {
		return ClusterMaintenanceRun{}, fmt.Errorf("%w: linked operation is not awaiting approval", ErrPrerequisite)
	}
	now := nowUTC(s.now)
	op.State = OperationApproved
	op.Revision++
	op.UpdatedAt = now
	op.State = OperationQueued
	op.Revision++
	op.UpdatedAt = now
	s.operations[op.ID] = op
	v.State = ClusterMaintenanceQueued
	v.ApprovedBy = strings.TrimSpace(actor)
	v.ApprovedAt = &now
	v.Revision++
	v.UpdatedAt = now
	s.clusterMaintenanceRuns[id] = cloneClusterMaintenanceRun(v)
	s.appendAuditLocked(actor, "cluster_maintenance.run_approved", "clusterMaintenanceRun", id, v.Revision, map[string]any{"operationId": v.OperationID, "windowId": v.WindowID})
	s.appendAuditLocked(actor, "operation.approved_queued", "operation", op.ID, op.Revision, map[string]any{"maintenanceRunId": id})
	s.appendOutboxLocked("clusterMaintenanceRun", id, "cluster_maintenance.run_queued", v)
	s.appendOutboxLocked("operation", op.ID, "operation.queued", op)
	return cloneClusterMaintenanceRun(v), nil
}

func (s *MemoryStore) failQueuedMaintenanceRunLocked(v ClusterMaintenanceRun, op Operation, message string, now time.Time) {
	v.State = ClusterMaintenanceFailed
	v.LastError = message
	v.FinishedAt = &now
	v.Revision++
	v.UpdatedAt = now
	op.State = OperationFailed
	op.LastError = message
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	op.Revision++
	op.UpdatedAt = now
	s.clusterMaintenanceRuns[v.ID] = cloneClusterMaintenanceRun(v)
	s.operations[op.ID] = op
	s.appendAuditLocked("cluster-agent", "cluster_maintenance.run_failed_before_claim", "clusterMaintenanceRun", v.ID, v.Revision, map[string]any{"error": message, "operationId": op.ID})
	s.appendOutboxLocked("clusterMaintenanceRun", v.ID, "cluster_maintenance.run_failed", v)
}

func (s *MemoryStore) NextClusterMaintenanceTask(_ context.Context, clusterID, agentTokenDigest string) (ClusterMaintenanceRun, Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, agentTokenDigest)
	if err != nil {
		return ClusterMaintenanceRun{}, Operation{}, err
	}
	now := nowUTC(s.now)
	s.expireStaleRunningMaintenanceLocked(clusterID, now)
	if !clusterHasCapability(cluster, ClusterMaintenanceFencedReportCapability) {
		return ClusterMaintenanceRun{}, Operation{}, ErrNotFound
	}
	ids := make([]string, 0)
	for id, v := range s.clusterMaintenanceRuns {
		if v.ClusterID == clusterID && v.State == ClusterMaintenanceQueued {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		left := s.clusterMaintenanceRuns[ids[i]]
		right := s.clusterMaintenanceRuns[ids[j]]
		if left.CreatedAt.Equal(right.CreatedAt) {
			return ids[i] < ids[j]
		}
		return left.CreatedAt.Before(right.CreatedAt)
	})
	for _, id := range ids {
		v := s.clusterMaintenanceRuns[id]
		window, wok := s.clusterMaintenanceWindows[v.WindowID]
		op, ook := s.operations[v.OperationID]
		if !wok || !ook || op.State != OperationQueued {
			if ook {
				s.failQueuedMaintenanceRunLocked(v, op, "maintenance authority state is inconsistent", now)
			}
			continue
		}
		if window.State != ClusterMaintenanceWindowActive {
			s.failQueuedMaintenanceRunLocked(v, op, "maintenance window is no longer active", now)
			continue
		}
		if err := ValidateDay2ExecutionWindow(window.StartsAt, window.EndsAt, now); err != nil {
			if now.Before(window.StartsAt) {
				continue
			}
			s.failQueuedMaintenanceRunLocked(v, op, "maintenance window expired before task claim", now)
			continue
		}
		inv, iok := s.clusterInventories[clusterID]
		if !iok || inv.Digest != v.InventoryDigest || cluster.InventoryDigest != v.InventoryDigest {
			s.failQueuedMaintenanceRunLocked(v, op, "cluster inventory changed after maintenance approval; submit a new run", now)
			continue
		}
		if err := maintenanceNodeIdentityMatches(inv, v.NodeNames, v.NodeUIDs); err != nil {
			s.failQueuedMaintenanceRunLocked(v, op, err.Error(), now)
			continue
		}
		if v.Action == TargetNodeActionOSPatch {
			descriptor := lifecycleDescriptor(v.Action, inv, false)
			if !descriptor.Executable {
				s.failQueuedMaintenanceRunLocked(v, op, "OS patch target capability/executor admission changed after approval", now)
				continue
			}
		}
		v.State = ClusterMaintenanceRunning
		v.StartedAt = &now
		v.Revision++
		v.UpdatedAt = now
		op.State = OperationRunning
		op.Attempt++
		op.FenceToken++
		op.LeaseOwner = "cluster-maintenance-agent:" + clusterID
		lease := now.Add(clusterMaintenanceLeaseDuration(v))
		op.LeaseExpiresAt = &lease
		op.Revision++
		op.UpdatedAt = now
		s.clusterMaintenanceRuns[id] = cloneClusterMaintenanceRun(v)
		s.operations[op.ID] = op
		s.appendAuditLocked("cluster-agent", "cluster_maintenance.run_claimed", "clusterMaintenanceRun", id, v.Revision, map[string]any{"operationId": op.ID, "fenceToken": op.FenceToken})
		s.appendOutboxLocked("clusterMaintenanceRun", id, "cluster_maintenance.run_started", v)
		return cloneClusterMaintenanceRun(v), op, nil
	}
	return ClusterMaintenanceRun{}, Operation{}, ErrNotFound
}

func (s *MemoryStore) ReportClusterMaintenanceTask(_ context.Context, clusterID, runID string, expected int64, result ClusterMaintenanceTaskResult) (ClusterMaintenanceRun, Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cluster, ok := s.managedClusters[clusterID]
	if !ok {
		return ClusterMaintenanceRun{}, Operation{}, ErrNotFound
	}
	if !ClusterTaskAdmitted(cluster) {
		return ClusterMaintenanceRun{}, Operation{}, ErrPrerequisite
	}
	v, ok := s.clusterMaintenanceRuns[runID]
	if !ok || v.ClusterID != clusterID {
		return ClusterMaintenanceRun{}, Operation{}, ErrNotFound
	}
	if v.Revision != expected {
		return ClusterMaintenanceRun{}, Operation{}, ErrConflict
	}
	if v.State != ClusterMaintenanceRunning {
		return ClusterMaintenanceRun{}, Operation{}, ErrInvalidTransition
	}
	op, ok := s.operations[v.OperationID]
	now := nowUTC(s.now)
	if !ok || op.State != OperationRunning || op.LeaseOwner != "cluster-maintenance-agent:"+clusterID {
		return ClusterMaintenanceRun{}, Operation{}, fmt.Errorf("%w: linked operation is not owned by the cluster maintenance agent", ErrPrerequisite)
	}
	if err := ValidateDay2Fence(op.FenceToken, result.OperationFenceToken, op.LeaseExpiresAt, now); err != nil {
		return ClusterMaintenanceRun{}, Operation{}, err
	}
	if len(result.Results) == 0 {
		return ClusterMaintenanceRun{}, Operation{}, fmt.Errorf("%w: node maintenance results are required", ErrValidation)
	}
	selected := map[string]bool{}
	for _, n := range v.NodeNames {
		selected[n] = true
	}
	seen := map[string]bool{}
	needsOperator := false
	allSafe := true
	for _, r := range result.Results {
		if !selected[r.NodeName] || seen[r.NodeName] {
			return ClusterMaintenanceRun{}, Operation{}, fmt.Errorf("%w: result node set must match the requested nodes", ErrValidation)
		}
		seen[r.NodeName] = true
		if r.Cordoned && !r.Uncordoned {
			needsOperator = true
		}
		if !r.Cordoned || !r.DrainAttempted || !r.Drained || !r.Uncordoned || strings.TrimSpace(r.Error) != "" {
			allSafe = false
		}
		if v.Action == TargetNodeActionOSPatch && (!r.HostActionAttempted || !r.HostActionSucceeded || r.HostActionAuthority != "TARGET_NODE_HOST_MAINTENANCE_EXECUTOR_V1" || strings.TrimSpace(r.HostActionEvidence) == "") {
			allSafe = false
		}
	}
	if len(seen) != len(selected) {
		return ClusterMaintenanceRun{}, Operation{}, fmt.Errorf("%w: result node set must match the requested nodes", ErrValidation)
	}
	if result.Success && !allSafe {
		return ClusterMaintenanceRun{}, Operation{}, fmt.Errorf("%w: successful maintenance requires every node action to satisfy its cordon/drain/host-action/uncordon contract", ErrValidation)
	}
	v.Results = append([]NodeMaintenanceResult(nil), result.Results...)
	v.FinishedAt = &now
	v.LastError = strings.TrimSpace(result.Error)
	if result.Success {
		v.State = ClusterMaintenanceSucceeded
		op.State = OperationVerifying
		op.Revision++
		op.State = OperationSucceeded
		op.LastError = ""
		op.Revision++
	} else if needsOperator {
		v.State = ClusterMaintenanceNeedsOperator
		if v.LastError == "" {
			v.LastError = "one or more nodes could not be restored to schedulable state"
		}
		op.State = OperationRollingBack
		op.Revision++
		op.State = OperationNeedsOperator
		op.LastError = v.LastError
		op.Revision++
	} else {
		v.State = ClusterMaintenanceFailed
		if v.LastError == "" {
			v.LastError = "cluster maintenance task failed"
		}
		op.State = OperationFailed
		op.LastError = v.LastError
		op.Revision++
	}
	op.LeaseOwner = ""
	op.LeaseExpiresAt = nil
	op.UpdatedAt = now
	v.Revision++
	v.UpdatedAt = now
	s.clusterMaintenanceRuns[runID] = cloneClusterMaintenanceRun(v)
	s.operations[op.ID] = op
	s.appendAuditLocked("cluster-agent", "cluster_maintenance.run_reported", "clusterMaintenanceRun", runID, v.Revision, map[string]any{"operationId": op.ID, "state": v.State, "action": v.Action, "nodes": len(v.Results), "method": ClusterMaintenanceAuthorityMethod})
	s.appendOutboxLocked("clusterMaintenanceRun", runID, "cluster_maintenance.run_completed", v)
	s.appendOutboxLocked("operation", op.ID, "operation.completed", op)
	return cloneClusterMaintenanceRun(v), op, nil
}
