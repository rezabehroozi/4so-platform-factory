package controlplane

import (
	"context"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/virtualcluster"
)

func NormalizeVirtualClusterLifecycleAction(action virtualcluster.Action) (virtualcluster.Action, error) {
	action = virtualcluster.Action(strings.ToUpper(strings.TrimSpace(string(action))))
	switch action {
	case virtualcluster.ActionSuspend, virtualcluster.ActionResume, virtualcluster.ActionDelete:
		return action, nil
	default:
		return "", fmt.Errorf("%w: unsupported virtual cluster lifecycle action %q", ErrValidation, action)
	}
}

func VirtualClusterKnownTaskAction(action string) bool {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "APPLY", "INSPECT", "SUSPEND", "RESUME", "DELETE", "LIFECYCLE_INSPECT":
		return true
	default:
		return false
	}
}

func VirtualClusterMutationTaskAction(action string) bool {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "SUSPEND", "RESUME", "DELETE":
		return true
	default:
		return false
	}
}

func PrepareVirtualClusterLifecycleRequest(v VirtualCluster, expected int64, action virtualcluster.Action, idempotencyKey, requestDigest string, now time.Time) (VirtualCluster, bool, error) {
	var err error
	action, err = NormalizeVirtualClusterLifecycleAction(action)
	if err != nil {
		return VirtualCluster{}, false, err
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	requestDigest = strings.TrimSpace(requestDigest)
	if idempotencyKey == "" || len(idempotencyKey) > 200 || !virtualClusterDigestPattern.MatchString(requestDigest) {
		return VirtualCluster{}, false, fmt.Errorf("%w: lifecycle idempotency key/digest is invalid", ErrValidation)
	}
	if v.LifecycleIdempotencyKey == idempotencyKey {
		if v.LifecycleAction != action || v.LifecycleRequestDigest != requestDigest {
			return VirtualCluster{}, false, ErrIdempotencyConflict
		}
		return cloneVirtualCluster(v), true, nil
	}
	if expected <= 0 || v.Revision != expected {
		return VirtualCluster{}, false, ErrConflict
	}
	switch action {
	case virtualcluster.ActionSuspend:
		if v.State != virtualcluster.StateActive {
			return VirtualCluster{}, false, ErrInvalidTransition
		}
	case virtualcluster.ActionResume:
		if v.State != virtualcluster.StateSuspended {
			return VirtualCluster{}, false, ErrInvalidTransition
		}
	case virtualcluster.ActionDelete:
		switch v.State {
		case virtualcluster.StateRequested, virtualcluster.StateActive, virtualcluster.StateSuspended, virtualcluster.StateFailed:
		default:
			return VirtualCluster{}, false, ErrInvalidTransition
		}
	}
	v.State = virtualcluster.BeginState(action)
	v.PendingAction = action
	v.LifecycleAction = action
	v.LifecycleIdempotencyKey = idempotencyKey
	v.LifecycleRequestDigest = requestDigest
	v.TaskAction = ""
	v.TaskLeaseExpiresAt = nil
	v.TaskDispatchedAt = nil
	v.LastError = ""
	v.Phase = string(action) + "Requested"
	v.Revision++
	v.UpdatedAt = now.UTC()
	return v, false, nil
}

func ApplyVirtualClusterTaskDispatch(v VirtualCluster, expected, fence int64, action string, now time.Time) (VirtualCluster, bool, error) {
	action = strings.ToUpper(strings.TrimSpace(action))
	if !VirtualClusterMutationTaskAction(action) {
		return VirtualCluster{}, false, ErrValidation
	}
	if v.TaskFenceToken == fence && v.TaskAction == action && v.TaskDispatchedAt != nil {
		return cloneVirtualCluster(v), true, nil
	}
	if expected <= 0 || v.Revision != expected || fence <= 0 || v.TaskFenceToken != fence || v.TaskAction != action || !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		return VirtualCluster{}, false, ErrConflict
	}
	stamp := now.UTC()
	v.TaskDispatchedAt = &stamp
	v.Phase = action + "Dispatched"
	v.Revision++
	v.UpdatedAt = stamp
	return v, false, nil
}

func (s *MemoryStore) RequestVirtualClusterLifecycle(_ context.Context, id string, expected int64, action string, idempotencyKey, requestDigest, actor string) (VirtualCluster, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.virtualClusters[strings.TrimSpace(id)]
	if !ok {
		return VirtualCluster{}, false, ErrNotFound
	}
	if strings.TrimSpace(idempotencyKey) != "" && v.LifecycleIdempotencyKey == strings.TrimSpace(idempotencyKey) {
		return PrepareVirtualClusterLifecycleRequest(v, expected, virtualcluster.Action(action), idempotencyKey, requestDigest, nowUTC(s.now))
	}
	if err := s.virtualClusterBindingFenceCurrentLocked(v); err != nil {
		return VirtualCluster{}, false, err
	}
	updated, replay, err := PrepareVirtualClusterLifecycleRequest(v, expected, virtualcluster.Action(action), idempotencyKey, requestDigest, nowUTC(s.now))
	if err != nil || replay {
		return updated, replay, err
	}
	s.virtualClusters[updated.ID] = updated
	s.appendAuditLocked(actor, "virtual_cluster.lifecycle.requested", "virtualCluster", updated.ID, updated.Revision, map[string]any{"action": updated.LifecycleAction, "workspaceId": updated.WorkspaceID, "hostClusterId": updated.HostClusterID})
	s.appendOutboxLocked("virtualCluster", updated.ID, "virtual_cluster.state.changed", updated)
	return cloneVirtualCluster(updated), false, nil
}

func (s *MemoryStore) DispatchVirtualClusterTask(_ context.Context, clusterID, tokenDigest, virtualClusterID string, expected, fence int64, action string) (VirtualClusterTask, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, tokenDigest); err != nil {
		return VirtualClusterTask{}, false, err
	}
	v, ok := s.virtualClusters[strings.TrimSpace(virtualClusterID)]
	if !ok || v.HostClusterID != strings.TrimSpace(clusterID) {
		return VirtualClusterTask{}, false, ErrNotFound
	}
	updated, replay, err := ApplyVirtualClusterTaskDispatch(v, expected, fence, action, nowUTC(s.now))
	if err != nil {
		return VirtualClusterTask{}, false, err
	}
	if !replay {
		s.virtualClusters[updated.ID] = updated
		s.appendAuditLocked("cluster-agent", "virtual_cluster.task.dispatched", "virtualCluster", updated.ID, updated.Revision, map[string]any{"action": updated.TaskAction, "taskFenceToken": updated.TaskFenceToken})
		s.appendOutboxLocked("virtualCluster", updated.ID, "virtual_cluster.state.changed", updated)
	}
	return VirtualClusterTaskFromRecord(updated), replay, nil
}


func VirtualClusterTaskClaimable(v VirtualCluster, now time.Time) bool {
	if v.State == virtualcluster.StateRequested {
		return true
	}
	switch v.State {
	case virtualcluster.StateProvisioning, virtualcluster.StateSuspending, virtualcluster.StateResuming, virtualcluster.StateDeleting:
		return !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now)
	default:
		return false
	}
}

func VirtualClusterExpiredDispatchedMutation(v VirtualCluster, now time.Time) bool {
	return v.TaskLeaseExpiresAt != nil && !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) && v.TaskDispatchedAt != nil && VirtualClusterMutationTaskAction(v.TaskAction)
}

func VirtualClusterTaskClaimAction(v VirtualCluster) (string, error) {
	switch v.State {
	case virtualcluster.StateRequested:
		return "APPLY", nil
	case virtualcluster.StateProvisioning:
		switch v.TaskAction {
		case "", "APPLY":
			return "APPLY", nil
		case "INSPECT":
			return "INSPECT", nil
		}
	case virtualcluster.StateSuspending, virtualcluster.StateResuming, virtualcluster.StateDeleting:
		pending, err := NormalizeVirtualClusterLifecycleAction(v.PendingAction)
		if err != nil {
			return "", err
		}
		if v.TaskAction == "LIFECYCLE_INSPECT" {
			return "LIFECYCLE_INSPECT", nil
		}
		if v.TaskAction == "" || (strings.EqualFold(v.TaskAction, string(pending)) && v.TaskDispatchedAt == nil) {
			return string(pending), nil
		}
	}
	return "", fmt.Errorf("%w: virtual cluster task journal cannot be safely claimed", ErrConflict)
}

func PrepareVirtualClusterTaskClaim(v VirtualCluster, runtimeSourceDigest string, now time.Time) (VirtualCluster, VirtualClusterTask, error) {
	runtimeSourceDigest = strings.TrimSpace(runtimeSourceDigest)
	if err := ValidateVirtualClusterRuntimeSourceDigest(runtimeSourceDigest); err != nil {
		return VirtualCluster{}, VirtualClusterTask{}, err
	}
	if v.RuntimeSourceDigest != "" && v.RuntimeSourceDigest != runtimeSourceDigest {
		return VirtualCluster{}, VirtualClusterTask{}, ErrConflict
	}
	action, err := VirtualClusterTaskClaimAction(v)
	if err != nil {
		return VirtualCluster{}, VirtualClusterTask{}, err
	}
	if v.RuntimeSourceDigest == "" {
		v.RuntimeSourceDigest = runtimeSourceDigest
	}
	if v.State == virtualcluster.StateRequested {
		v.State = virtualcluster.StateProvisioning
	}
	lease := now.UTC().Add(AgentTaskLeaseDuration)
	v.TaskAction = action
	v.TaskAttempt++
	if action == "INSPECT" || action == "LIFECYCLE_INSPECT" {
		if v.TaskFenceToken <= 0 {
			return VirtualCluster{}, VirtualClusterTask{}, fmt.Errorf("%w: inspect task has no prior mutation fence", ErrConflict)
		}
	} else {
		v.TaskFenceToken++
	}
	v.TaskLeaseExpiresAt = &lease
	v.TaskDispatchedAt = nil
	v.Phase = action + "Claimed"
	v.LastError = ""
	v.Revision++
	v.UpdatedAt = now.UTC()
	return v, VirtualClusterTaskFromRecord(v), nil
}

func virtualClusterLifecycleTargetState(action virtualcluster.Action) (virtualcluster.State, error) {
	switch action {
	case virtualcluster.ActionSuspend:
		return virtualcluster.StateSuspended, nil
	case virtualcluster.ActionResume:
		return virtualcluster.StateActive, nil
	case virtualcluster.ActionDelete:
		return virtualcluster.StateDeleted, nil
	default:
		return "", ErrValidation
	}
}

func ApplyVirtualClusterTaskResult(v VirtualCluster, result VirtualClusterTaskResult, now time.Time) (VirtualCluster, error) {
	action := strings.ToUpper(strings.TrimSpace(result.Action))
	if !VirtualClusterKnownTaskAction(action) || action != v.TaskAction {
		return VirtualCluster{}, ErrValidation
	}
	if result.RecoveryRequired && result.Success {
		return VirtualCluster{}, ErrValidation
	}
	if VirtualClusterMutationTaskAction(action) && v.TaskDispatchedAt == nil {
		return VirtualCluster{}, fmt.Errorf("%w: lifecycle mutation result has no durable dispatch acknowledgement", ErrConflict)
	}
	if action == "LIFECYCLE_INSPECT" && v.TaskDispatchedAt != nil {
		return VirtualCluster{}, fmt.Errorf("%w: lifecycle inspect unexpectedly carries dispatch state", ErrValidation)
	}
	result.ObservedDigest = strings.TrimSpace(result.ObservedDigest)
	result.Phase = strings.TrimSpace(result.Phase)
	result.Error = strings.TrimSpace(result.Error)

	finish := func() VirtualCluster {
		v.TaskLeaseExpiresAt = nil
		v.TaskDispatchedAt = nil
		v.Revision++
		v.UpdatedAt = now.UTC()
		return v
	}

	if action == "APPLY" || action == "INSPECT" {
		if !result.Success {
			if result.RecoveryRequired {
				v = markVirtualClusterRecovery(v, now, result.Error)
				v.TaskAction = ""
				v.TaskDispatchedAt = nil
				return v, nil
			}
			if action == "APPLY" {
				v.State = virtualcluster.StateFailed
				v.Phase = "ApplyFailed"
				v.LastError = result.Error
				if v.LastError == "" {
					v.LastError = "virtual cluster apply failed before mutation convergence"
				}
				v.TaskAction = ""
				return finish(), nil
			}
			v.State = virtualcluster.StateProvisioning
			v.Phase = "InspectRetry"
			v.LastError = result.Error
			if v.LastError == "" {
				v.LastError = "virtual cluster authoritative readback failed"
			}
			v.TaskAction = "INSPECT"
			return finish(), nil
		}
		if result.ObservedDigest != v.DesiredDigest {
			v = markVirtualClusterRecovery(v, now, "virtual cluster authoritative readback digest does not match desired state")
			v.TaskAction = ""
			v.TaskDispatchedAt = nil
			return v, nil
		}
		if result.Ready {
			v.State = virtualcluster.StateActive
			v.ObservedDigest = result.ObservedDigest
			v.Phase = result.Phase
			if v.Phase == "" {
				v.Phase = "Ready"
			}
			v.PendingAction = ""
			v.TaskAction = ""
			v.LastError = ""
			return finish(), nil
		}
		v.State = virtualcluster.StateProvisioning
		v.ObservedDigest = result.ObservedDigest
		v.Phase = result.Phase
		if v.Phase == "" {
			v.Phase = "Reconciling"
		}
		v.TaskAction = "INSPECT"
		v.LastError = ""
		return finish(), nil
	}

	lifecycleAction := result.LifecycleAction
	if action != "LIFECYCLE_INSPECT" {
		lifecycleAction = virtualcluster.Action(action)
	}
	normalized, err := NormalizeVirtualClusterLifecycleAction(lifecycleAction)
	if err != nil || normalized != v.PendingAction || normalized != v.LifecycleAction {
		return VirtualCluster{}, fmt.Errorf("%w: lifecycle result does not match pending journal", ErrConflict)
	}
	if !result.Success {
		if result.RecoveryRequired || VirtualClusterMutationTaskAction(action) {
			v = markVirtualClusterRecovery(v, now, result.Error)
			v.TaskAction = ""
			v.TaskDispatchedAt = nil
			return v, nil
		}
		v.Phase = "LifecycleInspectRetry"
		v.LastError = result.Error
		if v.LastError == "" {
			v.LastError = "virtual cluster lifecycle authoritative readback failed"
		}
		v.TaskAction = "LIFECYCLE_INSPECT"
		return finish(), nil
	}
	if normalized == virtualcluster.ActionDelete {
		if result.Ready && result.ObservedDigest != "" {
			v = markVirtualClusterRecovery(v, now, "deleted virtual cluster returned a non-empty observed digest")
			v.TaskAction = ""
			v.TaskDispatchedAt = nil
			return v, nil
		}
	} else if result.ObservedDigest != v.DesiredDigest {
		v = markVirtualClusterRecovery(v, now, "virtual cluster lifecycle readback digest does not match desired state")
		v.TaskAction = ""
		v.TaskDispatchedAt = nil
		return v, nil
	}
	if result.Ready {
		target, err := virtualClusterLifecycleTargetState(normalized)
		if err != nil {
			return VirtualCluster{}, err
		}
		v.State = target
		if target == virtualcluster.StateDeleted {
			v.ObservedDigest = ""
		} else {
			v.ObservedDigest = result.ObservedDigest
		}
		v.Phase = result.Phase
		if v.Phase == "" {
			v.Phase = string(target)
		}
		v.PendingAction = ""
		v.TaskAction = ""
		v.LastError = ""
		return finish(), nil
	}
	v.State = virtualcluster.BeginState(normalized)
	v.Phase = result.Phase
	if v.Phase == "" {
		v.Phase = string(normalized) + "Reconciling"
	}
	v.TaskAction = "LIFECYCLE_INSPECT"
	v.LastError = ""
	return finish(), nil
}
