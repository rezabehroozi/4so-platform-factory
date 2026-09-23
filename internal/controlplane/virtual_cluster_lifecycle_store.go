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
