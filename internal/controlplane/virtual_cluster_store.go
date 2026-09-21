package controlplane

import (
	"context"
	"time"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/virtualcluster"
)

const VirtualClusterStoreAuthority = "VIRTUAL_CLUSTER_DURABLE_AUTHORITY_V1"

type VirtualCluster struct {
	ResourceMeta
	ProjectID          string               `json:"projectId"`
	WorkspaceID        string               `json:"workspaceId"`
	WorkspaceBindingID string               `json:"workspaceBindingId"`
	WorkspaceBindingRevision int64           `json:"workspaceBindingRevision"`
	HostClusterID      string               `json:"hostClusterId"`
	HostNamespace      string               `json:"hostNamespace"`
	Name               string               `json:"name"`
	Profile            virtualcluster.ProfileID `json:"profile"`
	DeveloperMode      bool                 `json:"developerMode"`
	KubernetesVersion  string               `json:"kubernetesVersion"`
	CPUMilli           int                  `json:"cpuMilli"`
	MemoryMiB          int                  `json:"memoryMiB"`
	StorageGiB         int                  `json:"storageGiB"`
	MaxNamespaces      int                  `json:"maxNamespaces"`
	SleepAfterMinutes  int                  `json:"sleepAfterMinutes,omitempty"`
	DesiredDigest      string               `json:"desiredDigest"`
	State              virtualcluster.State `json:"state"`
	PendingAction      virtualcluster.Action `json:"pendingAction,omitempty"`
	RequestedBy        string               `json:"requestedBy"`
	IdempotencyKey     string               `json:"idempotencyKey"`
	RequestDigest      string               `json:"requestDigest"`
	ObservedDigest     string               `json:"observedDigest,omitempty"`
	Phase              string               `json:"phase,omitempty"`
	RuntimeSourceDigest string              `json:"runtimeSourceDigest,omitempty"`
	TaskAttempt        int                  `json:"taskAttempt,omitempty"`
	TaskFenceToken     int64                `json:"taskFenceToken,omitempty"`
	TaskAction         string               `json:"taskAction,omitempty"`
	TaskLeaseExpiresAt *time.Time            `json:"taskLeaseExpiresAt,omitempty"`
	LastError          string               `json:"lastError,omitempty"`
}

type VirtualClusterCreateRequest struct {
	WorkspaceID       string                 `json:"workspaceId"`
	WorkspaceBindingID string                `json:"workspaceBindingId"`
	Spec              virtualcluster.Request `json:"spec"`
	IdempotencyKey    string                 `json:"idempotencyKey"`
	RequestDigest     string                 `json:"requestDigest"`
}

type VirtualClusterTask struct {
	VirtualClusterID         string                   `json:"virtualClusterId"`
	ClusterRevision          int64                    `json:"clusterRevision"`
	TaskFenceToken           int64                    `json:"taskFenceToken"`
	LeaseExpiresAt           time.Time                `json:"leaseExpiresAt"`
	Action                   string                   `json:"action"`
	ProjectID                string                   `json:"projectId"`
	WorkspaceID              string                   `json:"workspaceId"`
	WorkspaceBindingID       string                   `json:"workspaceBindingId"`
	WorkspaceBindingRevision int64                    `json:"workspaceBindingRevision"`
	HostClusterID            string                   `json:"hostClusterId"`
	HostNamespace            string                   `json:"hostNamespace"`
	Name                     string                   `json:"name"`
	Profile                  virtualcluster.ProfileID `json:"profile"`
	DeveloperMode            bool                     `json:"developerMode"`
	KubernetesVersion        string                   `json:"kubernetesVersion"`
	CPUMilli                 int                      `json:"cpuMilli"`
	MemoryMiB                int                      `json:"memoryMiB"`
	StorageGiB               int                      `json:"storageGiB"`
	MaxNamespaces            int                      `json:"maxNamespaces"`
	SleepAfterMinutes        int                      `json:"sleepAfterMinutes,omitempty"`
	DesiredDigest            string                   `json:"desiredDigest"`
	RuntimeSourceDigest      string                   `json:"runtimeSourceDigest"`
}

type VirtualClusterTaskResult struct {
	VirtualClusterID string `json:"-"`
	TaskFenceToken   int64  `json:"taskFenceToken"`
	Action           string `json:"action"`
	Success          bool   `json:"success"`
	Ready            bool   `json:"ready,omitempty"`
	ObservedDigest   string `json:"observedDigest,omitempty"`
	Phase            string `json:"phase,omitempty"`
	Error            string `json:"error,omitempty"`
	RecoveryRequired bool   `json:"recoveryRequired,omitempty"`
}

func VirtualClusterTaskFromRecord(v VirtualCluster) VirtualClusterTask {
	lease := time.Time{}
	if v.TaskLeaseExpiresAt != nil {
		lease = *v.TaskLeaseExpiresAt
	}
	return VirtualClusterTask{
		VirtualClusterID: v.ID, ClusterRevision: v.Revision, TaskFenceToken: v.TaskFenceToken, LeaseExpiresAt: lease,
		Action: v.TaskAction, ProjectID: v.ProjectID, WorkspaceID: v.WorkspaceID,
		WorkspaceBindingID: v.WorkspaceBindingID, WorkspaceBindingRevision: v.WorkspaceBindingRevision,
		HostClusterID: v.HostClusterID, HostNamespace: v.HostNamespace, Name: v.Name, Profile: v.Profile,
		DeveloperMode: v.DeveloperMode, KubernetesVersion: v.KubernetesVersion, CPUMilli: v.CPUMilli,
		MemoryMiB: v.MemoryMiB, StorageGiB: v.StorageGiB, MaxNamespaces: v.MaxNamespaces,
		SleepAfterMinutes: v.SleepAfterMinutes, DesiredDigest: v.DesiredDigest, RuntimeSourceDigest: v.RuntimeSourceDigest,
	}
}

func ValidateVirtualClusterRuntimeSourceDigest(value string) error {
	if !virtualClusterDigestPattern.MatchString(strings.TrimSpace(value)) {
		return fmt.Errorf("%w: runtimeSourceDigest must be an exact lowercase sha256 digest", ErrValidation)
	}
	return nil
}

var virtualClusterDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func virtualClusterWorkspaceAuthority(workspace Workspace, binding WorkspaceBinding) (virtualcluster.WorkspaceAuthority, error) {
	if binding.WorkspaceID != workspace.ID || binding.ProjectID != workspace.ProjectID {
		return virtualcluster.WorkspaceAuthority{}, fmt.Errorf("%w: virtual cluster workspace binding is outside workspace project authority", ErrValidation)
	}
	return virtualcluster.WorkspaceAuthority{
		WorkspaceID: workspace.ID, ProjectID: workspace.ProjectID, WorkspaceDigest: workspace.Digest,
		BindingID: binding.ID, BindingRevision: binding.Revision, HostClusterID: binding.ClusterID,
		HostNamespace: binding.Namespace, BindingActive: binding.State == WorkspaceBindingActive,
	}, nil
}

func normalizeVirtualClusterCreateRequest(v VirtualClusterCreateRequest) (VirtualClusterCreateRequest, error) {
	v.WorkspaceID = strings.TrimSpace(v.WorkspaceID)
	v.WorkspaceBindingID = strings.TrimSpace(v.WorkspaceBindingID)
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	v.RequestDigest = strings.TrimSpace(v.RequestDigest)
	if v.WorkspaceID == "" || v.WorkspaceBindingID == "" {
		return VirtualClusterCreateRequest{}, fmt.Errorf("%w: workspaceId and workspaceBindingId are required", ErrValidation)
	}
	if v.IdempotencyKey == "" || len(v.IdempotencyKey) > 200 {
		return VirtualClusterCreateRequest{}, fmt.Errorf("%w: idempotencyKey is required and must be bounded", ErrValidation)
	}
	if !virtualClusterDigestPattern.MatchString(v.RequestDigest) {
		return VirtualClusterCreateRequest{}, fmt.Errorf("%w: requestDigest must be an exact lowercase sha256 digest", ErrValidation)
	}
	return v, nil
}

func virtualClusterFromPlan(plan virtualcluster.Plan, request VirtualClusterCreateRequest, actor string, meta ResourceMeta) VirtualCluster {
	return VirtualCluster{
		ResourceMeta: meta,
		ProjectID: plan.ProjectID, WorkspaceID: plan.WorkspaceID, WorkspaceBindingID: plan.BindingID,
		WorkspaceBindingRevision: plan.BindingRevision,
		HostClusterID: plan.HostClusterID, HostNamespace: plan.HostNamespace, Name: plan.Name,
		Profile: plan.Profile, DeveloperMode: plan.DeveloperMode, KubernetesVersion: plan.KubernetesVersion,
		CPUMilli: plan.CPUMilli, MemoryMiB: plan.MemoryMiB, StorageGiB: plan.StorageGiB,
		MaxNamespaces: plan.MaxNamespaces, SleepAfterMinutes: plan.SleepAfterMinutes,
		DesiredDigest: plan.DesiredDigest, State: virtualcluster.StateRequested, PendingAction: virtualcluster.ActionProvision,
		RequestedBy: strings.TrimSpace(actor), IdempotencyKey: request.IdempotencyKey, RequestDigest: request.RequestDigest,
	}
}

func validateVirtualClusterRecord(v VirtualCluster, workspaces map[string]Workspace, bindings map[string]WorkspaceBinding) error {
	workspace, ok := workspaces[v.WorkspaceID]
	if !ok || workspace.ProjectID != v.ProjectID {
		return fmt.Errorf("%w: virtual cluster workspace authority is invalid", ErrValidation)
	}
	binding, ok := bindings[v.WorkspaceBindingID]
	if !ok || binding.WorkspaceID != workspace.ID || binding.ProjectID != v.ProjectID {
		return fmt.Errorf("%w: virtual cluster workspace binding authority is invalid", ErrValidation)
	}
	if v.WorkspaceBindingRevision <= 0 || binding.ClusterID != v.HostClusterID || binding.Namespace != v.HostNamespace {
		return fmt.Errorf("%w: stored virtual cluster binding snapshot is incomplete", ErrValidation)
	}
	authority := virtualcluster.WorkspaceAuthority{
		WorkspaceID: workspace.ID,
		ProjectID: workspace.ProjectID,
		WorkspaceDigest: workspace.Digest,
		BindingID: binding.ID,
		BindingRevision: v.WorkspaceBindingRevision,
		HostClusterID: v.HostClusterID,
		HostNamespace: v.HostNamespace,
		BindingActive: true,
	}
	plan, err := virtualcluster.BuildPlan(authority, virtualcluster.Request{
		Name: v.Name, Profile: v.Profile, KubernetesVersion: v.KubernetesVersion,
		CPUMilli: v.CPUMilli, MemoryMiB: v.MemoryMiB, StorageGiB: v.StorageGiB,
		MaxNamespaces: v.MaxNamespaces, SleepAfterMinutes: v.SleepAfterMinutes,
	})
	if err != nil {
		return fmt.Errorf("%w: stored virtual cluster plan is invalid: %v", ErrValidation, err)
	}
	if plan.ProjectID != v.ProjectID || plan.HostClusterID != v.HostClusterID || plan.HostNamespace != v.HostNamespace || plan.DesiredDigest != v.DesiredDigest {
		return fmt.Errorf("%w: stored virtual cluster authority snapshot drift", ErrValidation)
	}
	if v.State == "" {
		return fmt.Errorf("%w: virtual cluster state is required", ErrValidation)
	}
	switch v.State {
	case virtualcluster.StateRequested, virtualcluster.StateProvisioning, virtualcluster.StateActive,
		virtualcluster.StateSuspending, virtualcluster.StateSuspended, virtualcluster.StateResuming,
		virtualcluster.StateDeleting, virtualcluster.StateDeleted, virtualcluster.StateRecoveryRequired, virtualcluster.StateFailed:
	default:
		return fmt.Errorf("%w: unsupported virtual cluster state %q", ErrValidation, v.State)
	}
	if !virtualClusterDigestPattern.MatchString(v.RequestDigest) || v.IdempotencyKey == "" {
		return fmt.Errorf("%w: virtual cluster idempotency authority is incomplete", ErrValidation)
	}
	return nil
}

func cloneVirtualCluster(v VirtualCluster) VirtualCluster { return v }

func sortVirtualClusters(out []VirtualCluster) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].WorkspaceID != out[j].WorkspaceID {
			return out[i].WorkspaceID < out[j].WorkspaceID
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
}

func (s *MemoryStore) CreateVirtualCluster(_ context.Context, request VirtualClusterCreateRequest, actor string) (VirtualCluster, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, err := normalizeVirtualClusterCreateRequest(request)
	if err != nil {
		return VirtualCluster{}, false, err
	}
	workspace, ok := s.workspaces[request.WorkspaceID]
	if !ok {
		return VirtualCluster{}, false, ErrNotFound
	}
	binding, ok := s.workspaceBindings[request.WorkspaceBindingID]
	if !ok || binding.WorkspaceID != workspace.ID || binding.ProjectID != workspace.ProjectID {
		return VirtualCluster{}, false, ErrNotFound
	}
	for _, existing := range s.virtualClusters {
		if existing.ProjectID == workspace.ProjectID && existing.IdempotencyKey == request.IdempotencyKey {
			if existing.RequestDigest != request.RequestDigest {
				return VirtualCluster{}, false, ErrIdempotencyConflict
			}
			return cloneVirtualCluster(existing), true, nil
		}
	}
	authority, err := virtualClusterWorkspaceAuthority(workspace, binding)
	if err != nil {
		return VirtualCluster{}, false, err
	}
	plan, err := virtualcluster.BuildPlan(authority, request.Spec)
	if err != nil {
		return VirtualCluster{}, false, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	for _, existing := range s.virtualClusters {
		if existing.WorkspaceID == workspace.ID && existing.Name == plan.Name && existing.State != virtualcluster.StateDeleted {
			return VirtualCluster{}, false, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v := virtualClusterFromPlan(plan, request, actor, ResourceMeta{ID: s.id("vcl"), Revision: 1, CreatedAt: now, UpdatedAt: now})
	s.virtualClusters[v.ID] = v
	s.appendAuditLocked(actor, "virtual_cluster.created", "virtualCluster", v.ID, v.Revision, map[string]any{
		"projectId": v.ProjectID, "workspaceId": v.WorkspaceID, "workspaceBindingId": v.WorkspaceBindingID,
		"hostClusterId": v.HostClusterID, "hostNamespace": v.HostNamespace, "profile": v.Profile, "desiredDigest": v.DesiredDigest,
	})
	s.appendOutboxLocked("virtualCluster", v.ID, "virtual_cluster.created", v)
	return cloneVirtualCluster(v), false, nil
}

func (s *MemoryStore) GetVirtualCluster(_ context.Context, id string) (VirtualCluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.virtualClusters[strings.TrimSpace(id)]
	if !ok {
		return VirtualCluster{}, ErrNotFound
	}
	return cloneVirtualCluster(v), nil
}

func (s *MemoryStore) ListVirtualClusters(_ context.Context, projectID, workspaceID string) ([]VirtualCluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	projectID, workspaceID = strings.TrimSpace(projectID), strings.TrimSpace(workspaceID)
	out := []VirtualCluster{}
	for _, v := range s.virtualClusters {
		if (projectID == "" || v.ProjectID == projectID) && (workspaceID == "" || v.WorkspaceID == workspaceID) {
			out = append(out, cloneVirtualCluster(v))
		}
	}
	sortVirtualClusters(out)
	return out, nil
}

func VirtualClusterWorkspaceAuthorityForPersistence(workspace Workspace, binding WorkspaceBinding) (virtualcluster.WorkspaceAuthority, error) {
	return virtualClusterWorkspaceAuthority(workspace, binding)
}

func VirtualClusterFromPlanForPersistence(plan virtualcluster.Plan, request VirtualClusterCreateRequest, actor string, meta ResourceMeta) VirtualCluster {
	return virtualClusterFromPlan(plan, request, actor, meta)
}


func (s *MemoryStore) virtualClusterBindingFenceCurrentLocked(v VirtualCluster) error {
	binding, ok := s.workspaceBindings[v.WorkspaceBindingID]
	if !ok || binding.WorkspaceID != v.WorkspaceID || binding.ProjectID != v.ProjectID ||
		binding.ClusterID != v.HostClusterID || binding.Namespace != v.HostNamespace ||
		binding.Revision != v.WorkspaceBindingRevision || binding.State != WorkspaceBindingActive {
		return ErrPrerequisite
	}
	return nil
}

func markVirtualClusterRecovery(v VirtualCluster, now time.Time, message string) VirtualCluster {
	v.State = virtualcluster.StateRecoveryRequired
	v.Phase = "RecoveryRequired"
	v.LastError = strings.TrimSpace(message)
	if v.LastError == "" {
		v.LastError = "virtual cluster runtime outcome requires authoritative recovery"
	}
	v.TaskLeaseExpiresAt = nil
	v.Revision++
	v.UpdatedAt = now
	return v
}

func (s *MemoryStore) NextVirtualClusterTask(_ context.Context, clusterID, tokenDigest, runtimeSourceDigest string) (VirtualClusterTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requireFreshClusterTaskAdmissionLocked(clusterID, tokenDigest); err != nil {
		return VirtualClusterTask{}, err
	}
	clusterID = strings.TrimSpace(clusterID)
	runtimeSourceDigest = strings.TrimSpace(runtimeSourceDigest)
	if err := ValidateVirtualClusterRuntimeSourceDigest(runtimeSourceDigest); err != nil {
		return VirtualClusterTask{}, err
	}
	now := nowUTC(s.now)
	ids := make([]string, 0)
	for id, current := range s.virtualClusters {
		if current.HostClusterID != clusterID {
			continue
		}
		if current.State == virtualcluster.StateRequested ||
			(current.State == virtualcluster.StateProvisioning && !AgentTaskLeaseActive(current.TaskLeaseExpiresAt, now)) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return VirtualClusterTask{}, ErrNotFound
	}
	sort.Slice(ids, func(i, j int) bool {
		return resourceUpdatedBefore(s.virtualClusters[ids[i]].ResourceMeta, s.virtualClusters[ids[j]].ResourceMeta)
	})
	v := s.virtualClusters[ids[0]]

	if v.State == virtualcluster.StateProvisioning && v.TaskAction == "APPLY" && v.TaskLeaseExpiresAt != nil && !AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) {
		v = markVirtualClusterRecovery(v, now, "virtual cluster APPLY lease expired; mutation outcome is ambiguous and automatic replay is forbidden")
		s.virtualClusters[v.ID] = v
		s.appendAuditLocked("cluster-agent", "virtual_cluster.apply.lease_expired_recovery_required", "virtualCluster", v.ID, v.Revision, map[string]any{"taskFenceToken": v.TaskFenceToken, "runtimeSourceDigest": v.RuntimeSourceDigest})
		s.appendOutboxLocked("virtualCluster", v.ID, "virtual_cluster.state.changed", v)
		return VirtualClusterTask{}, ErrNotFound
	}

	if err := s.virtualClusterBindingFenceCurrentLocked(v); err != nil {
		message := "workspace binding revision/state changed before virtual cluster runtime claim"
		if v.State == virtualcluster.StateRequested {
			v.State = virtualcluster.StateFailed
			v.Phase = "BindingFenceRejected"
			v.LastError = message
			v.TaskLeaseExpiresAt = nil
			v.Revision++
			v.UpdatedAt = now
		} else {
			v = markVirtualClusterRecovery(v, now, message)
		}
		s.virtualClusters[v.ID] = v
		s.appendAuditLocked("cluster-agent", "virtual_cluster.binding_fence.rejected", "virtualCluster", v.ID, v.Revision, map[string]any{"workspaceBindingId": v.WorkspaceBindingID, "workspaceBindingRevision": v.WorkspaceBindingRevision})
		s.appendOutboxLocked("virtualCluster", v.ID, "virtual_cluster.state.changed", v)
		return VirtualClusterTask{}, ErrNotFound
	}

	if v.RuntimeSourceDigest != "" && v.RuntimeSourceDigest != runtimeSourceDigest {
		return VirtualClusterTask{}, ErrConflict
	}
	action := "APPLY"
	if v.State == virtualcluster.StateProvisioning {
		action = "INSPECT"
	}
	if v.RuntimeSourceDigest == "" {
		v.RuntimeSourceDigest = runtimeSourceDigest
	}
	lease := now.Add(AgentTaskLeaseDuration)
	v.State = virtualcluster.StateProvisioning
	v.TaskAction = action
	v.TaskAttempt++
	v.TaskFenceToken++
	v.TaskLeaseExpiresAt = &lease
	v.Phase = action + "Claimed"
	v.LastError = ""
	v.Revision++
	v.UpdatedAt = now
	s.virtualClusters[v.ID] = v
	s.appendAuditLocked("cluster-agent", "virtual_cluster.task.claimed", "virtualCluster", v.ID, v.Revision, map[string]any{"action": action, "taskFenceToken": v.TaskFenceToken, "runtimeSourceDigest": v.RuntimeSourceDigest})
	s.appendOutboxLocked("virtualCluster", v.ID, "virtual_cluster.state.changed", v)
	return VirtualClusterTaskFromRecord(v), nil
}

func (s *MemoryStore) ReportVirtualClusterTask(_ context.Context, clusterID, tokenDigest string, expected int64, result VirtualClusterTaskResult) (VirtualCluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requireClusterTaskAdmissionLocked(clusterID, tokenDigest); err != nil {
		return VirtualCluster{}, err
	}
	v, ok := s.virtualClusters[strings.TrimSpace(result.VirtualClusterID)]
	if !ok || v.HostClusterID != strings.TrimSpace(clusterID) {
		return VirtualCluster{}, ErrNotFound
	}
	now := nowUTC(s.now)
	action := strings.ToUpper(strings.TrimSpace(result.Action))
	if v.Revision != expected || result.TaskFenceToken <= 0 || v.TaskFenceToken != result.TaskFenceToken ||
		!AgentTaskLeaseActive(v.TaskLeaseExpiresAt, now) || action != v.TaskAction {
		return VirtualCluster{}, ErrConflict
	}
	if action != "APPLY" && action != "INSPECT" {
		return VirtualCluster{}, ErrValidation
	}
	if result.RecoveryRequired && result.Success {
		return VirtualCluster{}, ErrValidation
	}
	result.ObservedDigest = strings.TrimSpace(result.ObservedDigest)
	result.Phase = strings.TrimSpace(result.Phase)
	result.Error = strings.TrimSpace(result.Error)

	if !result.Success {
		if result.RecoveryRequired {
			v = markVirtualClusterRecovery(v, now, result.Error)
		} else if action == "APPLY" {
			v.State = virtualcluster.StateFailed
			v.Phase = "ApplyFailed"
			v.LastError = result.Error
			if v.LastError == "" {
				v.LastError = "virtual cluster apply failed before mutation convergence"
			}
			v.TaskLeaseExpiresAt = nil
			v.TaskAction = ""
			v.Revision++
			v.UpdatedAt = now
		} else {
			v.State = virtualcluster.StateProvisioning
			v.Phase = "InspectRetry"
			v.LastError = result.Error
			if v.LastError == "" {
				v.LastError = "virtual cluster authoritative readback failed"
			}
			v.TaskLeaseExpiresAt = nil
			v.TaskAction = "INSPECT"
			v.Revision++
			v.UpdatedAt = now
		}
	} else {
		if result.ObservedDigest != v.DesiredDigest {
			v = markVirtualClusterRecovery(v, now, "virtual cluster authoritative readback digest does not match desired state")
		} else if result.Ready {
			v.State = virtualcluster.StateActive
			v.ObservedDigest = result.ObservedDigest
			v.Phase = result.Phase
			if v.Phase == "" {
				v.Phase = "Ready"
			}
			v.PendingAction = ""
			v.TaskAction = ""
			v.TaskLeaseExpiresAt = nil
			v.LastError = ""
			v.Revision++
			v.UpdatedAt = now
		} else {
			v.State = virtualcluster.StateProvisioning
			v.ObservedDigest = result.ObservedDigest
			v.Phase = result.Phase
			if v.Phase == "" {
				v.Phase = "Reconciling"
			}
			v.TaskAction = "INSPECT"
			v.TaskLeaseExpiresAt = nil
			v.LastError = ""
			v.Revision++
			v.UpdatedAt = now
		}
	}
	s.virtualClusters[v.ID] = v
	s.appendAuditLocked("cluster-agent", "virtual_cluster.task.reported", "virtualCluster", v.ID, v.Revision, map[string]any{"action": action, "success": result.Success, "ready": result.Ready, "recoveryRequired": result.RecoveryRequired, "taskFenceToken": result.TaskFenceToken})
	s.appendOutboxLocked("virtualCluster", v.ID, "virtual_cluster.state.changed", v)
	return cloneVirtualCluster(v), nil
}
