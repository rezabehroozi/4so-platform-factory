package controlplane

import (
	"context"
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
	LastError          string               `json:"lastError,omitempty"`
}

type VirtualClusterCreateRequest struct {
	WorkspaceID       string                 `json:"workspaceId"`
	WorkspaceBindingID string                `json:"workspaceBindingId"`
	Spec              virtualcluster.Request `json:"spec"`
	IdempotencyKey    string                 `json:"idempotencyKey"`
	RequestDigest     string                 `json:"requestDigest"`
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
	authority, err := virtualClusterWorkspaceAuthority(workspace, binding)
	if err != nil {
		return err
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
