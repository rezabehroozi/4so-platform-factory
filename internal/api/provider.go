package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

const providerAdapter = "cluster-api-topology-v1beta2"
const providerNamespace = "4so-provider-system"

type createProviderProfileInput struct {
	ProjectID                string   `json:"projectId"`
	ManagementClusterID      string   `json:"managementClusterId"`
	Name                     string   `json:"name"`
	DisplayName              string   `json:"displayName"`
	ClusterClassName         string   `json:"clusterClassName"`
	WorkerClassName          string   `json:"workerClassName"`
	DefaultKubernetesVersion string   `json:"defaultKubernetesVersion"`
	KubernetesSeries         []string `json:"kubernetesSeries"`
	Architectures            []string `json:"architectures"`
	DistributionProfiles     []string `json:"distributionProfiles"`
	InfrastructureProvider   string   `json:"infrastructureProvider,omitempty"`
	InfrastructureEndpoint   string   `json:"infrastructureEndpoint,omitempty"`
	CredentialRef            string   `json:"credentialRef,omitempty"`
	MaxWorkerReplicas        int      `json:"maxWorkerReplicas"`
}

type createProviderClusterInput struct {
	ProjectID            string `json:"projectId"`
	ProviderProfileID    string `json:"providerProfileId"`
	Name                 string `json:"name"`
	DisplayName          string `json:"displayName"`
	KubernetesVersion    string `json:"kubernetesVersion"`
	Architecture         string `json:"architecture"`
	Distribution         string `json:"distribution,omitempty"`
	DistributionIdentity string `json:"distributionIdentity,omitempty"`
	ControlPlaneReplicas int    `json:"controlPlaneReplicas"`
	WorkerReplicas       int    `json:"workerReplicas"`
}

type scaleProviderClusterInput struct {
	ControlPlaneReplicas int `json:"controlPlaneReplicas"`
	WorkerReplicas       int `json:"workerReplicas"`
}

type upgradeProviderClusterInput struct {
	KubernetesVersion string `json:"kubernetesVersion"`
}

func requireIdempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required")
		return "", false
	}
	return key, true
}

func (s *Server) createProviderProfile(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	if err = requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", err.Error())
		return
	}
	key, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var in createProviderProfileInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	profile := controlplane.ProviderProfile{
		ProjectID: in.ProjectID, ManagementClusterID: in.ManagementClusterID, Name: in.Name, DisplayName: in.DisplayName,
		Adapter: providerAdapter, Namespace: providerNamespace, ClusterClassName: in.ClusterClassName, WorkerClassName: in.WorkerClassName,
		DefaultKubernetesVersion: in.DefaultKubernetesVersion, KubernetesSeries: in.KubernetesSeries, Architectures: in.Architectures, DistributionProfiles: in.DistributionProfiles, InfrastructureProvider: in.InfrastructureProvider, InfrastructureEndpoint: in.InfrastructureEndpoint, CredentialRef: in.CredentialRef, MaxWorkerReplicas: in.MaxWorkerReplicas,
		IdempotencyKey: key, RequestDigest: digestValue(in),
	}
	dummy := controlplane.ProviderClusterSpec{}
	controlplane.NormalizeProviderCompatibility(&profile, &dummy)
	profile.DesiredDigest = digestValue(map[string]any{
		"adapter": profile.Adapter, "namespace": profile.Namespace,
		"clusterClassName": profile.ClusterClassName, "workerClassName": profile.WorkerClassName,
		"defaultKubernetesVersion": profile.DefaultKubernetesVersion, "kubernetesSeries": profile.KubernetesSeries,
		"architectures": profile.Architectures, "distributionProfiles": profile.DistributionProfiles, "infrastructureProvider": profile.InfrastructureProvider, "infrastructureEndpoint": profile.InfrastructureEndpoint, "credentialRef": profile.CredentialRef, "maxWorkerReplicas": profile.MaxWorkerReplicas,
	})
	v, replay, err := s.store.CreateProviderProfile(r.Context(), profile, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"providerProfile": v, "idempotentReplay": replay, "next": "agent-verification"})
}

func (s *Server) listProviderProfiles(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("managementClusterId"))
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.ProviderProfile, error)
	if pager, ok := s.store.(providerProfilePageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ProviderProfile, error) {
			return pager.ListProviderProfilesPage(r.Context(), ids, all, clusterID, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.ProviderProfile, error) {
		return s.store.ListProviderProfiles(r.Context(), projectID, clusterID)
	}, page, func(item controlplane.ProviderProfile) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}

func (s *Server) getProviderProfile(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetProviderProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) retryProviderProfile(w http.ResponseWriter, r *http.Request) {
	current, lookupErr := s.store.GetProviderProfile(r.Context(), r.PathValue("id"))
	if lookupErr != nil {
		writeStoreError(w, lookupErr)
		return
	}
	if _, lookupErr = s.requireProjectAccess(r, current.ProjectID, organizationWrite); lookupErr != nil {
		writeScopeError(w, lookupErr)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	if err = requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RetryProviderProfile(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createProviderCluster(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var in createProviderClusterInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	profile, err := s.store.GetProviderProfile(r.Context(), in.ProviderProfileID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	spec := controlplane.ProviderClusterSpec{KubernetesVersion: in.KubernetesVersion, Architecture: in.Architecture, Distribution: in.Distribution, DistributionIdentity: in.DistributionIdentity, ControlPlaneReplicas: in.ControlPlaneReplicas, WorkerReplicas: in.WorkerReplicas}
	controlplane.NormalizeProviderCompatibility(&profile, &spec)
	desired := controlplane.ProviderClusterDesiredDigest(in.ProviderProfileID, in.Name, spec)
	v, replay, err := s.store.CreateProviderCluster(r.Context(), controlplane.ProviderCluster{
		ProjectID: in.ProjectID, ProviderProfileID: in.ProviderProfileID, Name: in.Name, DisplayName: in.DisplayName,
		Desired: spec, DesiredDigest: desired, IdempotencyKey: key, RequestDigest: digestValue(in),
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"providerCluster": v, "idempotentReplay": replay, "next": "approval"})
}

func (s *Server) listProviderClusters(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	profileID := strings.TrimSpace(r.URL.Query().Get("providerProfileId"))
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.ProviderCluster, error)
	if pager, ok := s.store.(providerClusterPageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ProviderCluster, error) {
			return pager.ListProviderClustersPage(r.Context(), ids, all, profileID, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.ProviderCluster, error) {
		return s.store.ListProviderClusters(r.Context(), projectID, profileID)
	}, page, func(item controlplane.ProviderCluster) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}

func (s *Server) getProviderCluster(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetProviderCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) approveProviderCluster(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetProviderCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := approvalActor(r, current.RequestedBy)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.ApproveProviderCluster(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) queueProviderClusterChange(w http.ResponseWriter, r *http.Request, action string) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	current, err := s.store.GetProviderCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	desired := current.Desired
	var request any
	recoveryCheckpointID := ""
	switch action {
	case "SCALE":
		var in scaleProviderClusterInput
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		desired.ControlPlaneReplicas, desired.WorkerReplicas = in.ControlPlaneReplicas, in.WorkerReplicas
		request = in
	case "UPGRADE":
		var in upgradeProviderClusterInput
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		desired.KubernetesVersion = in.KubernetesVersion
		request = in
	case "DELETE":
		if strings.TrimSpace(r.Header.Get("X-Confirm-Delete")) != "delete-provider-cluster" {
			writeError(w, http.StatusPreconditionRequired, "DELETE_CONFIRMATION_REQUIRED", "X-Confirm-Delete: delete-provider-cluster is required")
			return
		}
		var in destructiveRecoveryInput
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		if err = in.validate(); err != nil {
			writeError(w, http.StatusBadRequest, "RECOVERY_CHECKPOINT_REQUIRED", err.Error())
			return
		}
		recoveryCheckpointID = in.RecoveryCheckpointID
		request = map[string]string{"confirm": "delete-provider-cluster", "recoveryCheckpointId": in.RecoveryCheckpointID}
	default:
		writeError(w, http.StatusBadRequest, "ACTION_NOT_SUPPORTED", "unsupported provider cluster action")
		return
	}
	desiredDigest := current.DesiredDigest
	if action != "DELETE" {
		desiredDigest = controlplane.ProviderClusterDesiredDigest(current.ProviderProfileID, current.Name, desired)
	}
	v, err := s.store.QueueProviderClusterChange(r.Context(), current.ID, rev, action, desired, desiredDigest, actor, digestValue(request), recoveryCheckpointID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"providerCluster": v, "next": "approval"})
}

func (s *Server) scaleProviderCluster(w http.ResponseWriter, r *http.Request) {
	s.queueProviderClusterChange(w, r, "SCALE")
}
func (s *Server) upgradeProviderCluster(w http.ResponseWriter, r *http.Request) {
	s.queueProviderClusterChange(w, r, "UPGRADE")
}
func (s *Server) deleteProviderCluster(w http.ResponseWriter, r *http.Request) {
	s.queueProviderClusterChange(w, r, "DELETE")
}

func (s *Server) retryProviderCluster(w http.ResponseWriter, r *http.Request) {
	current, lookupErr := s.store.GetProviderCluster(r.Context(), r.PathValue("id"))
	if lookupErr != nil {
		writeStoreError(w, lookupErr)
		return
	}
	if _, lookupErr = s.requireProjectAccess(r, current.ProjectID, organizationWrite); lookupErr != nil {
		writeScopeError(w, lookupErr)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RetryProviderCluster(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) nextProviderProfileTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	v, err := s.store.NextProviderProfileTask(r.Context(), r.PathValue("id"), agentDigest)
	if err != nil {
		if errors.Is(err, controlplane.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, controlplane.ProviderProfileTask{ProfileID: v.ID, ProfileRevision: v.Revision, TaskFenceToken: v.TaskFenceToken, LeaseExpiresAt: *v.TaskLeaseExpiresAt, Namespace: v.Namespace, ClusterClassName: v.ClusterClassName, WorkerClassName: v.WorkerClassName, InfrastructureProvider: v.InfrastructureProvider})
}

func (s *Server) reportProviderProfileTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.ProviderProfileTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result.ProfileID = r.PathValue("profileId")
	v, err := s.store.ReportProviderProfileTask(r.Context(), r.PathValue("id"), agentDigest, rev, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func providerClusterObject(v controlplane.ProviderCluster, profile controlplane.ProviderProfile) map[string]any {
	labels := map[string]any{
		"platform.4so.io/managed": "true", "platform.4so.io/provider-cluster-id": v.ID,
		"platform.4so.io/project-id": v.ProjectID, "platform.4so.io/provider-profile-id": profile.ID,
	}
	annotations := map[string]any{"platform.4so.io/desired-digest": v.DesiredDigest, "platform.4so.io/pending-action": strings.ToLower(v.PendingAction)}
	return map[string]any{
		"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster",
		"metadata": map[string]any{"name": v.ResourceName, "namespace": v.Namespace, "labels": labels, "annotations": annotations},
		"spec": map[string]any{"topology": map[string]any{
			"classRef":     map[string]any{"name": profile.ClusterClassName, "namespace": profile.Namespace},
			"version":      v.Desired.KubernetesVersion,
			"controlPlane": map[string]any{"replicas": v.Desired.ControlPlaneReplicas},
			"workers":      map[string]any{"machineDeployments": []any{map[string]any{"class": profile.WorkerClassName, "name": "workers", "replicas": v.Desired.WorkerReplicas}}},
		}},
	}
}

func (s *Server) nextProviderClusterTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	v, profile, err := s.store.NextProviderClusterTask(r.Context(), r.PathValue("id"), agentDigest)
	if err != nil {
		if errors.Is(err, controlplane.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeStoreError(w, err)
		return
	}
	action := ""
	var resource map[string]any
	switch v.State {
	case controlplane.ProviderClusterApplying:
		action, resource = "APPLY", providerClusterObject(v, profile)
	case controlplane.ProviderClusterReconciling:
		action = "INSPECT"
	case controlplane.ProviderClusterDeleting:
		if v.Phase == "RecoveryInspectQueued" || v.TaskAttempt > 1 {
			action = "INSPECT_DELETE"
		} else {
			action = "DELETE"
		}
	default:
		writeError(w, http.StatusConflict, "PROVIDER_TASK_STATE_INVALID", fmt.Sprintf("provider cluster state %s has no task", v.State))
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, controlplane.ProviderClusterTask{ProviderClusterID: v.ID, ClusterRevision: v.Revision, TaskFenceToken: v.TaskFenceToken, LeaseExpiresAt: *v.TaskLeaseExpiresAt, Action: action, PendingAction: v.PendingAction, Namespace: v.Namespace, ResourceName: v.ResourceName, DesiredDigest: v.DesiredDigest, InfrastructureProvider: profile.InfrastructureProvider, CredentialRef: profile.CredentialRef, Resource: resource, TargetNodeMutation: v.TargetNodeMutation})
}

func (s *Server) reportProviderClusterTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.ProviderClusterTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result.ProviderClusterID = r.PathValue("providerClusterId")
	v, err := s.store.ReportProviderClusterTask(r.Context(), r.PathValue("id"), agentDigest, rev, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
