package api

import (
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func (s *Server) targetNodeProviderBindingReady(r *http.Request, cluster controlplane.ManagedCluster) bool {
	id := strings.TrimSpace(cluster.ProviderClusterID)
	if id == "" {
		return false
	}
	provider, err := s.store.GetProviderCluster(r.Context(), id)
	return err == nil && provider.ProjectID == cluster.ProjectID && provider.State == controlplane.ProviderClusterActive
}

func (s *Server) targetNodeProviderMachineLifecycleReady(r *http.Request, cluster controlplane.ManagedCluster) bool {
	id := strings.TrimSpace(cluster.ProviderClusterID)
	if id == "" {
		return false
	}
	provider, err := s.store.GetProviderCluster(r.Context(), id)
	if err != nil || provider.ProjectID != cluster.ProjectID || provider.State != controlplane.ProviderClusterActive {
		return false
	}
	inv, err := s.store.GetLatestClusterInventory(r.Context(), provider.ManagementClusterID)
	if err != nil {
		return false
	}
	for _, capability := range inv.Capabilities {
		if strings.EqualFold(strings.TrimSpace(capability), controlplane.TargetNodeProviderMachineLifecycleCapability) {
			return true
		}
	}
	return false
}

func (s *Server) getTargetNodeLifecycleAuthority(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, controlplane.BuildTargetNodeLifecycleAuthority(cluster, inventory, s.targetNodeProviderBindingReady(r, cluster), s.targetNodeProviderMachineLifecycleReady(r, cluster)))
}

func (s *Server) planTargetNodeLifecycle(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var in controlplane.TargetNodeLifecyclePlanRequest
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	plan, err := controlplane.BuildTargetNodeLifecyclePlan(cluster, inventory, in, s.targetNodeProviderBindingReady(r, cluster), s.targetNodeProviderMachineLifecycleReady(r, cluster))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

type bindTargetProviderInput struct {
	ProviderClusterID string `json:"providerClusterId"`
}

type executeTargetNodeLifecycleInput struct {
	Action   controlplane.TargetNodeLifecycleAction `json:"action"`
	NodeName string                                 `json:"nodeName,omitempty"`
	WindowID string                                 `json:"windowId,omitempty"`
}

func (s *Server) bindTargetNodeProvider(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	if err = requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", err.Error())
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
	var in bindTargetProviderInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if in.ProviderClusterID == "" {
		writeError(w, http.StatusBadRequest, "PROVIDER_CLUSTER_REQUIRED", "providerClusterId is required")
		return
	}
	bound, err := s.store.BindManagedClusterProvider(r.Context(), cluster.ID, rev, in.ProviderClusterID, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, bound.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"cluster": bound, "authority": controlplane.TargetNodeProviderBindingAuthority})
}

func (s *Server) executeTargetNodeLifecycleAction(w http.ResponseWriter, r *http.Request) {
	cluster, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var in executeTargetNodeLifecycleInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	action := controlplane.TargetNodeLifecycleAction(strings.ToUpper(strings.TrimSpace(string(in.Action))))
	if action != controlplane.TargetNodeActionAdd && action != controlplane.TargetNodeActionRemove && action != controlplane.TargetNodeActionReplace && action != controlplane.TargetNodeActionCertificateRenewal && action != controlplane.TargetNodeActionRemediate {
		writeError(w, http.StatusBadRequest, "ACTION_NOT_SUPPORTED", "provider-backed lifecycle endpoint supports ADD, REMOVE, REPLACE, CERTIFICATE_RENEWAL and REMEDIATE")
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if strings.TrimSpace(cluster.ProviderClusterID) == "" {
		writeError(w, http.StatusPreconditionFailed, "TARGET_PROVIDER_BINDING_REQUIRED", "target cluster has no authoritative provider binding")
		return
	}
	provider, err := s.store.GetProviderCluster(r.Context(), cluster.ProviderClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	providerBound := provider.ProjectID == cluster.ProjectID && provider.State == controlplane.ProviderClusterActive
	machineReady := s.targetNodeProviderMachineLifecycleReady(r, cluster)
	planReq := controlplane.TargetNodeLifecyclePlanRequest{Action: action, NodeName: strings.TrimSpace(in.NodeName)}
	plan, planErr := controlplane.BuildTargetNodeLifecyclePlan(cluster, inventory, planReq, providerBound, machineReady)
	// ADD preserves the existing replay semantics even while the provider is no longer ACTIVE.
	if action == controlplane.TargetNodeActionAdd {
		requestDigest := digestValue(map[string]any{"authority": controlplane.TargetNodeProviderBindingAuthority, "clusterId": cluster.ID, "providerClusterId": provider.ID, "inventoryDigest": inventory.Digest, "action": action, "idempotencyKey": key})
		if provider.RequestDigest == requestDigest {
			next := "provider-cluster-execution"
			if provider.State == controlplane.ProviderClusterAwaitingApproval {
				next = "provider-cluster-approval"
			} else if provider.State == controlplane.ProviderClusterActive {
				next = "completed"
			}
			setRevisionETag(w, provider.Revision)
			writeJSON(w, http.StatusOK, map[string]any{"providerCluster": provider, "plan": plan, "idempotentReplay": true, "next": next})
			return
		}
		if planErr != nil {
			writeStoreError(w, planErr)
			return
		}
		if !plan.Executable {
			writeError(w, http.StatusPreconditionFailed, "TARGET_NODE_LIFECYCLE_BLOCKED", strings.Join(plan.Blockers, "; "))
			return
		}
		if provider.State != controlplane.ProviderClusterActive {
			writeError(w, http.StatusConflict, "PROVIDER_CLUSTER_NOT_ACTIVE", "bound provider cluster must be ACTIVE before ADD can be requested")
			return
		}
		desired := provider.Desired
		desired.WorkerReplicas++
		desiredDigest := controlplane.ProviderClusterDesiredDigest(provider.ProviderProfileID, provider.Name, desired)
		provider, err = s.store.QueueProviderClusterChange(r.Context(), provider.ID, provider.Revision, "SCALE", desired, desiredDigest, actor, requestDigest, "")
		if err != nil {
			writeStoreError(w, err)
			return
		}
		setRevisionETag(w, provider.Revision)
		writeJSON(w, http.StatusAccepted, map[string]any{"providerCluster": provider, "plan": plan, "idempotentReplay": false, "next": "provider-cluster-approval"})
		return
	}
	if strings.TrimSpace(in.WindowID) == "" {
		writeError(w, http.StatusBadRequest, "MAINTENANCE_WINDOW_REQUIRED", "windowId is required for destructive provider-backed node lifecycle actions")
		return
	}
	window, err := s.store.GetClusterMaintenanceWindow(r.Context(), strings.TrimSpace(in.WindowID))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	if window.ClusterID != cluster.ID || window.State != controlplane.ClusterMaintenanceWindowActive || now.Before(window.StartsAt) || !window.EndsAt.After(now) {
		writeError(w, http.StatusPreconditionFailed, "MAINTENANCE_WINDOW_NOT_ACTIVE", "provider-backed node mutation requires an active maintenance window")
		return
	}
	if planErr != nil {
		writeStoreError(w, planErr)
		return
	}
	requestDigest := digestValue(map[string]any{"authority": controlplane.TargetNodeProviderMachineLifecycleAuthority, "clusterId": cluster.ID, "providerClusterId": provider.ID, "inventoryDigest": inventory.Digest, "action": action, "nodeName": plan.NodeName, "nodeUid": plan.NodeUID, "windowId": window.ID, "windowEndsAt": window.EndsAt, "idempotencyKey": key})
	if provider.RequestDigest == requestDigest && (controlplane.IsTargetNodeProviderPendingAction(provider.PendingAction) || provider.State == controlplane.ProviderClusterActive) {
		next := "provider-cluster-execution"
		if provider.State == controlplane.ProviderClusterAwaitingApproval {
			next = "provider-cluster-approval"
		} else if provider.State == controlplane.ProviderClusterActive {
			next = "completed"
		}
		setRevisionETag(w, provider.Revision)
		writeJSON(w, http.StatusOK, map[string]any{"providerCluster": provider, "plan": plan, "idempotentReplay": true, "next": next})
		return
	}
	if !plan.Executable {
		writeError(w, http.StatusPreconditionFailed, "TARGET_NODE_LIFECYCLE_BLOCKED", strings.Join(append(plan.Blockers, "TARGET_PROVIDER_MACHINE_LIFECYCLE_CAPABILITY_REQUIRED"), "; "))
		return
	}
	if provider.State != controlplane.ProviderClusterActive {
		writeError(w, http.StatusConflict, "PROVIDER_CLUSTER_NOT_ACTIVE", "bound provider cluster must be ACTIVE before destructive target-node mutation")
		return
	}
	desired := provider.Desired
	if action == controlplane.TargetNodeActionRemove {
		if desired.WorkerReplicas <= 1 {
			writeError(w, http.StatusPreconditionFailed, "LAST_WORKER_REMOVE_FORBIDDEN", "REMOVE cannot reduce the provider topology below one worker")
			return
		}
		desired.WorkerReplicas--
	}
	mutation := controlplane.TargetNodeProviderMutation{Authority: controlplane.TargetNodeProviderMachineLifecycleAuthority, Action: action, TargetClusterID: cluster.ID, NodeName: plan.NodeName, NodeUID: plan.NodeUID, InventoryDigest: inventory.Digest, WindowID: window.ID, WindowEndsAt: window.EndsAt}
	provider, err = s.store.QueueTargetNodeProviderMutation(r.Context(), provider.ID, provider.Revision, mutation, desired, actor, requestDigest)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, provider.Revision)
	writeJSON(w, http.StatusAccepted, map[string]any{"providerCluster": provider, "plan": plan, "mutation": mutation, "idempotentReplay": false, "next": "provider-cluster-approval"})
}
