package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	daprruntime "platform.4so.io/factory/internal/dapr"
	"platform.4so.io/factory/internal/targetmodel"
)

const (
	daprLifecycleOperationKind = "dapr.runtime.lifecycle"
	daprLifecycleTargetPrefix  = "dapr:"
	daprLifecycleLease         = 30 * time.Minute
	daprRecoveryEvidenceKind   = "dapr-runtime-recovery-confirmed"
)

type daprLifecycleInput struct {
	ProjectID                  string                      `json:"projectId"`
	ClusterID                  string                      `json:"clusterId"`
	Action                     daprruntime.LifecycleAction `json:"action"`
	ExpectedObservedLockDigest string                      `json:"expectedObservedLockDigest,omitempty"`
	Disconnected               bool                        `json:"disconnected,omitempty"`
}

type daprLifecycleTask struct {
	OperationID       string                       `json:"operationId"`
	OperationRevision int64                        `json:"operationRevision"`
	TaskFenceToken    int64                        `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                    `json:"leaseExpiresAt"`
	Request           daprruntime.LifecycleRequest `json:"request"`
	RuntimeLock       daprruntime.RuntimeLock       `json:"runtimeLock"`
}

type daprLifecycleResult struct {
	TaskFenceToken          int64                                  `json:"taskFenceToken"`
	Success                 bool                                   `json:"success"`
	RecoveryRequired        bool                                   `json:"recoveryRequired,omitempty"`
	Installed               bool                                   `json:"installed"`
	ObservedLockDigest      string                                 `json:"observedLockDigest,omitempty"`
	Version                 string                                 `json:"version,omitempty"`
	UpstreamCommit          string                                 `json:"upstreamCommit,omitempty"`
	MirrorPullEvidence      *daprruntime.TargetMirrorPullEvidence `json:"mirrorPullEvidence,omitempty"`
	MirrorPullEvidenceDigest string                                `json:"mirrorPullEvidenceDigest,omitempty"`
	Phase                   string                                 `json:"phase,omitempty"`
	Error                   string                                 `json:"error,omitempty"`
}

type daprLifecycleOperationPager interface {
	ListClaimableOperationsByKindTargetPrefix(context.Context, string, string, time.Time, int) ([]controlplane.Operation, error)
}

type daprRecoveryOperationPager interface {
	ListUnknownRecoveryOperationsByKindTargetPrefix(context.Context, string, string, int) ([]controlplane.Operation, error)
}

const daprRecoveryReadbackAuthority = "DAPR_TARGET_RECOVERY_READBACK_V1"

type daprRecoveryTask struct {
	OperationID       string                       `json:"operationId"`
	OperationRevision int64                        `json:"operationRevision"`
	TaskFenceToken    int64                        `json:"taskFenceToken"`
	Request           daprruntime.LifecycleRequest `json:"request"`
	RuntimeLock       daprruntime.RuntimeLock       `json:"runtimeLock"`
}

type daprRecoveryResult struct {
	ConfirmedSuccess        bool                                   `json:"confirmedSuccess"`
	Installed               bool                                   `json:"installed"`
	ObservedLockDigest      string                                 `json:"observedLockDigest,omitempty"`
	Version                 string                                 `json:"version,omitempty"`
	UpstreamCommit          string                                 `json:"upstreamCommit,omitempty"`
	MirrorPullEvidence      *daprruntime.TargetMirrorPullEvidence `json:"mirrorPullEvidence,omitempty"`
	MirrorPullEvidenceDigest string                                `json:"mirrorPullEvidenceDigest,omitempty"`
	Phase                   string                                 `json:"phase,omitempty"`
	Error                   string                                 `json:"error,omitempty"`
}

type daprRecoveryReadback struct {
	Authority                string                                 `json:"authority"`
	OperationID              string                                 `json:"operationId"`
	ClusterID                string                                 `json:"clusterId"`
	TaskFenceToken           int64                                  `json:"taskFenceToken"`
	Action                   daprruntime.LifecycleAction            `json:"action"`
	ConfirmedSuccess         bool                                   `json:"confirmedSuccess"`
	Installed                bool                                   `json:"installed"`
	ObservedLockDigest       string                                 `json:"observedLockDigest,omitempty"`
	Version                  string                                 `json:"version,omitempty"`
	UpstreamCommit           string                                 `json:"upstreamCommit,omitempty"`
	MirrorPullEvidence       *daprruntime.TargetMirrorPullEvidence `json:"mirrorPullEvidence,omitempty"`
	MirrorPullEvidenceDigest string                                 `json:"mirrorPullEvidenceDigest,omitempty"`
	Phase                    string                                 `json:"phase"`
}

func daprLifecycleTarget(clusterID string, action daprruntime.LifecycleAction) string {
	return daprLifecycleTargetPrefix + strings.TrimSpace(clusterID) + ":" + strings.ToLower(string(action))
}

func parseDaprLifecycleTarget(target string) (string, daprruntime.LifecycleAction, error) {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, daprLifecycleTargetPrefix) {
		return "", "", fmt.Errorf("%w: Dapr lifecycle target is invalid", controlplane.ErrValidation)
	}
	rest := strings.TrimPrefix(target, daprLifecycleTargetPrefix)
	index := strings.LastIndexByte(rest, ':')
	if index <= 0 {
		return "", "", fmt.Errorf("%w: Dapr lifecycle target is invalid", controlplane.ErrValidation)
	}
	action, err := daprruntime.NormalizeLifecycleAction(daprruntime.LifecycleAction(rest[index+1:]))
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", controlplane.ErrValidation, err)
	}
	return strings.TrimSpace(rest[:index]), action, nil
}

func (s *Server) daprAdmissionForCluster(cluster controlplane.ManagedCluster, inventory controlplane.ClusterInventory, disconnected bool) targetmodel.DaprTargetAdmission {
	return targetmodel.EvaluateDaprTargetAdmission(targetmodel.DaprTargetAdmissionInput{
		DistributionIdentity:        inventory.Distribution,
		TargetAdmitted:              controlplane.ClusterTaskAdmitted(cluster),
		TargetMutationReady:         openChoreoInventoryCapability(inventory, controlplane.TargetMutationRBACActiveCapability),
		ExecutorRBACReady:           openChoreoInventoryCapability(inventory, controlplane.DaprExecutorRBACCapability),
		CapabilityDiscoveryComplete: inventory.APIDiscoveryComplete && inventory.CRDDiscoveryComplete && inventory.SchemaDiscoveryComplete,
		ObservedCapabilities:        inventory.Capabilities,
		ExactSourceAdmitted:         s.daprRuntimeReady,
		Disconnected:                disconnected,
		DisconnectedProductMirrorAdmitted:  s.daprRuntimeReady,
		DurableLifecycleReady:       true,
	})
}

func (s *Server) latestDaprObserved(ctx context.Context, projectID, clusterID string) (*daprruntime.ObservedState, error) {
	operations, err := s.store.ListOperations(ctx, projectID)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(operations, func(i, j int) bool {
		if operations[i].UpdatedAt.Equal(operations[j].UpdatedAt) {
			return operations[i].ID > operations[j].ID
		}
		return operations[i].UpdatedAt.After(operations[j].UpdatedAt)
	})
	for _, op := range operations {
		if op.Kind != daprLifecycleOperationKind || op.State != controlplane.OperationSucceeded {
			continue
		}
		targetCluster, _, parseErr := parseDaprLifecycleTarget(op.TargetRef)
		if parseErr != nil || targetCluster != clusterID {
			continue
		}
		evidence, listErr := s.store.ListEvidence(ctx, op.ID)
		if listErr != nil {
			return nil, listErr
		}
		sort.SliceStable(evidence, func(i, j int) bool { return evidence[i].CreatedAt.After(evidence[j].CreatedAt) })
		for _, ev := range evidence {
			if ev.Kind != daprruntime.ObservedEvidenceKind || !ev.HasPayload {
				continue
			}
			_, payload, getErr := s.store.GetEvidencePayload(ctx, ev.ID)
			if getErr != nil {
				return nil, getErr
			}
			var observed daprruntime.ObservedState
			if json.Unmarshal(payload, &observed) != nil || observed.Authority != daprruntime.LifecycleAuthority || observed.ClusterID != clusterID {
				return nil, fmt.Errorf("%w: invalid Dapr observed evidence", controlplane.ErrConflict)
			}
			return &observed, nil
		}
		if strings.TrimSpace(op.RecoveryEvidenceDigest) != "" {
			for _, ev := range evidence {
				if ev.Kind != daprRecoveryEvidenceKind || ev.Digest != op.RecoveryEvidenceDigest || !ev.HasPayload || !ev.Sealed {
					continue
				}
				_, payload, getErr := s.store.GetEvidencePayload(ctx, ev.ID)
				if getErr != nil {
					return nil, getErr
				}
				var recovered daprRecoveryReadback
				decoder := json.NewDecoder(strings.NewReader(string(payload)))
				decoder.DisallowUnknownFields()
				if decodeErr := decoder.Decode(&recovered); decodeErr != nil || recovered.Authority != daprRecoveryReadbackAuthority ||
					recovered.OperationID != op.ID || recovered.ClusterID != clusterID || !recovered.ConfirmedSuccess {
					return nil, fmt.Errorf("%w: invalid sealed Dapr recovery readback", controlplane.ErrConflict)
				}
				return &daprruntime.ObservedState{
					Authority: daprruntime.LifecycleAuthority,
					OperationID: op.ID,
					ClusterID: clusterID,
					Action: recovered.Action,
					Installed: recovered.Installed,
					RuntimeLockDigest: recovered.ObservedLockDigest,
					Version: recovered.Version,
					UpstreamCommit: recovered.UpstreamCommit,
					MirrorPullEvidence: recovered.MirrorPullEvidence,
					MirrorPullEvidenceDigest: recovered.MirrorPullEvidenceDigest,
					ObservedAt: op.UpdatedAt.UTC().Format(time.RFC3339Nano),
					Phase: "RecoveredConfirmedSuccess",
				}, nil
			}
			return nil, fmt.Errorf("%w: recovered Dapr operation is missing its sealed recovery payload", controlplane.ErrConflict)
		}
	}
	return nil, nil
}

func daprLifecycleStateBlocksNewMutation(op controlplane.Operation) bool {
	switch op.State {
	case controlplane.OperationDraft, controlplane.OperationPlanning, controlplane.OperationAwaitingApproval,
		controlplane.OperationApproved, controlplane.OperationQueued, controlplane.OperationRunning,
		controlplane.OperationRetryWait, controlplane.OperationCancelRequested, controlplane.OperationVerifying,
		controlplane.OperationRollingBack, controlplane.OperationNeedsOperator, controlplane.OperationRollbackFailed:
		return true
	case controlplane.OperationFailed:
		return op.LastFailureClass == controlplane.OperationFailureUnknown
	default:
		return false
	}
}

func (s *Server) daprLifecycleClusterBlocker(ctx context.Context, projectID, clusterID, idempotencyKey string) (*controlplane.Operation, error) {
	operations, err := s.store.ListOperations(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for i := range operations {
		op := operations[i]
		if op.Kind != daprLifecycleOperationKind || strings.TrimSpace(op.IdempotencyKey) == strings.TrimSpace(idempotencyKey) {
			continue
		}
		targetCluster, _, parseErr := parseDaprLifecycleTarget(op.TargetRef)
		if parseErr != nil || targetCluster != clusterID {
			continue
		}
		if daprLifecycleStateBlocksNewMutation(op) {
			return &op, nil
		}
	}
	return nil, nil
}

func (s *Server) createDaprLifecycle(w http.ResponseWriter, r *http.Request) {
	if !s.daprRuntimeReady {
		writeError(w, http.StatusServiceUnavailable, "DAPR_RUNTIME_SOURCE_NOT_READY", "exact Dapr runtime lock is not configured")
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, err := requiredIdempotencyKey(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", err.Error())
		return
	}
	var input daprLifecycleInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.ClusterID = strings.TrimSpace(input.ClusterID)
	input.ExpectedObservedLockDigest = strings.ToLower(strings.TrimSpace(input.ExpectedObservedLockDigest))
	action, err := daprruntime.NormalizeLifecycleAction(input.Action)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_LIFECYCLE_ACTION_INVALID", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, input.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), input.ClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if cluster.ProjectID != input.ProjectID {
		writeError(w, http.StatusForbidden, "SCOPE_FORBIDDEN", "cluster is outside requested project")
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) {
		writeError(w, http.StatusConflict, "INVENTORY_STALE", "fresh target capability discovery is required")
		return
	}
	admission := s.daprAdmissionForCluster(cluster, inventory, input.Disconnected)
	if admission.Mode == "USE_NATIVE" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": map[string]any{"code": "DAPR_NATIVE_RUNTIME_NOT_PRODUCT_MANAGED", "message": "target-native Dapr is consumed but not mutated by the product lifecycle"},
			"admission": admission,
		})
		return
	}
	if !admission.Eligible {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": map[string]any{"code": "DAPR_TARGET_NOT_ADMITTED", "message": "target is not eligible for product-managed Dapr lifecycle"},
			"admission": admission,
		})
		return
	}
	blocker, err := s.daprLifecycleClusterBlocker(r.Context(), input.ProjectID, input.ClusterID, key)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if blocker != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": map[string]any{
				"code": "DAPR_LIFECYCLE_RECOVERY_OR_OPERATION_PENDING",
				"message": "an existing Dapr lifecycle operation must converge or be operator-resolved before another mutation",
			},
			"blockingOperationId": blocker.ID,
			"blockingOperationState": blocker.State,
			"physicalCertificationInferred": false,
		})
		return
	}
	lockDigest := s.daprRuntimeDigest
	observed, err := s.latestDaprObserved(r.Context(), input.ProjectID, input.ClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if input.ExpectedObservedLockDigest != "" && (observed == nil || !strings.EqualFold(observed.RuntimeLockDigest, input.ExpectedObservedLockDigest)) {
		writeError(w, http.StatusConflict, "DAPR_OBSERVED_FENCE_CHANGED", "observed Dapr runtime lock changed after request preparation")
		return
	}
	if err = daprruntime.ValidateLifecycleTransition(action, observed, lockDigest); err != nil {
		writeError(w, http.StatusConflict, "DAPR_LIFECYCLE_TRANSITION_REJECTED", err.Error())
		return
	}
	req := daprruntime.LifecycleRequest{
		ProjectID: input.ProjectID,
		ClusterID: input.ClusterID,
		Action: action,
		RuntimeLockDigest: lockDigest,
		RuntimeVersion: s.daprRuntimeLock.Version,
		UpstreamCommit: s.daprRuntimeLock.UpstreamCommit,
		Disconnected: input.Disconnected,
	}
	if observed != nil {
		req.ExpectedObservedLockDigest = observed.RuntimeLockDigest
	}
	payload, requestDigest, err := daprruntime.MarshalLifecycleRequest(req)
	if err != nil {
		writeStoreError(w, fmt.Errorf("%w: %v", controlplane.ErrValidation, err))
		return
	}
	op, replay, err := s.store.CreateOperationAwaitingApprovalWithPayload(r.Context(), controlplane.OperationRequest{
		ProjectID: input.ProjectID,
		Kind: daprLifecycleOperationKind,
		TargetRef: daprLifecycleTarget(input.ClusterID, action),
		DesiredRevision: requestDigest,
		Risk: "high",
		Class: controlplane.OperationClassMutating,
	}, key, actor, r.Header.Get("X-Request-ID"), daprruntime.LifecyclePayloadMediaType, payload)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, status, map[string]any{
		"authority": daprruntime.LifecycleAuthority,
		"operation": op,
		"request": req,
		"admission": admission,
		"idempotentReplay": replay,
		"physicalCertificationInferred": false,
	})
}

func (s *Server) daprLifecycleOperation(r *http.Request) (controlplane.Operation, daprruntime.LifecycleRequest, error) {
	op, err := s.store.GetOperation(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		return controlplane.Operation{}, daprruntime.LifecycleRequest{}, err
	}
	if op.Kind != daprLifecycleOperationKind {
		return controlplane.Operation{}, daprruntime.LifecycleRequest{}, controlplane.ErrNotFound
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
		return controlplane.Operation{}, daprruntime.LifecycleRequest{}, err
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		return controlplane.Operation{}, daprruntime.LifecycleRequest{}, err
	}
	if sealed.MediaType != daprruntime.LifecyclePayloadMediaType {
		return controlplane.Operation{}, daprruntime.LifecycleRequest{}, controlplane.ErrConflict
	}
	req, err := daprruntime.ParseLifecycleRequest(sealed.Payload, sealed.PayloadDigest)
	return op, req, err
}

func (s *Server) getDaprLifecycle(w http.ResponseWriter, r *http.Request) {
	op, req, err := s.daprLifecycleOperation(r)
	if err != nil {
		if errors.Is(err, errOrganizationAccessDenied) {
			writeScopeError(w, err)
		} else {
			writeStoreError(w, err)
		}
		return
	}
	observed, err := s.latestDaprObserved(r.Context(), req.ProjectID, req.ClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": daprruntime.LifecycleAuthority,
		"operation": op,
		"request": req,
		"observed": observed,
		"physicalCertificationInferred": false,
	})
}

func (s *Server) approveDaprLifecycle(w http.ResponseWriter, r *http.Request) {
	op, req, err := s.daprLifecycleOperation(r)
	if err != nil {
		if errors.Is(err, errOrganizationAccessDenied) {
			writeScopeError(w, err)
		} else {
			writeStoreError(w, err)
		}
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	if !s.daprRuntimeReady || req.RuntimeLockDigest != s.daprRuntimeDigest {
		writeError(w, http.StatusConflict, "DAPR_RUNTIME_LOCK_FENCE_CHANGED", "configured exact Dapr runtime lock changed before approval")
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), req.ClusterID)
	if err != nil || cluster.ProjectID != req.ProjectID {
		if err == nil { err = controlplane.ErrNotFound }
		writeStoreError(w, err)
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) {
		writeError(w, http.StatusConflict, "INVENTORY_STALE", "fresh target capability discovery is required before Dapr approval")
		return
	}
	admission := s.daprAdmissionForCluster(cluster, inventory, req.Disconnected)
	if admission.Mode == "USE_NATIVE" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": map[string]any{"code": "DAPR_NATIVE_RUNTIME_NOT_PRODUCT_MANAGED", "message": "target-native Dapr appeared before approval; product lifecycle mutation is suppressed"},
			"admission": admission,
		})
		return
	}
	if !admission.Eligible {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": map[string]any{"code": "DAPR_TARGET_NOT_ADMITTED", "message": "current target admission changed before Dapr approval"},
			"admission": admission,
		})
		return
	}
	observed, err := s.latestDaprObserved(r.Context(), req.ProjectID, req.ClusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = daprruntime.ValidateLifecycleTransition(req.Action, observed, req.RuntimeLockDigest); err != nil {
		writeError(w, http.StatusConflict, "DAPR_LIFECYCLE_FENCE_CHANGED", err.Error())
		return
	}
	if req.ExpectedObservedLockDigest != "" && (observed == nil || observed.RuntimeLockDigest != req.ExpectedObservedLockDigest) {
		writeError(w, http.StatusConflict, "DAPR_OBSERVED_FENCE_CHANGED", "observed Dapr runtime changed before approval")
		return
	}
	op, err = s.store.ApproveOperationAndQueue(r.Context(), op.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusAccepted, map[string]any{"authority": daprruntime.LifecycleAuthority, "operation": op, "request": req})
}

func (s *Server) nextDaprLifecycleTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	if !s.daprRuntimeReady {
		writeError(w, http.StatusServiceUnavailable, "DAPR_RUNTIME_SOURCE_NOT_READY", "exact Dapr runtime is unavailable")
		return
	}
	cluster, clusterErr := s.store.GetManagedCluster(r.Context(), clusterID)
	if clusterErr != nil {
		writeStoreError(w, clusterErr)
		return
	}
	inventory, inventoryErr := s.store.GetLatestClusterInventory(r.Context(), clusterID)
	if inventoryErr != nil || !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) {
		// Do not claim a durable mutation while current target authority is stale.
		// The agent will refresh inventory and poll again without consuming the task.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	pager, ok := s.store.(daprLifecycleOperationPager)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "DAPR_LIFECYCLE_QUEUE_UNAVAILABLE", "bounded lifecycle operation queue is unavailable")
		return
	}
	jobs, err := pager.ListClaimableOperationsByKindTargetPrefix(r.Context(), daprLifecycleOperationKind, daprLifecycleTargetPrefix+clusterID+":", time.Now().UTC(), 4)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, candidate := range jobs {
		claim, claimErr := s.store.ClaimOperation(r.Context(), candidate.ID, "agent:"+clusterID, daprLifecycleLease, time.Now().UTC())
		if errors.Is(claimErr, controlplane.ErrLeaseHeld) || errors.Is(claimErr, controlplane.ErrNotClaimable) {
			continue
		}
		if claimErr != nil {
			writeStoreError(w, claimErr)
			return
		}
		op, err := s.store.GetOperation(r.Context(), candidate.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		req, parseErr := daprruntime.ParseLifecycleRequest(sealed.Payload, sealed.PayloadDigest)
		if parseErr == nil && req.ClusterID == clusterID && req.RuntimeLockDigest == s.daprRuntimeDigest {
			admission := s.daprAdmissionForCluster(cluster, inventory, req.Disconnected)
			if cluster.ProjectID != req.ProjectID || admission.Mode == "USE_NATIVE" || !admission.Eligible {
				if op.State == controlplane.OperationQueued {
					op, _ = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
				}
				if op.State == controlplane.OperationRunning {
					class := controlplane.OperationFailureDependencyUnavailable
					code := "DAPR_CURRENT_ADMISSION_BLOCKED"
					message := "current target capability/RBAC admission no longer permits Dapr lifecycle dispatch"
					if admission.Mode == "USE_NATIVE" || cluster.ProjectID != req.ProjectID {
						class = controlplane.OperationFailurePermanent
						code = "DAPR_NATIVE_OR_SCOPE_DRIFT"
						message = "target became native-Dapr managed or project scope changed before dispatch"
					}
					_, _ = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, controlplane.OperationFailureReport{
						Class: class, Code: code, Message: message,
					}, "agent:"+clusterID)
				}
				continue
			}
		}
		if parseErr != nil || req.ClusterID != clusterID || req.RuntimeLockDigest != s.daprRuntimeDigest {
			if op.State == controlplane.OperationQueued {
				op, _ = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
			}
			if op.State == controlplane.OperationRunning {
				_, _ = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, controlplane.OperationFailureReport{
					Class: controlplane.OperationFailurePermanent,
					Code: "DAPR_RUNTIME_LOCK_FENCE_CHANGED",
					Message: "sealed lifecycle request no longer matches configured exact Dapr runtime lock",
				}, "agent:"+clusterID)
			}
			continue
		}
		observed, observedErr := s.latestDaprObserved(r.Context(), req.ProjectID, req.ClusterID)
		if observedErr != nil {
			writeStoreError(w, observedErr)
			return
		}
		if fenceErr := daprruntime.ValidateLifecycleDispatchFence(req.Action, observed, req.RuntimeLockDigest, req.ExpectedObservedLockDigest); fenceErr != nil {
			if op.State == controlplane.OperationQueued {
				op, _ = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
			}
			if op.State == controlplane.OperationRunning {
				_, _ = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, controlplane.OperationFailureReport{
					Class: controlplane.OperationFailurePermanent,
					Code: "DAPR_DISPATCH_FENCE_CHANGED",
					Message: fenceErr.Error(),
				}, "agent:"+clusterID)
			}
			continue
		}
		op, err = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		setRevisionETag(w, op.Revision)
		writeJSON(w, http.StatusOK, daprLifecycleTask{
			OperationID: op.ID,
			OperationRevision: op.Revision,
			TaskFenceToken: claim.FenceToken,
			LeaseExpiresAt: claim.LeaseExpiresAt,
			Request: req,
			RuntimeLock: s.daprRuntimeLock,
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reportDaprLifecycleTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result daprLifecycleResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if result.TaskFenceToken <= 0 {
		writeError(w, http.StatusUnprocessableEntity, "FENCE_REQUIRED", "taskFenceToken is required")
		return
	}
	op, err := s.store.GetOperation(r.Context(), r.PathValue("operationId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != daprLifecycleOperationKind || op.Revision != rev {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	req, err := daprruntime.ParseLifecycleRequest(sealed.Payload, sealed.PayloadDigest)
	if err != nil || req.ClusterID != clusterID {
		writeError(w, http.StatusForbidden, "AGENT_SCOPE_MISMATCH", "Dapr lifecycle task belongs to another cluster")
		return
	}
	worker := "agent:" + clusterID
	if result.RecoveryRequired {
		payload, _ := json.Marshal(map[string]any{
			"authority": daprruntime.LifecycleAuthority,
			"clusterId": clusterID,
			"operationId": op.ID,
			"action": req.Action,
			"message": strings.TrimSpace(result.Error),
			"runtimeLockDigest": req.RuntimeLockDigest,
		})
		if _, appendErr := s.store.AppendOperationEvidencePayload(r.Context(), controlplane.EvidenceMetadata{
			OperationID: op.ID, Kind: daprruntime.RecoveryEvidenceKind, MediaType: "application/json",
		}, payload, worker, result.TaskFenceToken, worker); appendErr != nil {
			writeStoreError(w, appendErr)
			return
		}
		op, err = s.store.GetOperation(r.Context(), op.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "Dapr mutation outcome requires authoritative recovery readback"
		}
		op, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{
			Class: controlplane.OperationFailureUnknown,
			Code: "DAPR_RECOVERY_REQUIRED",
			Message: message,
		}, worker)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"operation": op, "recoveryRequired": true, "automaticRollback": false})
		return
	}
	if !result.Success {
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "Dapr lifecycle executor failed before successful observed readback"
		}
		op, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{
			Class: controlplane.OperationFailureDependencyUnavailable,
			Code: "DAPR_EXECUTION_FAILED",
			Message: message,
		}, worker)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"operation": op, "automaticRollback": false})
		return
	}
	wantInstalled := req.Action != daprruntime.ActionRemove
	if result.Installed != wantInstalled || strings.TrimSpace(result.Phase) == "" {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_OBSERVED_READBACK_INVALID", "terminal executor result must contain authoritative installed state and phase")
		return
	}
	if wantInstalled {
		if result.ObservedLockDigest != req.RuntimeLockDigest || result.Version != req.RuntimeVersion || result.UpstreamCommit != req.UpstreamCommit {
			writeError(w, http.StatusUnprocessableEntity, "DAPR_OBSERVED_LOCK_MISMATCH", "observed target Dapr runtime does not match sealed lifecycle authority")
			return
		}
		if !s.daprRuntimeReady || s.daprRuntimeDigest != req.RuntimeLockDigest {
			writeError(w, http.StatusConflict, "DAPR_RUNTIME_LOCK_FENCE_CHANGED", "configured exact Dapr runtime lock changed before target mirror-pull evidence admission")
			return
		}
		if result.MirrorPullEvidence == nil || strings.TrimSpace(result.MirrorPullEvidenceDigest) == "" {
			writeError(w, http.StatusUnprocessableEntity, "DAPR_TARGET_MIRROR_PULL_EVIDENCE_REQUIRED", "installed Dapr runtime must include exact target mirror-pull readback")
			return
		}
		if evidenceErr := daprruntime.ValidateTargetMirrorPullEvidence(
			*result.MirrorPullEvidence, s.daprRuntimeLock, clusterID, op.ID, result.TaskFenceToken, req.RuntimeLockDigest,
		); evidenceErr != nil {
			writeError(w, http.StatusUnprocessableEntity, "DAPR_TARGET_MIRROR_PULL_EVIDENCE_INVALID", evidenceErr.Error())
			return
		}
		evidenceDigest, evidenceErr := daprruntime.TargetMirrorPullEvidenceDigest(
			*result.MirrorPullEvidence, s.daprRuntimeLock, clusterID, op.ID, result.TaskFenceToken, req.RuntimeLockDigest,
		)
		if evidenceErr != nil || evidenceDigest != strings.ToLower(strings.TrimSpace(result.MirrorPullEvidenceDigest)) {
			writeError(w, http.StatusUnprocessableEntity, "DAPR_TARGET_MIRROR_PULL_EVIDENCE_DIGEST_MISMATCH", "target mirror-pull evidence digest does not match canonical readback")
			return
		}
		result.MirrorPullEvidenceDigest = evidenceDigest
	} else if result.MirrorPullEvidence != nil || strings.TrimSpace(result.MirrorPullEvidenceDigest) != "" {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_REMOVED_MIRROR_PULL_EVIDENCE_INVALID", "removed Dapr result must not retain installed mirror-pull evidence")
		return
	}
	observed := daprruntime.ObservedState{
		Authority: daprruntime.LifecycleAuthority,
		OperationID: op.ID,
		ClusterID: clusterID,
		Action: req.Action,
		Installed: result.Installed,
		RuntimeLockDigest: result.ObservedLockDigest,
		Version: result.Version,
		UpstreamCommit: result.UpstreamCommit,
		MirrorPullEvidence: result.MirrorPullEvidence,
		MirrorPullEvidenceDigest: result.MirrorPullEvidenceDigest,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Phase: strings.TrimSpace(result.Phase),
	}
	payload, _ := json.Marshal(observed)
	if _, err = s.store.AppendOperationEvidencePayload(r.Context(), controlplane.EvidenceMetadata{
		OperationID: op.ID, Kind: daprruntime.ObservedEvidenceKind, MediaType: "application/json",
	}, payload, worker, result.TaskFenceToken, worker); err != nil {
		writeStoreError(w, err)
		return
	}
	op, err = s.store.GetOperation(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	op, err = s.store.BeginOperationVerification(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, worker)
	if err == nil {
		op, err = s.store.CompleteOperation(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, worker)
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"operation": op,
		"observed": observed,
		"automaticRollback": false,
		"physicalCertificationInferred": false,
	})
}


func (s *Server) nextDaprRecoveryTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	pager, ok := s.store.(daprRecoveryOperationPager)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "DAPR_RECOVERY_QUEUE_UNAVAILABLE", "bounded Dapr recovery queue is unavailable")
		return
	}
	operations, err := pager.ListUnknownRecoveryOperationsByKindTargetPrefix(r.Context(), daprLifecycleOperationKind, daprLifecycleTargetPrefix+clusterID+":", 8)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, op := range operations {
		sealed, getErr := s.store.GetOperationRequestPayload(r.Context(), op.ID)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		req, parseErr := daprruntime.ParseLifecycleRequest(sealed.Payload, sealed.PayloadDigest)
		if parseErr != nil || req.ClusterID != clusterID {
			continue
		}
		if !s.daprRuntimeReady || req.RuntimeLockDigest != s.daprRuntimeDigest {
			// Unknown-outcome recovery may only re-attest the exact runtime lock
			// originally dispatched. A later product lock must never reinterpret
			// older target state as a confirmed success.
			continue
		}
		setRevisionETag(w, op.Revision)
		writeJSON(w, http.StatusOK, daprRecoveryTask{
			OperationID: op.ID,
			OperationRevision: op.Revision,
			TaskFenceToken: op.FenceToken,
			Request: req,
			RuntimeLock: s.daprRuntimeLock,
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func canonicalDaprRecoveryReadback(task daprRecoveryTask, result daprRecoveryResult) (daprRecoveryReadback, []byte, string, error) {
	if task.OperationID == "" || task.TaskFenceToken <= 0 || task.Request.ClusterID == "" {
		return daprRecoveryReadback{}, nil, "", fmt.Errorf("DAPR_RECOVERY_TASK_INVALID")
	}
	if !result.ConfirmedSuccess {
		return daprRecoveryReadback{}, nil, "", fmt.Errorf("DAPR_RECOVERY_NOT_CONFIRMED")
	}
	wantInstalled := task.Request.Action != daprruntime.ActionRemove
	phase := strings.TrimSpace(result.Phase)
	if result.Installed != wantInstalled || phase == "" {
		return daprRecoveryReadback{}, nil, "", fmt.Errorf("DAPR_RECOVERY_READBACK_INVALID")
	}
	lockDigest := strings.ToLower(strings.TrimSpace(result.ObservedLockDigest))
	version := strings.TrimSpace(result.Version)
	commit := strings.ToLower(strings.TrimSpace(result.UpstreamCommit))
	if wantInstalled && (lockDigest != task.Request.RuntimeLockDigest || version != task.Request.RuntimeVersion || commit != task.Request.UpstreamCommit) {
		return daprRecoveryReadback{}, nil, "", fmt.Errorf("DAPR_RECOVERY_RUNTIME_IDENTITY_MISMATCH")
	}
	if wantInstalled {
		if result.MirrorPullEvidence == nil || strings.TrimSpace(result.MirrorPullEvidenceDigest) == "" {
			return daprRecoveryReadback{}, nil, "", fmt.Errorf("DAPR_RECOVERY_TARGET_MIRROR_PULL_EVIDENCE_REQUIRED")
		}
		if err := daprruntime.ValidateTargetMirrorPullEvidence(
			*result.MirrorPullEvidence, task.RuntimeLock, task.Request.ClusterID, task.OperationID,
			task.TaskFenceToken, task.Request.RuntimeLockDigest,
		); err != nil {
			return daprRecoveryReadback{}, nil, "", fmt.Errorf("DAPR_RECOVERY_TARGET_MIRROR_PULL_EVIDENCE_INVALID: %w", err)
		}
		digest, err := daprruntime.TargetMirrorPullEvidenceDigest(
			*result.MirrorPullEvidence, task.RuntimeLock, task.Request.ClusterID, task.OperationID,
			task.TaskFenceToken, task.Request.RuntimeLockDigest,
		)
		if err != nil || digest != strings.ToLower(strings.TrimSpace(result.MirrorPullEvidenceDigest)) {
			return daprRecoveryReadback{}, nil, "", fmt.Errorf("DAPR_RECOVERY_TARGET_MIRROR_PULL_EVIDENCE_DIGEST_MISMATCH")
		}
		result.MirrorPullEvidenceDigest = digest
	}
	if !wantInstalled && (lockDigest != "" || version != "" || commit != "" || result.MirrorPullEvidence != nil || strings.TrimSpace(result.MirrorPullEvidenceDigest) != "") {
		return daprRecoveryReadback{}, nil, "", fmt.Errorf("DAPR_RECOVERY_REMOVED_IDENTITY_INVALID")
	}
	readback := daprRecoveryReadback{
		Authority: daprRecoveryReadbackAuthority,
		OperationID: task.OperationID,
		ClusterID: task.Request.ClusterID,
		TaskFenceToken: task.TaskFenceToken,
		Action: task.Request.Action,
		ConfirmedSuccess: true,
		Installed: result.Installed,
		ObservedLockDigest: lockDigest,
		Version: version,
		UpstreamCommit: commit,
		MirrorPullEvidence: result.MirrorPullEvidence,
		MirrorPullEvidenceDigest: result.MirrorPullEvidenceDigest,
		Phase: phase,
	}
	raw, err := json.Marshal(readback)
	if err != nil {
		return daprRecoveryReadback{}, nil, "", err
	}
	sum := sha256.Sum256(raw)
	return readback, raw, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (s *Server) reportDaprRecoveryTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result daprRecoveryResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	op, err := s.store.GetOperation(r.Context(), strings.TrimSpace(r.PathValue("operationId")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != daprLifecycleOperationKind {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	targetCluster, _, parseTargetErr := parseDaprLifecycleTarget(op.TargetRef)
	if parseTargetErr != nil || targetCluster != clusterID {
		writeError(w, http.StatusForbidden, "AGENT_SCOPE_MISMATCH", "Dapr recovery belongs to another cluster")
		return
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	req, err := daprruntime.ParseLifecycleRequest(sealed.Payload, sealed.PayloadDigest)
	if err != nil || req.ClusterID != clusterID {
		writeError(w, http.StatusConflict, "DAPR_RECOVERY_REQUEST_INVALID", "sealed Dapr lifecycle request is invalid")
		return
	}
	if result.ConfirmedSuccess && (!s.daprRuntimeReady || req.RuntimeLockDigest != s.daprRuntimeDigest) {
		writeError(w, http.StatusConflict, "DAPR_RECOVERY_RUNTIME_LOCK_FENCE_CHANGED", "automatic Dapr recovery requires the exact originally dispatched runtime lock")
		return
	}
	task := daprRecoveryTask{OperationID: op.ID, OperationRevision: op.Revision, TaskFenceToken: op.FenceToken, Request: req, RuntimeLock: s.daprRuntimeLock}
	if !result.ConfirmedSuccess {
		if op.Revision != expected || op.State != controlplane.OperationFailed || op.LastFailureClass != controlplane.OperationFailureUnknown {
			writeError(w, http.StatusConflict, "DAPR_RECOVERY_STATE_CHANGED", "operation is no longer the expected FAILED/UNKNOWN revision")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"authority": daprRecoveryReadbackAuthority,
			"operation": op,
			"stillAmbiguous": true,
			"automaticReplay": false,
			"physicalCertificationInferred": false,
		})
		return
	}
	readback, raw, digest, validateErr := canonicalDaprRecoveryReadback(task, result)
	if validateErr != nil {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_RECOVERY_READBACK_INVALID", validateErr.Error())
		return
	}
	if op.State == controlplane.OperationSucceeded && op.RecoveryEvidenceDigest == digest {
		writeJSON(w, http.StatusOK, map[string]any{
			"authority": daprRecoveryReadbackAuthority,
			"operation": op,
			"readback": readback,
			"idempotentReplay": true,
			"physicalCertificationInferred": false,
		})
		return
	}
	if op.Revision != expected {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if op.State != controlplane.OperationFailed || op.LastFailureClass != controlplane.OperationFailureUnknown {
		writeError(w, http.StatusConflict, "DAPR_RECOVERY_STATE_CHANGED", "operation is no longer FAILED/UNKNOWN")
		return
	}
	actor := "agent:" + clusterID
	var sealedEvidence controlplane.EvidenceMetadata
	op, sealedEvidence, err = s.store.ResolveUnknownOperationOutcomeWithEvidence(
		r.Context(), op.ID, op.Revision, controlplane.OperationUnknownOutcomeConfirmedSuccess,
		controlplane.EvidenceMetadata{
			OperationID: op.ID,
			Kind: daprRecoveryEvidenceKind,
			Digest: digest,
			MediaType: "application/json",
			Location: "authority://dapr/recovery/" + op.ID + "/" + strings.TrimPrefix(digest, "sha256:"),
			Size: int64(len(raw)),
		},
		raw, actor,
	)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": daprRecoveryReadbackAuthority,
		"operation": op,
		"readback": readback,
		"evidence": sealedEvidence,
		"automaticReplay": false,
		"physicalCertificationInferred": false,
	})
}
