package api

import (
	"context"
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
	daprLifecycleLease         = 15 * time.Minute
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
	TaskFenceToken     int64  `json:"taskFenceToken"`
	Success            bool   `json:"success"`
	RecoveryRequired   bool   `json:"recoveryRequired,omitempty"`
	Installed          bool   `json:"installed"`
	ObservedLockDigest string `json:"observedLockDigest,omitempty"`
	Version            string `json:"version,omitempty"`
	UpstreamCommit     string `json:"upstreamCommit,omitempty"`
	Phase              string `json:"phase,omitempty"`
	Error              string `json:"error,omitempty"`
}

type daprLifecycleOperationPager interface {
	ListClaimableOperationsByKindTargetPrefix(context.Context, string, string, time.Time, int) ([]controlplane.Operation, error)
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
		TargetAdmitted:              cluster.ConnectionState != "REVOKED",
		TargetMutationReady:         openChoreoInventoryCapability(inventory, controlplane.TargetMutationRBACActiveCapability),
		ExecutorRBACReady:           openChoreoInventoryCapability(inventory, controlplane.DaprExecutorRBACCapability),
		CapabilityDiscoveryComplete: inventory.APIDiscoveryComplete && inventory.CRDDiscoveryComplete && inventory.SchemaDiscoveryComplete,
		ObservedCapabilities:        inventory.Capabilities,
		ExactSourceAdmitted:         s.daprRuntimeReady,
		Disconnected:                disconnected,
		DisconnectedMirrorAdmitted:  s.daprRuntimeReady,
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
		if result.ObservedLockDigest != req.RuntimeLockDigest || result.Version != s.daprRuntimeLock.Version || result.UpstreamCommit != s.daprRuntimeLock.UpstreamCommit {
			writeError(w, http.StatusUnprocessableEntity, "DAPR_OBSERVED_LOCK_MISMATCH", "observed target Dapr runtime does not match exact admitted lock")
			return
		}
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
