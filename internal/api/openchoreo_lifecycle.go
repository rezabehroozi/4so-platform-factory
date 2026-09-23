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
	"platform.4so.io/factory/internal/openchoreo"
	"platform.4so.io/factory/internal/targetmodel"
)

const (
	openChoreoLifecycleOperationKind = "openchoreo.runtime.lifecycle"
	openChoreoLifecycleTargetPrefix = "openchoreo:"
	openChoreoLifecycleLease = 15 * time.Minute
)

type openChoreoLifecycleInput struct {
	ProjectID                    string                         `json:"projectId"`
	ClusterID                    string                         `json:"clusterId"`
	Action                       openchoreo.LifecycleAction     `json:"action"`
	ExpectedObservedSourceDigest string                         `json:"expectedObservedSourceDigest,omitempty"`
	Disconnected                 bool                           `json:"disconnected,omitempty"`
}

type openChoreoLifecycleTask struct {
	OperationID       string                      `json:"operationId"`
	OperationRevision int64                       `json:"operationRevision"`
	TaskFenceToken    int64                       `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                   `json:"leaseExpiresAt"`
	Request           openchoreo.LifecycleRequest `json:"request"`
	RuntimeSource     openchoreo.RuntimeSource    `json:"runtimeSource"`
}

type openChoreoLifecycleResult struct {
	TaskFenceToken    int64  `json:"taskFenceToken"`
	Success           bool   `json:"success"`
	RecoveryRequired  bool   `json:"recoveryRequired,omitempty"`
	Installed         bool   `json:"installed"`
	ObservedSourceDigest string `json:"observedSourceDigest,omitempty"`
	Version            string `json:"version,omitempty"`
	UpstreamCommit     string `json:"upstreamCommit,omitempty"`
	Phase              string `json:"phase,omitempty"`
	Error              string `json:"error,omitempty"`
}

type openChoreoLifecycleOperationPager interface {
	ListClaimableOperationsByKindTargetPrefix(context.Context, string, string, time.Time, int) ([]controlplane.Operation, error)
}

func openChoreoLifecycleTarget(clusterID string, action openchoreo.LifecycleAction) string {
	return openChoreoLifecycleTargetPrefix + strings.TrimSpace(clusterID) + ":" + strings.ToLower(string(action))
}

func parseOpenChoreoLifecycleTarget(target string) (string, openchoreo.LifecycleAction, error) {
	if !strings.HasPrefix(strings.TrimSpace(target), openChoreoLifecycleTargetPrefix) {
		return "", "", fmt.Errorf("%w: OpenChoreo lifecycle target is invalid", controlplane.ErrValidation)
	}
	rest := strings.TrimPrefix(strings.TrimSpace(target), openChoreoLifecycleTargetPrefix)
	index := strings.LastIndexByte(rest, ':')
	if index <= 0 {
		return "", "", fmt.Errorf("%w: OpenChoreo lifecycle target is invalid", controlplane.ErrValidation)
	}
	action, err := openchoreo.NormalizeLifecycleAction(openchoreo.LifecycleAction(rest[index+1:]))
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", controlplane.ErrValidation, err)
	}
	return strings.TrimSpace(rest[:index]), action, nil
}

func (s *Server) openChoreoAdmissionForCluster(ctx context.Context, cluster controlplane.ManagedCluster, inventory controlplane.ClusterInventory, disconnected bool) targetmodel.OpenChoreoTargetAdapterAdmission {
	return targetmodel.EvaluateOpenChoreoTargetAdapterAdmission(targetmodel.OpenChoreoTargetAdapterAdmissionInput{
		DistributionIdentity: inventory.Distribution,
		TargetAdmitted: cluster.ConnectionState != "REVOKED",
		CapabilityDiscoveryComplete: inventory.APIDiscoveryComplete && inventory.CRDDiscoveryComplete && inventory.SchemaDiscoveryComplete,
		ObservedCapabilities: inventory.Capabilities,
		ExactSourceAdmitted: s.openChoreoRuntimeReady,
		Disconnected: disconnected,
		DisconnectedMirrorAdmitted: s.openChoreoRuntimeReady,
		DurableLifecycleReady: s.openChoreoRuntimeReady,
		DuplicateStackResolved: inventory.APIDiscoveryComplete && inventory.CRDDiscoveryComplete && inventory.SchemaDiscoveryComplete,
	})
}

func (s *Server) latestOpenChoreoObserved(ctx context.Context, projectID, clusterID string) (*openchoreo.ObservedState, error) {
	operations, err := s.store.ListOperations(ctx, projectID)
	if err != nil { return nil, err }
	sort.SliceStable(operations, func(i, j int) bool {
		if operations[i].UpdatedAt.Equal(operations[j].UpdatedAt) { return operations[i].ID > operations[j].ID }
		return operations[i].UpdatedAt.After(operations[j].UpdatedAt)
	})
	for _, op := range operations {
		if op.Kind != openChoreoLifecycleOperationKind || op.State != controlplane.OperationSucceeded {
			continue
		}
		targetCluster, _, parseErr := parseOpenChoreoLifecycleTarget(op.TargetRef)
		if parseErr != nil || targetCluster != clusterID {
			continue
		}
		evidence, listErr := s.store.ListEvidence(ctx, op.ID)
		if listErr != nil { return nil, listErr }
		sort.SliceStable(evidence, func(i, j int) bool { return evidence[i].CreatedAt.After(evidence[j].CreatedAt) })
		for _, ev := range evidence {
			if ev.Kind != openchoreo.ObservedEvidenceKind || !ev.HasPayload {
				continue
			}
			_, payload, getErr := s.store.GetEvidencePayload(ctx, ev.ID)
			if getErr != nil { return nil, getErr }
			var observed openchoreo.ObservedState
			if json.Unmarshal(payload, &observed) != nil || observed.Authority != openchoreo.LifecycleAuthority || observed.ClusterID != clusterID {
				return nil, fmt.Errorf("%w: invalid OpenChoreo observed evidence", controlplane.ErrConflict)
			}
			return &observed, nil
		}
	}
	return nil, nil
}

func (s *Server) createOpenChoreoLifecycle(w http.ResponseWriter, r *http.Request) {
	if !s.openChoreoRuntimeReady {
		writeError(w, http.StatusServiceUnavailable, "OPENCHOREO_RUNTIME_SOURCE_NOT_READY", "exact-source OpenChoreo runtime is not configured")
		return
	}
	actor, err := actorID(r)
	if err != nil { writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error()); return }
	key, err := requiredIdempotencyKey(r)
	if err != nil { writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", err.Error()); return }
	var input openChoreoLifecycleInput
	if err = decodeJSON(w, r, &input); err != nil { writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error()); return }
	input.ProjectID, input.ClusterID = strings.TrimSpace(input.ProjectID), strings.TrimSpace(input.ClusterID)
	input.ExpectedObservedSourceDigest = strings.TrimSpace(input.ExpectedObservedSourceDigest)
	action, err := openchoreo.NormalizeLifecycleAction(input.Action)
	if err != nil { writeError(w, http.StatusUnprocessableEntity, "OPENCHOREO_LIFECYCLE_ACTION_INVALID", err.Error()); return }
	if _, err = s.requireProjectAccess(r, input.ProjectID, organizationWrite); err != nil { writeScopeError(w, err); return }
	cluster, err := s.store.GetManagedCluster(r.Context(), input.ClusterID)
	if err != nil { writeStoreError(w, err); return }
	if cluster.ProjectID != input.ProjectID { writeError(w, http.StatusForbidden, "SCOPE_FORBIDDEN", "cluster is outside requested project"); return }
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), cluster.ID)
	if err != nil { writeStoreError(w, err); return }
	if !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) {
		writeError(w, http.StatusConflict, "INVENTORY_STALE", "fresh target capability discovery is required")
		return
	}
	admission := s.openChoreoAdmissionForCluster(r.Context(), cluster, inventory, input.Disconnected)
	if !admission.Eligible {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{"code":"OPENCHOREO_TARGET_NOT_ADMITTED","message":"target is not eligible for OpenChoreo lifecycle"}, "admission": admission})
		return
	}
	sourceDigest := s.openChoreoRuntimeDigest
	observed, err := s.latestOpenChoreoObserved(r.Context(), input.ProjectID, input.ClusterID)
	if err != nil { writeStoreError(w, err); return }
	if input.ExpectedObservedSourceDigest != "" {
		if observed == nil || !strings.EqualFold(observed.RuntimeSourceDigest, input.ExpectedObservedSourceDigest) {
			writeError(w, http.StatusConflict, "OPENCHOREO_OBSERVED_FENCE_CHANGED", "observed runtime source changed after request preparation")
			return
		}
	}
	if err = openchoreo.ValidateLifecycleTransition(action, observed, sourceDigest); err != nil {
		writeError(w, http.StatusConflict, "OPENCHOREO_LIFECYCLE_TRANSITION_REJECTED", err.Error())
		return
	}
	req := openchoreo.LifecycleRequest{
		ProjectID: input.ProjectID, ClusterID: input.ClusterID, Action: action,
		RuntimeSourceDigest: sourceDigest, Disconnected: input.Disconnected,
		NativeCapabilitySuppressions: admission.NativeCapabilitySuppressions,
	}
	if observed != nil { req.ExpectedObservedSourceDigest = observed.RuntimeSourceDigest }
	payload, requestDigest, err := openchoreo.MarshalLifecycleRequest(req)
	if err != nil { writeStoreError(w, fmt.Errorf("%w: %v", controlplane.ErrValidation, err)); return }
	risk := "high"
	op, replay, err := s.store.CreateOperationAwaitingApprovalWithPayload(r.Context(), controlplane.OperationRequest{
		ProjectID: input.ProjectID, Kind: openChoreoLifecycleOperationKind,
		TargetRef: openChoreoLifecycleTarget(input.ClusterID, action),
		DesiredRevision: requestDigest, Risk: risk, Class: controlplane.OperationClassMutating,
	}, key, actor, r.Header.Get("X-Request-ID"), openchoreo.LifecyclePayloadMediaType, payload)
	if err != nil { writeStoreError(w, err); return }
	status := http.StatusAccepted
	if replay { status = http.StatusOK }
	setRevisionETag(w, op.Revision)
	writeJSON(w, status, map[string]any{"authority":openchoreo.LifecycleAuthority,"operation":op,"request":req,"admission":admission,"idempotentReplay":replay,"physicalCertificationInferred":false})
}

func (s *Server) openChoreoLifecycleOperation(r *http.Request) (controlplane.Operation, openchoreo.LifecycleRequest, error) {
	op, err := s.store.GetOperation(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil { return controlplane.Operation{}, openchoreo.LifecycleRequest{}, err }
	if op.Kind != openChoreoLifecycleOperationKind { return controlplane.Operation{}, openchoreo.LifecycleRequest{}, controlplane.ErrNotFound }
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil { return controlplane.Operation{}, openchoreo.LifecycleRequest{}, err }
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil { return controlplane.Operation{}, openchoreo.LifecycleRequest{}, err }
	if sealed.MediaType != openchoreo.LifecyclePayloadMediaType { return controlplane.Operation{}, openchoreo.LifecycleRequest{}, controlplane.ErrConflict }
	req, err := openchoreo.ParseLifecycleRequest(sealed.Payload, sealed.PayloadDigest)
	return op, req, err
}

func (s *Server) getOpenChoreoLifecycle(w http.ResponseWriter, r *http.Request) {
	op, req, err := s.openChoreoLifecycleOperation(r)
	if err != nil { if errors.Is(err, errOrganizationAccessDenied) { writeScopeError(w, err) } else { writeStoreError(w, err) }; return }
	observed, err := s.latestOpenChoreoObserved(r.Context(), req.ProjectID, req.ClusterID)
	if err != nil { writeStoreError(w, err); return }
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"authority":openchoreo.LifecycleAuthority,"operation":op,"request":req,"observed":observed,"physicalCertificationInferred":false})
}

func (s *Server) approveOpenChoreoLifecycle(w http.ResponseWriter, r *http.Request) {
	op, req, err := s.openChoreoLifecycleOperation(r)
	if err != nil { if errors.Is(err, errOrganizationAccessDenied) { writeScopeError(w, err) } else { writeStoreError(w, err) }; return }
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationAdminAccess); err != nil { writeScopeError(w, err); return }
	expected, err := parseExpectedRevision(r)
	if err != nil { writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error()); return }
	actor, err := actorID(r)
	if err != nil { writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error()); return }
	observed, err := s.latestOpenChoreoObserved(r.Context(), req.ProjectID, req.ClusterID)
	if err != nil { writeStoreError(w, err); return }
	if err = openchoreo.ValidateLifecycleTransition(req.Action, observed, req.RuntimeSourceDigest); err != nil {
		writeError(w, http.StatusConflict, "OPENCHOREO_LIFECYCLE_FENCE_CHANGED", err.Error()); return
	}
	if req.ExpectedObservedSourceDigest != "" && (observed == nil || observed.RuntimeSourceDigest != req.ExpectedObservedSourceDigest) {
		writeError(w, http.StatusConflict, "OPENCHOREO_OBSERVED_FENCE_CHANGED", "observed runtime source changed before approval"); return
	}
	op, err = s.store.ApproveOperationAndQueue(r.Context(), op.ID, expected, actor)
	if err != nil { writeStoreError(w, err); return }
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusAccepted, map[string]any{"authority":openchoreo.LifecycleAuthority,"operation":op,"request":req})
}

func (s *Server) nextOpenChoreoLifecycleTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil { writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error()); return }
	if !s.openChoreoRuntimeReady { writeError(w, http.StatusServiceUnavailable, "OPENCHOREO_RUNTIME_SOURCE_NOT_READY", "exact-source runtime is unavailable"); return }
	pager, ok := s.store.(openChoreoLifecycleOperationPager)
	if !ok { writeError(w, http.StatusServiceUnavailable, "OPENCHOREO_LIFECYCLE_QUEUE_UNAVAILABLE", "bounded lifecycle operation queue is unavailable"); return }
	jobs, err := pager.ListClaimableOperationsByKindTargetPrefix(r.Context(), openChoreoLifecycleOperationKind, openChoreoLifecycleTargetPrefix+clusterID+":", time.Now().UTC(), 4)
	if err != nil { writeStoreError(w, err); return }
	for _, candidate := range jobs {
		claim, claimErr := s.store.ClaimOperation(r.Context(), candidate.ID, "agent:"+clusterID, openChoreoLifecycleLease, time.Now().UTC())
		if errors.Is(claimErr, controlplane.ErrLeaseHeld) || errors.Is(claimErr, controlplane.ErrNotClaimable) { continue }
		if claimErr != nil { writeStoreError(w, claimErr); return }
		op, err := s.store.GetOperation(r.Context(), candidate.ID)
		if err != nil { writeStoreError(w, err); return }
		sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
		if err != nil { writeStoreError(w, err); return }
		req, parseErr := openchoreo.ParseLifecycleRequest(sealed.Payload, sealed.PayloadDigest)
		if parseErr != nil || req.ClusterID != clusterID || req.RuntimeSourceDigest != s.openChoreoRuntimeDigest {
			if op.State == controlplane.OperationQueued {
				op, _ = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
			}
			if op.State == controlplane.OperationRunning {
				_, _ = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, controlplane.OperationFailureReport{Class:controlplane.OperationFailurePermanent,Code:"OPENCHOREO_SOURCE_FENCE_CHANGED",Message:"sealed lifecycle request no longer matches configured exact runtime source"}, "agent:"+clusterID)
			}
			continue
		}
		observed, observedErr := s.latestOpenChoreoObserved(r.Context(), req.ProjectID, req.ClusterID)
		if observedErr != nil {
			writeStoreError(w, observedErr)
			return
		}
		if fenceErr := openchoreo.ValidateLifecycleDispatchFence(req.Action, observed, req.RuntimeSourceDigest, req.ExpectedObservedSourceDigest); fenceErr != nil {
			if op.State == controlplane.OperationQueued {
				op, _ = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
			}
			if op.State == controlplane.OperationRunning {
				_, _ = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, controlplane.OperationFailureReport{Class:controlplane.OperationFailurePermanent,Code:"OPENCHOREO_DISPATCH_FENCE_CHANGED",Message:fenceErr.Error()}, "agent:"+clusterID)
			}
			continue
		}
		op, err = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
		if err != nil { writeStoreError(w, err); return }
		setRevisionETag(w, op.Revision)
		writeJSON(w, http.StatusOK, openChoreoLifecycleTask{OperationID:op.ID,OperationRevision:op.Revision,TaskFenceToken:claim.FenceToken,LeaseExpiresAt:claim.LeaseExpiresAt,Request:req,RuntimeSource:s.openChoreoRuntimeSource})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reportOpenChoreoLifecycleTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil { writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error()); return }
	rev, err := parseExpectedRevision(r)
	if err != nil { writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error()); return }
	var result openChoreoLifecycleResult
	if err = decodeJSON(w, r, &result); err != nil { writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error()); return }
	if result.TaskFenceToken <= 0 { writeError(w, http.StatusUnprocessableEntity, "FENCE_REQUIRED", "taskFenceToken is required"); return }
	op, err := s.store.GetOperation(r.Context(), r.PathValue("operationId"))
	if err != nil { writeStoreError(w, err); return }
	if op.Kind != openChoreoLifecycleOperationKind || op.Revision != rev { writeStoreError(w, controlplane.ErrConflict); return }
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil { writeStoreError(w, err); return }
	req, err := openchoreo.ParseLifecycleRequest(sealed.Payload, sealed.PayloadDigest)
	if err != nil || req.ClusterID != clusterID { writeError(w, http.StatusForbidden, "AGENT_SCOPE_MISMATCH", "OpenChoreo lifecycle task belongs to another cluster"); return }
	worker := "agent:"+clusterID
	if result.RecoveryRequired {
		payload, _ := json.Marshal(map[string]any{"authority":openchoreo.LifecycleAuthority,"clusterId":clusterID,"operationId":op.ID,"action":req.Action,"message":strings.TrimSpace(result.Error),"runtimeSourceDigest":req.RuntimeSourceDigest})
		if _, appendErr := s.store.AppendOperationEvidencePayload(r.Context(), controlplane.EvidenceMetadata{OperationID:op.ID,Kind:openchoreo.RecoveryEvidenceKind,MediaType:"application/json"}, payload, worker, result.TaskFenceToken, worker); appendErr != nil { writeStoreError(w, appendErr); return }
		op, err = s.store.GetOperation(r.Context(), op.ID)
		if err != nil { writeStoreError(w, err); return }
		message := strings.TrimSpace(result.Error); if message == "" { message = "OpenChoreo mutation outcome requires authoritative recovery readback" }
		op, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{Class:controlplane.OperationFailureUnknown,Code:"OPENCHOREO_RECOVERY_REQUIRED",Message:message}, worker)
		if err != nil { writeStoreError(w, err); return }
		writeJSON(w, http.StatusOK, map[string]any{"operation":op,"recoveryRequired":true,"automaticRollback":false})
		return
	}
	if !result.Success {
		message := strings.TrimSpace(result.Error); if message == "" { message = "OpenChoreo lifecycle executor failed before a successful observed readback" }
		op, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{Class:controlplane.OperationFailureDependencyUnavailable,Code:"OPENCHOREO_EXECUTION_FAILED",Message:message}, worker)
		if err != nil { writeStoreError(w, err); return }
		writeJSON(w, http.StatusOK, map[string]any{"operation":op,"automaticRollback":false})
		return
	}
	wantInstalled := req.Action != openchoreo.ActionRemove
	if result.Installed != wantInstalled || strings.TrimSpace(result.Phase) == "" {
		writeError(w, http.StatusUnprocessableEntity, "OPENCHOREO_OBSERVED_READBACK_INVALID", "terminal executor result must contain authoritative installed state and phase")
		return
	}
	if wantInstalled {
		if result.ObservedSourceDigest != req.RuntimeSourceDigest || result.Version != s.openChoreoRuntimeSource.Version || result.UpstreamCommit != s.openChoreoRuntimeSource.UpstreamCommit {
			writeError(w, http.StatusUnprocessableEntity, "OPENCHOREO_OBSERVED_SOURCE_MISMATCH", "observed target runtime does not match exact admitted source")
			return
		}
	}
	observed := openchoreo.ObservedState{Authority:openchoreo.LifecycleAuthority,OperationID:op.ID,ClusterID:clusterID,Action:req.Action,Installed:result.Installed,RuntimeSourceDigest:result.ObservedSourceDigest,Version:result.Version,UpstreamCommit:result.UpstreamCommit,ObservedAt:time.Now().UTC().Format(time.RFC3339Nano),Phase:strings.TrimSpace(result.Phase)}
	payload, _ := json.Marshal(observed)
	if _, err = s.store.AppendOperationEvidencePayload(r.Context(), controlplane.EvidenceMetadata{OperationID:op.ID,Kind:openchoreo.ObservedEvidenceKind,MediaType:"application/json"}, payload, worker, result.TaskFenceToken, worker); err != nil { writeStoreError(w, err); return }
	op, err = s.store.GetOperation(r.Context(), op.ID)
	if err != nil { writeStoreError(w, err); return }
	op, err = s.store.BeginOperationVerification(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, worker)
	if err == nil { op, err = s.store.CompleteOperation(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, worker) }
	if err != nil { writeStoreError(w, err); return }
	writeJSON(w, http.StatusOK, map[string]any{"operation":op,"observed":observed,"automaticRollback":false,"physicalCertificationInferred":false})
}
