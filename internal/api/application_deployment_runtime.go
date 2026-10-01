package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const applicationDeploymentLease = 3 * time.Minute

type applicationDeploymentTask struct {
	OperationID       string                                    `json:"operationId"`
	OperationRevision int64                                     `json:"operationRevision"`
	TaskFenceToken    int64                                     `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                                 `json:"leaseExpiresAt"`
	Request           controlplane.ApplicationDeploymentRequest `json:"request"`
}

type applicationDeploymentResult struct {
	Success          bool                                        `json:"success"`
	RecoveryRequired bool                                        `json:"recoveryRequired,omitempty"`
	TaskFenceToken   int64                                       `json:"taskFenceToken"`
	Error            string                                      `json:"error,omitempty"`
	Evidence         *controlplane.ApplicationDeploymentEvidence `json:"evidence,omitempty"`
	EvidenceDigest   string                                      `json:"evidenceDigest,omitempty"`
}

type applicationDeploymentOperationPager interface {
	ListClaimableOperationsByKindTargetPrefix(context.Context, string, string, time.Time, int) ([]controlplane.Operation, error)
}

type applicationDeploymentRecoveryOperationPager interface {
	ListUnknownRecoveryOperationsByKindTargetPrefix(context.Context, string, string, int) ([]controlplane.Operation, error)
}

type applicationDeploymentRecoveryTask struct {
	OperationID       string                                    `json:"operationId"`
	OperationRevision int64                                     `json:"operationRevision"`
	TaskFenceToken    int64                                     `json:"taskFenceToken"`
	Request           controlplane.ApplicationDeploymentRequest `json:"request"`
}

type applicationDeploymentRecoveryResult struct {
	ConfirmedSuccess bool                                        `json:"confirmedSuccess"`
	Evidence         *controlplane.ApplicationDeploymentEvidence `json:"evidence,omitempty"`
	EvidenceDigest   string                                      `json:"evidenceDigest,omitempty"`
	Error            string                                      `json:"error,omitempty"`
}

func applicationDeploymentTarget(clusterID, bindingID string) string {
	return applicationDeploymentTargetPrefix + strings.TrimSpace(clusterID) + ":" + strings.TrimSpace(bindingID)
}

func parseApplicationDeploymentTarget(target string) (clusterID, bindingID string, err error) {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, applicationDeploymentTargetPrefix) {
		return "", "", fmt.Errorf("%w: invalid application deployment target", controlplane.ErrValidation)
	}
	raw := strings.TrimSpace(strings.TrimPrefix(target, applicationDeploymentTargetPrefix))
	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 1:
		if strings.TrimSpace(parts[0]) == "" {
			return "", "", fmt.Errorf("%w: invalid application deployment target", controlplane.ErrValidation)
		}
		return "", strings.TrimSpace(parts[0]), nil
	case 2:
		if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return "", "", fmt.Errorf("%w: invalid application deployment target", controlplane.ErrValidation)
		}
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	default:
		return "", "", fmt.Errorf("%w: invalid application deployment target", controlplane.ErrValidation)
	}
}

func applicationDeploymentStateBlocksNewMutation(op controlplane.Operation) bool {
	return controlplane.ApplicationDeploymentOperationBlocksDesiredMutation(op)
}

func (s *Server) applicationDeploymentBindingBlocker(ctx context.Context, projectID, clusterID, bindingID, idempotencyKey string) (*controlplane.Operation, error) {
	operations, err := s.store.ListOperations(ctx, strings.TrimSpace(projectID))
	if err != nil {
		return nil, err
	}
	for i := range operations {
		op := operations[i]
		if op.Kind != applicationDeploymentOperationKind || strings.TrimSpace(op.IdempotencyKey) == strings.TrimSpace(idempotencyKey) {
			continue
		}
		targetCluster, targetBinding, parseErr := parseApplicationDeploymentTarget(op.TargetRef)
		if parseErr != nil || targetBinding != strings.TrimSpace(bindingID) {
			continue
		}
		if targetCluster != "" && targetCluster != strings.TrimSpace(clusterID) {
			continue
		}
		if applicationDeploymentStateBlocksNewMutation(op) {
			return &op, nil
		}
	}
	return nil, nil
}

func (s *Server) applicationDeploymentWorkspaceBindingBlocker(ctx context.Context, projectID, workspaceBindingID string) (*controlplane.Operation, error) {
	appStore, ok := s.store.(applicationPlatformStore)
	if !ok {
		return nil, fmt.Errorf("%w: application platform persistence authority is unavailable", controlplane.ErrPrerequisite)
	}
	bindings, err := appStore.ListEnvironmentBindings(ctx, strings.TrimSpace(projectID))
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if binding.WorkspaceBindingID != strings.TrimSpace(workspaceBindingID) {
			continue
		}
		blocker, blockerErr := s.applicationDeploymentBindingBlocker(ctx, projectID, binding.ClusterID, binding.ID, "")
		if blockerErr != nil {
			return nil, blockerErr
		}
		if blocker != nil {
			return blocker, nil
		}
	}
	return nil, nil
}

func (s *Server) buildApplicationDeploymentRequest(ctx context.Context, bindingID string, runtime controlplane.ApplicationRuntimeSpec) (controlplane.ApplicationDeploymentRequest, error) {
	appStore, ok := s.store.(applicationPlatformStore)
	if !ok {
		return controlplane.ApplicationDeploymentRequest{}, fmt.Errorf("%w: application platform persistence authority is unavailable", controlplane.ErrPrerequisite)
	}
	binding, err := appStore.GetEnvironmentBinding(ctx, strings.TrimSpace(bindingID))
	if err != nil {
		return controlplane.ApplicationDeploymentRequest{}, err
	}
	release, err := appStore.GetApplicationRelease(ctx, binding.ReleaseID)
	if err != nil {
		return controlplane.ApplicationDeploymentRequest{}, err
	}
	workspaceBinding, err := s.store.GetWorkspaceBinding(ctx, binding.WorkspaceBindingID)
	if err != nil {
		return controlplane.ApplicationDeploymentRequest{}, err
	}
	cluster, err := s.store.GetManagedCluster(ctx, binding.ClusterID)
	if err != nil {
		return controlplane.ApplicationDeploymentRequest{}, err
	}
	inventory, err := s.store.GetLatestClusterInventory(ctx, binding.ClusterID)
	if err != nil {
		return controlplane.ApplicationDeploymentRequest{}, err
	}
	if cluster.ProjectID != binding.ProjectID || release.ProjectID != binding.ProjectID ||
		workspaceBinding.ProjectID != binding.ProjectID || workspaceBinding.ClusterID != binding.ClusterID {
		return controlplane.ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment project/cluster scope mismatch", controlplane.ErrPrerequisite)
	}
	if cluster.InventoryDigest != inventory.Digest || !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) ||
		!controlplane.ClusterTaskAdmitted(cluster) {
		return controlplane.ApplicationDeploymentRequest{}, fmt.Errorf("%w: fresh mutation-admitted target inventory is required", controlplane.ErrPrerequisite)
	}
	if !inventory.APIDiscoveryComplete || !openChoreoInventoryCapability(inventory, controlplane.ApplicationDeploymentRBACCapability) {
		return controlplane.ApplicationDeploymentRequest{}, fmt.Errorf("%w: application deployment target RBAC/discovery authority is unavailable", controlplane.ErrPrerequisite)
	}
	plan, err := controlplane.ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, runtime)
	if err != nil {
		return controlplane.ApplicationDeploymentRequest{}, err
	}
	request := controlplane.ApplicationDeploymentRequest{
		Authority: controlplane.ApplicationDeploymentRequestAuthority,
		InventoryDigest: inventory.Digest,
		Plan: plan,
	}
	raw, _, err := controlplane.MarshalApplicationDeploymentRequest(request)
	if err != nil {
		return controlplane.ApplicationDeploymentRequest{}, err
	}
	return controlplane.ParseApplicationDeploymentRequest(raw, "")
}

func (s *Server) validateApplicationDeploymentCurrentAuthority(ctx context.Context, request controlplane.ApplicationDeploymentRequest) error {
	appStore, ok := s.store.(applicationPlatformStore)
	if !ok {
		return fmt.Errorf("%w: application platform persistence authority is unavailable", controlplane.ErrPrerequisite)
	}
	raw, _, err := controlplane.MarshalApplicationDeploymentRequest(request)
	if err != nil {
		return err
	}
	request, err = controlplane.ParseApplicationDeploymentRequest(raw, "")
	if err != nil {
		return err
	}
	plan := request.Plan
	binding, err := appStore.GetEnvironmentBinding(ctx, plan.EnvironmentBindingID)
	if err != nil {
		return err
	}
	release, err := appStore.GetApplicationRelease(ctx, plan.ReleaseID)
	if err != nil {
		return err
	}
	workspaceBinding, err := s.store.GetWorkspaceBinding(ctx, plan.WorkspaceBindingID)
	if err != nil {
		return err
	}
	cluster, err := s.store.GetManagedCluster(ctx, plan.ClusterID)
	if err != nil {
		return err
	}
	inventory, err := s.store.GetLatestClusterInventory(ctx, plan.ClusterID)
	if err != nil {
		return err
	}
	if binding.ProjectID != plan.ProjectID || binding.ID != plan.EnvironmentBindingID ||
		binding.Revision != plan.EnvironmentBindingRevision || binding.Digest != plan.EnvironmentBindingDigest ||
		binding.ReleaseID != plan.ReleaseID || binding.ReleaseDigest != plan.ReleaseDigest ||
		binding.WorkspaceBindingID != plan.WorkspaceBindingID || binding.WorkspaceBindingRevision != plan.WorkspaceBindingRevision ||
		binding.ClusterID != plan.ClusterID || binding.Namespace != plan.Namespace {
		return fmt.Errorf("%w: application environment binding authority changed", controlplane.ErrPrerequisite)
	}
	if release.ProjectID != plan.ProjectID || release.Digest != plan.ReleaseDigest ||
		release.WorkloadImageReference != plan.WorkloadImageReference {
		return fmt.Errorf("%w: immutable application release authority changed", controlplane.ErrPrerequisite)
	}
	if workspaceBinding.State != controlplane.WorkspaceBindingActive ||
		workspaceBinding.ProjectID != plan.ProjectID || workspaceBinding.WorkspaceID != plan.WorkspaceID ||
		workspaceBinding.ClusterID != plan.ClusterID || workspaceBinding.Namespace != plan.Namespace ||
		workspaceBinding.Revision != plan.WorkspaceBindingRevision {
		return fmt.Errorf("%w: WorkspaceBinding authority changed", controlplane.ErrPrerequisite)
	}
	if cluster.ProjectID != plan.ProjectID || cluster.InventoryDigest != request.InventoryDigest ||
		inventory.Digest != request.InventoryDigest || !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) ||
		!controlplane.ClusterTaskAdmitted(cluster) {
		return fmt.Errorf("%w: application deployment inventory/task fence changed", controlplane.ErrPrerequisite)
	}
	if !inventory.APIDiscoveryComplete || !openChoreoInventoryCapability(inventory, controlplane.ApplicationDeploymentRBACCapability) {
		return fmt.Errorf("%w: application deployment target RBAC/discovery authority changed", controlplane.ErrPrerequisite)
	}
	resolved, err := controlplane.ResolveApplicationDeploymentPlan(release, binding, workspaceBinding, plan.RuntimeSpec)
	if err != nil {
		return err
	}
	if resolved.RenderedDigest != plan.RenderedDigest || resolved.RuntimeSpecDigest != plan.RuntimeSpecDigest ||
		resolved.ReleaseDigest != plan.ReleaseDigest || resolved.EnvironmentBindingDigest != plan.EnvironmentBindingDigest ||
		resolved.WorkspaceBindingRevision != plan.WorkspaceBindingRevision ||
		resolved.WorkloadImageReference != plan.WorkloadImageReference {
		return fmt.Errorf("%w: application deployment rendered authority changed", controlplane.ErrPrerequisite)
	}
	return nil
}

func (s *Server) createApplicationDeployment(w http.ResponseWriter, r *http.Request) {
	appStore, ok := s.store.(applicationPlatformStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "APPLICATION_PLATFORM_AUTHORITY_UNAVAILABLE", "application platform persistence authority is unavailable")
		return
	}
	var runtime controlplane.ApplicationRuntimeSpec
	if err := decodeJSON(w, r, &runtime); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	binding, err := appStore.GetEnvironmentBinding(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, binding.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	request, err := s.buildApplicationDeploymentRequest(r.Context(), binding.ID, runtime)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	payload, _, err := controlplane.MarshalApplicationDeploymentRequest(request)
	if err != nil {
		writeStoreError(w, fmt.Errorf("%w: %v", controlplane.ErrValidation, err))
		return
	}
	key, err := requiredIdempotencyKey(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", err.Error())
		return
	}
	blocker, err := s.applicationDeploymentBindingBlocker(r.Context(), request.Plan.ProjectID, request.Plan.ClusterID, request.Plan.EnvironmentBindingID, key)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if blocker != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": map[string]any{
				"code": "APPLICATION_DEPLOYMENT_RECOVERY_OR_OPERATION_PENDING",
				"message": "an existing deployment for this environment binding must converge or be recovery-resolved before another mutation",
			},
			"blockingOperationId": blocker.ID,
			"blockingState": blocker.State,
			"blockingFailureClass": blocker.LastFailureClass,
			"automaticReplay": false,
		})
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	risk := "medium"
	if request.Plan.Environment == "production" {
		risk = "high"
	}
	op, replay, err := s.store.CreateOperationAwaitingApprovalWithPayload(r.Context(), controlplane.OperationRequest{
		ProjectID: request.Plan.ProjectID,
		Kind: applicationDeploymentOperationKind,
		TargetRef: applicationDeploymentTarget(request.Plan.ClusterID, request.Plan.EnvironmentBindingID),
		DesiredRevision: request.Plan.ReleaseDigest,
		Risk: risk,
		Class: controlplane.OperationClassMutating,
	}, key, actor, r.Header.Get("X-Request-ID"), controlplane.ApplicationDeploymentPayloadMediaType, payload)
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
		"authority": controlplane.ApplicationDeploymentRequestAuthority,
		"operation": op,
		"request": request,
		"idempotentReplay": replay,
		"runtimeMutationPerformed": false,
		"physicalCertificationInferred": false,
	})
}

func (s *Server) applicationDeploymentOperation(r *http.Request) (controlplane.Operation, controlplane.ApplicationDeploymentRequest, error) {
	op, err := s.store.GetOperation(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		return controlplane.Operation{}, controlplane.ApplicationDeploymentRequest{}, err
	}
	if op.Kind != applicationDeploymentOperationKind {
		return controlplane.Operation{}, controlplane.ApplicationDeploymentRequest{}, controlplane.ErrNotFound
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
		return controlplane.Operation{}, controlplane.ApplicationDeploymentRequest{}, err
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		return controlplane.Operation{}, controlplane.ApplicationDeploymentRequest{}, err
	}
	if sealed.MediaType != controlplane.ApplicationDeploymentPayloadMediaType {
		return controlplane.Operation{}, controlplane.ApplicationDeploymentRequest{}, controlplane.ErrConflict
	}
	req, err := controlplane.ParseApplicationDeploymentRequest(sealed.Payload, sealed.PayloadDigest)
	return op, req, err
}

func (s *Server) getApplicationDeployment(w http.ResponseWriter, r *http.Request) {
	op, req, err := s.applicationDeploymentOperation(r)
	if err != nil {
		if errors.Is(err, errOrganizationAccessDenied) { writeScopeError(w, err) } else { writeStoreError(w, err) }
		return
	}
	out := map[string]any{
		"authority": controlplane.ApplicationDeploymentRequestAuthority,
		"operation": op,
		"request": req,
		"ready": false,
		"physicalCertificationInferred": false,
	}
	evidence, err := s.store.ListEvidence(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, item := range evidence {
		if item.Kind != controlplane.ApplicationDeploymentEvidenceKind || !item.HasPayload {
			continue
		}
		_, payload, getErr := s.store.GetEvidencePayload(r.Context(), item.ID)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		var value controlplane.ApplicationDeploymentEvidence
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(&value); decodeErr != nil ||
			controlplane.ValidateApplicationDeploymentEvidence(value, req, op.ID) != nil {
			writeError(w, http.StatusConflict, "APPLICATION_DEPLOYMENT_EVIDENCE_INVALID", "sealed application deployment evidence failed validation")
			return
		}
		out["evidence"] = value
		out["evidenceDigest"] = item.Digest
		break
	}
	currentErr := s.validateApplicationDeploymentCurrentAuthority(r.Context(), req)
	out["currentAuthority"] = currentErr == nil
	out["ready"] = currentErr == nil && op.State == controlplane.OperationSucceeded
	if currentErr != nil {
		out["stale"] = true
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) approveApplicationDeployment(w http.ResponseWriter, r *http.Request) {
	op, req, err := s.applicationDeploymentOperation(r)
	if err != nil {
		if errors.Is(err, errOrganizationAccessDenied) { writeScopeError(w, err) } else { writeStoreError(w, err) }
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
	if err = s.validateApplicationDeploymentCurrentAuthority(r.Context(), req); err != nil {
		writeError(w, http.StatusConflict, "APPLICATION_DEPLOYMENT_FENCE_CHANGED", err.Error())
		return
	}
	op, err = s.store.ApproveOperationAndQueue(r.Context(), op.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"authority": controlplane.ApplicationDeploymentRequestAuthority,
		"operation": op,
		"request": req,
		"runtimeMutationPerformed": false,
		"physicalCertificationInferred": false,
	})
}

func (s *Server) nextApplicationDeploymentTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	pager, ok := s.store.(applicationDeploymentOperationPager)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "APPLICATION_DEPLOYMENT_QUEUE_UNAVAILABLE", "bounded application deployment queue is unavailable")
		return
	}
	jobs, err := pager.ListClaimableOperationsByKindTargetPrefix(r.Context(), applicationDeploymentOperationKind, applicationDeploymentTargetPrefix+clusterID+":", time.Now().UTC(), 8)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, candidate := range jobs {
		claim, claimErr := s.store.ClaimOperation(r.Context(), candidate.ID, "agent:"+clusterID, applicationDeploymentLease, time.Now().UTC())
		if errors.Is(claimErr, controlplane.ErrLeaseHeld) || errors.Is(claimErr, controlplane.ErrNotClaimable) {
			continue
		}
		if claimErr != nil {
			writeStoreError(w, claimErr)
			return
		}
		op, getErr := s.store.GetOperation(r.Context(), candidate.ID)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		sealed, getErr := s.store.GetOperationRequestPayload(r.Context(), op.ID)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		req, parseErr := controlplane.ParseApplicationDeploymentRequest(sealed.Payload, sealed.PayloadDigest)
		fenceErr := parseErr
		if fenceErr == nil && req.Plan.ClusterID != clusterID {
			fenceErr = fmt.Errorf("%w: application deployment cluster scope changed", controlplane.ErrPrerequisite)
		}
		if fenceErr == nil {
			fenceErr = s.validateApplicationDeploymentCurrentAuthority(r.Context(), req)
		}
		if fenceErr != nil {
			op, startErr := s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
			if startErr == nil {
				_, startErr = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, controlplane.OperationFailureReport{
					Class: controlplane.OperationFailurePermanent,
					Code: "APPLICATION_DEPLOYMENT_FENCE_CHANGED",
					Message: "release, environment binding, WorkspaceBinding or target inventory changed before dispatch",
				}, "agent:"+clusterID)
			}
			if startErr != nil {
				writeStoreError(w, startErr)
				return
			}
			continue
		}
		op, err = s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		setRevisionETag(w, op.Revision)
		writeJSON(w, http.StatusOK, applicationDeploymentTask{
			OperationID: op.ID,
			OperationRevision: op.Revision,
			TaskFenceToken: claim.FenceToken,
			LeaseExpiresAt: claim.LeaseExpiresAt,
			Request: req,
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) nextApplicationDeploymentRecoveryTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	pager, ok := s.store.(applicationDeploymentRecoveryOperationPager)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "APPLICATION_DEPLOYMENT_RECOVERY_QUEUE_UNAVAILABLE", "bounded application deployment recovery queue is unavailable")
		return
	}
	operations, err := pager.ListUnknownRecoveryOperationsByKindTargetPrefix(r.Context(), applicationDeploymentOperationKind, applicationDeploymentTargetPrefix+clusterID+":", 8)
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
		req, parseErr := controlplane.ParseApplicationDeploymentRequest(sealed.Payload, sealed.PayloadDigest)
		if parseErr != nil || req.Plan.ClusterID != clusterID {
			continue
		}
		setRevisionETag(w, op.Revision)
		writeJSON(w, http.StatusOK, applicationDeploymentRecoveryTask{
			OperationID: op.ID,
			OperationRevision: op.Revision,
			TaskFenceToken: op.FenceToken,
			Request: req,
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reportApplicationDeploymentRecoveryTask(w http.ResponseWriter, r *http.Request) {
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
	var result applicationDeploymentRecoveryResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	op, err := s.store.GetOperation(r.Context(), strings.TrimSpace(r.PathValue("operationId")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != applicationDeploymentOperationKind {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	targetCluster, _, parseTargetErr := parseApplicationDeploymentTarget(op.TargetRef)
	if parseTargetErr != nil || targetCluster != clusterID {
		writeError(w, http.StatusForbidden, "AGENT_SCOPE_MISMATCH", "application deployment recovery belongs to another cluster")
		return
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	req, err := controlplane.ParseApplicationDeploymentRequest(sealed.Payload, sealed.PayloadDigest)
	if err != nil || req.Plan.ClusterID != clusterID {
		writeError(w, http.StatusConflict, "APPLICATION_DEPLOYMENT_RECOVERY_REQUEST_INVALID", "sealed application deployment request is invalid")
		return
	}
	if !result.ConfirmedSuccess {
		if op.Revision != expected || op.State != controlplane.OperationFailed || op.LastFailureClass != controlplane.OperationFailureUnknown {
			writeError(w, http.StatusConflict, "APPLICATION_DEPLOYMENT_RECOVERY_STATE_CHANGED", "operation is no longer the expected FAILED/UNKNOWN revision")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"authority": controlplane.ApplicationDeploymentEvidenceAuthority,
			"operation": op,
			"stillAmbiguous": true,
			"automaticReplay": false,
			"physicalCertificationInferred": false,
		})
		return
	}
	if result.Evidence == nil {
		writeError(w, http.StatusUnprocessableEntity, "APPLICATION_DEPLOYMENT_RECOVERY_EVIDENCE_REQUIRED", "confirmed recovery requires canonical observed deployment evidence")
		return
	}
	if err = controlplane.ValidateApplicationDeploymentEvidence(*result.Evidence, req, op.ID); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "APPLICATION_DEPLOYMENT_RECOVERY_EVIDENCE_INVALID", err.Error())
		return
	}
	digest, err := controlplane.ApplicationDeploymentEvidenceDigest(*result.Evidence, req, op.ID)
	if err != nil || !strings.EqualFold(digest, strings.TrimSpace(result.EvidenceDigest)) {
		writeError(w, http.StatusUnprocessableEntity, "APPLICATION_DEPLOYMENT_RECOVERY_EVIDENCE_DIGEST_MISMATCH", "canonical application deployment recovery evidence digest mismatch")
		return
	}
	if op.State == controlplane.OperationSucceeded && strings.EqualFold(op.RecoveryEvidenceDigest, digest) {
		writeJSON(w, http.StatusOK, map[string]any{
			"authority": controlplane.ApplicationDeploymentEvidenceAuthority,
			"operation": op,
			"evidence": result.Evidence,
			"evidenceDigest": digest,
			"idempotentReplay": true,
			"automaticReplay": false,
			"physicalCertificationInferred": false,
		})
		return
	}
	if op.Revision != expected {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if op.State != controlplane.OperationFailed || op.LastFailureClass != controlplane.OperationFailureUnknown {
		writeError(w, http.StatusConflict, "APPLICATION_DEPLOYMENT_RECOVERY_STATE_CHANGED", "operation is no longer FAILED/UNKNOWN")
		return
	}
	payload, _ := json.Marshal(result.Evidence)
	actor := "agent:" + clusterID
	var sealedEvidence controlplane.EvidenceMetadata
	op, sealedEvidence, err = s.store.ResolveUnknownOperationOutcomeWithEvidence(
		r.Context(), op.ID, op.Revision, controlplane.OperationUnknownOutcomeConfirmedSuccess,
		controlplane.EvidenceMetadata{
			OperationID: op.ID,
			Kind: controlplane.ApplicationDeploymentEvidenceKind,
			Digest: digest,
			MediaType: "application/json",
			Location: "authority://application-deployment/recovery/" + op.ID + "/" + strings.TrimPrefix(digest, "sha256:"),
			Size: int64(len(payload)),
		},
		payload, actor,
	)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authority": controlplane.ApplicationDeploymentEvidenceAuthority,
		"operation": op,
		"evidence": result.Evidence,
		"evidenceDigest": sealedEvidence.Digest,
		"automaticReplay": false,
		"physicalCertificationInferred": false,
	})
}

func (s *Server) reportApplicationDeploymentTask(w http.ResponseWriter, r *http.Request) {
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
	var result applicationDeploymentResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if result.TaskFenceToken <= 0 {
		writeError(w, http.StatusUnprocessableEntity, "FENCE_REQUIRED", "taskFenceToken is required")
		return
	}
	op, err := s.store.GetOperation(r.Context(), strings.TrimSpace(r.PathValue("operationId")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != applicationDeploymentOperationKind || op.Revision != rev {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	req, err := controlplane.ParseApplicationDeploymentRequest(sealed.Payload, sealed.PayloadDigest)
	if err != nil || req.Plan.ClusterID != clusterID {
		writeError(w, http.StatusForbidden, "AGENT_SCOPE_MISMATCH", "application deployment belongs to another cluster")
		return
	}
	worker := "agent:" + clusterID
	if result.RecoveryRequired {
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "application deployment mutation outcome requires authoritative operator recovery"
		}
		op, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{
			Class: controlplane.OperationFailureUnknown,
			Code: "APPLICATION_DEPLOYMENT_RECOVERY_REQUIRED",
			Message: message,
		}, worker)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"operation": op, "recoveryRequired": true, "automaticReplay": false})
		return
	}
	if !result.Success {
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "application deployment executor failed before authoritative convergence"
		}
		op, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{
			Class: controlplane.OperationFailureDependencyUnavailable,
			Code: "APPLICATION_DEPLOYMENT_FAILED",
			Message: message,
		}, worker)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"operation": op, "recoveryRequired": false})
		return
	}
	if fenceErr := s.validateApplicationDeploymentCurrentAuthority(r.Context(), req); fenceErr != nil {
		op, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{
			Class: controlplane.OperationFailurePermanent,
			Code: "APPLICATION_DEPLOYMENT_RESULT_FENCE_CHANGED",
			Message: "release, environment binding, WorkspaceBinding or inventory authority changed before result commit",
		}, worker)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"operation": op, "staleResultRejected": true})
		return
	}
	if result.Evidence == nil {
		writeError(w, http.StatusUnprocessableEntity, "APPLICATION_DEPLOYMENT_EVIDENCE_REQUIRED", "successful application deployment requires canonical observed evidence")
		return
	}
	if err = controlplane.ValidateApplicationDeploymentEvidence(*result.Evidence, req, op.ID); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "APPLICATION_DEPLOYMENT_EVIDENCE_INVALID", err.Error())
		return
	}
	digest, err := controlplane.ApplicationDeploymentEvidenceDigest(*result.Evidence, req, op.ID)
	if err != nil || !strings.EqualFold(digest, strings.TrimSpace(result.EvidenceDigest)) {
		writeError(w, http.StatusUnprocessableEntity, "APPLICATION_DEPLOYMENT_EVIDENCE_DIGEST_MISMATCH", "canonical application deployment evidence digest mismatch")
		return
	}
	payload, _ := json.Marshal(result.Evidence)
	if _, err = s.store.AppendOperationEvidencePayload(r.Context(), controlplane.EvidenceMetadata{
		OperationID: op.ID,
		Kind: controlplane.ApplicationDeploymentEvidenceKind,
		Digest: digest,
		MediaType: "application/json",
		Size: int64(len(payload)),
	}, payload, worker, result.TaskFenceToken, worker); err != nil {
		writeStoreError(w, err)
		return
	}
	op, err = s.store.GetOperation(r.Context(), op.ID)
	if err == nil {
		op, err = s.store.BeginOperationVerification(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, worker)
	}
	if err == nil {
		op, err = s.store.CompleteOperation(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, worker)
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"operation": op,
		"deployed": true,
		"evidenceDigest": digest,
		"physicalCertificationInferred": false,
	})
}
