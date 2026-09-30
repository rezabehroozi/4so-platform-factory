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
	daprruntime "platform.4so.io/factory/internal/dapr"
	"platform.4so.io/factory/internal/targetmodel"
)

const (
	daprWorkloadAdmissionOperationKind = "dapr.workload.admission"
	daprWorkloadAdmissionTargetPrefix  = "dapr-workload:"
	daprWorkloadAdmissionEvidenceKind  = "dapr-workload-admission"
	daprWorkloadAdmissionLease         = 2 * time.Minute
)

type daprWorkloadAdmissionInput struct {
	ProjectID        string   `json:"projectId"`
	ClusterID        string   `json:"clusterId"`
	TraitID          string   `json:"traitId"`
	WorkloadImage    string   `json:"workloadImage"`
	Namespace        string   `json:"namespace"`
	AppID            string   `json:"appId"`
	AppPort          int      `json:"appPort,omitempty"`
	AppProtocol      string   `json:"appProtocol,omitempty"`
	CPURequest       string   `json:"cpuRequest"`
	CPULimit         string   `json:"cpuLimit"`
	MemoryRequest    string   `json:"memoryRequest"`
	MemoryLimit      string   `json:"memoryLimit"`
	ComponentNames   []string `json:"componentNames,omitempty"`
	EnablePubSub     bool     `json:"enablePubSub"`
	EnableBindings   bool     `json:"enableBindings"`
	EnableInvocation bool     `json:"enableInvocation"`
}

type daprWorkloadAdmissionTask struct {
	OperationID       string                               `json:"operationId"`
	OperationRevision int64                                `json:"operationRevision"`
	TaskFenceToken    int64                                `json:"taskFenceToken"`
	LeaseExpiresAt    time.Time                            `json:"leaseExpiresAt"`
	Request           daprruntime.WorkloadAdmissionRequest `json:"request"`
	ExecutorAuthority daprruntime.ExecutorAuthority         `json:"executorAuthority"`
	RuntimeLock       *daprruntime.RuntimeLock              `json:"runtimeLock,omitempty"`
}

type daprWorkloadAdmissionResult struct {
	Success        bool                                  `json:"success"`
	TaskFenceToken int64                                 `json:"taskFenceToken"`
	Error          string                                `json:"error,omitempty"`
	Evidence       *daprruntime.WorkloadAdmissionEvidence `json:"evidence,omitempty"`
	EvidenceDigest string                                `json:"evidenceDigest,omitempty"`
}

type daprWorkloadAdmissionOperationPager interface {
	ListClaimableOperationsByKindTargetPrefix(context.Context, string, string, time.Time, int) ([]controlplane.Operation, error)
}

type queuedRequestPayloadStore interface {
	CreateOperationQueuedWithPayload(context.Context, controlplane.OperationRequest, string, string, string, string, []byte) (controlplane.Operation, bool, error)
}

func daprRuntimeImageByRole(lock daprruntime.RuntimeLock, role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	for _, image := range lock.ImageLocks {
		if strings.ToLower(strings.TrimSpace(image.Role)) == role {
			return strings.TrimSpace(image.MirrorReference)
		}
	}
	return ""
}

func daprWorkloadAdmissionTarget(clusterID, namespace, appID string) string {
	return daprWorkloadAdmissionTargetPrefix + strings.TrimSpace(clusterID) + ":" + strings.TrimSpace(namespace) + ":" + strings.TrimSpace(appID)
}

func parseDaprWorkloadAdmissionTarget(target string) (clusterID, namespace, appID string, err error) {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, daprWorkloadAdmissionTargetPrefix) {
		return "", "", "", fmt.Errorf("%w: invalid Dapr workload admission target", controlplane.ErrValidation)
	}
	parts := strings.Split(strings.TrimPrefix(target, daprWorkloadAdmissionTargetPrefix), ":")
	if len(parts) != 3 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return "", "", "", fmt.Errorf("%w: invalid Dapr workload admission target", controlplane.ErrValidation)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), nil
}

func (s *Server) validateDaprWorkloadAdmissionCurrentAuthority(ctx context.Context, request daprruntime.WorkloadAdmissionRequest) error {
	request, err := daprruntime.CanonicalWorkloadAdmissionRequest(request)
	if err != nil {
		return err
	}
	cluster, err := s.store.GetManagedCluster(ctx, request.ClusterID)
	if err != nil {
		return err
	}
	if cluster.ProjectID != request.ProjectID {
		return fmt.Errorf("%w: Dapr workload admission project scope changed", controlplane.ErrPrerequisite)
	}
	inventory, err := s.store.GetLatestClusterInventory(ctx, request.ClusterID)
	if err != nil {
		return err
	}
	if cluster.InventoryDigest != request.InventoryDigest || inventory.Digest != request.InventoryDigest {
		return fmt.Errorf("%w: Dapr workload admission inventory fence changed", controlplane.ErrPrerequisite)
	}
	if !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) || !controlplane.ClusterTaskAdmitted(cluster) {
		return fmt.Errorf("%w: Dapr workload admission target authority is stale or not task-admitted", controlplane.ErrPrerequisite)
	}
	if !inventory.APIDiscoveryComplete || !inventory.CRDDiscoveryComplete || !inventory.SchemaDiscoveryComplete ||
		!openChoreoInventoryCapability(inventory, "strict-schema-dry-run") {
		return fmt.Errorf("%w: Dapr workload admission target discovery is incomplete", controlplane.ErrPrerequisite)
	}
	if !openChoreoInventoryCapability(inventory, controlplane.TargetMutationRBACActiveCapability) ||
		!openChoreoInventoryCapability(inventory, controlplane.DaprWorkloadAdmissionRBACCapability) {
		return fmt.Errorf("%w: Dapr workload admission executor RBAC is not active", controlplane.ErrPrerequisite)
	}
	if !s.daprExecutorReady ||
		!strings.EqualFold(strings.TrimSpace(s.daprExecutorAuthority.EvidenceDigest), request.ExecutorEvidenceDigest) ||
		!strings.EqualFold(strings.TrimSpace(s.daprExecutorAuthority.SourceReleaseDigest), request.ExecutorSourceReleaseDigest) ||
		strings.TrimSpace(s.daprExecutorAuthority.ImageReference) != request.ExecutorImageReference {
		return fmt.Errorf("%w: Dapr workload executor authority changed", controlplane.ErrPrerequisite)
	}
	switch request.RuntimeMode {
	case "USE_NATIVE":
		if !openChoreoInventoryCapability(inventory, targetmodel.DaprApplicationRuntimeCapability) {
			return fmt.Errorf("%w: native Dapr capability is no longer observed", controlplane.ErrPrerequisite)
		}
	case "PRODUCT_MANAGED":
		if !s.daprRuntimeReady || s.daprRuntimeDigest != request.RuntimeLockDigest ||
			daprRuntimeImageByRole(s.daprRuntimeLock, "sidecar") != request.ExpectedSidecarImage {
			return fmt.Errorf("%w: product-managed Dapr runtime authority changed", controlplane.ErrPrerequisite)
		}
		runtimeExecutor, executorErr := daprruntime.ExecutorAuthorityFromRuntimeLock(s.daprRuntimeLock)
		if executorErr != nil || !daprruntime.ExecutorAuthoritiesEqual(runtimeExecutor, s.daprExecutorAuthority) {
			return fmt.Errorf("%w: Dapr runtime executor authority diverged", controlplane.ErrPrerequisite)
		}
		observed, observedErr := s.latestDaprObserved(ctx, request.ProjectID, request.ClusterID)
		if observedErr != nil {
			return observedErr
		}
		if observed == nil || !observed.Installed || observed.RuntimeLockDigest != request.RuntimeLockDigest {
			return fmt.Errorf("%w: product-managed Dapr runtime observation changed", controlplane.ErrPrerequisite)
		}
	default:
		return fmt.Errorf("%w: invalid Dapr workload runtime mode", controlplane.ErrValidation)
	}
	return nil
}

func (s *Server) buildDaprWorkloadAdmissionRequest(ctx context.Context, input daprWorkloadAdmissionInput) (daprruntime.WorkloadAdmissionRequest, targetmodel.DaprTargetAdmission, error) {
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.ClusterID = strings.TrimSpace(input.ClusterID)
	input.TraitID = strings.TrimSpace(input.TraitID)
	input.WorkloadImage = strings.TrimSpace(input.WorkloadImage)
	if input.ProjectID == "" || input.ClusterID == "" || input.TraitID == "" {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, fmt.Errorf("%w: projectId, clusterId and traitId are required", controlplane.ErrValidation)
	}
	appStore, ok := s.store.(interface {
		GetCapabilityTrait(context.Context, string) (controlplane.CapabilityTrait, error)
	})
	if !ok {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, fmt.Errorf("%w: capability trait authority unavailable", controlplane.ErrPrerequisite)
	}
	trait, err := appStore.GetCapabilityTrait(ctx, input.TraitID)
	if err != nil {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, err
	}
	if trait.ProjectID != input.ProjectID || trait.Kind != "sidecar" || trait.Capability != controlplane.ApplicationRuntimeDaprCapability {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, fmt.Errorf("%w: trait is not the project Dapr sidecar capability", controlplane.ErrValidation)
	}
	if !s.daprExecutorReady {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, fmt.Errorf("%w: exact Dapr executor image authority is unavailable", controlplane.ErrPrerequisite)
	}
	cluster, err := s.store.GetManagedCluster(ctx, input.ClusterID)
	if err != nil {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, err
	}
	if cluster.ProjectID != input.ProjectID {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, controlplane.ErrNotFound
	}
	inventory, err := s.store.GetLatestClusterInventory(ctx, cluster.ID)
	if err != nil {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, err
	}
	if !controlplane.ClusterInventoryAuthorityFreshAt(cluster, time.Now().UTC()) {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, fmt.Errorf("%w: fresh target inventory is required", controlplane.ErrPrerequisite)
	}
	if !controlplane.ClusterTaskAdmitted(cluster) {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, fmt.Errorf("%w: target is not admitted for Agent tasks", controlplane.ErrPrerequisite)
	}
	if !inventory.APIDiscoveryComplete || !inventory.CRDDiscoveryComplete || !inventory.SchemaDiscoveryComplete ||
		!openChoreoInventoryCapability(inventory, "strict-schema-dry-run") {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, fmt.Errorf("%w: complete target discovery and strict schema dry-run capability are required", controlplane.ErrPrerequisite)
	}
	if !openChoreoInventoryCapability(inventory, controlplane.TargetMutationRBACActiveCapability) ||
		!openChoreoInventoryCapability(inventory, controlplane.DaprWorkloadAdmissionRBACCapability) {
		return daprruntime.WorkloadAdmissionRequest{}, targetmodel.DaprTargetAdmission{}, fmt.Errorf("%w: target Dapr workload admission prober RBAC is not active", controlplane.ErrPrerequisite)
	}
	admission := s.daprAdmissionForCluster(cluster, inventory, false)
	plan, err := targetmodel.ResolveDaprWorkloadRuntimePlan(targetmodel.DaprWorkloadPlanInput{
		Namespace: input.Namespace, AppID: input.AppID, AppPort: input.AppPort, AppProtocol: input.AppProtocol,
		CPURequest: input.CPURequest, CPULimit: input.CPULimit, MemoryRequest: input.MemoryRequest, MemoryLimit: input.MemoryLimit,
		ComponentNames: append([]string(nil), input.ComponentNames...),
		EnablePubSub: input.EnablePubSub, EnableBindings: input.EnableBindings, EnableInvocation: input.EnableInvocation,
	})
	if err != nil {
		return daprruntime.WorkloadAdmissionRequest{}, admission, err
	}
	planDigest, err := daprruntime.WorkloadPlanDigest(plan)
	if err != nil {
		return daprruntime.WorkloadAdmissionRequest{}, admission, err
	}
	request := daprruntime.WorkloadAdmissionRequest{
		Authority: daprruntime.WorkloadAdmissionAuthority,
		ProjectID: input.ProjectID, ClusterID: input.ClusterID,
		TraitID: trait.ID, TraitDigest: trait.Digest,
		InventoryDigest: inventory.Digest,
		ExecutorEvidenceDigest: s.daprExecutorAuthority.EvidenceDigest,
		ExecutorSourceReleaseDigest: s.daprExecutorAuthority.SourceReleaseDigest,
		ExecutorImageReference: s.daprExecutorAuthority.ImageReference,
		WorkloadImage: input.WorkloadImage,
		Plan: plan, PlanDigest: planDigest,
	}
	if admission.Mode == "USE_NATIVE" && admission.Eligible {
		request.RuntimeMode = "USE_NATIVE"
	} else {
		if !s.daprRuntimeReady {
			return daprruntime.WorkloadAdmissionRequest{}, admission, fmt.Errorf("%w: product-managed Dapr runtime authority is unavailable", controlplane.ErrPrerequisite)
		}
		observed, observedErr := s.latestDaprObserved(ctx, input.ProjectID, input.ClusterID)
		if observedErr != nil {
			return daprruntime.WorkloadAdmissionRequest{}, admission, observedErr
		}
		if observed == nil || !observed.Installed || observed.RuntimeLockDigest != s.daprRuntimeDigest {
			return daprruntime.WorkloadAdmissionRequest{}, admission, fmt.Errorf("%w: Dapr runtime is not currently installed with admitted authority", controlplane.ErrPrerequisite)
		}
		request.RuntimeMode = "PRODUCT_MANAGED"
		request.RuntimeLockDigest = s.daprRuntimeDigest
		request.ExpectedSidecarImage = daprRuntimeImageByRole(s.daprRuntimeLock, "sidecar")
	}
	request, err = daprruntime.CanonicalWorkloadAdmissionRequest(request)
	return request, admission, err
}

func (s *Server) createDaprWorkloadAdmission(w http.ResponseWriter, r *http.Request) {
	var input daprWorkloadAdmissionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if _, err := s.requireProjectAccess(r, input.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	request, admission, err := s.buildDaprWorkloadAdmissionRequest(r.Context(), input)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	payload, requestDigest, err := daprruntime.MarshalWorkloadAdmissionRequest(request)
	if err != nil {
		writeStoreError(w, fmt.Errorf("%w: %v", controlplane.ErrValidation, err))
		return
	}
	key, err := requiredIdempotencyKey(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", err.Error())
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	queueStore, ok := s.store.(queuedRequestPayloadStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "DAPR_WORKLOAD_ADMISSION_QUEUE_UNAVAILABLE", "durable queued request payload authority is unavailable")
		return
	}
	op, replay, err := queueStore.CreateOperationQueuedWithPayload(r.Context(), controlplane.OperationRequest{
		ProjectID: request.ProjectID, Kind: daprWorkloadAdmissionOperationKind,
		TargetRef: daprWorkloadAdmissionTarget(request.ClusterID, request.Plan.Namespace, request.Plan.AppID),
		DesiredRevision: requestDigest, Risk: "low", Class: controlplane.OperationClassReadOnly,
	}, key, actor, r.Header.Get("X-Request-ID"), daprruntime.WorkloadAdmissionPayloadMediaType, payload)
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
		"authority": daprruntime.WorkloadAdmissionAuthority,
		"operation": op, "request": request, "targetAdmission": admission,
		"idempotentReplay": replay, "runtimeMutationPerformed": false,
		"sidecarPullObserved": false, "physicalCertificationInferred": false,
	})
}

func (s *Server) getDaprWorkloadAdmission(w http.ResponseWriter, r *http.Request) {
	op, err := s.store.GetOperation(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != daprWorkloadAdmissionOperationKind {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Dapr workload admission not found")
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	request, err := daprruntime.ParseWorkloadAdmissionRequest(sealed.Payload, sealed.PayloadDigest)
	if err != nil {
		writeError(w, http.StatusConflict, "DAPR_WORKLOAD_ADMISSION_REQUEST_INVALID", err.Error())
		return
	}
	out := map[string]any{"authority": daprruntime.WorkloadAdmissionAuthority, "operation": op, "request": request, "ready": false, "physicalCertificationInferred": false}
	evidence, err := s.store.ListEvidence(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, item := range evidence {
		if item.Kind != daprWorkloadAdmissionEvidenceKind || !item.HasPayload {
			continue
		}
		_, payload, getErr := s.store.GetEvidencePayload(r.Context(), item.ID)
		if getErr != nil {
			writeStoreError(w, getErr)
			return
		}
		var value daprruntime.WorkloadAdmissionEvidence
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(&value); decodeErr != nil || daprruntime.ValidateWorkloadAdmissionEvidence(value, request, op.ID) != nil {
			writeError(w, http.StatusConflict, "DAPR_WORKLOAD_ADMISSION_EVIDENCE_INVALID", "sealed workload admission evidence failed validation")
			return
		}
		out["evidence"] = value
		out["evidenceDigest"] = item.Digest
		currentErr := s.validateDaprWorkloadAdmissionCurrentAuthority(r.Context(), request)
		out["currentAuthority"] = currentErr == nil
		out["ready"] = currentErr == nil && op.State == controlplane.OperationSucceeded
		if currentErr != nil {
			out["stale"] = true
		}
		break
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) nextDaprWorkloadAdmissionTask(w http.ResponseWriter, r *http.Request) {
	clusterID := strings.TrimSpace(r.PathValue("id"))
	if _, err := s.agentCredentialDigest(r, clusterID); err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	pager, ok := s.store.(daprWorkloadAdmissionOperationPager)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "DAPR_WORKLOAD_ADMISSION_QUEUE_UNAVAILABLE", "bounded Dapr workload admission queue is unavailable")
		return
	}
	jobs, err := pager.ListClaimableOperationsByKindTargetPrefix(r.Context(), daprWorkloadAdmissionOperationKind, daprWorkloadAdmissionTargetPrefix+clusterID+":", time.Now().UTC(), 8)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, candidate := range jobs {
		claim, claimErr := s.store.ClaimOperation(r.Context(), candidate.ID, "agent:"+clusterID, daprWorkloadAdmissionLease, time.Now().UTC())
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
		request, parseErr := daprruntime.ParseWorkloadAdmissionRequest(sealed.Payload, sealed.PayloadDigest)
		fenceErr := parseErr
		if fenceErr == nil && request.ClusterID != clusterID {
			fenceErr = fmt.Errorf("%w: Dapr workload admission cluster scope changed", controlplane.ErrPrerequisite)
		}
		if fenceErr == nil {
			fenceErr = s.validateDaprWorkloadAdmissionCurrentAuthority(r.Context(), request)
		}
		if fenceErr != nil {
			op, startErr := s.store.StartOperationAttempt(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, "agent:"+clusterID)
			if startErr == nil {
				_, startErr = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, "agent:"+clusterID, claim.FenceToken, controlplane.OperationFailureReport{
					Class: controlplane.OperationFailurePermanent, Code: "DAPR_WORKLOAD_ADMISSION_FENCE_CHANGED",
					Message: "target inventory, runtime or sealed workload admission authority changed before dispatch",
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
		var runtimeLock *daprruntime.RuntimeLock
		if request.RuntimeMode == "PRODUCT_MANAGED" {
			locked := s.daprRuntimeLock
			runtimeLock = &locked
		}
		writeJSON(w, http.StatusOK, daprWorkloadAdmissionTask{
			OperationID: op.ID, OperationRevision: op.Revision, TaskFenceToken: claim.FenceToken,
			LeaseExpiresAt: claim.LeaseExpiresAt, Request: request,
			ExecutorAuthority: s.daprExecutorAuthority, RuntimeLock: runtimeLock,
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reportDaprWorkloadAdmissionTask(w http.ResponseWriter, r *http.Request) {
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
	var result daprWorkloadAdmissionResult
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
	if op.Kind != daprWorkloadAdmissionOperationKind || op.Revision != rev {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	request, err := daprruntime.ParseWorkloadAdmissionRequest(sealed.Payload, sealed.PayloadDigest)
	if err != nil || request.ClusterID != clusterID {
		writeError(w, http.StatusForbidden, "AGENT_SCOPE_MISMATCH", "Dapr workload admission belongs to another cluster")
		return
	}
	worker := "agent:" + clusterID
	if !result.Success {
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "target Dapr workload server-side dry-run failed"
		}
		op, err = s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{
			Class: controlplane.OperationFailureDependencyUnavailable, Code: "DAPR_WORKLOAD_ADMISSION_FAILED", Message: message,
		}, worker)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"operation": op, "admitted": false})
		return
	}
	if fenceErr := s.validateDaprWorkloadAdmissionCurrentAuthority(r.Context(), request); fenceErr != nil {
		updated, reportErr := s.store.ReportOperationFailure(r.Context(), op.ID, op.Revision, worker, result.TaskFenceToken, controlplane.OperationFailureReport{
			Class: controlplane.OperationFailurePermanent,
			Code: "DAPR_WORKLOAD_ADMISSION_RESULT_FENCE_CHANGED",
			Message: "target inventory, RBAC, executor or runtime authority changed before workload admission result commit",
		}, worker)
		if reportErr != nil {
			writeStoreError(w, reportErr)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"operation": updated, "admitted": false, "staleResultRejected": true,
			"runtimeMutationPerformed": false, "sidecarPullObserved": false, "physicalCertificationInferred": false,
		})
		return
	}
	if result.Evidence == nil {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_WORKLOAD_ADMISSION_EVIDENCE_REQUIRED", "successful dry-run requires canonical sidecar admission evidence")
		return
	}
	if err = daprruntime.ValidateWorkloadAdmissionEvidence(*result.Evidence, request, op.ID); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_WORKLOAD_ADMISSION_EVIDENCE_INVALID", err.Error())
		return
	}
	digest, err := daprruntime.WorkloadAdmissionEvidenceDigest(*result.Evidence, request, op.ID)
	if err != nil || digest != strings.ToLower(strings.TrimSpace(result.EvidenceDigest)) {
		writeError(w, http.StatusUnprocessableEntity, "DAPR_WORKLOAD_ADMISSION_EVIDENCE_DIGEST_MISMATCH", "canonical evidence digest mismatch")
		return
	}
	payload, _ := json.Marshal(result.Evidence)
	meta := controlplane.EvidenceMetadata{OperationID: op.ID, Kind: daprWorkloadAdmissionEvidenceKind, Digest: digest, MediaType: "application/json", Size: int64(len(payload))}
	if _, err = s.store.AppendOperationEvidencePayload(r.Context(), meta, payload, worker, result.TaskFenceToken, worker); err != nil {
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
		"operation": op, "admitted": true, "evidenceDigest": digest,
		"runtimeMutationPerformed": false, "sidecarPullObserved": false, "physicalCertificationInferred": false,
	})
}
