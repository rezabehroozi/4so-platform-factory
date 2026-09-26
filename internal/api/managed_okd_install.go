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
	"platform.4so.io/factory/internal/managedinstall"
)

const (
	managedOKDInstallOperationKind = "managed.okd.install"
	managedOKDInstallWorkerID      = "managed-okd-install-worker"
	managedOKDInstallWorkerLease   = 2 * time.Minute
	managedOKDInstallWorkerBatch   = 4
	managedOKDInstallEvidenceKind  = "managed-okd-install/"
)

type managedOKDInstallOperationPager interface {
	ListClaimableOperationsByKind(context.Context, string, time.Time, int) ([]controlplane.Operation, error)
}

type managedOKDInstallView struct {
	Operation      controlplane.Operation    `json:"operation"`
	Authority      string                    `json:"authority"`
	OrganizationID string                    `json:"organizationId"`
	ProjectID      string                    `json:"projectId"`
	TargetVersion  string                    `json:"targetVersion"`
	ClusterName    string                    `json:"clusterName"`
	BaseDomain     string                    `json:"baseDomain"`
	APIVIP         string                    `json:"apiVip"`
	IngressVIP     string                    `json:"ingressVip"`
	Connectivity   string                    `json:"connectivity"`
	MirrorRegistry string                    `json:"mirrorRegistry,omitempty"`
	MachineIDs     []string                  `json:"machineIds"`
	Artifacts      []managedinstall.Artifact `json:"artifacts"`
}

func (s *Server) managedOKDInstallRuntime(w http.ResponseWriter, r *http.Request) {
	if _, err := actorID(r); err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	connectedConfigured := s.managedOKDInstallExecutor != nil && s.managedOKDInstallExecutor.ConnectedReady()
	disconnectedConfigured := s.managedOKDInstallExecutor != nil && s.managedOKDInstallExecutor.DisconnectedReady()
	configured := connectedConfigured
	writeJSON(w, http.StatusOK, map[string]any{
		"authority":                    managedinstall.ExecutorAuthority,
		"configured":                   configured,
		"connectedRequestAllowed":      connectedConfigured,
		"disconnectedRequestAllowed":   disconnectedConfigured,
		"requestCreationAllowed":       configured,
		"requiresExactWorkspace":       true,
		"requiresIndependentApproval":  true,
		"physicalCertificationImplied": false,
	})
}

func redactedManagedOKDInstallView(op controlplane.Operation, req managedinstall.Request) managedOKDInstallView {
	ids := make([]string, 0, len(req.Machines))
	for _, machine := range req.Machines {
		ids = append(ids, machine.ID)
	}
	artifacts := make([]managedinstall.Artifact, len(req.Artifacts))
	copy(artifacts, req.Artifacts)
	view := managedOKDInstallView{Operation: op, Authority: managedinstall.Authority, OrganizationID: req.OrganizationID, ProjectID: req.ProjectID, TargetVersion: req.TargetVersion, ClusterName: req.ClusterName, BaseDomain: req.BaseDomain, APIVIP: req.APIVIP, IngressVIP: req.IngressVIP, Connectivity: req.Connectivity, MachineIDs: ids, Artifacts: artifacts}
	if req.Disconnected != nil {
		view.MirrorRegistry = req.Disconnected.MirrorRegistry
	}
	return view
}

func (s *Server) createManagedOKDInstall(w http.ResponseWriter, r *http.Request) {
	if s.managedOKDInstallExecutor == nil {
		writeError(w, http.StatusServiceUnavailable, "MANAGED_OKD_RUNTIME_UNAVAILABLE", "managed OKD production runtime is not configured")
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
	var req managedinstall.Request
	if err = decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	canonical, err := managedinstall.CanonicalRequest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_MANAGED_INSTALL", err.Error())
		return
	}
	if managedinstall.IsDisconnected(canonical) {
		if !s.managedOKDInstallExecutor.DisconnectedReady() {
			writeError(w, http.StatusServiceUnavailable, "DISCONNECTED_OKD_RUNTIME_UNAVAILABLE", "disconnected OKD runtime requires exact workspace/media validation, Redfish execution, oc-mirror v2 and managed mirror registry")
			return
		}
	} else if !s.managedOKDInstallExecutor.ConnectedReady() {
		writeError(w, http.StatusServiceUnavailable, "MANAGED_OKD_RUNTIME_UNAVAILABLE", "connected OKD runtime requires exact workspace/media validation and Redfish execution")
		return
	}
	project, err := s.requireProjectAccess(r, canonical.ProjectID, organizationWrite)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	if project.OrganizationID != canonical.OrganizationID {
		writeError(w, http.StatusConflict, "ORGANIZATION_PROJECT_MISMATCH", "organizationId does not own projectId")
		return
	}
	payload, desired, err := managedinstall.MarshalCanonicalRequest(canonical)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_MANAGED_INSTALL", err.Error())
		return
	}
	op, replay, err := s.store.CreateOperationAwaitingApprovalWithPayload(r.Context(), controlplane.OperationRequest{
		ProjectID: canonical.ProjectID, Kind: managedOKDInstallOperationKind,
		TargetRef:       "managed-okd-install/" + canonical.ClusterName,
		DesiredRevision: desired, Risk: "critical", Class: controlplane.OperationClassMutating,
	}, key, actor, r.Header.Get("X-Request-ID"), managedinstall.PayloadMediaType, payload)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"install": redactedManagedOKDInstallView(op, canonical), "idempotentReplay": replay})
}

func (s *Server) managedOKDInstallOperation(r *http.Request) (controlplane.Operation, managedinstall.Request, error) {
	op, err := s.store.GetOperation(r.Context(), strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		return controlplane.Operation{}, managedinstall.Request{}, err
	}
	if op.Kind != managedOKDInstallOperationKind {
		return controlplane.Operation{}, managedinstall.Request{}, controlplane.ErrNotFound
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
		return controlplane.Operation{}, managedinstall.Request{}, err
	}
	sealed, err := s.store.GetOperationRequestPayload(r.Context(), op.ID)
	if err != nil {
		return controlplane.Operation{}, managedinstall.Request{}, err
	}
	if sealed.MediaType != managedinstall.PayloadMediaType {
		return controlplane.Operation{}, managedinstall.Request{}, fmt.Errorf("%w: managed install payload media type mismatch", controlplane.ErrConflict)
	}
	req, err := managedinstall.ParseCanonicalRequest(sealed.Payload, op.DesiredRevision)
	return op, req, err
}

func (s *Server) getManagedOKDInstall(w http.ResponseWriter, r *http.Request) {
	op, req, err := s.managedOKDInstallOperation(r)
	if err != nil {
		if errors.Is(err, errOrganizationAccessDenied) {
			writeScopeError(w, err)
		} else {
			writeStoreError(w, err)
		}
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"install": redactedManagedOKDInstallView(op, req)})
}

func (s *Server) approveManagedOKDInstall(w http.ResponseWriter, r *http.Request) {
	op, req, err := s.managedOKDInstallOperation(r)
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
	op, err = s.store.ApproveOperationAndQueue(r.Context(), op.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	writeJSON(w, http.StatusAccepted, map[string]any{"install": redactedManagedOKDInstallView(op, req)})
}

func managedInstallEvidenceStep(kind string) managedinstall.Step {
	if !strings.HasPrefix(kind, managedOKDInstallEvidenceKind) {
		return ""
	}
	return managedinstall.Step(strings.TrimPrefix(kind, managedOKDInstallEvidenceKind))
}

func nextManagedInstallStep(evidence []controlplane.EvidenceMetadata, req managedinstall.Request) (managedinstall.Step, bool) {
	done := make(map[managedinstall.Step]bool)
	for _, ev := range evidence {
		if step := managedInstallEvidenceStep(ev.Kind); step != "" {
			done[step] = true
		}
	}
	for _, step := range managedinstall.OrderedStepsFor(req) {
		if !done[step] {
			return step, true
		}
	}
	return "", false
}

func managedInstallOperationToken(op controlplane.Operation) string {
	return op.ID + "@" + fmt.Sprintf("%d", op.CreatedAt.UTC().Unix())
}

func (s *Server) executeManagedOKDInstallStepWithLease(ctx context.Context, op controlplane.Operation, claim controlplane.ClaimResult, req managedinstall.Request, step managedinstall.Step, lease time.Duration) ([]byte, error, error) {
	if lease <= 0 {
		lease = managedOKDInstallWorkerLease
	}
	execCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	heartbeatDone := make(chan error, 1)
	interval := lease / 3
	if interval < 250*time.Millisecond {
		interval = lease / 2
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-execCtx.Done():
				heartbeatDone <- nil
				return
			case now := <-ticker.C:
				if _, err := s.store.RenewOperationLease(execCtx, op.ID, managedOKDInstallWorkerID, claim.FenceToken, lease, now.UTC()); err != nil {
					cancelExec()
					heartbeatDone <- err
					return
				}
			}
		}
	}()
	payload, execErr := s.managedOKDInstallExecutor.ExecuteStep(execCtx, step, req, managedInstallOperationToken(op))
	cancelExec()
	heartbeatErr := <-heartbeatDone
	if heartbeatErr != nil {
		return nil, execErr, fmt.Errorf("managed OKD install lease heartbeat lost fence: %w", heartbeatErr)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err(), nil
	}
	return payload, execErr, nil
}

// ProcessManagedOKDInstallJobsOnce advances at most one durable step per job.
// Releasing the lease after each sealed checkpoint makes crash recovery bounded
// and ensures another replica can resume with a strictly newer fence token.
func (s *Server) ProcessManagedOKDInstallJobsOnce(ctx context.Context, at time.Time) error {
	if s.managedOKDInstallExecutor == nil {
		return fmt.Errorf("%w: managed OKD install executor is not configured", controlplane.ErrPrerequisite)
	}
	pager, ok := s.store.(managedOKDInstallOperationPager)
	if !ok {
		return fmt.Errorf("%w: managed install worker requires bounded operation queue", controlplane.ErrPrerequisite)
	}
	jobs, err := pager.ListClaimableOperationsByKind(ctx, managedOKDInstallOperationKind, at.UTC(), managedOKDInstallWorkerBatch)
	if err != nil {
		return err
	}
	for _, candidate := range jobs {
		claim, claimErr := s.store.ClaimOperation(ctx, candidate.ID, managedOKDInstallWorkerID, managedOKDInstallWorkerLease, at.UTC())
		if claimErr != nil {
			if errors.Is(claimErr, controlplane.ErrLeaseHeld) || errors.Is(claimErr, controlplane.ErrNotClaimable) {
				continue
			}
			return claimErr
		}
		op, err := s.store.GetOperation(ctx, candidate.ID)
		if err != nil {
			return err
		}
		if op.State == controlplane.OperationQueued {
			op, err = s.store.StartOperationAttempt(ctx, op.ID, op.Revision, managedOKDInstallWorkerID, claim.FenceToken, managedOKDInstallWorkerID)
			if err != nil {
				return err
			}
		} else if op.State != controlplane.OperationRunning {
			_ = s.store.ReleaseOperationLease(ctx, op.ID, managedOKDInstallWorkerID, claim.FenceToken)
			continue
		}
		sealed, err := s.store.GetOperationRequestPayload(ctx, op.ID)
		if err != nil {
			return err
		}
		req, parseErr := managedinstall.ParseCanonicalRequest(sealed.Payload, op.DesiredRevision)
		if parseErr != nil || sealed.MediaType != managedinstall.PayloadMediaType {
			msg := "invalid sealed managed install request"
			if parseErr != nil {
				msg = parseErr.Error()
			}
			_, _ = s.store.ReportOperationFailure(ctx, op.ID, op.Revision, managedOKDInstallWorkerID, claim.FenceToken, controlplane.OperationFailureReport{Class: controlplane.OperationFailurePermanent, Code: "MANAGED_INSTALL_REQUEST_INVALID", Message: msg}, managedOKDInstallWorkerID)
			continue
		}
		evidence, err := s.store.ListEvidence(ctx, op.ID)
		if err != nil {
			return err
		}
		step, pending := nextManagedInstallStep(evidence, req)
		if !pending {
			op, err = s.store.BeginOperationVerification(ctx, op.ID, op.Revision, managedOKDInstallWorkerID, claim.FenceToken, managedOKDInstallWorkerID)
			if err != nil {
				return err
			}
			if _, err = s.store.CompleteOperation(ctx, op.ID, op.Revision, managedOKDInstallWorkerID, claim.FenceToken, managedOKDInstallWorkerID); err != nil {
				return err
			}
			continue
		}
		payload, execErr, heartbeatErr := s.executeManagedOKDInstallStepWithLease(ctx, op, claim, req, step, managedOKDInstallWorkerLease)
		if heartbeatErr != nil {
			return heartbeatErr
		}
		// Lease renewal advances the durable operation revision. Re-read the
		// operation before any fenced evidence/failure mutation so a healthy
		// heartbeat cannot make the worker fail on its own stale revision.
		op, err = s.store.GetOperation(ctx, op.ID)
		if err != nil {
			return err
		}
		if op.FenceToken != claim.FenceToken || strings.TrimSpace(op.LeaseOwner) != managedOKDInstallWorkerID {
			return fmt.Errorf("%w: managed OKD install lease fence changed during step execution", controlplane.ErrStaleFence)
		}
		if execErr != nil {
			class := controlplane.OperationFailureDependencyUnavailable
			if errors.Is(execErr, controlplane.ErrValidation) {
				class = controlplane.OperationFailurePermanent
			}
			_, _ = s.store.ReportOperationFailure(ctx, op.ID, op.Revision, managedOKDInstallWorkerID, claim.FenceToken, controlplane.OperationFailureReport{Class: class, Code: "MANAGED_INSTALL_STEP_FAILED", Message: execErr.Error()}, managedOKDInstallWorkerID)
			continue
		}
		if _, err = s.store.AppendOperationEvidencePayload(ctx, controlplane.EvidenceMetadata{OperationID: op.ID, Kind: managedOKDInstallEvidenceKind + string(step), MediaType: "application/json"}, payload, managedOKDInstallWorkerID, claim.FenceToken, managedOKDInstallWorkerID); err != nil {
			return err
		}
		op, err = s.store.GetOperation(ctx, op.ID)
		if err != nil {
			return err
		}
		if step == managedinstall.StepComplete {
			op, err = s.store.BeginOperationVerification(ctx, op.ID, op.Revision, managedOKDInstallWorkerID, claim.FenceToken, managedOKDInstallWorkerID)
			if err != nil {
				return err
			}
			if _, err = s.store.CompleteOperation(ctx, op.ID, op.Revision, managedOKDInstallWorkerID, claim.FenceToken, managedOKDInstallWorkerID); err != nil {
				return err
			}
			continue
		}
		if err = s.store.ReleaseOperationLease(ctx, op.ID, managedOKDInstallWorkerID, claim.FenceToken); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) RunManagedOKDInstallWorker(ctx context.Context, poll time.Duration) {
	if poll <= 0 {
		poll = 2 * time.Second
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if err := s.ProcessManagedOKDInstallJobsOnce(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
			s.logger.Error("managed OKD install worker iteration failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

var _ = json.Marshal
