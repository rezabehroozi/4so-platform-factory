package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/fleethealth"
	"platform.4so.io/factory/internal/supportbundle"
)

const (
	supportBundleOperationKind = "support.bundle.generate"
	supportBundleWorkerID      = "support-bundle-worker"
	supportBundleWorkerLease   = 2 * time.Minute
	supportBundleWorkerBatch   = 8
)

type supportBundleArtifact struct {
	Raw          []byte
	Manifest     supportbundle.Manifest
	Verification supportbundle.Verification
	Filename     string
}

type supportBundleOperationPager interface {
	ListClaimableOperationsByKind(context.Context, string, time.Time, int) ([]controlplane.Operation, error)
}

func normalizeSupportBundleRequest(input supportBundleRequest) supportBundleRequest {
	input.Profile = strings.TrimSpace(input.Profile)
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	input.ClusterID = strings.TrimSpace(input.ClusterID)
	input.OperationID = strings.TrimSpace(input.OperationID)
	return input
}

func supportBundleTarget(input supportBundleRequest) (string, error) {
	raw, err := json.Marshal(normalizeSupportBundleRequest(input))
	if err != nil {
		return "", err
	}
	return "support-bundle:" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func parseSupportBundleTarget(target string) (supportBundleRequest, error) {
	const prefix = "support-bundle:"
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, prefix) {
		return supportBundleRequest{}, fmt.Errorf("%w: invalid support bundle target", controlplane.ErrValidation)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(target, prefix))
	if err != nil {
		return supportBundleRequest{}, fmt.Errorf("%w: invalid support bundle target encoding", controlplane.ErrValidation)
	}
	var input supportBundleRequest
	if err = json.Unmarshal(raw, &input); err != nil {
		return supportBundleRequest{}, fmt.Errorf("%w: invalid support bundle target payload", controlplane.ErrValidation)
	}
	return normalizeSupportBundleRequest(input), nil
}

func supportBundleRequestDigest(input supportBundleRequest) string {
	raw, _ := json.Marshal(normalizeSupportBundleRequest(input))
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *Server) authorizeSupportBundleRequest(r *http.Request, input supportBundleRequest) (string, error) {
	input = normalizeSupportBundleRequest(input)
	switch input.Profile {
	case "fleet-diagnostics":
		if input.ProjectID == "" {
			return "", fmt.Errorf("%w: projectId is required for fleet-diagnostics", controlplane.ErrValidation)
		}
		if _, err := s.requireProjectAccess(r, input.ProjectID, organizationRead); err != nil {
			return "", err
		}
		return input.ProjectID, nil
	case "cluster-diagnostics":
		if input.ClusterID == "" {
			return "", fmt.Errorf("%w: clusterId is required for cluster-diagnostics", controlplane.ErrValidation)
		}
		cluster, err := s.store.GetManagedCluster(r.Context(), input.ClusterID)
		if err != nil {
			return "", err
		}
		if _, err = s.requireProjectAccess(r, cluster.ProjectID, organizationRead); err != nil {
			return "", err
		}
		return cluster.ProjectID, nil
	case "operation-diagnostics":
		if input.OperationID == "" {
			return "", fmt.Errorf("%w: operationId is required for operation-diagnostics", controlplane.ErrValidation)
		}
		op, err := s.store.GetOperation(r.Context(), input.OperationID)
		if err != nil {
			return "", err
		}
		if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
			return "", err
		}
		return op.ProjectID, nil
	default:
		return "", fmt.Errorf("%w: profile must be fleet-diagnostics, cluster-diagnostics or operation-diagnostics", controlplane.ErrValidation)
	}
}

func (s *Server) clusterTimelineEventsContext(ctx context.Context, cluster controlplane.ManagedCluster) ([]controlplane.AuditEvent, error) {
	pager, ok := s.store.(clusterTimelinePageStore)
	if !ok {
		return nil, fmt.Errorf("%w: cluster timeline requires bounded scoped audit pager", controlplane.ErrPrerequisite)
	}
	return pager.ListClusterTimelineAuditPage(ctx, cluster.ID, 200)
}

func (s *Server) projectAuditEventsContext(ctx context.Context, project controlplane.Project) ([]controlplane.AuditEvent, error) {
	pager, ok := s.store.(auditScopedPageStore)
	if !ok {
		return nil, fmt.Errorf("%w: project audit diagnostics require bounded scoped audit pager", controlplane.ErrPrerequisite)
	}
	return pager.ListAuditPageByScopes(ctx, nil, []string{project.ID}, 1000)
}

func (s *Server) generateSupportBundle(ctx context.Context, input supportBundleRequest, now time.Time) (supportBundleArtifact, error) {
	input = normalizeSupportBundleRequest(input)
	files := map[string]any{"support-policy.json": fleethealth.SnapshotPolicy(now)}
	scope := map[string]any{}
	filename := "4so-support-bundle.zip"
	switch input.Profile {
	case "fleet-diagnostics":
		project, err := s.store.GetProject(ctx, input.ProjectID)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		clusterPager, ok := s.store.(managedClusterPageStore)
		if !ok {
			return supportBundleArtifact{}, fmt.Errorf("%w: fleet support bundles require a bounded cluster pager", controlplane.ErrPrerequisite)
		}
		clusters, err := clusterPager.ListManagedClustersPage(ctx, []string{input.ProjectID}, false, nil, 51)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		if len(clusters) > 50 {
			return supportBundleArtifact{}, fmt.Errorf("%w: fleet-diagnostics is limited to 50 clusters", controlplane.ErrValidation)
		}
		details := make([]clusterSupportSnapshot, 0, len(clusters))
		for _, cluster := range clusters {
			inventory, err := optionalClusterInventory(s.store, ctx, cluster.ID)
			if err != nil {
				return supportBundleArtifact{}, err
			}
			certs, err := s.store.ListAgentCertificates(ctx, cluster.ID)
			if err != nil {
				return supportBundleArtifact{}, err
			}
			timeline, err := s.clusterTimelineEventsContext(ctx, cluster)
			if err != nil {
				return supportBundleArtifact{}, err
			}
			details = append(details, clusterSupportSnapshot{Cluster: cluster, Inventory: inventory, Certificates: certs, Health: fleethealth.Evaluate(cluster, inventory, certs, now), Timeline: timeline})
		}
		opPager, ok := s.store.(operationPageStore)
		if !ok {
			return supportBundleArtifact{}, fmt.Errorf("%w: fleet support bundles require bounded operation paging", controlplane.ErrPrerequisite)
		}
		operations, err := opPager.ListOperationsPage(ctx, input.ProjectID, 201)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		if len(operations) > 200 {
			return supportBundleArtifact{}, fmt.Errorf("%w: fleet-diagnostics is limited to 200 recent operations", controlplane.ErrValidation)
		}
		audit, err := s.projectAuditEventsContext(ctx, project)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		files["project.json"], files["clusters.json"], files["operations.json"], files["audit.json"] = project, details, operations, audit
		scope = map[string]any{"projectId": project.ID, "organizationId": project.OrganizationID}
		filename = "4so-fleet-support-" + safeFileName(project.Name) + ".zip"
	case "cluster-diagnostics":
		cluster, err := s.store.GetManagedCluster(ctx, input.ClusterID)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		inventory, err := optionalClusterInventory(s.store, ctx, cluster.ID)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		certs, err := s.store.ListAgentCertificates(ctx, cluster.ID)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		timeline, err := s.clusterTimelineEventsContext(ctx, cluster)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		files["cluster.json"] = clusterSupportSnapshot{Cluster: cluster, Inventory: inventory, Certificates: certs, Health: fleethealth.Evaluate(cluster, inventory, certs, now), Timeline: timeline}
		scope = map[string]any{"projectId": cluster.ProjectID, "clusterId": cluster.ID}
		filename = "4so-cluster-support-" + safeFileName(cluster.Name) + ".zip"
	case "operation-diagnostics":
		operation, err := s.store.GetOperation(ctx, input.OperationID)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		steps, err := s.store.ListOperationSteps(ctx, operation.ID)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		evidence, err := s.store.ListEvidence(ctx, operation.ID)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		project, err := s.store.GetProject(ctx, operation.ProjectID)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		audit, err := s.projectAuditEventsContext(ctx, project)
		if err != nil {
			return supportBundleArtifact{}, err
		}
		related := make([]controlplane.AuditEvent, 0)
		for _, event := range audit {
			if event.ResourceID == operation.ID || metadataString(event.Metadata, "operationId") == operation.ID {
				related = append(related, event)
			}
		}
		sort.SliceStable(related, func(i, j int) bool { return related[i].OccurredAt.Before(related[j].OccurredAt) })
		files["operation.json"] = map[string]any{"operation": operation, "steps": steps, "evidence": evidence, "audit": related}
		scope = map[string]any{"projectId": operation.ProjectID, "operationId": operation.ID}
		filename = "4so-operation-support-" + safeFileName(operation.ID) + ".zip"
	default:
		return supportBundleArtifact{}, fmt.Errorf("%w: invalid support bundle profile", controlplane.ErrValidation)
	}
	raw, manifest, err := supportbundle.Build(supportbundle.Input{ProductVersion: s.version, Profile: input.Profile, Scope: scope, GeneratedAt: now.UTC(), Files: files})
	if err != nil {
		return supportBundleArtifact{}, err
	}
	verification, err := supportbundle.Verify(raw)
	if err != nil || !verification.Valid {
		return supportBundleArtifact{}, fmt.Errorf("%w: generated support bundle failed verification", controlplane.ErrPrerequisite)
	}
	return supportBundleArtifact{Raw: raw, Manifest: manifest, Verification: verification, Filename: filename}, nil
}

func (s *Server) createSupportBundleJob(w http.ResponseWriter, r *http.Request) {
	var input supportBundleRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input = normalizeSupportBundleRequest(input)
	projectID, err := s.authorizeSupportBundleRequest(r, input)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required")
		return
	}
	target, err := supportBundleTarget(input)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	actor, actorErr := actorID(r)
	if actorErr != nil {
		writeError(w, http.StatusBadRequest, "ACTOR_REQUIRED", actorErr.Error())
		return
	}
	op, replay, err := s.store.CreateOperation(r.Context(), controlplane.OperationRequest{ProjectID: projectID, Kind: supportBundleOperationKind, TargetRef: target, DesiredRevision: supportBundleRequestDigest(input), Risk: "low", Class: controlplane.OperationClassReadOnly}, key, actor, r.Header.Get("X-Request-ID"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !replay && op.State == controlplane.OperationDraft {
		op, err = s.store.TransitionOperation(r.Context(), op.ID, op.Revision, controlplane.OperationPlanning, "", actor)
		if err == nil {
			op, err = s.store.TransitionOperation(r.Context(), op.ID, op.Revision, controlplane.OperationQueued, "", actor)
		}
		if err != nil {
			writeStoreError(w, err)
			return
		}
	}
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"operation": op, "replay": replay, "statusUrl": "/api/v1/support-bundle-jobs/" + op.ID})
}

func (s *Server) getSupportBundleJob(w http.ResponseWriter, r *http.Request) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != supportBundleOperationKind {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "support bundle job not found")
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	evidence, err := s.store.ListEvidence(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var bundle *controlplane.EvidenceMetadata
	for i := range evidence {
		if evidence[i].Kind == "support-bundle" && evidence[i].HasPayload {
			v := evidence[i]
			bundle = &v
			break
		}
	}
	out := map[string]any{"operation": op, "ready": bundle != nil}
	if bundle != nil {
		out["evidence"] = bundle
		out["downloadUrl"] = "/api/v1/support-bundle-jobs/" + op.ID + "/download"
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) downloadSupportBundleJob(w http.ResponseWriter, r *http.Request) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if op.Kind != supportBundleOperationKind {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "support bundle job not found")
		return
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	evidence, err := s.store.ListEvidence(r.Context(), op.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, item := range evidence {
		if item.Kind != "support-bundle" || !item.HasPayload {
			continue
		}
		_, payload, err := s.store.GetEvidencePayload(r.Context(), item.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		verification, verifyErr := supportbundle.Verify(payload)
		if verifyErr != nil || !verification.Valid {
			writeError(w, http.StatusConflict, "SUPPORT_BUNDLE_EVIDENCE_INVALID", "sealed support bundle failed verification")
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="4so-support-bundle-`+safeFileName(op.ID)+`.zip"`)
		w.Header().Set("X-Support-Bundle-Digest", verification.Digest)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return
	}
	writeError(w, http.StatusConflict, "SUPPORT_BUNDLE_NOT_READY", "support bundle job has no sealed payload yet")
}

// ProcessSupportBundleJobsOnce executes one bounded durable job page. Multiple
// replicas may call it concurrently: ClaimOperation is the sole lease/fence
// authority, so only one worker can mutate a given operation attempt.
func (s *Server) ProcessSupportBundleJobsOnce(ctx context.Context, at time.Time) error {
	pager, ok := s.store.(supportBundleOperationPager)
	if !ok {
		return fmt.Errorf("%w: durable support bundle worker requires bounded operation queue", controlplane.ErrPrerequisite)
	}
	jobs, err := pager.ListClaimableOperationsByKind(ctx, supportBundleOperationKind, at.UTC(), supportBundleWorkerBatch)
	if err != nil {
		return err
	}
	for _, candidate := range jobs {
		claim, claimErr := s.store.ClaimOperation(ctx, candidate.ID, supportBundleWorkerID, supportBundleWorkerLease, at.UTC())
		if claimErr != nil {
			if errors.Is(claimErr, controlplane.ErrLeaseHeld) || errors.Is(claimErr, controlplane.ErrNotClaimable) {
				continue
			}
			return claimErr
		}
		op, getErr := s.store.GetOperation(ctx, candidate.ID)
		if getErr != nil {
			return getErr
		}
		op, getErr = s.store.StartOperationAttempt(ctx, op.ID, op.Revision, supportBundleWorkerID, claim.FenceToken, supportBundleWorkerID)
		if getErr != nil {
			return getErr
		}
		input, parseErr := parseSupportBundleTarget(op.TargetRef)
		if parseErr != nil {
			_, _ = s.store.ReportOperationFailure(ctx, op.ID, op.Revision, supportBundleWorkerID, claim.FenceToken, controlplane.OperationFailureReport{Class: controlplane.OperationFailurePermanent, Code: "SUPPORT_TARGET_INVALID", Message: parseErr.Error()}, supportBundleWorkerID)
			continue
		}
		artifact, buildErr := s.generateSupportBundle(ctx, input, at.UTC())
		if buildErr != nil {
			class := controlplane.OperationFailureDependencyUnavailable
			if errors.Is(buildErr, controlplane.ErrValidation) || errors.Is(buildErr, controlplane.ErrNotFound) {
				class = controlplane.OperationFailurePermanent
			}
			_, _ = s.store.ReportOperationFailure(ctx, op.ID, op.Revision, supportBundleWorkerID, claim.FenceToken, controlplane.OperationFailureReport{Class: class, Code: "SUPPORT_BUNDLE_GENERATION_FAILED", Message: buildErr.Error()}, supportBundleWorkerID)
			continue
		}
		meta := controlplane.EvidenceMetadata{OperationID: op.ID, Kind: "support-bundle", Digest: artifact.Verification.Digest, MediaType: "application/zip", Size: int64(len(artifact.Raw))}
		if _, err = s.store.AppendOperationEvidencePayload(ctx, meta, artifact.Raw, supportBundleWorkerID, claim.FenceToken, supportBundleWorkerID); err != nil {
			return err
		}
		// Evidence mutation does not change the operation revision. Verification
		// and completion remain lease/fence controlled and use the latest op.
		op, err = s.store.GetOperation(ctx, op.ID)
		if err != nil {
			return err
		}
		op, err = s.store.BeginOperationVerification(ctx, op.ID, op.Revision, supportBundleWorkerID, claim.FenceToken, supportBundleWorkerID)
		if err != nil {
			return err
		}
		if _, err = s.store.CompleteOperation(ctx, op.ID, op.Revision, supportBundleWorkerID, claim.FenceToken, supportBundleWorkerID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) RunSupportBundleWorker(ctx context.Context, poll time.Duration) {
	if poll <= 0 {
		poll = 2 * time.Second
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if err := s.ProcessSupportBundleJobsOnce(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
			s.logger.Error("support bundle worker iteration failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
