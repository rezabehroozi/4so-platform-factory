package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"platform.4so.io/factory/internal/baseline"
	"platform.4so.io/factory/internal/controlplane"
	"strings"
	"time"
)

type createBaselineDeploymentInput struct {
	ProjectID       string `json:"projectId"`
	ClusterID       string `json:"clusterId"`
	BaselineID      string `json:"baselineId"`
	BaselineVersion string `json:"baselineVersion,omitempty"`
}

func (s *Server) listBaselines(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, baseline.Catalog())
}

func (s *Server) createBaselineDeployment(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		writeError(w, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required and must be at most 200 characters")
		return
	}
	var in createBaselineDeploymentInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	version := strings.TrimSpace(in.BaselineVersion)
	if version == "" {
		version = baseline.SecureNamespaceVersion
	}
	def, ok := baseline.GetVersion(strings.TrimSpace(in.BaselineID), version)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, "BASELINE_NOT_FOUND", "selected baseline is not available")
		return
	}
	desired, err := baseline.DesiredDigestVersion(in.ProjectID, in.ClusterID, def.ID, def.Version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "BASELINE_DIGEST_FAILED", err.Error())
		return
	}
	raw, _ := json.Marshal(struct{ ProjectID, ClusterID, BaselineID, DesiredDigest string }{in.ProjectID, in.ClusterID, def.ID, desired})
	sum := sha256.Sum256(raw)
	requestDigest := "sha256:" + hex.EncodeToString(sum[:])
	v, replay, err := s.store.CreateBaselineDeployment(r.Context(), controlplane.BaselineDeployment{
		ProjectID: in.ProjectID, ClusterID: in.ClusterID, BaselineID: def.ID, BaselineVersion: def.Version,
		TargetNamespace: def.TargetNamespace, Risk: def.Risk, DesiredDigest: desired,
		RequestDigest: requestDigest, IdempotencyKey: key,
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
	writeJSON(w, status, map[string]any{"deployment": v, "idempotentReplay": replay, "next": "agent-read-only-plan"})
}

func (s *Server) listBaselineDeployments(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.BaselineDeployment, error)
	if pager, ok := s.store.(baselineDeploymentPageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.BaselineDeployment, error) {
			return pager.ListBaselineDeploymentsPage(r.Context(), ids, all, clusterID, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.BaselineDeployment, error) {
		return s.store.ListBaselineDeployments(r.Context(), projectID, clusterID)
	}, page, func(item controlplane.BaselineDeployment) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
}
func (s *Server) getBaselineDeployment(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetBaselineDeployment(r.Context(), r.PathValue("id"))
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

func (s *Server) getBaselineEvidenceArtifact(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetBaselineDeployment(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	key := strings.TrimSpace(r.PathValue("key"))
	for _, item := range v.Evidence {
		if item.Key != key {
			continue
		}
		if item.RetainUntil != nil && !time.Now().UTC().Before(*item.RetainUntil) {
			writeError(w, http.StatusGone, "EVIDENCE_RETENTION_EXPIRED", "baseline evidence retention window has expired")
			return
		}
		w.Header().Set("Content-Type", item.MediaType)
		w.Header().Set("X-Evidence-Digest", item.Digest)
		w.Header().Set("X-Evidence-Authority", item.Authority)
		if item.RetainUntil != nil {
			w.Header().Set("X-Evidence-Retain-Until", item.RetainUntil.UTC().Format(time.RFC3339))
		}
		writeJSON(w, http.StatusOK, item.Payload)
		return
	}
	writeError(w, http.StatusNotFound, "EVIDENCE_NOT_FOUND", "baseline evidence artifact was not found")
}
func (s *Server) approveBaselineDeployment(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetBaselineDeployment(r.Context(), r.PathValue("id"))
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
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.ApproveBaselineDeployment(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) revalidateBaselineDeployment(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetBaselineDeployment(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RevalidateBaselineDeployment(r.Context(), current.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusAccepted, v)
}

func (s *Server) retryBaselineDeployment(w http.ResponseWriter, r *http.Request) {
	current, lookupErr := s.store.GetBaselineDeployment(r.Context(), r.PathValue("id"))
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
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.RetryBaselineDeployment(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusAccepted, v)
}

func (s *Server) rollbackBaselineDeployment(w http.ResponseWriter, r *http.Request) {
	current, lookupErr := s.store.GetBaselineDeployment(r.Context(), r.PathValue("id"))
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
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
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
	v, err := s.store.QueueBaselineRollback(r.Context(), r.PathValue("id"), rev, actor, in.RecoveryCheckpointID, digestValue(in))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusAccepted, v)
}

func baselineAction(v controlplane.BaselineDeployment) string {
	switch v.State {
	case controlplane.BaselineDeploymentPlanning:
		return "PLAN"
	case controlplane.BaselineDeploymentApplying:
		return "APPLY"
	case controlplane.BaselineDeploymentRollingBack:
		return "ROLLBACK"
	default:
		return ""
	}
}

func (s *Server) nextBaselineTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, 401, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	v, err := s.store.NextBaselineTask(r.Context(), r.PathValue("id"), agentDigest)
	if errors.Is(err, controlplane.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	action := baselineAction(v)
	if action == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resources := baseline.ResourcesForVersion(v.ID, v.DesiredDigest, v.BaselineVersion)
	rollback := []controlplane.PlanRollbackResource(nil)
	if action == "ROLLBACK" {
		for i := range resources {
			resources[i].Object = nil
		}
		rollback = append(rollback, v.PlanImpact.Rollback.Resources...)
	}
	var inventory controlplane.ClusterInventory
	if action == "PLAN" {
		inventory, err = s.store.GetLatestClusterInventory(r.Context(), v.ClusterID)
		if err != nil || inventory.Digest == "" {
			writeError(w, http.StatusUnprocessableEntity, "PLAN_INVENTORY_REQUIRED", "fresh cluster inventory with API discovery is required before planning")
			return
		}
	}
	setRevisionETag(w, v.Revision)
	task := controlplane.BaselineTask{DeploymentID: v.ID, DeploymentRev: v.Revision, TaskFenceToken: v.TaskFenceToken, LeaseExpiresAt: *v.TaskLeaseExpiresAt, Action: action, BaselineID: v.BaselineID, BaselineVersion: v.BaselineVersion, TargetNamespace: v.TargetNamespace, DesiredDigest: v.DesiredDigest, Inventory: inventory, Resources: resources, Rollback: rollback}
	if action == "APPLY" {
		task.EvidencePlan = v.PlanImpact.Evidence
		task.PlanImpactDigest = v.PlanImpactDigest
	}
	writeJSON(w, http.StatusOK, task)
}
func (s *Server) reportBaselineTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, 401, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.BaselineTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	result.DeploymentID = r.PathValue("deploymentId")
	if strings.EqualFold(result.Action, "PLAN") && result.Success {
		deployment, lookupErr := s.store.GetBaselineDeployment(r.Context(), result.DeploymentID)
		if lookupErr != nil {
			writeStoreError(w, lookupErr)
			return
		}
		inventory, inventoryErr := s.store.GetLatestClusterInventory(r.Context(), deployment.ClusterID)
		if inventoryErr != nil {
			writeStoreError(w, inventoryErr)
			return
		}
		resources := baseline.ResourcesForVersion(deployment.ID, deployment.DesiredDigest, deployment.BaselineVersion)
		if impactErr := controlplane.ValidatePlanningImpactSemantics(result.Impact, inventory, resources, result.Changes); impactErr != nil {
			writeError(w, http.StatusUnprocessableEntity, "PLAN_IMPACT_INVALID", impactErr.Error())
			return
		}
		if impactErr := controlplane.ValidateEvidenceCollectionPlanSemantics(result.Impact.Evidence, deployment.ID, resources); impactErr != nil {
			writeError(w, http.StatusUnprocessableEntity, "PLAN_EVIDENCE_INVALID", impactErr.Error())
			return
		}
	}
	v, err := s.store.ReportBaselineTask(r.Context(), r.PathValue("id"), agentDigest, rev, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}
