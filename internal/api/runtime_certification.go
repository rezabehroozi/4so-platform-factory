package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
)

type createRuntimeCertificationInput struct {
	ProjectID        string `json:"projectId"`
	ClusterID        string `json:"clusterId"`
	CatalogReleaseID string `json:"catalogReleaseId"`
	Profile          string `json:"profile"`
	Namespace        string `json:"namespace"`
}

type certificationRenderContext struct {
	Revision         controlplane.CatalogRevision
	RenderedDigest   string
	SourceLockDigest string
	Resources        []map[string]any
}

func (s *Server) runtimeCertificationRenderContext(r *http.Request, release controlplane.CatalogRelease, namespace string) (certificationRenderContext, error) {
	if release.State != controlplane.CatalogPublished || !catalogChannelRenderable(release.Channel) {
		return certificationRenderContext{}, fmt.Errorf("published RENDER/RUNTIME/PRODUCTION catalog release is required")
	}
	if trust := s.trustStatus(r, release); !trust.Verified {
		return certificationRenderContext{}, fmt.Errorf("catalog trust invalid: %s", trust.Reason)
	}
	revision, err := s.store.GetCatalogRevision(r.Context(), release.CurrentRevisionID)
	if err != nil {
		return certificationRenderContext{}, err
	}
	components, err := catalog.ParseReleasePayload(revision.Payload)
	if err != nil {
		return certificationRenderContext{}, err
	}
	blockers := catalog.AdmissionBlockers(string(release.Channel), components)
	blockers = append(blockers, s.catalogCertificationAuthorityAdmission(r, release, components)...)
	if len(blockers) > 0 {
		sort.Strings(blockers)
		return certificationRenderContext{}, fmt.Errorf("catalog admission blocked: %s", strings.Join(blockers, "; "))
	}
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)
	// Certification is bound to the entire immutable catalog through the ordered
	// source-lock digest below, but installs only the dedicated six-resource
	// namespace harness. Applying every platform component here would duplicate
	// the product installation and makes TARGET_RUNTIME certification impossible
	// for a real multi-component catalog.
	foundation, ok := components["secure-namespace-foundation"]
	if !ok {
		return certificationRenderContext{}, fmt.Errorf("secure-namespace-foundation component is required for runtime certification")
	}
	for _, name := range names {
		component := components[name]
		if !component.Spec.Source.Resolved || !strings.HasPrefix(component.Spec.Source.SourceLockDigest, "sha256:") {
			return certificationRenderContext{}, fmt.Errorf("component %s is not source-lock resolved", name)
		}
	}
	rendered, renderErr := catalog.RenderComponent(foundation, namespace, release.ID)
	if renderErr != nil {
		return certificationRenderContext{}, renderErr
	}
	resources := rendered.Resources
	identityRaw, _ := json.Marshal(struct {
		CatalogReleaseID string           `json:"catalogReleaseId"`
		ManifestDigest   string           `json:"manifestDigest"`
		Namespace        string           `json:"namespace"`
		Resources        []map[string]any `json:"resources"`
	}{release.ID, release.ManifestDigest, namespace, resources})
	renderedSum := sha256.Sum256(identityRaw)
	return certificationRenderContext{
		Revision:         revision,
		RenderedDigest:   "sha256:" + hex.EncodeToString(renderedSum[:]),
		SourceLockDigest: catalog.SourceLockDigest(components),
		Resources:        resources,
	}, nil
}

func (s *Server) createRuntimeCertification(w http.ResponseWriter, r *http.Request) {
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
	var in createRuntimeCertificationInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	in.ProjectID, in.ClusterID, in.CatalogReleaseID, in.Namespace = strings.TrimSpace(in.ProjectID), strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.CatalogReleaseID), strings.TrimSpace(in.Namespace)
	profile := controlplane.RuntimeCertificationProfile(strings.ToUpper(strings.TrimSpace(in.Profile)))
	if profile == "" {
		profile = controlplane.RuntimeCertificationFoundationV1
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	cluster, err := s.store.GetManagedCluster(r.Context(), in.ClusterID)
	if err != nil || cluster.ProjectID != in.ProjectID {
		writeStoreError(w, controlplane.ErrNotFound)
		return
	}
	inventory, err := s.store.GetLatestClusterInventory(r.Context(), in.ClusterID)
	if err != nil || inventory.Digest == "" || inventory.Digest != cluster.InventoryDigest {
		writeError(w, http.StatusUnprocessableEntity, "RUNTIME_CERTIFICATION_INVENTORY_REQUIRED", "fresh digest-bearing cluster inventory is required")
		return
	}
	release, err := s.store.GetCatalogRelease(r.Context(), in.CatalogReleaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if release.Visibility == controlplane.CatalogVisibilityPrivate {
		if err = s.requireOrganizationAccess(r, release.OrganizationID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	rendered, err := s.runtimeCertificationRenderContext(r, release, in.Namespace)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "RUNTIME_CERTIFICATION_RENDER_INVALID", err.Error())
		return
	}
	requestDigest := digestValue(map[string]any{
		"projectId": in.ProjectID, "clusterId": in.ClusterID, "catalogReleaseId": in.CatalogReleaseID,
		"profile": profile, "namespace": in.Namespace, "inventoryDigest": inventory.Digest, "renderedDigest": rendered.RenderedDigest,
	})
	run, replay, err := s.store.CreateRuntimeCertification(r.Context(), controlplane.RuntimeCertificationRun{
		ProjectID: in.ProjectID, ClusterID: in.ClusterID, CatalogReleaseID: release.ID, CatalogRevisionID: rendered.Revision.ID,
		Profile: profile, Namespace: in.Namespace, InventoryDigest: inventory.Digest,
		EnvironmentFingerprint: controlplane.RuntimeEnvironmentFingerprint(inventory), ManifestDigest: release.ManifestDigest,
		SourceLockDigest: rendered.SourceLockDigest, RenderedDigest: rendered.RenderedDigest, ResourceCount: len(rendered.Resources),
		IdempotencyKey: key, RequestDigest: requestDigest,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, run.Revision)
	writeJSON(w, status, map[string]any{"run": run, "idempotentReplay": replay, "externalLiveCertified": false})
}

func (s *Server) listRuntimeCertifications(w http.ResponseWriter, r *http.Request) {
	projectID, clusterID := strings.TrimSpace(r.URL.Query().Get("projectId")), strings.TrimSpace(r.URL.Query().Get("clusterId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	items, err := s.store.ListRuntimeCertifications(r.Context(), projectID, clusterID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	items = filterProjectScoped(items, allowed, all, func(item controlplane.RuntimeCertificationRun) string { return item.ProjectID })
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) getRuntimeCertification(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetRuntimeCertification(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, run.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, run.Revision)
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) revokeRuntimeCertification(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	run, err := s.store.GetRuntimeCertification(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, run.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	updated, err := s.store.RevokeRuntimeCertification(r.Context(), run.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) runtimeCertificationReport(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetRuntimeCertification(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, run.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	if run.State != controlplane.RuntimeCertificationSucceeded && run.State != controlplane.RuntimeCertificationRevoked {
		writeError(w, http.StatusConflict, "RUNTIME_CERTIFICATION_NOT_COMPLETE", "certification evidence is available only after a successful run")
		return
	}
	if err = controlplane.ValidateRuntimeCertificationEvidence(run); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "RUNTIME_CERTIFICATION_EVIDENCE_INVALID", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema": "platform.4so.io/runtime-certification-report/v1", "run": run,
		"claims":  map[string]any{"profileCertified": run.Profile, "externalLiveCertified": false, "productionReady": false},
		"warning": "This report proves an evidence-bound local/runtime agent run. External lab certification is tracked separately and remains false until executed in an approved environment.",
	})
}

func (s *Server) nextRuntimeCertificationTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	run, err := s.store.NextRuntimeCertificationTask(r.Context(), r.PathValue("id"), agentDigest)
	if errors.Is(err, controlplane.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if run.State == controlplane.RuntimeCertificationFailed || run.State == controlplane.RuntimeCertificationBlocked {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	release, err := s.store.GetCatalogRelease(r.Context(), run.CatalogReleaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	rendered, err := s.runtimeCertificationRenderContext(r, release, run.Namespace)
	if err != nil || rendered.RenderedDigest != run.RenderedDigest || rendered.SourceLockDigest != run.SourceLockDigest || len(rendered.Resources) != run.ResourceCount {
		result := controlplane.RuntimeCertificationResult{RunID: run.ID, TaskFenceToken: run.TaskFenceToken, Phase: run.Phase, Success: false, InventoryDigest: run.InventoryDigest, RenderedDigest: run.RenderedDigest, Error: "immutable catalog render context no longer matches certification run"}
		if _, reportErr := s.store.ReportRuntimeCertificationTask(r.Context(), r.PathValue("id"), agentDigest, run.Revision, result); reportErr != nil {
			writeStoreError(w, reportErr)
			return
		}
		writeError(w, http.StatusConflict, "RUNTIME_CERTIFICATION_CONTEXT_INVALID", result.Error)
		return
	}
	task := controlplane.RuntimeCertificationTask{
		RunID: run.ID, RunRevision: run.Revision, TaskFenceToken: run.TaskFenceToken, LeaseExpiresAt: *run.TaskLeaseExpiresAt, Profile: run.Profile, Phase: run.Phase, Namespace: run.Namespace,
		InventoryDigest: run.InventoryDigest, EnvironmentFingerprint: run.EnvironmentFingerprint, CatalogReleaseID: run.CatalogReleaseID,
		ManifestDigest: run.ManifestDigest, SourceLockDigest: run.SourceLockDigest, RenderedDigest: run.RenderedDigest,
		InstallCheckpointDigest: run.InstallCheckpointDigest, TaskAttempt: run.TaskAttempt,
		CleanupToken:            run.CleanupGenerations[len(run.CleanupGenerations)-1].Token,
		PriorCleanupGenerations: append([]controlplane.RuntimeCertificationCleanupGeneration(nil), run.CleanupGenerations[:len(run.CleanupGenerations)-1]...),
		Resources:               rendered.Resources,
	}
	setRevisionETag(w, run.Revision)
	writeJSON(w, http.StatusOK, task)
}

func (s *Server) reportRuntimeCertificationTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.RuntimeCertificationResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	result.RunID = r.PathValue("runId")
	updated, err := s.store.ReportRuntimeCertificationTask(r.Context(), r.PathValue("id"), agentDigest, expected, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusOK, updated)
}
