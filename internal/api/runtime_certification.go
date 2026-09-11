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
	ComponentName    string `json:"componentName,omitempty"`
	Profile          string `json:"profile"`
	Namespace        string `json:"namespace"`
}

type certificationRenderContext struct {
	Revision         controlplane.CatalogRevision
	RenderedDigest   string
	SourceLockDigest string
	Resources        []map[string]any
}

const (
	componentRuntimeMaxResources    = 256
	componentRuntimeMaxPayloadBytes = 4 << 20
)

func componentRuntimeContract(registry catalog.ComponentRuntimeCertificationRegistry, name string) (catalog.ComponentRuntimeCertificationContract, bool) {
	for _, contract := range registry.Spec.Components {
		if contract.Component == name {
			return contract, true
		}
	}
	return catalog.ComponentRuntimeCertificationContract{}, false
}

func annotateComponentRuntimeResources(resources []map[string]any, component, releaseID string) ([]map[string]any, error) {
	if len(resources) == 0 || len(resources) > componentRuntimeMaxResources {
		return nil, fmt.Errorf("component runtime resource count must be between 1 and %d", componentRuntimeMaxResources)
	}
	out := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		raw, err := json.Marshal(resource)
		if err != nil {
			return nil, err
		}
		var cloned map[string]any
		if err = json.Unmarshal(raw, &cloned); err != nil {
			return nil, err
		}
		delete(cloned, "status") // status is observed state, never desired mutation authority.
		metadata, _ := cloned["metadata"].(map[string]any)
		if metadata == nil {
			return nil, fmt.Errorf("component runtime resource metadata is missing")
		}
		labels, _ := metadata["labels"].(map[string]any)
		if labels == nil {
			labels = map[string]any{}
			metadata["labels"] = labels
		}
		labels["app.kubernetes.io/managed-by"] = "4so-platform-factory"
		labels["platform.4so.io/component"] = component
		labels["platform.4so.io/catalog-release-id"] = releaseID
		labels["platform.4so.io/runtime-certification-profile"] = string(controlplane.RuntimeCertificationComponentV1)
		out = append(out, cloned)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(raw) > componentRuntimeMaxPayloadBytes {
		return nil, fmt.Errorf("component runtime rendered payload exceeds %d bytes", componentRuntimeMaxPayloadBytes)
	}
	return out, nil
}

func (s *Server) componentRuntimeCertificationRenderContext(r *http.Request, release controlplane.CatalogRelease, componentName, namespace string) (certificationRenderContext, string, error) {
	if release.State != controlplane.CatalogPublished || release.Channel != controlplane.CatalogChannelRender {
		return certificationRenderContext{}, "", fmt.Errorf("published RENDER catalog release is required for component runtime certification")
	}
	if trust := s.trustStatus(r, release); !trust.Verified {
		return certificationRenderContext{}, "", fmt.Errorf("catalog trust invalid: %s", trust.Reason)
	}
	revision, err := s.store.GetCatalogRevision(r.Context(), release.CurrentRevisionID)
	if err != nil {
		return certificationRenderContext{}, "", err
	}
	components, err := catalog.ParseReleasePayload(revision.Payload)
	if err != nil {
		return certificationRenderContext{}, "", err
	}
	componentName = strings.TrimSpace(componentName)
	component, ok := components[componentName]
	if !ok {
		return certificationRenderContext{}, "", fmt.Errorf("component %s is not present in catalog release", componentName)
	}
	if !component.Spec.Source.Resolved || !strings.HasPrefix(component.Spec.Source.SourceLockDigest, "sha256:") {
		return certificationRenderContext{}, "", fmt.Errorf("component %s source is not immutable/resolved", componentName)
	}
	registry, err := catalog.LoadComponentRuntimeCertificationRegistry()
	if err != nil {
		return certificationRenderContext{}, "", err
	}
	if err = catalog.ValidateComponentRuntimeCertificationRegistry(registry, s.components); err != nil {
		return certificationRenderContext{}, "", err
	}
	contract, ok := componentRuntimeContract(registry, componentName)
	if !ok || contract.Release != component.Spec.Release || contract.SourceBinding.SourceLockDigest != component.Spec.Source.SourceLockDigest || contract.Executor.Profile != string(controlplane.RuntimeCertificationComponentV1) || contract.Executor.Status != "component-install-readiness-dependency-failure-remove-partial" {
		return certificationRenderContext{}, "", fmt.Errorf("component %s does not have executable COMPONENT_RUNTIME_V1 install/readiness/dependency authority", componentName)
	}
	rendered, err := catalog.RenderComponent(component, namespace, release.ID)
	if err != nil {
		return certificationRenderContext{}, "", err
	}
	resources, err := annotateComponentRuntimeResources(rendered.Resources, componentName, release.ID)
	if err != nil {
		return certificationRenderContext{}, "", err
	}
	identityRaw, _ := json.Marshal(struct {
		CatalogReleaseID string           `json:"catalogReleaseId"`
		Component        string           `json:"component"`
		Release          string           `json:"release"`
		SourceLock       string           `json:"sourceLockDigest"`
		Namespace        string           `json:"namespace"`
		Resources        []map[string]any `json:"resources"`
	}{release.ID, componentName, component.Spec.Release, component.Spec.Source.SourceLockDigest, namespace, resources})
	sum := sha256.Sum256(identityRaw)
	return certificationRenderContext{Revision: revision, RenderedDigest: "sha256:" + hex.EncodeToString(sum[:]), SourceLockDigest: component.Spec.Source.SourceLockDigest, Resources: resources}, component.Spec.Release, nil
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
	in.ProjectID, in.ClusterID, in.CatalogReleaseID, in.ComponentName, in.Namespace = strings.TrimSpace(in.ProjectID), strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.CatalogReleaseID), strings.TrimSpace(in.ComponentName), strings.TrimSpace(in.Namespace)
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
	var rendered certificationRenderContext
	componentRelease := ""
	if profile == controlplane.RuntimeCertificationComponentV1 {
		if in.ComponentName == "" {
			writeError(w, http.StatusBadRequest, "COMPONENT_NAME_REQUIRED", "componentName is required for COMPONENT_RUNTIME_V1")
			return
		}
		if in.Namespace == "" {
			in.Namespace = "4so-component-cert"
		}
		rendered, componentRelease, err = s.componentRuntimeCertificationRenderContext(r, release, in.ComponentName, in.Namespace)
	} else {
		if in.ComponentName != "" {
			writeError(w, http.StatusBadRequest, "COMPONENT_NAME_NOT_ALLOWED", "componentName is valid only for COMPONENT_RUNTIME_V1")
			return
		}
		rendered, err = s.runtimeCertificationRenderContext(r, release, in.Namespace)
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "RUNTIME_CERTIFICATION_RENDER_INVALID", err.Error())
		return
	}
	requestDigest := digestValue(map[string]any{
		"projectId": in.ProjectID, "clusterId": in.ClusterID, "catalogReleaseId": in.CatalogReleaseID, "componentName": in.ComponentName, "componentRelease": componentRelease,
		"profile": profile, "namespace": in.Namespace, "inventoryDigest": inventory.Digest, "renderedDigest": rendered.RenderedDigest,
	})
	run, replay, err := s.store.CreateRuntimeCertification(r.Context(), controlplane.RuntimeCertificationRun{
		ProjectID: in.ProjectID, ClusterID: in.ClusterID, CatalogReleaseID: release.ID, CatalogRevisionID: rendered.Revision.ID, ComponentName: in.ComponentName, ComponentRelease: componentRelease,
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
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	clusterID := strings.TrimSpace(r.URL.Query().Get("clusterId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.RuntimeCertificationRun, error)
	if pager, ok := s.store.(runtimeCertificationPageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.RuntimeCertificationRun, error) {
			return pager.ListRuntimeCertificationsPage(r.Context(), ids, all, clusterID, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.RuntimeCertificationRun, error) {
		return s.store.ListRuntimeCertifications(r.Context(), projectID, clusterID)
	}, page, func(item controlplane.RuntimeCertificationRun) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, http.StatusOK, v)
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
		"claims": map[string]any{
			"profileCertified": run.Profile, "componentName": run.ComponentName, "componentRelease": run.ComponentRelease,
			"lifecycleStagesCertified": func() []string {
				if run.Profile == controlplane.RuntimeCertificationComponentV1 {
					return []string{"install", "readiness", "dependency", "failure", "remove"}
				}
				return nil
			}(),
			"fullLifecycleCertified": false, "externalLiveCertified": false, "productionReady": false,
		},
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
	var rendered certificationRenderContext
	componentRelease := ""
	if run.Profile == controlplane.RuntimeCertificationComponentV1 {
		rendered, componentRelease, err = s.componentRuntimeCertificationRenderContext(r, release, run.ComponentName, run.Namespace)
	} else {
		rendered, err = s.runtimeCertificationRenderContext(r, release, run.Namespace)
	}
	if err != nil || rendered.RenderedDigest != run.RenderedDigest || rendered.SourceLockDigest != run.SourceLockDigest || len(rendered.Resources) != run.ResourceCount || (run.Profile == controlplane.RuntimeCertificationComponentV1 && componentRelease != run.ComponentRelease) {
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
		InventoryDigest: run.InventoryDigest, EnvironmentFingerprint: run.EnvironmentFingerprint, CatalogReleaseID: run.CatalogReleaseID, ComponentName: run.ComponentName, ComponentRelease: run.ComponentRelease,
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
