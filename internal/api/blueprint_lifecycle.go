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
	bp "platform.4so.io/factory/internal/blueprint"
	"platform.4so.io/factory/internal/blueprintoverlay"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/domain"
	"platform.4so.io/factory/internal/plan"
)

type blueprintReleaseInput struct {
	ProjectID            string           `json:"projectId"`
	CatalogReleaseID     string           `json:"catalogReleaseId,omitempty"`
	Blueprint            domain.Blueprint `json:"blueprint"`
	UpgradeFromIDs       []string         `json:"upgradeFromIds,omitempty"`
	SourceReleaseID      string           `json:"sourceReleaseId,omitempty"`
	ProviderOverlayID    string           `json:"providerOverlayId,omitempty"`
	EnvironmentOverlayID string           `json:"environmentOverlayId,omitempty"`
}

type blueprintDraftUpdateInput struct {
	Blueprint            domain.Blueprint `json:"blueprint"`
	UpgradeFromIDs       []string         `json:"upgradeFromIds,omitempty"`
	ProviderOverlayID    *string          `json:"providerOverlayId,omitempty"`
	EnvironmentOverlayID *string          `json:"environmentOverlayId,omitempty"`
}

type blueprintCloneInput struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	UpgradeFromIDs []string `json:"upgradeFromIds,omitempty"`
}

type blueprintCompareInput struct {
	LeftReleaseID  string `json:"leftReleaseId"`
	RightReleaseID string `json:"rightReleaseId"`
}

type blueprintDifference struct {
	Path  string `json:"path"`
	Kind  string `json:"kind"`
	Left  any    `json:"left,omitempty"`
	Right any    `json:"right,omitempty"`
}

func blueprintMaterial(base domain.Blueprint, provider, environment *controlplane.BlueprintOverlay, components map[string]catalog.Component, certificationAuthorityVerified bool) (controlplane.BlueprintRevision, domain.Blueprint, controlplane.BlueprintResolution, domain.DeploymentPlan, domain.ValidationResult, error) {
	resolved, resolution, err := blueprintoverlay.Resolve(base, provider, environment)
	if err != nil {
		return controlplane.BlueprintRevision{}, domain.Blueprint{}, controlplane.BlueprintResolution{}, domain.DeploymentPlan{}, domain.ValidationResult{}, err
	}
	validation := bp.Validate(resolved, components)
	if !validation.Valid {
		return controlplane.BlueprintRevision{}, resolved, resolution, domain.DeploymentPlan{}, validation, nil
	}
	var deploymentPlan domain.DeploymentPlan
	if certificationAuthorityVerified {
		deploymentPlan, err = plan.BuildWithCertificationAuthority(resolved, components)
	} else {
		deploymentPlan, err = plan.Build(resolved, components)
	}
	if err != nil {
		return controlplane.BlueprintRevision{}, resolved, resolution, domain.DeploymentPlan{}, validation, err
	}
	baseRaw, err := json.Marshal(base)
	if err != nil {
		return controlplane.BlueprintRevision{}, resolved, resolution, domain.DeploymentPlan{}, validation, fmt.Errorf("marshal base blueprint: %w", err)
	}
	resolvedRaw, err := json.Marshal(resolved)
	if err != nil {
		return controlplane.BlueprintRevision{}, resolved, resolution, domain.DeploymentPlan{}, validation, fmt.Errorf("marshal resolved blueprint: %w", err)
	}
	resolutionRaw, err := json.Marshal(resolution)
	if err != nil {
		return controlplane.BlueprintRevision{}, resolved, resolution, domain.DeploymentPlan{}, validation, fmt.Errorf("marshal blueprint resolution: %w", err)
	}
	sum := sha256.Sum256(resolvedRaw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	return controlplane.BlueprintRevision{
		BlueprintName: resolved.Metadata.Name, BlueprintVersion: resolved.Metadata.Version,
		BlueprintDigest: digest, CatalogDigest: catalog.Digest(components), BaseBlueprintDigest: resolution.BaseBlueprintDigest,
		OverlayDigest: resolution.OverlayDigest, OwnershipDigest: resolution.OwnershipDigest, ProviderOverlayID: resolution.ProviderOverlayID,
		EnvironmentOverlayID: resolution.EnvironmentOverlayID, BasePayload: baseRaw, ResolutionPayload: resolutionRaw, Payload: resolvedRaw,
	}, resolved, resolution, deploymentPlan, validation, nil
}

func (s *Server) blueprintOverlayInputs(r *http.Request, projectID, providerID, environmentID string) (*controlplane.BlueprintOverlay, *controlplane.BlueprintOverlay, error) {
	var provider, environment *controlplane.BlueprintOverlay
	if id := strings.TrimSpace(providerID); id != "" {
		value, err := s.store.GetBlueprintOverlay(r.Context(), id)
		if err != nil {
			return nil, nil, err
		}
		if value.ProjectID != projectID || value.Scope != controlplane.BlueprintOverlayProvider {
			return nil, nil, fmt.Errorf("%w: provider overlay scope/project mismatch", controlplane.ErrValidation)
		}
		provider = &value
	}
	if id := strings.TrimSpace(environmentID); id != "" {
		value, err := s.store.GetBlueprintOverlay(r.Context(), id)
		if err != nil {
			return nil, nil, err
		}
		if value.ProjectID != projectID || value.Scope != controlplane.BlueprintOverlayEnvironment {
			return nil, nil, fmt.Errorf("%w: environment overlay scope/project mismatch", controlplane.ErrValidation)
		}
		environment = &value
	}
	return provider, environment, nil
}

func (s *Server) blueprintCatalogComponents(r *http.Request, projectID, catalogReleaseID string) (map[string]catalog.Component, bool, error) {
	catalogReleaseID = strings.TrimSpace(catalogReleaseID)
	if catalogReleaseID == "" {
		return s.components, false, nil
	}
	project, err := s.store.GetProject(r.Context(), projectID)
	if err != nil {
		return nil, false, err
	}
	release, err := s.store.GetCatalogRelease(r.Context(), catalogReleaseID)
	if err != nil {
		return nil, false, err
	}
	if release.State != controlplane.CatalogPublished {
		return nil, false, fmt.Errorf("%w: catalog release must be PUBLISHED", controlplane.ErrValidation)
	}
	if release.Visibility == controlplane.CatalogVisibilityPrivate && release.OrganizationID != project.OrganizationID {
		return nil, false, fmt.Errorf("%w: private catalog release belongs to another organization", controlplane.ErrValidation)
	}
	key, err := s.store.GetCatalogTrustKey(r.Context(), release.SigningKeyID)
	if err != nil {
		return nil, false, err
	}
	if err = controlplane.VerifyCatalogReleaseSignature(release, key); err != nil {
		return nil, false, fmt.Errorf("%w: catalog trust verification failed: %v", controlplane.ErrValidation, err)
	}
	revision, err := s.store.GetCatalogRevision(r.Context(), release.CurrentRevisionID)
	if err != nil {
		return nil, false, err
	}
	components, err := catalog.ParseReleasePayload(revision.Payload)
	if err != nil {
		return nil, false, fmt.Errorf("%w: catalog release payload is invalid: %v", controlplane.ErrValidation, err)
	}
	if catalog.Digest(components) != release.ManifestDigest {
		return nil, false, fmt.Errorf("%w: catalog manifest digest does not match immutable release", controlplane.ErrValidation)
	}
	blockers := catalog.AdmissionBlockers(string(release.Channel), components)
	blockers = append(blockers, s.catalogCertificationAuthorityAdmission(r, release, components)...)
	if len(blockers) > 0 {
		sort.Strings(blockers)
		return nil, false, fmt.Errorf("%w: catalog release admission is no longer valid: %s", controlplane.ErrValidation, strings.Join(blockers, "; "))
	}
	return components, release.Channel == controlplane.CatalogChannelRuntime || release.Channel == controlplane.CatalogChannelProduction, nil
}

func (s *Server) createBlueprintRelease(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input blueprintReleaseInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	input.ProjectID = strings.TrimSpace(input.ProjectID)
	if _, err = s.requireProjectAccess(r, input.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	components, certificationAuthorityVerified, err := s.blueprintCatalogComponents(r, input.ProjectID, input.CatalogReleaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	providerOverlay, environmentOverlay, err := s.blueprintOverlayInputs(r, input.ProjectID, input.ProviderOverlayID, input.EnvironmentOverlayID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	revision, resolvedBlueprint, resolution, deploymentPlan, validation, err := blueprintMaterial(input.Blueprint, providerOverlay, environmentOverlay, components, certificationAuthorityVerified)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "BLUEPRINT_PLAN_FAILED", err.Error())
		return
	}
	if !validation.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "BLUEPRINT_INVALID", "message": "blueprint validation failed"}, "validation": validation})
		return
	}
	revision.ProjectID = input.ProjectID
	_, release, err := s.store.CreateBlueprintReleaseWithRevision(r.Context(), revision, controlplane.BlueprintRelease{
		ProjectID: input.ProjectID, BlueprintName: revision.BlueprintName, BlueprintVersion: revision.BlueprintVersion,
		CatalogReleaseID: strings.TrimSpace(input.CatalogReleaseID), SourceReleaseID: strings.TrimSpace(input.SourceReleaseID), UpgradeFromIDs: input.UpgradeFromIDs,
		ExecutionReady: deploymentPlan.Executable, PlanStatus: deploymentPlan.Status,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, release.Revision)
	writeJSON(w, http.StatusCreated, map[string]any{"release": release, "baseBlueprint": input.Blueprint, "blueprint": resolvedBlueprint, "resolution": resolution, "plan": deploymentPlan, "validation": validation})
}

func (s *Server) listBlueprintReleases(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	items, err := s.store.ListBlueprintReleases(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	items = filterProjectScoped(items, allowed, all, func(v controlplane.BlueprintRelease) string { return v.ProjectID })
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) getBlueprintRelease(w http.ResponseWriter, r *http.Request) {
	release, err := s.store.GetBlueprintRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, release.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	revision, err := s.store.GetBlueprintRevision(r.Context(), release.CurrentRevisionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var blueprint, baseBlueprint domain.Blueprint
	var resolution controlplane.BlueprintResolution
	if err = json.Unmarshal(revision.Payload, &blueprint); err != nil {
		writeError(w, http.StatusInternalServerError, "BLUEPRINT_PAYLOAD_INVALID", "stored resolved blueprint payload is invalid")
		return
	}
	if err = json.Unmarshal(revision.BasePayload, &baseBlueprint); err != nil {
		writeError(w, http.StatusInternalServerError, "BLUEPRINT_BASE_PAYLOAD_INVALID", "stored base blueprint payload is invalid")
		return
	}
	if err = json.Unmarshal(revision.ResolutionPayload, &resolution); err != nil {
		writeError(w, http.StatusInternalServerError, "BLUEPRINT_RESOLUTION_INVALID", "stored blueprint resolution provenance is invalid")
		return
	}
	setRevisionETag(w, release.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"release": release, "revision": revision, "baseBlueprint": baseBlueprint, "blueprint": blueprint, "resolution": resolution})
}

func (s *Server) updateBlueprintReleaseDraft(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetBlueprintRelease(r.Context(), r.PathValue("id"))
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
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var input blueprintDraftUpdateInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if input.Blueprint.Metadata.Name != current.BlueprintName || input.Blueprint.Metadata.Version != current.BlueprintVersion {
		writeError(w, http.StatusUnprocessableEntity, "BLUEPRINT_IDENTITY_IMMUTABLE", "draft updates cannot change blueprint name or version; clone the release instead")
		return
	}
	components, certificationAuthorityVerified, err := s.blueprintCatalogComponents(r, current.ProjectID, current.CatalogReleaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	currentRevision, err := s.store.GetBlueprintRevision(r.Context(), current.CurrentRevisionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	providerOverlayID, environmentOverlayID := currentRevision.ProviderOverlayID, currentRevision.EnvironmentOverlayID
	if input.ProviderOverlayID != nil {
		providerOverlayID = strings.TrimSpace(*input.ProviderOverlayID)
	}
	if input.EnvironmentOverlayID != nil {
		environmentOverlayID = strings.TrimSpace(*input.EnvironmentOverlayID)
	}
	providerOverlay, environmentOverlay, err := s.blueprintOverlayInputs(r, current.ProjectID, providerOverlayID, environmentOverlayID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	revision, resolvedBlueprint, resolution, deploymentPlan, validation, err := blueprintMaterial(input.Blueprint, providerOverlay, environmentOverlay, components, certificationAuthorityVerified)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "BLUEPRINT_PLAN_FAILED", err.Error())
		return
	}
	if !validation.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "BLUEPRINT_INVALID", "message": "blueprint validation failed"}, "validation": validation})
		return
	}
	revision.ProjectID = current.ProjectID
	_, updated, err := s.store.UpdateBlueprintReleaseDraftWithRevision(r.Context(), current.ID, expected, revision, deploymentPlan.Executable, deploymentPlan.Status, input.UpgradeFromIDs, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"release": updated, "baseBlueprint": input.Blueprint, "blueprint": resolvedBlueprint, "resolution": resolution, "plan": deploymentPlan, "validation": validation})
}

func (s *Server) transitionBlueprintRelease(w http.ResponseWriter, r *http.Request, to controlplane.BlueprintLifecycleState, admin bool, publish bool) {
	current, err := s.store.GetBlueprintRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	required := organizationWrite
	if admin {
		required = organizationAdminAccess
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, required); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	if publish {
		if principal, ok := requestPrincipal(r); !ok || principal.Subject != "local-development" {
			if strings.TrimSpace(current.RequestedBy) != "" && strings.TrimSpace(current.RequestedBy) == strings.TrimSpace(actor) {
				writeError(w, http.StatusForbidden, "SEPARATION_OF_DUTIES_REQUIRED", "a different organization administrator must publish the reviewed blueprint")
				return
			}
		}
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	updated, err := s.store.TransitionBlueprintRelease(r.Context(), current.ID, expected, to, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) submitBlueprintReview(w http.ResponseWriter, r *http.Request) {
	s.transitionBlueprintRelease(w, r, controlplane.BlueprintReview, false, false)
}
func (s *Server) requestBlueprintChanges(w http.ResponseWriter, r *http.Request) {
	s.transitionBlueprintRelease(w, r, controlplane.BlueprintDraft, true, false)
}
func (s *Server) publishBlueprintRelease(w http.ResponseWriter, r *http.Request) {
	s.transitionBlueprintRelease(w, r, controlplane.BlueprintPublished, true, true)
}
func (s *Server) deprecateBlueprintRelease(w http.ResponseWriter, r *http.Request) {
	s.transitionBlueprintRelease(w, r, controlplane.BlueprintDeprecated, true, false)
}
func (s *Server) revokeBlueprintRelease(w http.ResponseWriter, r *http.Request) {
	s.transitionBlueprintRelease(w, r, controlplane.BlueprintRevoked, true, false)
}

func (s *Server) cloneBlueprintRelease(w http.ResponseWriter, r *http.Request) {
	source, err := s.store.GetBlueprintRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, source.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input blueprintCloneInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	revision, err := s.store.GetBlueprintRevision(r.Context(), source.CurrentRevisionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var blueprint domain.Blueprint
	if err = json.Unmarshal(revision.BasePayload, &blueprint); err != nil {
		writeError(w, http.StatusInternalServerError, "BLUEPRINT_BASE_PAYLOAD_INVALID", "stored base blueprint payload is invalid")
		return
	}
	blueprint.Metadata.Name = strings.TrimSpace(input.Name)
	blueprint.Metadata.Version = strings.TrimSpace(input.Version)
	upgradeFrom := append([]string(nil), input.UpgradeFromIDs...)
	if len(upgradeFrom) == 0 && (source.State == controlplane.BlueprintPublished || source.State == controlplane.BlueprintDeprecated) && blueprint.Metadata.Name == source.BlueprintName {
		upgradeFrom = []string{source.ID}
	}
	components, certificationAuthorityVerified, err := s.blueprintCatalogComponents(r, source.ProjectID, source.CatalogReleaseID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	providerOverlay, environmentOverlay, err := s.blueprintOverlayInputs(r, source.ProjectID, revision.ProviderOverlayID, revision.EnvironmentOverlayID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	material, resolvedBlueprint, resolution, deploymentPlan, validation, err := blueprintMaterial(blueprint, providerOverlay, environmentOverlay, components, certificationAuthorityVerified)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "BLUEPRINT_PLAN_FAILED", err.Error())
		return
	}
	if !validation.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "BLUEPRINT_INVALID", "message": "cloned blueprint metadata is invalid"}, "validation": validation})
		return
	}
	material.ProjectID = source.ProjectID
	_, created, err := s.store.CreateBlueprintReleaseWithRevision(r.Context(), material, controlplane.BlueprintRelease{
		ProjectID: source.ProjectID, BlueprintName: material.BlueprintName, BlueprintVersion: material.BlueprintVersion,
		CatalogReleaseID: source.CatalogReleaseID, SourceReleaseID: source.ID, UpgradeFromIDs: upgradeFrom, ExecutionReady: deploymentPlan.Executable, PlanStatus: deploymentPlan.Status,
	}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, created.Revision)
	writeJSON(w, http.StatusCreated, map[string]any{"release": created, "baseBlueprint": blueprint, "blueprint": resolvedBlueprint, "resolution": resolution, "plan": deploymentPlan, "validation": validation})
}

func (s *Server) compareBlueprintReleases(w http.ResponseWriter, r *http.Request) {
	var input blueprintCompareInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	left, err := s.store.GetBlueprintRelease(r.Context(), strings.TrimSpace(input.LeftReleaseID))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	right, err := s.store.GetBlueprintRelease(r.Context(), strings.TrimSpace(input.RightReleaseID))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if left.ProjectID != right.ProjectID {
		writeError(w, http.StatusUnprocessableEntity, "BLUEPRINT_COMPARE_SCOPE_MISMATCH", "blueprint releases must belong to the same project")
		return
	}
	if _, err = s.requireProjectAccess(r, left.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	leftRevision, err := s.store.GetBlueprintRevision(r.Context(), left.CurrentRevisionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	rightRevision, err := s.store.GetBlueprintRevision(r.Context(), right.CurrentRevisionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var leftValue, rightValue any
	if err = json.Unmarshal(leftRevision.Payload, &leftValue); err != nil {
		writeError(w, 500, "BLUEPRINT_PAYLOAD_INVALID", "left blueprint payload is invalid")
		return
	}
	if err = json.Unmarshal(rightRevision.Payload, &rightValue); err != nil {
		writeError(w, 500, "BLUEPRINT_PAYLOAD_INVALID", "right blueprint payload is invalid")
		return
	}
	differences := compareJSON("", leftValue, rightValue)
	writeJSON(w, http.StatusOK, map[string]any{
		"left":  map[string]any{"release": left, "revision": leftRevision},
		"right": map[string]any{"release": right, "revision": rightRevision},
		"equal": len(differences) == 0, "differenceCount": len(differences), "differences": differences,
	})
}

func compareJSON(path string, left, right any) []blueprintDifference {
	if path == "" {
		path = "/"
	}
	leftMap, lok := left.(map[string]any)
	rightMap, rok := right.(map[string]any)
	if lok && rok {
		keys := map[string]bool{}
		for key := range leftMap {
			keys[key] = true
		}
		for key := range rightMap {
			keys[key] = true
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		out := []blueprintDifference{}
		for _, key := range ordered {
			lv, lexists := leftMap[key]
			rv, rexists := rightMap[key]
			child := joinJSONPointer(path, key)
			switch {
			case !lexists:
				out = append(out, blueprintDifference{Path: child, Kind: "ADDED", Right: rv})
			case !rexists:
				out = append(out, blueprintDifference{Path: child, Kind: "REMOVED", Left: lv})
			default:
				out = append(out, compareJSON(child, lv, rv)...)
			}
		}
		return out
	}
	leftSlice, lok := left.([]any)
	rightSlice, rok := right.([]any)
	if lok && rok {
		out := []blueprintDifference{}
		max := len(leftSlice)
		if len(rightSlice) > max {
			max = len(rightSlice)
		}
		for i := 0; i < max; i++ {
			child := joinJSONPointer(path, fmt.Sprintf("%d", i))
			switch {
			case i >= len(leftSlice):
				out = append(out, blueprintDifference{Path: child, Kind: "ADDED", Right: rightSlice[i]})
			case i >= len(rightSlice):
				out = append(out, blueprintDifference{Path: child, Kind: "REMOVED", Left: leftSlice[i]})
			default:
				out = append(out, compareJSON(child, leftSlice[i], rightSlice[i])...)
			}
		}
		return out
	}
	leftRaw, _ := json.Marshal(left)
	rightRaw, _ := json.Marshal(right)
	if string(leftRaw) == string(rightRaw) {
		return nil
	}
	return []blueprintDifference{{Path: path, Kind: "CHANGED", Left: left, Right: right}}
}

func joinJSONPointer(base, part string) string {
	part = strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	if base == "/" {
		return "/" + part
	}
	return strings.TrimRight(base, "/") + "/" + part
}

var _ = errors.Is
