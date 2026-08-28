package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
)

type catalogRenderInput struct {
	Namespace  string   `json:"namespace"`
	Components []string `json:"components,omitempty"`
}

type catalogRenderOutput struct {
	CatalogReleaseID string                      `json:"catalogReleaseId"`
	CatalogName      string                      `json:"catalogName"`
	CatalogVersion   string                      `json:"catalogVersion"`
	Channel          controlplane.CatalogChannel `json:"channel"`
	ManifestDigest   string                      `json:"manifestDigest"`
	Namespace        string                      `json:"namespace"`
	RenderedDigest   string                      `json:"renderedDigest"`
	ResourceCount    int                         `json:"resourceCount"`
	Components       []catalog.RenderedComponent `json:"components"`
	Resources        []map[string]any            `json:"resources"`
	ImageMirrors     map[string]string           `json:"imageMirrors,omitempty"`
}

func catalogChannelRenderable(channel controlplane.CatalogChannel) bool {
	return channel == controlplane.CatalogChannelRender || channel == controlplane.CatalogChannelRuntime || channel == controlplane.CatalogChannelProduction
}

func rewriteRuntimeImages(v any, mirrors map[string]string) error {
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			if err := rewriteRuntimeImages(item, mirrors); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, value := range x {
			if key == "image" {
				ref, ok := value.(string)
				if !ok || strings.TrimSpace(ref) == "" {
					return fmt.Errorf("rendered image field is not a non-empty string")
				}
				mirror, ok := mirrors[strings.TrimSpace(ref)]
				if !ok || strings.TrimSpace(mirror) == "" {
					return fmt.Errorf("runtime image %s has no verified internal mirror", ref)
				}
				x[key] = mirror
			}
			if err := rewriteRuntimeImages(value, mirrors); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderedComponentDigest(resources []map[string]any) string {
	raw, _ := json.Marshal(resources)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func renderedResourceIdentity(resource map[string]any) string {
	apiVersion, _ := resource["apiVersion"].(string)
	kind, _ := resource["kind"].(string)
	metadata, _ := resource["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	return apiVersion + "|" + kind + "|" + namespace + "|" + name
}

func (s *Server) renderCatalogRelease(w http.ResponseWriter, r *http.Request) {
	release, err := s.store.GetCatalogRelease(r.Context(), r.PathValue("id"))
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
	if release.State != controlplane.CatalogPublished {
		writeError(w, http.StatusConflict, "CATALOG_RENDER_STATE_INVALID", "only a published catalog release can be rendered for a new deployment")
		return
	}
	if !catalogChannelRenderable(release.Channel) {
		writeError(w, http.StatusUnprocessableEntity, "CATALOG_RENDER_CHANNEL_INVALID", "catalog release must be published in RENDER, RUNTIME or PRODUCTION channel")
		return
	}
	trust := s.trustStatus(r, release)
	if !trust.Verified {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "CATALOG_RENDER_TRUST_INVALID", "message": trust.Reason}, "trust": trust})
		return
	}
	revision, err := s.store.GetCatalogRevision(r.Context(), release.CurrentRevisionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	components, err := catalog.ParseReleasePayload(revision.Payload)
	if err != nil {
		writeError(w, 500, "CATALOG_RENDER_REVISION_INVALID", err.Error())
		return
	}
	blockers := catalog.AdmissionBlockers(string(release.Channel), components)
	blockers = append(blockers, s.catalogCertificationAuthorityAdmission(r, release, components)...)
	if len(blockers) > 0 {
		sort.Strings(blockers)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "CATALOG_RENDER_ADMISSION_FAILED", "message": "published catalog no longer satisfies render admission"}, "blockers": blockers})
		return
	}
	mirrorStatuses, mirrorBlockers := s.catalogImageMirrorAdmission(r, release, components)
	if len(mirrorBlockers) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "CATALOG_RUNTIME_IMAGE_MIRROR_REQUIRED", "message": "runtime catalog images are not fully mirrored into the managed registry"}, "blockers": mirrorBlockers, "imageMirrors": mirrorStatuses})
		return
	}
	mirrorMap := map[string]string{}
	if release.Channel == controlplane.CatalogChannelRuntime || release.Channel == controlplane.CatalogChannelProduction {
		for _, status := range mirrorStatuses {
			source, _ := status["sourceReference"].(string)
			mirror, _ := status["mirrorReference"].(string)
			available, _ := status["available"].(bool)
			if available && source != "" && mirror != "" {
				mirrorMap[source] = mirror
			}
		}
	}
	var input catalogRenderInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	input.Namespace = strings.TrimSpace(input.Namespace)
	if input.Namespace == "" {
		writeError(w, 422, "CATALOG_RENDER_NAMESPACE_REQUIRED", "namespace is required")
		return
	}
	selected := map[string]bool{}
	for _, name := range input.Components {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if selected[name] {
			writeError(w, 422, "CATALOG_RENDER_COMPONENT_DUPLICATE", "component selection contains duplicates")
			return
		}
		if _, ok := components[name]; !ok {
			writeError(w, 422, "CATALOG_RENDER_COMPONENT_UNKNOWN", fmt.Sprintf("component %s is not part of this catalog release", name))
			return
		}
		selected[name] = true
	}
	names := make([]string, 0, len(components))
	for name := range components {
		if len(selected) == 0 || selected[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		writeError(w, 422, "CATALOG_RENDER_COMPONENTS_REQUIRED", "at least one component must be selected")
		return
	}

	result := catalogRenderOutput{
		CatalogReleaseID: release.ID, CatalogName: release.CatalogName, CatalogVersion: release.CatalogVersion,
		Channel: release.Channel, ManifestDigest: release.ManifestDigest, Namespace: input.Namespace,
		Components: make([]catalog.RenderedComponent, 0, len(names)), Resources: []map[string]any{}, ImageMirrors: mirrorMap,
	}
	resourceDigests := map[string]string{}
	for _, name := range names {
		rendered, renderErr := catalog.RenderComponent(components[name], input.Namespace, release.ID)
		if renderErr != nil {
			writeError(w, 422, "CATALOG_COMPONENT_NOT_RENDERABLE", renderErr.Error())
			return
		}
		if release.Channel == controlplane.CatalogChannelRuntime || release.Channel == controlplane.CatalogChannelProduction {
			for _, resource := range rendered.Resources {
				if err := rewriteRuntimeImages(resource, mirrorMap); err != nil {
					writeError(w, 422, "CATALOG_RUNTIME_IMAGE_REWRITE_FAILED", err.Error())
					return
				}
			}
			rendered.RenderedDigest = renderedComponentDigest(rendered.Resources)
		}
		result.Components = append(result.Components, rendered)
		for _, resource := range rendered.Resources {
			identity := renderedResourceIdentity(resource)
			raw, _ := json.Marshal(resource)
			sum := sha256.Sum256(raw)
			digest := hex.EncodeToString(sum[:])
			if previous, exists := resourceDigests[identity]; exists {
				if previous != digest {
					writeError(w, 409, "CATALOG_RENDER_RESOURCE_COLLISION", "multiple components render conflicting resource "+identity)
					return
				}
				continue
			}
			resourceDigests[identity] = digest
			result.Resources = append(result.Resources, resource)
		}
	}
	result.ResourceCount = len(result.Resources)
	identityRaw, err := json.Marshal(struct {
		CatalogReleaseID string           `json:"catalogReleaseId"`
		ManifestDigest   string           `json:"manifestDigest"`
		Namespace        string           `json:"namespace"`
		Resources        []map[string]any `json:"resources"`
	}{release.ID, release.ManifestDigest, input.Namespace, result.Resources})
	if err != nil {
		writeError(w, 500, "CATALOG_RENDER_DIGEST_FAILED", err.Error())
		return
	}
	sum := sha256.Sum256(identityRaw)
	result.RenderedDigest = "sha256:" + hex.EncodeToString(sum[:])
	writeJSON(w, http.StatusOK, result)
}
