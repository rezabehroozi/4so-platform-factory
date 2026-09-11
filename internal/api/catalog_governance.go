package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/controlplane"
)

type catalogTrustKeyInput struct {
	OrganizationID string `json:"organizationId,omitempty"`
	Name           string `json:"name"`
	PublicKey      string `json:"publicKey"`
}

type catalogReleaseInput struct {
	OrganizationID string              `json:"organizationId,omitempty"`
	CatalogName    string              `json:"catalogName"`
	CatalogVersion string              `json:"catalogVersion"`
	Visibility     string              `json:"visibility"`
	Channel        string              `json:"channel"`
	Components     []catalog.Component `json:"components"`
}

type catalogDraftInput struct {
	Components []catalog.Component `json:"components"`
}

type catalogPromoteInput struct {
	Channel string `json:"channel,omitempty"`
}

type catalogTrustStatus struct {
	Verified     bool   `json:"verified"`
	Reason       string `json:"reason,omitempty"`
	SigningKeyID string `json:"signingKeyId,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
}

func catalogManifest(components []catalog.Component) ([]byte, map[string]catalog.Component, string, error) {
	raw, items, err := catalog.CanonicalReleasePayload(components)
	if err != nil {
		return nil, nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, items, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (s *Server) catalogSigningIdentityModel() map[string]any {
	if len(s.catalogSigner) != ed25519.PrivateKeySize {
		return map[string]any{"available": false, "mode": "disabled", "algorithm": "Ed25519"}
	}
	publicKey := s.catalogSigner.Public().(ed25519.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(publicKey)
	fingerprint, _ := controlplane.CatalogKeyFingerprint(encoded)
	return map[string]any{"available": true, "mode": s.catalogSignerMode, "algorithm": "Ed25519", "publicKey": encoded, "fingerprint": fingerprint}
}

func (s *Server) catalogSigningIdentity(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.catalogSigningIdentityModel())
}

func (s *Server) createCatalogTrustKey(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input catalogTrustKeyInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	input.OrganizationID = strings.TrimSpace(input.OrganizationID)
	if input.OrganizationID == "" {
		if err = requirePlatformAdmin(r); err != nil {
			writeError(w, 403, "PLATFORM_ADMIN_REQUIRED", "platform trust keys require platform-admin")
			return
		}
	} else if err = s.requireOrganizationAccess(r, input.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	key, err := s.store.CreateCatalogTrustKey(r.Context(), controlplane.CatalogTrustKey{OrganizationID: input.OrganizationID, Name: input.Name, PublicKey: input.PublicKey}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, key.Revision)
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) listCatalogTrustKeys(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListCatalogTrustKeys(r.Context(), "")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	orgs, all, err := s.resourceOrganizationSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]controlplane.CatalogTrustKey, 0, len(items))
	for _, item := range items {
		if item.OrganizationID == "" || all || orgs[item.OrganizationID] {
			out = append(out, item)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getCatalogTrustKeyImpact(w http.ResponseWriter, r *http.Request) {
	key, err := s.store.GetCatalogTrustKey(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if key.OrganizationID != "" {
		if err = s.requireOrganizationAccess(r, key.OrganizationID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	releaseIDs := map[string]bool{}
	releases := []controlplane.CatalogRelease{}
	for _, release := range snap.CatalogReleases {
		if release.SigningKeyID == key.ID {
			releaseIDs[release.ID] = true
			releases = append(releases, release)
		}
	}
	blueprints := []controlplane.BlueprintRelease{}
	revisionIDs := map[string]bool{}
	for _, release := range snap.BlueprintReleases {
		if releaseIDs[release.CatalogReleaseID] {
			blueprints = append(blueprints, release)
			revisionIDs[release.CurrentRevisionID] = true
		}
	}
	targetSet := map[string]bool{}
	for _, assignment := range snap.Assignments {
		if revisionIDs[assignment.BlueprintRevisionID] {
			targetSet[assignment.TargetRef] = true
		}
	}
	targets := make([]string, 0, len(targetSet))
	for target := range targetSet {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	writeJSON(w, http.StatusOK, map[string]any{"trustKey": key, "catalogReleases": releases, "blueprintReleases": blueprints, "affectedTargetRefs": targets})
}

func (s *Server) revokeCatalogTrustKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.store.GetCatalogTrustKey(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if key.OrganizationID == "" {
		if err = requirePlatformAdmin(r); err != nil {
			writeError(w, 403, "PLATFORM_ADMIN_REQUIRED", "platform trust key revocation requires platform-admin")
			return
		}
	} else if err = s.requireOrganizationAccess(r, key.OrganizationID, organizationAdminAccess); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	updated, err := s.store.RevokeCatalogTrustKey(r.Context(), key.ID, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, 200, updated)
}

func catalogReleaseRequiredAccess(release controlplane.CatalogRelease, admin bool) organizationAccessLevel {
	if admin {
		return organizationAdminAccess
	}
	return organizationWrite
}

func (s *Server) requireCatalogReleaseAccess(r *http.Request, release controlplane.CatalogRelease, admin bool) error {
	if release.Visibility == controlplane.CatalogVisibilityPlatform {
		return requirePlatformAdmin(r)
	}
	return s.requireOrganizationAccess(r, release.OrganizationID, catalogReleaseRequiredAccess(release, admin))
}

func (s *Server) trustStatus(ctxReq *http.Request, release controlplane.CatalogRelease) catalogTrustStatus {
	status := catalogTrustStatus{SigningKeyID: release.SigningKeyID, Fingerprint: release.SigningKeyFingerprint}
	if strings.TrimSpace(release.SigningKeyID) == "" || strings.TrimSpace(release.Signature) == "" {
		status.Reason = "release is not signed"
		return status
	}
	key, err := s.store.GetCatalogTrustKey(ctxReq.Context(), release.SigningKeyID)
	if err != nil {
		status.Reason = "signing trust key is unavailable"
		return status
	}
	if err = controlplane.VerifyCatalogReleaseSignature(release, key); err != nil {
		status.Reason = err.Error()
		return status
	}
	status.Verified = true
	return status
}

func (s *Server) catalogImageMirrorAdmission(r *http.Request, release controlplane.CatalogRelease, components map[string]catalog.Component) ([]map[string]any, []string) {
	refs, err := catalog.ReleaseImageReferences(components)
	if err != nil {
		return nil, []string{"image mirror inventory invalid: " + err.Error()}
	}
	statuses := make([]map[string]any, 0, len(refs))
	blockers := []string{}
	requireMirror := release.Channel == controlplane.CatalogChannelRuntime || release.Channel == controlplane.CatalogChannelProduction
	for _, ref := range refs {
		status := map[string]any{"sourceReference": ref, "requiredForChannel": requireMirror, "available": false}
		if s.services == nil || !s.services.RegistryConfigured() {
			status["error"] = "managed zot integration is not configured"
			if requireMirror {
				blockers = append(blockers, ref+": managed internal registry mirror is not configured")
			}
			statuses = append(statuses, status)
			continue
		}
		checked := s.services.CheckMirroredImage(r.Context(), ref)
		status["mirrorReference"] = checked.MirrorReference
		status["available"] = checked.Available
		if checked.Error != "" {
			status["error"] = checked.Error
		}
		if requireMirror && !checked.Available {
			message := checked.Error
			if strings.TrimSpace(message) == "" {
				message = "digest is not present in the managed registry mirror"
			}
			blockers = append(blockers, ref+": "+message)
		}
		statuses = append(statuses, status)
	}
	sort.Strings(blockers)
	return statuses, blockers
}

func (s *Server) catalogCertificationAuthorityAdmission(r *http.Request, release controlplane.CatalogRelease, components map[string]catalog.Component) []string {
	if release.Channel != controlplane.CatalogChannelRuntime && release.Channel != controlplane.CatalogChannelProduction {
		return nil
	}
	blockers := []string{}
	if release.Channel == controlplane.CatalogChannelProduction {
		// upgrade-certified is a stronger claim than a successful target-runtime
		// run. No durable upgrade-certification evidence authority exists yet, so
		// accepting a digest-shaped string here would turn metadata into a false
		// production certification claim.
		for _, component := range catalog.Sorted(components) {
			if strings.EqualFold(strings.TrimSpace(component.Spec.Certification.Status), "upgrade-certified") {
				blockers = append(blockers, component.Metadata.Name+": upgrade certification evidence is not backed by an authoritative control-plane record")
			}
		}
		sort.Strings(blockers)
		return blockers
	}

	sourceID := strings.TrimSpace(release.SourceReleaseID)
	if sourceID == "" {
		return []string{"runtime certification authority requires the source RENDER release"}
	}
	source, err := s.store.GetCatalogRelease(r.Context(), sourceID)
	if err != nil || source.Channel != controlplane.CatalogChannelRender || (source.State != controlplane.CatalogPublished && source.State != controlplane.CatalogDeprecated) {
		return []string{"runtime certification authority source RENDER release is unavailable or invalid"}
	}
	if source.CurrentRevisionID == "" || source.ManifestDigest == "" {
		return []string{"runtime certification authority source RENDER release has no immutable revision binding"}
	}
	if trust := s.trustStatus(r, source); !trust.Verified {
		return []string{"runtime certification authority source RENDER trust is no longer valid: " + trust.Reason}
	}

	runs, err := s.store.ListRuntimeCertifications(r.Context(), "", "")
	if err != nil {
		return []string{"runtime certification authority records are unavailable"}
	}
	now := time.Now().UTC()
	expectedSourceLocks := catalog.SourceLockDigest(components)
	authoritative := map[string]bool{}
	for _, run := range runs {
		// Certification that authorizes a Catalog channel transition is owned by
		// the Catalog owner organization, not by whichever actor happens to read
		// the release. This both prevents cross-organization evidence injection for
		// PUBLIC catalogs and prevents validity from changing with viewer RBAC.
		project, projectErr := s.store.GetProject(r.Context(), run.ProjectID)
		if projectErr != nil || project.OrganizationID != release.OrganizationID {
			continue
		}
		if run.State != controlplane.RuntimeCertificationSucceeded || run.Profile != controlplane.RuntimeCertificationTargetV1 || run.ExpiresAt == nil || !run.ExpiresAt.After(now) {
			continue
		}
		if run.CatalogReleaseID != source.ID || run.CatalogRevisionID != source.CurrentRevisionID || run.ManifestDigest != source.ManifestDigest || run.SourceLockDigest != expectedSourceLocks {
			continue
		}
		if err := controlplane.ValidateRuntimeCertificationEvidence(run); err != nil {
			continue
		}
		cluster, clusterErr := s.store.GetManagedCluster(r.Context(), run.ClusterID)
		if clusterErr != nil || cluster.ProjectID != run.ProjectID || cluster.InventoryDigest != run.InventoryDigest {
			continue
		}
		inventory, inventoryErr := s.store.GetLatestClusterInventory(r.Context(), run.ClusterID)
		if inventoryErr != nil || inventory.Digest != run.InventoryDigest || controlplane.RuntimeEnvironmentFingerprint(inventory) != run.EnvironmentFingerprint {
			continue
		}
		haveCapabilities := map[string]bool{}
		for _, capability := range inventory.Capabilities {
			haveCapabilities[strings.TrimSpace(capability)] = true
		}
		capabilitiesValid := true
		for _, required := range controlplane.RuntimeCertificationRequiredCapabilities(run.Profile) {
			if !haveCapabilities[required] {
				capabilitiesValid = false
				break
			}
		}
		if !capabilitiesValid {
			continue
		}
		rendered, renderErr := s.runtimeCertificationRenderContext(r, source, run.Namespace)
		if renderErr != nil || rendered.Revision.ID != run.CatalogRevisionID || rendered.RenderedDigest != run.RenderedDigest || rendered.SourceLockDigest != run.SourceLockDigest {
			continue
		}
		authoritative[run.EvidenceDigest] = true
	}
	for _, component := range catalog.Sorted(components) {
		status := strings.ToLower(strings.TrimSpace(component.Spec.Certification.Status))
		if status != "target-runtime-certified" {
			// Static admission reports missing/invalid status. This authority layer
			// only adds a blocker for stronger metadata that cannot be proven here.
			if status == "upgrade-certified" {
				blockers = append(blockers, component.Metadata.Name+": upgrade-certified metadata cannot substitute for authoritative TARGET_RUNTIME_V1 evidence in the RUNTIME channel")
			}
			continue
		}
		profileBound := false
		for _, profile := range component.Spec.Certification.Profiles {
			if strings.EqualFold(strings.TrimSpace(profile), string(controlplane.RuntimeCertificationTargetV1)) {
				profileBound = true
				break
			}
		}
		if !profileBound {
			blockers = append(blockers, component.Metadata.Name+": target runtime certification metadata is not bound to TARGET_RUNTIME_V1 profile")
			continue
		}
		// TARGET_RUNTIME_V1 currently installs and verifies only the dedicated
		// secure-namespace-foundation harness. The remaining checks prove target
		// cluster capabilities (DNS/TLS/network/storage/backup/observability), not
		// that an arbitrary Catalog component from this source release was itself
		// installed from its immutable bundle and passed component readiness. Do
		// not turn catalog-wide source-lock binding into a per-component runtime
		// certification claim. Other components require a future component-owned
		// runtime certification authority before they may enter RUNTIME.
		if component.Metadata.Name != "secure-namespace-foundation" {
			blockers = append(blockers, component.Metadata.Name+": TARGET_RUNTIME_V1 evidence proves the target capability harness but does not install and verify this component from its immutable Catalog source; component-specific runtime certification authority is required")
			continue
		}
		if !authoritative[strings.TrimSpace(component.Spec.Certification.EvidenceDigest)] {
			blockers = append(blockers, component.Metadata.Name+": target runtime certification evidence is not backed by an active TARGET_RUNTIME_V1 control-plane run for this RENDER source release, current cluster inventory and source-lock set")
		}
	}
	sort.Strings(blockers)
	return blockers
}

func (s *Server) catalogReleaseDetail(r *http.Request, release controlplane.CatalogRelease) (map[string]any, error) {
	revision, err := s.store.GetCatalogRevision(r.Context(), release.CurrentRevisionID)
	if err != nil {
		return nil, err
	}
	components, err := catalog.ParseReleasePayload(revision.Payload)
	if err != nil {
		return nil, fmt.Errorf("stored catalog revision invalid: %w", err)
	}
	blockers := catalog.AdmissionBlockers(string(release.Channel), components)
	blockers = append(blockers, s.catalogCertificationAuthorityAdmission(r, release, components)...)
	mirrors, mirrorBlockers := s.catalogImageMirrorAdmission(r, release, components)
	blockers = append(blockers, mirrorBlockers...)
	sort.Strings(blockers)
	return map[string]any{"release": release, "revision": revision, "components": catalog.Sorted(components), "trust": s.trustStatus(r, release), "admission": map[string]any{"eligible": len(blockers) == 0, "blockers": blockers, "imageMirrors": mirrors}}, nil
}

func (s *Server) createCatalogRelease(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input catalogReleaseInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	input.OrganizationID = strings.TrimSpace(input.OrganizationID)
	visibility := controlplane.CatalogVisibility(strings.ToUpper(strings.TrimSpace(input.Visibility)))
	channel := controlplane.CatalogChannel(strings.ToUpper(strings.TrimSpace(input.Channel)))
	if channel == "" {
		channel = controlplane.CatalogChannelCandidate
	}
	if visibility == "" {
		if input.OrganizationID != "" {
			visibility = controlplane.CatalogVisibilityPrivate
		} else {
			visibility = controlplane.CatalogVisibilityPlatform
		}
	}
	if visibility == controlplane.CatalogVisibilityPlatform {
		if err = requirePlatformAdmin(r); err != nil {
			writeError(w, 403, "PLATFORM_ADMIN_REQUIRED", "platform catalog authoring requires platform-admin")
			return
		}
	} else if visibility == controlplane.CatalogVisibilityPrivate {
		if err = s.requireOrganizationAccess(r, input.OrganizationID, organizationWrite); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	raw, _, digest, err := catalogManifest(input.Components)
	if err != nil {
		writeError(w, 422, "CATALOG_MANIFEST_INVALID", err.Error())
		return
	}
	_, release, err := s.store.CreateCatalogReleaseWithRevision(r.Context(), controlplane.CatalogRevision{OrganizationID: input.OrganizationID, CatalogName: input.CatalogName, CatalogVersion: input.CatalogVersion, ManifestDigest: digest, Payload: raw}, controlplane.CatalogRelease{OrganizationID: input.OrganizationID, CatalogName: input.CatalogName, CatalogVersion: input.CatalogVersion, Visibility: visibility, Channel: channel, ManifestDigest: digest}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	detail, err := s.catalogReleaseDetail(r, release)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, release.Revision)
	writeJSON(w, 201, detail)
}

func (s *Server) listCatalogReleases(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListCatalogReleases(r.Context(), "")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	orgs, all, err := s.resourceOrganizationSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]controlplane.CatalogRelease, 0, len(items))
	for _, item := range items {
		if item.Visibility == controlplane.CatalogVisibilityPlatform || all || orgs[item.OrganizationID] {
			out = append(out, item)
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) getCatalogRelease(w http.ResponseWriter, r *http.Request) {
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
	detail, err := s.catalogReleaseDetail(r, release)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, release.Revision)
	writeJSON(w, 200, detail)
}

func (s *Server) updateCatalogReleaseDraft(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetCatalogRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireCatalogReleaseAccess(r, current, false); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var input catalogDraftInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	raw, _, digest, err := catalogManifest(input.Components)
	if err != nil {
		writeError(w, 422, "CATALOG_MANIFEST_INVALID", err.Error())
		return
	}
	_, updated, err := s.store.UpdateCatalogReleaseDraftWithRevision(r.Context(), current.ID, expected, controlplane.CatalogRevision{OrganizationID: current.OrganizationID, CatalogName: current.CatalogName, CatalogVersion: current.CatalogVersion, ManifestDigest: digest, Payload: raw}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	detail, err := s.catalogReleaseDetail(r, updated)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, 200, detail)
}

func (s *Server) findTrustedSignerKey(r *http.Request, release controlplane.CatalogRelease) (controlplane.CatalogTrustKey, string, string, error) {
	if len(s.catalogSigner) != ed25519.PrivateKeySize {
		return controlplane.CatalogTrustKey{}, "", "", fmt.Errorf("catalog signing identity is not configured")
	}
	public := s.catalogSigner.Public().(ed25519.PublicKey)
	publicB64 := base64.StdEncoding.EncodeToString(public)
	fingerprint, _ := controlplane.CatalogKeyFingerprint(publicB64)
	keys, err := s.store.ListCatalogTrustKeys(r.Context(), "")
	if err != nil {
		return controlplane.CatalogTrustKey{}, "", "", err
	}
	var platform *controlplane.CatalogTrustKey
	for i := range keys {
		key := keys[i]
		if key.State != controlplane.CatalogTrustKeyActive || key.Fingerprint != fingerprint {
			continue
		}
		if key.OrganizationID == release.OrganizationID && release.Visibility == controlplane.CatalogVisibilityPrivate {
			return key, publicB64, fingerprint, nil
		}
		if key.OrganizationID == "" {
			copyKey := key
			platform = &copyKey
		}
	}
	if platform != nil {
		return *platform, publicB64, fingerprint, nil
	}
	return controlplane.CatalogTrustKey{}, publicB64, fingerprint, fmt.Errorf("configured catalog signer is not trusted for this release scope")
}

func (s *Server) submitCatalogReview(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetCatalogRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireCatalogReleaseAccess(r, current, false); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	key, publicKey, fingerprint, err := s.findTrustedSignerKey(r, current)
	if err != nil {
		writeJSON(w, 422, map[string]any{"error": map[string]string{"code": "CATALOG_SIGNER_NOT_TRUSTED", "message": err.Error()}, "signer": map[string]any{"publicKey": publicKey, "fingerprint": fingerprint, "mode": s.catalogSignerMode}})
		return
	}
	payload, err := controlplane.CatalogSignaturePayload(current)
	if err != nil {
		writeError(w, 500, "CATALOG_SIGN_FAILED", err.Error())
		return
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(s.catalogSigner, payload))
	updated, err := s.store.SubmitCatalogReleaseReview(r.Context(), current.ID, expected, key.ID, key.Fingerprint, signature, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, 200, updated)
}

func (s *Server) catalogTransition(w http.ResponseWriter, r *http.Request, to controlplane.CatalogLifecycleState, admin bool, publish bool) {
	current, err := s.store.GetCatalogRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.requireCatalogReleaseAccess(r, current, admin); err != nil {
		if current.Visibility == controlplane.CatalogVisibilityPlatform {
			writeError(w, 403, "PLATFORM_ADMIN_REQUIRED", "platform catalog lifecycle requires platform-admin")
		} else {
			writeScopeError(w, err)
		}
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	if publish {
		if principal, ok := requestPrincipal(r); ok && principal.Subject != "local-development" && strings.TrimSpace(current.RequestedBy) == strings.TrimSpace(actor) {
			writeError(w, 403, "SEPARATION_OF_DUTIES_REQUIRED", "a different administrator must publish the reviewed catalog release")
			return
		}
		detail, e := s.catalogReleaseDetail(r, current)
		if e != nil {
			writeStoreError(w, e)
			return
		}
		admission := detail["admission"].(map[string]any)
		if admission["eligible"] != true {
			writeJSON(w, 422, map[string]any{"error": map[string]string{"code": "CATALOG_CHANNEL_ADMISSION_FAILED", "message": "catalog release does not satisfy channel admission requirements"}, "admission": admission})
			return
		}
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	updated, err := s.store.TransitionCatalogRelease(r.Context(), current.ID, expected, to, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, 200, updated)
}

func (s *Server) requestCatalogChanges(w http.ResponseWriter, r *http.Request) {
	s.catalogTransition(w, r, controlplane.CatalogDraft, true, false)
}
func (s *Server) publishCatalogRelease(w http.ResponseWriter, r *http.Request) {
	s.catalogTransition(w, r, controlplane.CatalogPublished, true, true)
}
func (s *Server) deprecateCatalogRelease(w http.ResponseWriter, r *http.Request) {
	s.catalogTransition(w, r, controlplane.CatalogDeprecated, true, false)
}
func (s *Server) revokeCatalogRelease(w http.ResponseWriter, r *http.Request) {
	s.catalogTransition(w, r, controlplane.CatalogRevoked, true, false)
}

func (s *Server) promoteCatalogRelease(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetCatalogRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if current.State != controlplane.CatalogPublished && current.State != controlplane.CatalogDeprecated {
		writeError(w, 409, "CATALOG_PROMOTION_SOURCE_INVALID", "only published or deprecated releases can be promoted")
		return
	}
	if err = s.requireCatalogReleaseAccess(r, current, false); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	var input catalogPromoteInput
	if err = decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	next := controlplane.CatalogChannel("")
	switch current.Channel {
	case controlplane.CatalogChannelCandidate:
		next = controlplane.CatalogChannelRender
	case controlplane.CatalogChannelRender:
		next = controlplane.CatalogChannelRuntime
	case controlplane.CatalogChannelRuntime:
		next = controlplane.CatalogChannelProduction
	}
	if strings.TrimSpace(input.Channel) != "" && controlplane.CatalogChannel(strings.ToUpper(strings.TrimSpace(input.Channel))) != next {
		writeError(w, 422, "CATALOG_PROMOTION_CHANNEL_INVALID", "promotion must move exactly one channel forward")
		return
	}
	if next == "" {
		writeError(w, 409, "CATALOG_ALREADY_PRODUCTION", "production is the terminal promotion channel")
		return
	}
	created, err := s.store.CreateCatalogRelease(r.Context(), controlplane.CatalogRelease{OrganizationID: current.OrganizationID, CatalogName: current.CatalogName, CatalogVersion: current.CatalogVersion, Visibility: current.Visibility, Channel: next, CurrentRevisionID: current.CurrentRevisionID, ManifestDigest: current.ManifestDigest, SourceReleaseID: current.ID}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	detail, err := s.catalogReleaseDetail(r, created)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, created.Revision)
	writeJSON(w, 201, detail)
}
