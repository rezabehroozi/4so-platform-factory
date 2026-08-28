package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func validSHA256(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func digestPayload(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func catalogChannelValid(channel CatalogChannel) bool {
	switch channel {
	case CatalogChannelCandidate, CatalogChannelRender, CatalogChannelRuntime, CatalogChannelProduction:
		return true
	default:
		return false
	}
}

func nextCatalogChannel(channel CatalogChannel) CatalogChannel {
	switch channel {
	case CatalogChannelCandidate:
		return CatalogChannelRender
	case CatalogChannelRender:
		return CatalogChannelRuntime
	case CatalogChannelRuntime:
		return CatalogChannelProduction
	default:
		return ""
	}
}

func validCatalogTransition(from, to CatalogLifecycleState) bool {
	switch from {
	case CatalogDraft:
		return to == CatalogReview
	case CatalogReview:
		return to == CatalogDraft || to == CatalogPublished
	case CatalogPublished:
		return to == CatalogDeprecated || to == CatalogRevoked
	case CatalogDeprecated:
		return to == CatalogRevoked
	default:
		return false
	}
}

type catalogSignatureEnvelope struct {
	Schema            string            `json:"schema"`
	OrganizationID    string            `json:"organizationId,omitempty"`
	CatalogName       string            `json:"catalogName"`
	CatalogVersion    string            `json:"catalogVersion"`
	Visibility        CatalogVisibility `json:"visibility"`
	Channel           CatalogChannel    `json:"channel"`
	ManifestDigest    string            `json:"manifestDigest"`
	SourceReleaseID   string            `json:"sourceReleaseId,omitempty"`
	CurrentRevisionID string            `json:"currentRevisionId"`
}

// CatalogSignaturePayload is the canonical byte sequence signed by Ed25519.
// It intentionally excludes lifecycle timestamps/revision counters so a
// signature remains valid while the immutable release moves through governance.
func CatalogSignaturePayload(release CatalogRelease) ([]byte, error) {
	return json.Marshal(catalogSignatureEnvelope{
		Schema:            "platform.4so.io/catalog-release-signature/v1",
		OrganizationID:    strings.TrimSpace(release.OrganizationID),
		CatalogName:       normalizeName(release.CatalogName),
		CatalogVersion:    strings.TrimSpace(release.CatalogVersion),
		Visibility:        release.Visibility,
		Channel:           release.Channel,
		ManifestDigest:    strings.TrimSpace(release.ManifestDigest),
		SourceReleaseID:   strings.TrimSpace(release.SourceReleaseID),
		CurrentRevisionID: strings.TrimSpace(release.CurrentRevisionID),
	})
}

func CatalogKeyFingerprint(publicKeyBase64 string) (string, error) {
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyBase64))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: catalog trust key must be a base64 Ed25519 public key", ErrValidation)
	}
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func VerifyCatalogReleaseSignature(release CatalogRelease, key CatalogTrustKey) error {
	if key.State != CatalogTrustKeyActive {
		return fmt.Errorf("%w: catalog signing trust key is revoked", ErrValidation)
	}
	if !strings.EqualFold(strings.TrimSpace(key.Algorithm), "Ed25519") {
		return fmt.Errorf("%w: only Ed25519 catalog trust keys are supported", ErrValidation)
	}
	if release.Visibility == CatalogVisibilityPlatform && strings.TrimSpace(key.OrganizationID) != "" {
		return fmt.Errorf("%w: platform catalog releases require a platform trust key", ErrValidation)
	}
	if release.Visibility == CatalogVisibilityPrivate && strings.TrimSpace(key.OrganizationID) != "" && strings.TrimSpace(key.OrganizationID) != strings.TrimSpace(release.OrganizationID) {
		return fmt.Errorf("%w: private catalog trust key belongs to another organization", ErrValidation)
	}
	fingerprint, err := CatalogKeyFingerprint(key.PublicKey)
	if err != nil {
		return err
	}
	if fingerprint != strings.TrimSpace(key.Fingerprint) || fingerprint != strings.TrimSpace(release.SigningKeyFingerprint) || key.ID != strings.TrimSpace(release.SigningKeyID) {
		return fmt.Errorf("%w: catalog signing key identity mismatch", ErrValidation)
	}
	publicKeyRaw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(key.PublicKey))
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(release.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: catalog release signature is malformed", ErrValidation)
	}
	payload, err := CatalogSignaturePayload(release)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyRaw), payload, signature) {
		return fmt.Errorf("%w: catalog release signature verification failed", ErrValidation)
	}
	return nil
}

func (s *MemoryStore) CreateCatalogTrustKey(_ context.Context, key CatalogTrustKey, actor string) (CatalogTrustKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key.OrganizationID = strings.TrimSpace(key.OrganizationID)
	key.Name = normalizeName(key.Name)
	if key.Name == "" || strings.TrimSpace(actor) == "" {
		return CatalogTrustKey{}, fmt.Errorf("%w: trust key name and actor are required", ErrValidation)
	}
	if key.OrganizationID != "" {
		if _, ok := s.organizations[key.OrganizationID]; !ok {
			return CatalogTrustKey{}, ErrNotFound
		}
	}
	key.Algorithm = "Ed25519"
	fingerprint, err := CatalogKeyFingerprint(key.PublicKey)
	if err != nil {
		return CatalogTrustKey{}, err
	}
	for _, current := range s.catalogTrustKeys {
		if current.OrganizationID == key.OrganizationID && (current.Fingerprint == fingerprint || current.Name == key.Name) {
			return CatalogTrustKey{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	key.ResourceMeta = ResourceMeta{ID: s.id("ctk"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	key.Fingerprint = fingerprint
	key.State = CatalogTrustKeyActive
	key.CreatedBy = strings.TrimSpace(actor)
	s.catalogTrustKeys[key.ID] = key
	s.appendAuditLocked(actor, "catalog_trust_key.created", "catalogTrustKey", key.ID, key.Revision, map[string]any{"organizationId": key.OrganizationID, "fingerprint": key.Fingerprint})
	s.appendOutboxLocked("catalogTrustKey", key.ID, "catalog_trust_key.created", key)
	return key, nil
}

func (s *MemoryStore) GetCatalogTrustKey(_ context.Context, id string) (CatalogTrustKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.catalogTrustKeys[id]
	if !ok {
		return CatalogTrustKey{}, ErrNotFound
	}
	return value, nil
}

func (s *MemoryStore) ListCatalogTrustKeys(_ context.Context, organizationID string) ([]CatalogTrustKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organizationID = strings.TrimSpace(organizationID)
	out := []CatalogTrustKey{}
	for _, value := range s.catalogTrustKeys {
		if organizationID == "" || value.OrganizationID == organizationID {
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OrganizationID == out[j].OrganizationID {
			return out[i].Name < out[j].Name
		}
		return out[i].OrganizationID < out[j].OrganizationID
	})
	return out, nil
}

func (s *MemoryStore) RevokeCatalogTrustKey(_ context.Context, id string, expected int64, actor string) (CatalogTrustKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.catalogTrustKeys[id]
	if !ok {
		return CatalogTrustKey{}, ErrNotFound
	}
	if current.Revision != expected {
		return CatalogTrustKey{}, ErrConflict
	}
	if current.State == CatalogTrustKeyRevoked {
		return current, nil
	}
	now := nowUTC(s.now)
	current.State, current.RevokedBy, current.RevokedAt = CatalogTrustKeyRevoked, strings.TrimSpace(actor), &now
	current.Revision++
	current.UpdatedAt = now
	s.catalogTrustKeys[id] = current
	s.appendAuditLocked(actor, "catalog_trust_key.revoked", "catalogTrustKey", id, current.Revision, map[string]any{"fingerprint": current.Fingerprint})
	s.appendOutboxLocked("catalogTrustKey", id, "catalog_trust_key.revoked", current)
	return current, nil
}

func (s *MemoryStore) prepareCatalogRevisionLocked(revision CatalogRevision) (CatalogRevision, bool, error) {
	revision.OrganizationID = strings.TrimSpace(revision.OrganizationID)
	revision.CatalogName = normalizeName(revision.CatalogName)
	revision.CatalogVersion = strings.TrimSpace(revision.CatalogVersion)
	if revision.OrganizationID != "" {
		if _, ok := s.organizations[revision.OrganizationID]; !ok {
			return CatalogRevision{}, false, ErrNotFound
		}
	}
	if revision.CatalogName == "" || revision.CatalogVersion == "" || len(revision.Payload) == 0 || !json.Valid(revision.Payload) || !validSHA256(revision.ManifestDigest) {
		return CatalogRevision{}, false, fmt.Errorf("%w: catalog revision identity, JSON payload and sha256 manifest digest are required", ErrValidation)
	}
	if digestPayload(revision.Payload) != revision.ManifestDigest {
		return CatalogRevision{}, false, fmt.Errorf("%w: catalog revision payload digest mismatch", ErrValidation)
	}
	for _, current := range s.catalogRevisions {
		if current.OrganizationID == revision.OrganizationID && current.CatalogName == revision.CatalogName && current.CatalogVersion == revision.CatalogVersion && current.ManifestDigest == revision.ManifestDigest {
			current.Payload = append([]byte(nil), current.Payload...)
			return current, true, nil
		}
	}
	now := nowUTC(s.now)
	revision.ResourceMeta = ResourceMeta{ID: s.id("ctr"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	revision.Payload = append([]byte(nil), revision.Payload...)
	return revision, false, nil
}

func (s *MemoryStore) commitCatalogRevisionLocked(revision CatalogRevision, actor string) {
	s.catalogRevisions[revision.ID] = revision
	s.appendAuditLocked(actor, "catalog_revision.created", "catalogRevision", revision.ID, 1, map[string]any{"organizationId": revision.OrganizationID, "manifestDigest": revision.ManifestDigest})
	s.appendOutboxLocked("catalogRevision", revision.ID, "catalog_revision.created", revision)
}

func (s *MemoryStore) CreateCatalogRevision(_ context.Context, revision CatalogRevision, actor string) (CatalogRevision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prepared, existing, err := s.prepareCatalogRevisionLocked(revision)
	if err != nil {
		return CatalogRevision{}, err
	}
	if !existing {
		s.commitCatalogRevisionLocked(prepared, actor)
	}
	return prepared, nil
}

func (s *MemoryStore) GetCatalogRevision(_ context.Context, id string) (CatalogRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.catalogRevisions[id]
	if !ok {
		return CatalogRevision{}, ErrNotFound
	}
	value.Payload = append([]byte(nil), value.Payload...)
	return value, nil
}

func (s *MemoryStore) prepareCatalogReleaseLocked(release CatalogRelease, revision CatalogRevision, actor string) (CatalogRelease, error) {
	release.OrganizationID = strings.TrimSpace(release.OrganizationID)
	release.CatalogName = normalizeName(release.CatalogName)
	release.CatalogVersion = strings.TrimSpace(release.CatalogVersion)
	release.SourceReleaseID = strings.TrimSpace(release.SourceReleaseID)
	if release.CatalogName == "" || release.CatalogVersion == "" || release.CurrentRevisionID == "" || !validSHA256(release.ManifestDigest) || !catalogChannelValid(release.Channel) || strings.TrimSpace(actor) == "" {
		return CatalogRelease{}, fmt.Errorf("%w: catalog release identity, revision, channel, digest and actor are required", ErrValidation)
	}
	if (release.Visibility == CatalogVisibilityPrivate && release.OrganizationID == "") || (release.Visibility == CatalogVisibilityPlatform && release.OrganizationID != "") || (release.Visibility != CatalogVisibilityPrivate && release.Visibility != CatalogVisibilityPlatform) {
		return CatalogRelease{}, fmt.Errorf("%w: PRIVATE requires an organization and PLATFORM must be organization-independent", ErrValidation)
	}
	if release.OrganizationID != "" {
		if _, ok := s.organizations[release.OrganizationID]; !ok {
			return CatalogRelease{}, ErrNotFound
		}
	}
	if revision.OrganizationID != release.OrganizationID || revision.CatalogName != release.CatalogName || revision.CatalogVersion != release.CatalogVersion || revision.ManifestDigest != release.ManifestDigest {
		return CatalogRelease{}, fmt.Errorf("%w: catalog revision does not match release identity", ErrValidation)
	}
	for _, current := range s.catalogReleases {
		if current.OrganizationID == release.OrganizationID && current.CatalogName == release.CatalogName && current.CatalogVersion == release.CatalogVersion && current.Channel == release.Channel {
			return CatalogRelease{}, ErrDuplicateName
		}
	}
	if release.SourceReleaseID != "" {
		source, ok := s.catalogReleases[release.SourceReleaseID]
		if !ok {
			return CatalogRelease{}, ErrNotFound
		}
		if source.OrganizationID != release.OrganizationID || source.CatalogName != release.CatalogName || source.CatalogVersion != release.CatalogVersion || (source.State != CatalogPublished && source.State != CatalogDeprecated) || nextCatalogChannel(source.Channel) != release.Channel || source.ManifestDigest != release.ManifestDigest {
			return CatalogRelease{}, fmt.Errorf("%w: promotion source must be the previous published/deprecated channel with the same immutable manifest", ErrValidation)
		}
	}
	now := nowUTC(s.now)
	release.ResourceMeta = ResourceMeta{ID: s.id("ctl"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	release.State = CatalogDraft
	release.RequestedBy = strings.TrimSpace(actor)
	release.SigningKeyID, release.SigningKeyFingerprint, release.Signature = "", "", ""
	return release, nil
}

func (s *MemoryStore) commitCatalogReleaseLocked(release CatalogRelease, actor string) {
	s.catalogReleases[release.ID] = release
	s.appendAuditLocked(actor, "catalog_release.created", "catalogRelease", release.ID, 1, map[string]any{"organizationId": release.OrganizationID, "channel": release.Channel, "manifestDigest": release.ManifestDigest})
	s.appendOutboxLocked("catalogRelease", release.ID, "catalog_release.created", release)
}

func (s *MemoryStore) CreateCatalogRelease(_ context.Context, release CatalogRelease, actor string) (CatalogRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	revision, ok := s.catalogRevisions[release.CurrentRevisionID]
	if !ok {
		return CatalogRelease{}, ErrNotFound
	}
	prepared, err := s.prepareCatalogReleaseLocked(release, revision, actor)
	if err != nil {
		return CatalogRelease{}, err
	}
	s.commitCatalogReleaseLocked(prepared, actor)
	return prepared, nil
}

func (s *MemoryStore) CreateCatalogReleaseWithRevision(_ context.Context, revision CatalogRevision, release CatalogRelease, actor string) (CatalogRevision, CatalogRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	preparedRevision, existing, err := s.prepareCatalogRevisionLocked(revision)
	if err != nil {
		return CatalogRevision{}, CatalogRelease{}, err
	}
	release.OrganizationID = preparedRevision.OrganizationID
	release.CatalogName = preparedRevision.CatalogName
	release.CatalogVersion = preparedRevision.CatalogVersion
	release.CurrentRevisionID = preparedRevision.ID
	release.ManifestDigest = preparedRevision.ManifestDigest
	preparedRelease, err := s.prepareCatalogReleaseLocked(release, preparedRevision, actor)
	if err != nil {
		return CatalogRevision{}, CatalogRelease{}, err
	}
	if !existing {
		s.commitCatalogRevisionLocked(preparedRevision, actor)
	}
	s.commitCatalogReleaseLocked(preparedRelease, actor)
	return preparedRevision, preparedRelease, nil
}

func (s *MemoryStore) GetCatalogRelease(_ context.Context, id string) (CatalogRelease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.catalogReleases[id]
	if !ok {
		return CatalogRelease{}, ErrNotFound
	}
	return value, nil
}

func (s *MemoryStore) ListCatalogReleases(_ context.Context, organizationID string) ([]CatalogRelease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organizationID = strings.TrimSpace(organizationID)
	out := []CatalogRelease{}
	for _, value := range s.catalogReleases {
		if organizationID == "" || value.OrganizationID == organizationID {
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CatalogName == out[j].CatalogName {
			if out[i].CatalogVersion == out[j].CatalogVersion {
				return out[i].Channel < out[j].Channel
			}
			return out[i].CatalogVersion < out[j].CatalogVersion
		}
		return out[i].CatalogName < out[j].CatalogName
	})
	return out, nil
}

func (s *MemoryStore) prepareCatalogDraftUpdateLocked(id string, expected int64, revision CatalogRevision) (CatalogRelease, error) {
	current, ok := s.catalogReleases[id]
	if !ok {
		return CatalogRelease{}, ErrNotFound
	}
	if current.Revision != expected {
		return CatalogRelease{}, ErrConflict
	}
	if current.State != CatalogDraft {
		return CatalogRelease{}, ErrImmutable
	}
	if revision.OrganizationID != current.OrganizationID || revision.CatalogName != current.CatalogName || revision.CatalogVersion != current.CatalogVersion {
		return CatalogRelease{}, fmt.Errorf("%w: draft catalog revision does not match release identity", ErrValidation)
	}
	current.CurrentRevisionID, current.ManifestDigest = revision.ID, revision.ManifestDigest
	current.SigningKeyID, current.SigningKeyFingerprint, current.Signature = "", "", ""
	current.Revision++
	current.UpdatedAt = nowUTC(s.now)
	return current, nil
}

func (s *MemoryStore) commitCatalogDraftUpdateLocked(current CatalogRelease, actor string) {
	s.catalogReleases[current.ID] = current
	s.appendAuditLocked(actor, "catalog_release.draft_updated", "catalogRelease", current.ID, current.Revision, map[string]any{"revisionId": current.CurrentRevisionID, "manifestDigest": current.ManifestDigest})
	s.appendOutboxLocked("catalogRelease", current.ID, "catalog_release.draft_updated", current)
}

func (s *MemoryStore) UpdateCatalogReleaseDraft(_ context.Context, id string, expected int64, revisionID, manifestDigest, actor string) (CatalogRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	revision, ok := s.catalogRevisions[revisionID]
	if !ok {
		return CatalogRelease{}, ErrNotFound
	}
	if revision.ManifestDigest != manifestDigest {
		return CatalogRelease{}, fmt.Errorf("%w: draft catalog revision digest does not match request", ErrValidation)
	}
	updated, err := s.prepareCatalogDraftUpdateLocked(id, expected, revision)
	if err != nil {
		return CatalogRelease{}, err
	}
	s.commitCatalogDraftUpdateLocked(updated, actor)
	return updated, nil
}

func (s *MemoryStore) UpdateCatalogReleaseDraftWithRevision(_ context.Context, id string, expected int64, revision CatalogRevision, actor string) (CatalogRevision, CatalogRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.catalogReleases[id]
	if !ok {
		return CatalogRevision{}, CatalogRelease{}, ErrNotFound
	}
	if current.Revision != expected {
		return CatalogRevision{}, CatalogRelease{}, ErrConflict
	}
	if current.State != CatalogDraft {
		return CatalogRevision{}, CatalogRelease{}, ErrImmutable
	}
	preparedRevision, existing, err := s.prepareCatalogRevisionLocked(revision)
	if err != nil {
		return CatalogRevision{}, CatalogRelease{}, err
	}
	updated, err := s.prepareCatalogDraftUpdateLocked(id, expected, preparedRevision)
	if err != nil {
		return CatalogRevision{}, CatalogRelease{}, err
	}
	if !existing {
		s.commitCatalogRevisionLocked(preparedRevision, actor)
	}
	s.commitCatalogDraftUpdateLocked(updated, actor)
	return preparedRevision, updated, nil
}

func (s *MemoryStore) SubmitCatalogReleaseReview(_ context.Context, id string, expected int64, keyID, fingerprint, signature, actor string) (CatalogRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.catalogReleases[id]
	if !ok {
		return CatalogRelease{}, ErrNotFound
	}
	if current.Revision != expected {
		return CatalogRelease{}, ErrConflict
	}
	if current.State != CatalogDraft {
		return CatalogRelease{}, ErrInvalidTransition
	}
	key, ok := s.catalogTrustKeys[strings.TrimSpace(keyID)]
	if !ok {
		return CatalogRelease{}, ErrNotFound
	}
	current.SigningKeyID = strings.TrimSpace(keyID)
	current.SigningKeyFingerprint = strings.TrimSpace(fingerprint)
	current.Signature = strings.TrimSpace(signature)
	if err := VerifyCatalogReleaseSignature(current, key); err != nil {
		return CatalogRelease{}, err
	}
	now := nowUTC(s.now)
	current.State = CatalogReview
	current.RequestedBy = strings.TrimSpace(actor)
	current.ReviewRequestedAt = &now
	current.Revision++
	current.UpdatedAt = now
	s.catalogReleases[id] = current
	s.appendAuditLocked(actor, "catalog_release.review", "catalogRelease", id, current.Revision, map[string]any{"signingKeyId": key.ID, "fingerprint": key.Fingerprint})
	s.appendOutboxLocked("catalogRelease", id, "catalog_release.review", current)
	return current, nil
}

func (s *MemoryStore) TransitionCatalogRelease(_ context.Context, id string, expected int64, to CatalogLifecycleState, actor string) (CatalogRelease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.catalogReleases[id]
	if !ok {
		return CatalogRelease{}, ErrNotFound
	}
	if current.Revision != expected {
		return CatalogRelease{}, ErrConflict
	}
	if !validCatalogTransition(current.State, to) {
		return CatalogRelease{}, ErrInvalidTransition
	}
	now := nowUTC(s.now)
	from := current.State
	if from == CatalogReview && to == CatalogDraft {
		current.ReviewRequestedAt = nil
		current.SigningKeyID, current.SigningKeyFingerprint, current.Signature = "", "", ""
	}
	if to == CatalogPublished {
		key, ok := s.catalogTrustKeys[current.SigningKeyID]
		if !ok {
			return CatalogRelease{}, ErrNotFound
		}
		if err := VerifyCatalogReleaseSignature(current, key); err != nil {
			return CatalogRelease{}, err
		}
		current.PublishedBy, current.PublishedAt = strings.TrimSpace(actor), &now
	}
	if to == CatalogDeprecated {
		current.DeprecatedBy, current.DeprecatedAt = strings.TrimSpace(actor), &now
	}
	if to == CatalogRevoked {
		current.RevokedBy, current.RevokedAt = strings.TrimSpace(actor), &now
	}
	current.State = to
	current.Revision++
	current.UpdatedAt = now
	s.catalogReleases[id] = current
	action := "catalog_release." + strings.ToLower(string(to))
	s.appendAuditLocked(actor, action, "catalogRelease", id, current.Revision, map[string]any{"from": from, "to": to, "channel": current.Channel})
	s.appendOutboxLocked("catalogRelease", id, action, current)
	return current, nil
}
