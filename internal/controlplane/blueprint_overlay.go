package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var overlaySemver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var overlayName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var overlaySensitiveSegment = regexp.MustCompile(`(?i)(password|token|secret|private.?key|credential)`)

func cloneOverlay(v BlueprintOverlay) BlueprintOverlay {
	v.Changes = append([]BlueprintOverlayChange(nil), v.Changes...)
	for i := range v.Changes {
		v.Changes[i].Value = append(json.RawMessage(nil), v.Changes[i].Value...)
	}
	return v
}

// NormalizeBlueprintOverlay validates immutable overlay identity and returns a
// deterministic digest. It never accepts plaintext secret-shaped JSON by
// itself; Blueprint validation is still run on the resolved output.
func NormalizeBlueprintOverlay(v BlueprintOverlay) (BlueprintOverlay, error) {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.Name = strings.ToLower(strings.TrimSpace(v.Name))
	v.Version = strings.TrimSpace(v.Version)
	v.ScopeKey = strings.ToLower(strings.TrimSpace(v.ScopeKey))
	if v.ProjectID == "" || !overlayName.MatchString(v.Name) || len(v.Name) > 63 || !overlaySemver.MatchString(v.Version) || !overlayName.MatchString(v.ScopeKey) || len(v.ScopeKey) > 63 {
		return BlueprintOverlay{}, fmt.Errorf("%w: projectId, DNS-label name/scopeKey and semantic version are required", ErrValidation)
	}
	if v.Scope != BlueprintOverlayProvider && v.Scope != BlueprintOverlayEnvironment {
		return BlueprintOverlay{}, fmt.Errorf("%w: overlay scope must be PROVIDER or ENVIRONMENT", ErrValidation)
	}
	if len(v.Changes) == 0 || len(v.Changes) > 128 {
		return BlueprintOverlay{}, fmt.Errorf("%w: overlay must contain 1..128 changes", ErrValidation)
	}
	seen := map[string]bool{}
	for i := range v.Changes {
		v.Changes[i].Path = strings.TrimSpace(v.Changes[i].Path)
		if !strings.HasPrefix(v.Changes[i].Path, "/spec/") || strings.HasPrefix(v.Changes[i].Path, "/spec/fieldOwnership") || seen[v.Changes[i].Path] {
			return BlueprintOverlay{}, fmt.Errorf("%w: changes must use unique /spec JSON Pointers and cannot modify fieldOwnership", ErrValidation)
		}
		if len(v.Changes[i].Value) == 0 || !json.Valid(v.Changes[i].Value) {
			return BlueprintOverlay{}, fmt.Errorf("%w: overlay change %s requires valid JSON value", ErrValidation, v.Changes[i].Path)
		}
		for _, segment := range strings.Split(v.Changes[i].Path, "/") {
			segment = strings.ToLower(segment)
			if overlaySensitiveSegment.MatchString(segment) && !strings.HasSuffix(segment, "ref") && !strings.HasSuffix(segment, "reference") {
				return BlueprintOverlay{}, fmt.Errorf("%w: overlay change %s cannot persist plaintext secret-shaped fields; use a secret reference", ErrValidation, v.Changes[i].Path)
			}
		}
		seen[v.Changes[i].Path] = true
	}
	sort.Slice(v.Changes, func(i, j int) bool { return v.Changes[i].Path < v.Changes[j].Path })
	material := struct {
		ProjectID string                   `json:"projectId"`
		Name      string                   `json:"name"`
		Version   string                   `json:"version"`
		Scope     BlueprintOverlayScope    `json:"scope"`
		ScopeKey  string                   `json:"scopeKey"`
		Changes   []BlueprintOverlayChange `json:"changes"`
	}{v.ProjectID, v.Name, v.Version, v.Scope, v.ScopeKey, v.Changes}
	raw, _ := json.Marshal(material)
	sum := sha256.Sum256(raw)
	v.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return v, nil
}

const historicalResolutionDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// NormalizeBlueprintRevisionResolution preserves compatibility with historical
// revisions while making every newly persisted revision self-describing.
func NormalizeBlueprintRevisionResolution(v BlueprintRevision) BlueprintRevision {
	if v.BaseBlueprintDigest == "" {
		v.BaseBlueprintDigest = v.BlueprintDigest
	}
	if v.OverlayDigest == "" {
		v.OverlayDigest = historicalResolutionDigest
	}
	if v.OwnershipDigest == "" {
		v.OwnershipDigest = historicalResolutionDigest
	}
	if len(v.BasePayload) == 0 {
		v.BasePayload = append([]byte(nil), v.Payload...)
	}
	if len(v.ResolutionPayload) == 0 {
		v.ResolutionPayload = []byte(`{"fields":[],"migration":"historical-pre-overlay"}`)
	}
	return v
}
