package openchoreo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	LifecycleAuthority = "OPENCHOREO_TARGET_LIFECYCLE_AUTHORITY_V1"
	LifecyclePayloadMediaType = "application/vnd.4so.openchoreo-lifecycle+json"
	ObservedEvidenceKind = "openchoreo-runtime-observed"
	RecoveryEvidenceKind = "openchoreo-runtime-recovery-required"
)

type LifecycleAction string

const (
	ActionInstall LifecycleAction = "INSTALL"
	ActionUpgrade LifecycleAction = "UPGRADE"
	ActionRemove  LifecycleAction = "REMOVE"
)

type LifecycleRequest struct {
	ProjectID                    string          `json:"projectId"`
	ClusterID                    string          `json:"clusterId"`
	Action                       LifecycleAction `json:"action"`
	RuntimeSourceDigest          string          `json:"runtimeSourceDigest"`
	ExpectedObservedSourceDigest string          `json:"expectedObservedSourceDigest,omitempty"`
	Disconnected                 bool            `json:"disconnected,omitempty"`
	NativeCapabilitySuppressions []string        `json:"nativeCapabilitySuppressions,omitempty"`
}

type ObservedState struct {
	Authority           string          `json:"authority"`
	OperationID         string          `json:"operationId"`
	ClusterID           string          `json:"clusterId"`
	Action              LifecycleAction `json:"action"`
	Installed           bool            `json:"installed"`
	RuntimeSourceDigest string          `json:"runtimeSourceDigest,omitempty"`
	Version             string          `json:"version,omitempty"`
	UpstreamCommit      string          `json:"upstreamCommit,omitempty"`
	ObservedAt          string          `json:"observedAt"`
	Phase               string          `json:"phase"`
}

func NormalizeLifecycleAction(v LifecycleAction) (LifecycleAction, error) {
	switch LifecycleAction(strings.ToUpper(strings.TrimSpace(string(v)))) {
	case ActionInstall:
		return ActionInstall, nil
	case ActionUpgrade:
		return ActionUpgrade, nil
	case ActionRemove:
		return ActionRemove, nil
	default:
		return "", fmt.Errorf("OPENCHOREO_LIFECYCLE_ACTION_INVALID")
	}
}

func CanonicalLifecycleRequest(v LifecycleRequest) (LifecycleRequest, error) {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.ClusterID = strings.TrimSpace(v.ClusterID)
	v.RuntimeSourceDigest = strings.ToLower(strings.TrimSpace(v.RuntimeSourceDigest))
	v.ExpectedObservedSourceDigest = strings.ToLower(strings.TrimSpace(v.ExpectedObservedSourceDigest))
	action, err := NormalizeLifecycleAction(v.Action)
	if err != nil {
		return LifecycleRequest{}, err
	}
	v.Action = action
	if v.ProjectID == "" || v.ClusterID == "" {
		return LifecycleRequest{}, fmt.Errorf("OPENCHOREO_LIFECYCLE_SCOPE_REQUIRED")
	}
	if !validDigest(v.RuntimeSourceDigest) {
		return LifecycleRequest{}, fmt.Errorf("OPENCHOREO_LIFECYCLE_SOURCE_DIGEST_INVALID")
	}
	if v.ExpectedObservedSourceDigest != "" && !validDigest(v.ExpectedObservedSourceDigest) {
		return LifecycleRequest{}, fmt.Errorf("OPENCHOREO_LIFECYCLE_OBSERVED_DIGEST_INVALID")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(v.NativeCapabilitySuppressions))
	for _, raw := range v.NativeCapabilitySuppressions {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" || seen[value] {
			continue
		}
		switch value {
		case "networking-and-ingress-native", "observability-native", "operator-lifecycle-native", "tenancy-native":
		default:
			return LifecycleRequest{}, fmt.Errorf("OPENCHOREO_LIFECYCLE_SUPPRESSION_INVALID")
		}
		seen[value] = true
		out = append(out, value)
	}
	// Admission already returns suppressions in deterministic order. Rebuild in
	// the same fixed order so request digests are independent of caller ordering.
	order := []string{"networking-and-ingress-native", "observability-native", "operator-lifecycle-native", "tenancy-native"}
	v.NativeCapabilitySuppressions = v.NativeCapabilitySuppressions[:0]
	for _, key := range order {
		if seen[key] {
			v.NativeCapabilitySuppressions = append(v.NativeCapabilitySuppressions, key)
		}
	}
	return v, nil
}

func MarshalLifecycleRequest(v LifecycleRequest) ([]byte, string, error) {
	v, err := CanonicalLifecycleRequest(v)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ParseLifecycleRequest(raw []byte, digest string) (LifecycleRequest, error) {
	var v LifecycleRequest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return LifecycleRequest{}, fmt.Errorf("decode OpenChoreo lifecycle request: %w", err)
	}
	v, err := CanonicalLifecycleRequest(v)
	if err != nil {
		return LifecycleRequest{}, err
	}
	canonical, got, err := MarshalLifecycleRequest(v)
	if err != nil {
		return LifecycleRequest{}, err
	}
	_ = canonical
	if strings.TrimSpace(digest) != "" && got != strings.TrimSpace(digest) {
		return LifecycleRequest{}, fmt.Errorf("OPENCHOREO_LIFECYCLE_REQUEST_DIGEST_MISMATCH")
	}
	return v, nil
}

func ValidateLifecycleTransition(action LifecycleAction, observed *ObservedState, currentSourceDigest string) error {
	currentSourceDigest = strings.ToLower(strings.TrimSpace(currentSourceDigest))
	if !validDigest(currentSourceDigest) {
		return fmt.Errorf("OPENCHOREO_LIFECYCLE_SOURCE_DIGEST_INVALID")
	}
	action, err := NormalizeLifecycleAction(action)
	if err != nil {
		return err
	}
	switch action {
	case ActionInstall:
		if observed != nil && observed.Installed {
			return fmt.Errorf("OPENCHOREO_ALREADY_INSTALLED")
		}
	case ActionUpgrade:
		if observed == nil || !observed.Installed || !validDigest(observed.RuntimeSourceDigest) {
			return fmt.Errorf("OPENCHOREO_UPGRADE_REQUIRES_OBSERVED_INSTALL")
		}
		if strings.EqualFold(observed.RuntimeSourceDigest, currentSourceDigest) {
			return fmt.Errorf("OPENCHOREO_UPGRADE_TARGET_EQUALS_OBSERVED")
		}
	case ActionRemove:
		if observed == nil || !observed.Installed {
			return fmt.Errorf("OPENCHOREO_REMOVE_REQUIRES_OBSERVED_INSTALL")
		}
	}
	return nil
}
