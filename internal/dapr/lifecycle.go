package daprruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	LifecycleAuthority        = "DAPR_TARGET_LIFECYCLE_AUTHORITY_V1"
	LifecyclePayloadMediaType = "application/vnd.4so.dapr-lifecycle+json"
	ObservedEvidenceKind      = "dapr-runtime-observed"
	RecoveryEvidenceKind      = "dapr-runtime-recovery-required"
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
	RuntimeLockDigest            string          `json:"runtimeLockDigest"`
	ExpectedObservedLockDigest   string          `json:"expectedObservedLockDigest,omitempty"`
	Disconnected                 bool            `json:"disconnected,omitempty"`
}

type ObservedState struct {
	Authority         string          `json:"authority"`
	OperationID       string          `json:"operationId"`
	ClusterID         string          `json:"clusterId"`
	Action            LifecycleAction `json:"action"`
	Installed         bool            `json:"installed"`
	RuntimeLockDigest string          `json:"runtimeLockDigest,omitempty"`
	Version           string          `json:"version,omitempty"`
	UpstreamCommit    string          `json:"upstreamCommit,omitempty"`
	ObservedAt        string          `json:"observedAt"`
	Phase             string          `json:"phase"`
}

func lifecycleDigest(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, ch := range value[len("sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}

func NormalizeLifecycleAction(value LifecycleAction) (LifecycleAction, error) {
	switch LifecycleAction(strings.ToUpper(strings.TrimSpace(string(value)))) {
	case ActionInstall:
		return ActionInstall, nil
	case ActionUpgrade:
		return ActionUpgrade, nil
	case ActionRemove:
		return ActionRemove, nil
	default:
		return "", fmt.Errorf("DAPR_LIFECYCLE_ACTION_INVALID")
	}
}

func CanonicalLifecycleRequest(value LifecycleRequest) (LifecycleRequest, error) {
	value.ProjectID = strings.TrimSpace(value.ProjectID)
	value.ClusterID = strings.TrimSpace(value.ClusterID)
	value.RuntimeLockDigest = strings.ToLower(strings.TrimSpace(value.RuntimeLockDigest))
	value.ExpectedObservedLockDigest = strings.ToLower(strings.TrimSpace(value.ExpectedObservedLockDigest))
	action, err := NormalizeLifecycleAction(value.Action)
	if err != nil {
		return LifecycleRequest{}, err
	}
	value.Action = action
	if value.ProjectID == "" || value.ClusterID == "" {
		return LifecycleRequest{}, fmt.Errorf("DAPR_LIFECYCLE_SCOPE_REQUIRED")
	}
	if !lifecycleDigest(value.RuntimeLockDigest) {
		return LifecycleRequest{}, fmt.Errorf("DAPR_LIFECYCLE_LOCK_DIGEST_INVALID")
	}
	if value.ExpectedObservedLockDigest != "" && !lifecycleDigest(value.ExpectedObservedLockDigest) {
		return LifecycleRequest{}, fmt.Errorf("DAPR_LIFECYCLE_OBSERVED_DIGEST_INVALID")
	}
	return value, nil
}

func MarshalLifecycleRequest(value LifecycleRequest) ([]byte, string, error) {
	value, err := CanonicalLifecycleRequest(value)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ParseLifecycleRequest(raw []byte, digest string) (LifecycleRequest, error) {
	var value LifecycleRequest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return LifecycleRequest{}, fmt.Errorf("decode Dapr lifecycle request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return LifecycleRequest{}, fmt.Errorf("DAPR_LIFECYCLE_REQUEST_TRAILING_DATA")
		}
		return LifecycleRequest{}, fmt.Errorf("decode Dapr lifecycle request trailing data: %w", err)
	}
	value, err := CanonicalLifecycleRequest(value)
	if err != nil {
		return LifecycleRequest{}, err
	}
	_, got, err := MarshalLifecycleRequest(value)
	if err != nil {
		return LifecycleRequest{}, err
	}
	if strings.TrimSpace(digest) != "" && strings.TrimSpace(digest) != got {
		return LifecycleRequest{}, fmt.Errorf("DAPR_LIFECYCLE_REQUEST_DIGEST_MISMATCH")
	}
	return value, nil
}

func ValidateLifecycleTransition(action LifecycleAction, observed *ObservedState, currentLockDigest string) error {
	action, err := NormalizeLifecycleAction(action)
	if err != nil {
		return err
	}
	currentLockDigest = strings.ToLower(strings.TrimSpace(currentLockDigest))
	if !lifecycleDigest(currentLockDigest) {
		return fmt.Errorf("DAPR_LIFECYCLE_LOCK_DIGEST_INVALID")
	}
	switch action {
	case ActionInstall:
		if observed != nil && observed.Installed {
			return fmt.Errorf("DAPR_ALREADY_INSTALLED")
		}
	case ActionUpgrade:
		if observed == nil || !observed.Installed || !lifecycleDigest(observed.RuntimeLockDigest) {
			return fmt.Errorf("DAPR_UPGRADE_REQUIRES_OBSERVED_INSTALL")
		}
		if strings.EqualFold(observed.RuntimeLockDigest, currentLockDigest) {
			return fmt.Errorf("DAPR_UPGRADE_TARGET_EQUALS_OBSERVED")
		}
	case ActionRemove:
		if observed == nil || !observed.Installed {
			return fmt.Errorf("DAPR_REMOVE_REQUIRES_OBSERVED_INSTALL")
		}
	}
	return nil
}

func ValidateLifecycleDispatchFence(action LifecycleAction, observed *ObservedState, currentLockDigest, expectedObservedLockDigest string) error {
	if err := ValidateLifecycleTransition(action, observed, currentLockDigest); err != nil {
		return err
	}
	expectedObservedLockDigest = strings.ToLower(strings.TrimSpace(expectedObservedLockDigest))
	if expectedObservedLockDigest == "" {
		return nil
	}
	if observed == nil || !strings.EqualFold(strings.TrimSpace(observed.RuntimeLockDigest), expectedObservedLockDigest) {
		return fmt.Errorf("DAPR_OBSERVED_FENCE_CHANGED")
	}
	return nil
}
