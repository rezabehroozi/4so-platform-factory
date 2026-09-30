package daprruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
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
	RuntimeVersion               string          `json:"runtimeVersion"`
	UpstreamCommit               string          `json:"upstreamCommit"`
	ExpectedObservedLockDigest   string          `json:"expectedObservedLockDigest,omitempty"`
	Disconnected                 bool            `json:"disconnected,omitempty"`
}

type ObservedState struct {
	Authority                string                    `json:"authority"`
	OperationID              string                    `json:"operationId"`
	ClusterID                string                    `json:"clusterId"`
	Action                   LifecycleAction           `json:"action"`
	Installed                bool                      `json:"installed"`
	RuntimeLockDigest        string                    `json:"runtimeLockDigest,omitempty"`
	Version                  string                    `json:"version,omitempty"`
	UpstreamCommit           string                    `json:"upstreamCommit,omitempty"`
	MirrorPullEvidence       *TargetMirrorPullEvidence `json:"mirrorPullEvidence,omitempty"`
	MirrorPullEvidenceDigest string                    `json:"mirrorPullEvidenceDigest,omitempty"`
	ObservedAt               string                    `json:"observedAt"`
	Phase                    string                    `json:"phase"`
}

const TargetMirrorPullEvidenceAuthority = "DAPR_TARGET_MIRROR_PULL_EVIDENCE_V1"

type TargetMirrorPullObservation struct {
	Role           string `json:"role"`
	WorkloadKind   string `json:"workloadKind"`
	Namespace      string `json:"namespace"`
	WorkloadName   string `json:"workloadName"`
	Container      string `json:"container"`
	ImageReference string `json:"imageReference"`
	Ready          bool   `json:"ready"`
}

type TargetMirrorPullEvidence struct {
	Authority                           string                        `json:"authority"`
	ClusterID                           string                        `json:"clusterId"`
	OperationID                         string                        `json:"operationId"`
	FenceToken                          int64                         `json:"fenceToken"`
	RuntimeLockDigest                   string                        `json:"runtimeLockDigest"`
	MirrorRegistry                      string                        `json:"mirrorRegistry"`
	RuntimeImages                       []TargetMirrorPullObservation `json:"runtimeImages"`
	SidecarImageReference               string                        `json:"sidecarImageReference"`
	SidecarPullInferred                 bool                          `json:"sidecarPullInferred"`
	WorkloadSidecarPullEvidenceRequired bool                          `json:"workloadSidecarPullEvidenceRequired"`
	ObservedAt                          string                        `json:"observedAt"`
}

func ValidateTargetMirrorPullEvidence(value TargetMirrorPullEvidence, lock RuntimeLock, clusterID, operationID string, fenceToken int64, runtimeLockDigest string) error {
	if err := ValidateRuntimeLock(lock); err != nil {
		return err
	}
	clusterID = strings.TrimSpace(clusterID)
	operationID = strings.TrimSpace(operationID)
	runtimeLockDigest = strings.ToLower(strings.TrimSpace(runtimeLockDigest))
	lockDigest, err := RuntimeLockDigest(lock)
	if err != nil || lockDigest != runtimeLockDigest {
		return fmt.Errorf("DAPR_TARGET_MIRROR_PULL_RUNTIME_LOCK_MISMATCH")
	}
	if value.Authority != TargetMirrorPullEvidenceAuthority || strings.TrimSpace(value.ClusterID) != clusterID ||
		strings.TrimSpace(value.OperationID) != operationID || value.FenceToken != fenceToken || fenceToken <= 0 ||
		strings.ToLower(strings.TrimSpace(value.RuntimeLockDigest)) != runtimeLockDigest {
		return fmt.Errorf("DAPR_TARGET_MIRROR_PULL_EVIDENCE_BINDING_INVALID")
	}
	if strings.ToLower(strings.TrimSpace(value.MirrorRegistry)) != strings.ToLower(strings.TrimSpace(lock.MirrorRegistry)) ||
		strings.TrimSpace(value.ObservedAt) == "" || value.SidecarPullInferred || !value.WorkloadSidecarPullEvidenceRequired {
		return fmt.Errorf("DAPR_TARGET_MIRROR_PULL_EVIDENCE_SCOPE_INVALID")
	}
	expected := map[string]string{}
	for _, image := range lock.ImageLocks {
		expected[strings.ToLower(strings.TrimSpace(image.Role))] = strings.TrimSpace(image.MirrorReference)
	}
	if strings.TrimSpace(value.SidecarImageReference) == "" || strings.TrimSpace(value.SidecarImageReference) != expected["sidecar"] {
		return fmt.Errorf("DAPR_TARGET_SIDECAR_REFERENCE_INVALID")
	}
	seen := map[string]bool{}
	for _, observation := range value.RuntimeImages {
		role := strings.ToLower(strings.TrimSpace(observation.Role))
		if role != "operator" && role != "injector" && role != "sentry" {
			return fmt.Errorf("DAPR_TARGET_MIRROR_PULL_ROLE_INVALID")
		}
		if seen[role] || !observation.Ready || strings.TrimSpace(observation.WorkloadKind) != "Deployment" ||
			strings.TrimSpace(observation.Namespace) != "dapr-system" ||
			strings.TrimSpace(observation.ImageReference) != expected[role] ||
			strings.TrimSpace(observation.WorkloadName) == "" || strings.TrimSpace(observation.Container) == "" {
			return fmt.Errorf("DAPR_TARGET_MIRROR_PULL_OBSERVATION_INVALID")
		}
		seen[role] = true
	}
	for _, role := range []string{"operator", "injector", "sentry"} {
		if !seen[role] {
			return fmt.Errorf("DAPR_TARGET_MIRROR_PULL_EVIDENCE_INCOMPLETE")
		}
	}
	return nil
}

func TargetMirrorPullEvidenceDigest(value TargetMirrorPullEvidence, lock RuntimeLock, clusterID, operationID string, fenceToken int64, runtimeLockDigest string) (string, error) {
	if err := ValidateTargetMirrorPullEvidence(value, lock, clusterID, operationID, fenceToken, runtimeLockDigest); err != nil {
		return "", err
	}
	canonical := value
	canonical.RuntimeImages = append([]TargetMirrorPullObservation(nil), value.RuntimeImages...)
	sort.Slice(canonical.RuntimeImages, func(i, j int) bool {
		return canonical.RuntimeImages[i].Role < canonical.RuntimeImages[j].Role
	})
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
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
	value.RuntimeVersion = strings.TrimSpace(value.RuntimeVersion)
	value.UpstreamCommit = strings.ToLower(strings.TrimSpace(value.UpstreamCommit))
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
	if value.RuntimeVersion == "" || len(value.UpstreamCommit) != 40 {
		return LifecycleRequest{}, fmt.Errorf("DAPR_LIFECYCLE_RUNTIME_IDENTITY_INVALID")
	}
	for _, ch := range value.UpstreamCommit {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return LifecycleRequest{}, fmt.Errorf("DAPR_LIFECYCLE_RUNTIME_IDENTITY_INVALID")
		}
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
