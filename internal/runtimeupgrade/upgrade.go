package runtimeupgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const Authority = "COMPONENT_RUNTIME_UPGRADE_V1"

type Stage string

const (
	StagePreflight        Stage = "PREFLIGHT"
	StageApplyTarget      Stage = "APPLY_TARGET"
	StageReadiness        Stage = "READINESS"
	StageFailureRecovery  Stage = "FAILURE_RECOVERY"
	StageRemoveOldVersion Stage = "REMOVE_OLD_VERSION"
	StageComplete         Stage = "COMPLETE"
)

type State string

const (
	StateRequested State = "REQUESTED"
	StateRunning   State = "RUNNING"
	StateSucceeded State = "SUCCEEDED"
	StateFailed    State = "FAILED"
)

type Edge struct {
	Component            string `json:"component"`
	FromRelease          string `json:"fromRelease"`
	ToRelease            string `json:"toRelease"`
	FromSourceLockDigest string `json:"fromSourceLockDigest"`
	ToSourceLockDigest   string `json:"toSourceLockDigest"`
	FromRenderedDigest   string `json:"fromRenderedDigest"`
	ToRenderedDigest     string `json:"toRenderedDigest"`
}

type Operation struct {
	ID             string `json:"id"`
	PlanDigest     string `json:"planDigest"`
	State          State  `json:"state"`
	NextStage      Stage  `json:"nextStage"`
	Revision       int64  `json:"revision"`
	Fence          int64  `json:"fence"`
	LastError      string `json:"lastError,omitempty"`
	EvidenceDigest string `json:"evidenceDigest,omitempty"`
}

type Result struct {
	Stage             Stage  `json:"stage"`
	EvidenceDigest    string `json:"evidenceDigest"`
	Ready             bool   `json:"ready"`
	RecoveryVerified  bool   `json:"recoveryVerified"`
	OldVersionRemoved bool   `json:"oldVersionRemoved"`
}

type Executor interface {
	Preflight(edge Edge, operationToken string) (Result, error)
	ApplyTarget(edge Edge, operationToken string) (Result, error)
	VerifyReadiness(edge Edge, operationToken string) (Result, error)
	VerifyFailureRecovery(edge Edge, operationToken string) (Result, error)
	RemoveOldVersion(edge Edge, operationToken string) (Result, error)
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func ValidateEdge(e Edge) error {
	if strings.TrimSpace(e.Component) == "" || strings.TrimSpace(e.FromRelease) == "" || strings.TrimSpace(e.ToRelease) == "" {
		return errors.New("component/fromRelease/toRelease are required")
	}
	if e.FromRelease == e.ToRelease {
		return errors.New("upgrade edge requires distinct releases")
	}
	for name, v := range map[string]string{"fromSourceLockDigest": e.FromSourceLockDigest, "toSourceLockDigest": e.ToSourceLockDigest, "fromRenderedDigest": e.FromRenderedDigest, "toRenderedDigest": e.ToRenderedDigest} {
		if !digestRE.MatchString(v) {
			return fmt.Errorf("%s must be sha256:<64 lowercase hex>", name)
		}
	}
	if e.FromSourceLockDigest == e.ToSourceLockDigest {
		return errors.New("upgrade edge requires distinct source-lock digests")
	}
	if e.FromRenderedDigest == e.ToRenderedDigest {
		return errors.New("upgrade edge requires distinct rendered digests")
	}
	return nil
}

func PlanDigest(e Edge) (string, error) {
	if err := ValidateEdge(e); err != nil {
		return "", err
	}
	parts := []string{Authority, e.Component, e.FromRelease, e.ToRelease, e.FromSourceLockDigest, e.ToSourceLockDigest, e.FromRenderedDigest, e.ToRenderedDigest, "rollback=recovery-only-no-fake-rollback"}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func OperationToken(op Operation, stage Stage) string {
	h := sha256.Sum256([]byte(strings.Join([]string{Authority, op.ID, op.PlanDigest, string(stage)}, "\x00")))
	return hex.EncodeToString(h[:])
}

func Advance(ex Executor, edge Edge, op Operation, fence int64) (Operation, Result, error) {
	if ex == nil {
		return op, Result{}, errors.New("upgrade executor is required")
	}
	pd, err := PlanDigest(edge)
	if err != nil {
		return op, Result{}, err
	}
	if op.PlanDigest != "" && op.PlanDigest != pd {
		return op, Result{}, errors.New("upgrade plan digest mismatch")
	}
	if fence <= 0 || (op.Fence != 0 && op.Fence != fence) {
		return op, Result{}, errors.New("stale or invalid upgrade fence")
	}
	if op.State == StateSucceeded {
		return op, Result{Stage: StageComplete, Ready: true, RecoveryVerified: true, OldVersionRemoved: true, EvidenceDigest: op.EvidenceDigest}, nil
	}
	if op.ID == "" {
		return op, Result{}, errors.New("operation id is required")
	}
	if op.NextStage == "" {
		op.NextStage = StagePreflight
	}
	op.PlanDigest = pd
	op.Fence = fence
	op.State = StateRunning
	token := OperationToken(op, op.NextStage)
	var result Result
	switch op.NextStage {
	case StagePreflight:
		result, err = ex.Preflight(edge, token)
		if err == nil {
			op.NextStage = StageApplyTarget
		}
	case StageApplyTarget:
		result, err = ex.ApplyTarget(edge, token)
		if err == nil {
			op.NextStage = StageReadiness
		}
	case StageReadiness:
		result, err = ex.VerifyReadiness(edge, token)
		if err == nil && !result.Ready {
			err = errors.New("target release readiness not proven")
		}
		if err == nil {
			op.NextStage = StageFailureRecovery
		}
	case StageFailureRecovery:
		result, err = ex.VerifyFailureRecovery(edge, token)
		if err == nil && !result.RecoveryVerified {
			err = errors.New("failure recovery not proven")
		}
		if err == nil {
			op.NextStage = StageRemoveOldVersion
		}
	case StageRemoveOldVersion:
		result, err = ex.RemoveOldVersion(edge, token)
		if err == nil && !result.OldVersionRemoved {
			err = errors.New("old release removal not proven")
		}
		if err == nil {
			op.NextStage = StageComplete
			op.State = StateSucceeded
		}
	case StageComplete:
		op.State = StateSucceeded
		result = Result{Stage: StageComplete, Ready: true, RecoveryVerified: true, OldVersionRemoved: true}
	default:
		err = fmt.Errorf("unknown upgrade stage %q", op.NextStage)
	}
	op.Revision++
	if err != nil {
		op.State = StateFailed
		op.LastError = err.Error()
		return op, result, err
	}
	op.LastError = ""
	if strings.TrimSpace(result.EvidenceDigest) == "" {
		return op, result, errors.New("upgrade stage returned no evidence digest")
	}
	if !digestRE.MatchString(result.EvidenceDigest) {
		return op, result, errors.New("upgrade stage evidence digest is invalid")
	}
	if op.State == StateSucceeded {
		h := sha256.Sum256([]byte(strings.Join([]string{Authority, op.ID, op.PlanDigest, result.EvidenceDigest, "state=SUCCEEDED"}, "\x00")))
		op.EvidenceDigest = "sha256:" + hex.EncodeToString(h[:])
	}
	return op, result, nil
}
