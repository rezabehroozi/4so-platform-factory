package runtimeupgrade

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

type fakeExecutor struct {
	calls  []string
	fail   Stage
	tokens []string
}

func (f *fakeExecutor) result(stage Stage) (Result, error) {
	f.calls = append(f.calls, string(stage))
	f.tokens = append(f.tokens, "")
	if f.fail == stage {
		return Result{}, errors.New("boom")
	}
	r := Result{Stage: stage, EvidenceDigest: fmt.Sprintf("sha256:%064x", len(f.calls))}
	if stage == StageReadiness {
		r.Ready = true
	}
	if stage == StageFailureRecovery {
		r.RecoveryVerified = true
	}
	if stage == StageRemoveOldVersion {
		r.OldVersionRemoved = true
	}
	return r, nil
}
func (f *fakeExecutor) withToken(stage Stage, t string) (Result, error) {
	r, e := f.result(stage)
	f.tokens[len(f.tokens)-1] = t
	return r, e
}
func (f *fakeExecutor) Preflight(e Edge, t string) (Result, error) {
	return f.withToken(StagePreflight, t)
}
func (f *fakeExecutor) ApplyTarget(e Edge, t string) (Result, error) {
	return f.withToken(StageApplyTarget, t)
}
func (f *fakeExecutor) VerifyReadiness(e Edge, t string) (Result, error) {
	return f.withToken(StageReadiness, t)
}
func (f *fakeExecutor) VerifyFailureRecovery(e Edge, t string) (Result, error) {
	return f.withToken(StageFailureRecovery, t)
}
func (f *fakeExecutor) RemoveOldVersion(e Edge, t string) (Result, error) {
	return f.withToken(StageRemoveOldVersion, t)
}

func edge() Edge {
	return Edge{Component: "gateway-api", FromRelease: "1.5.0", ToRelease: "1.5.1", FromSourceLockDigest: "sha256:" + fmt.Sprintf("%064x", 1), ToSourceLockDigest: "sha256:" + fmt.Sprintf("%064x", 2), FromRenderedDigest: "sha256:" + fmt.Sprintf("%064x", 3), ToRenderedDigest: "sha256:" + fmt.Sprintf("%064x", 4)}
}

func TestUpgradeRequiresExactDistinctSourcePair(t *testing.T) {
	e := edge()
	if ValidateEdge(e) != nil {
		t.Fatal(ValidateEdge(e))
	}
	e.ToSourceLockDigest = e.FromSourceLockDigest
	if ValidateEdge(e) == nil {
		t.Fatal("same source lock admitted")
	}
}
func TestUpgradeFiveStagesAreFencedResumableAndEvidenceBacked(t *testing.T) {
	e := edge()
	pd, _ := PlanDigest(e)
	op := Operation{ID: "up-1", PlanDigest: pd, State: StateRequested}
	ex := &fakeExecutor{}
	for i := 0; i < 5; i++ {
		var err error
		op, _, err = Advance(ex, e, op, 9)
		if err != nil {
			t.Fatal(err)
		}
	}
	if op.State != StateSucceeded || op.EvidenceDigest == "" {
		t.Fatalf("bad op %#v", op)
	}
	want := []string{"PREFLIGHT", "APPLY_TARGET", "READINESS", "FAILURE_RECOVERY", "REMOVE_OLD_VERSION"}
	if !reflect.DeepEqual(ex.calls, want) {
		t.Fatalf("calls=%v", ex.calls)
	}
	seen := map[string]bool{}
	for _, tok := range ex.tokens {
		if tok == "" || seen[tok] {
			t.Fatalf("bad/reused token %q", tok)
		}
		seen[tok] = true
	}
	if _, _, err := Advance(ex, e, Operation{ID: "x", PlanDigest: pd, Fence: 9, NextStage: StagePreflight}, 10); err == nil {
		t.Fatal("stale fence admitted")
	}
}
func TestUpgradeFailureResumesSameStage(t *testing.T) {
	e := edge()
	pd, _ := PlanDigest(e)
	ex := &fakeExecutor{fail: StageReadiness}
	op := Operation{ID: "up-2", PlanDigest: pd, NextStage: StageReadiness}
	failed, _, err := Advance(ex, e, op, 4)
	if err == nil || failed.NextStage != StageReadiness {
		t.Fatalf("bad failure %#v %v", failed, err)
	}
	ex.fail = ""
	resumed, r, err := Advance(ex, e, failed, 4)
	if err != nil || resumed.NextStage != StageFailureRecovery || !r.Ready {
		t.Fatalf("bad resume %#v %#v %v", resumed, r, err)
	}
}
