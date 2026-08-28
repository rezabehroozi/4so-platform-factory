package bootstrap

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type gitOpsVerifySystem struct {
	*SimulatedSystem
	commit string
	digest string
}

func (s *gitOpsVerifySystem) Output(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "jsonpath={.status.sync.status}"):
		return []byte("Synced"), nil
	case strings.Contains(joined, "jsonpath={.status.health.status}"):
		return []byte("Healthy"), nil
	case strings.Contains(joined, "jsonpath={.status.sync.revision}"):
		return []byte(s.commit), nil
	case strings.Contains(joined, "jsonpath={.data.revisionDigest}"):
		return []byte(s.digest), nil
	default:
		return nil, fmt.Errorf("unexpected output command %s %v", name, args)
	}
}

// Keep explicit interface coverage here because GitOps verification runs through
// the same System boundary as the real bootstrap runner.
func (s *gitOpsVerifySystem) RunInput(ctx context.Context, name string, args []string, env map[string]string, input io.Reader) error {
	return s.SimulatedSystem.RunInput(ctx, name, args, env, input)
}

func TestVerifyGitOpsHandoverRequiresExactPublishedCommit(t *testing.T) {
	desiredCommit := strings.Repeat("a", 40)
	if err := validateObservedGitOpsCommit(desiredCommit, strings.Repeat("c", 40)); err == nil || !strings.Contains(err.Error(), "observed commit") {
		t.Fatalf("expected immutable commit mismatch, got %v", err)
	}
	if err := validateObservedGitOpsCommit("abcdef1", "abcdef1"); err == nil {
		t.Fatal("abbreviated desired commit was accepted")
	}
}

func TestVerifyGitOpsHandoverPersistsObservedCommit(t *testing.T) {
	root := t.TempDir()
	desiredCommit := strings.Repeat("a", 40)
	digest := "sha256:" + strings.Repeat("b", 64)
	system := &gitOpsVerifySystem{SimulatedSystem: &SimulatedSystem{Root: root}, commit: desiredCommit, digest: digest}
	runner := &Runner{system: system, simulation: false, now: func() time.Time { return time.Unix(1, 0).UTC() }}
	if err := runner.writeGitOpsStatus(GitOpsHandoverStatus{State: "REVISION_PUBLISHED", CommitSHA: desiredCommit, RevisionDigest: digest}); err != nil {
		t.Fatal(err)
	}
	if err := runner.verifyGitOpsHandover(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := runner.GitOpsStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "RECONCILED" || status.ObservedCommitSHA != desiredCommit || status.ObservedDigest != digest {
		t.Fatalf("status=%+v", status)
	}
}
