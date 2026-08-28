package controlplane

import (
	"context"
	"testing"
)

func gitEvidence() *GitDriftEvidence {
	return &GitDriftEvidence{Organization: "platform", Repository: "desired-state", Branch: "main", BaseRevisionID: "rev-base", BaseDigest: "sha256:" + repeatTestHex("a", 64), BaseCommitSHA: "basecommit", CurrentRevisionID: "rev-current", CurrentDigest: "sha256:" + repeatTestHex("b", 64), CurrentCommitSHA: "headcommit", PublicKeyFingerprint: "sha256:" + repeatTestHex("c", 64), CurrentTrusted: true}
}
func repeatTestHex(v string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += v
	}
	return out
}

func TestClassifyGitDrift(t *testing.T) {
	base := gitEvidence()
	cases := []struct {
		name, obs       string
		mutate          func(*GitDriftEvidence)
		want            GitDriftClassification
		conflict, adopt bool
	}{
		{"external pending", base.BaseDigest, nil, GitDriftExternalChange, false, false},
		{"external applied", base.CurrentDigest, nil, GitDriftExternalApplied, false, true},
		{"three way conflict", "sha256:" + repeatTestHex("d", 64), nil, GitDriftThreeWayConflict, true, false},
		{"untrusted", base.BaseDigest, func(v *GitDriftEvidence) { v.CurrentTrusted = false }, GitDriftUntrustedChange, true, false},
		{"live drift", "sha256:" + repeatTestHex("e", 64), func(v *GitDriftEvidence) { v.CurrentDigest = v.BaseDigest; v.CurrentCommitSHA = v.BaseCommitSHA }, GitDriftLiveDrift, true, false},
		{"in sync", base.BaseDigest, func(v *GitDriftEvidence) { v.CurrentDigest = v.BaseDigest; v.CurrentCommitSHA = v.BaseCommitSHA }, GitDriftInSync, false, false},
		{"unknown", "", nil, GitDriftObservedUnknown, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := *base
			if tc.mutate != nil {
				tc.mutate(&v)
			}
			got := ClassifyGitDrift(&v, tc.obs)
			if got.Classification != tc.want || got.Conflict != tc.conflict || got.Adoptable != tc.adopt {
				t.Fatalf("got=%+v", got)
			}
		})
	}
}

func TestManagedGitRevisionAuthority(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	v, err := s.RecordManagedGitRevision(ctx, ManagedGitRevision{Organization: "Platform", Repository: "Desired-State", Branch: "main", RevisionID: "rev-1", Digest: "sha256:" + repeatTestHex("a", 64), CommitSHA: repeatTestHex("a", 40), PublicKeyFingerprint: "sha256:" + repeatTestHex("b", 64)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	latest, err := s.GetLatestManagedGitRevision(ctx, "platform", "desired-state", "main")
	if err != nil || latest.ID != v.ID {
		t.Fatalf("latest=%+v err=%v", latest, err)
	}
}

func TestManagedGitRevisionRejectsAbbreviatedCommitSHA(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.RecordManagedGitRevision(context.Background(), ManagedGitRevision{Organization: "platform", Repository: "desired-state", Branch: "main", RevisionID: "rev-short", Digest: "sha256:" + repeatTestHex("a", 64), CommitSHA: "abcdef1", PublicKeyFingerprint: "sha256:" + repeatTestHex("b", 64)}, "operator")
	if err == nil {
		t.Fatal("abbreviated commit SHA was accepted as immutable Git authority")
	}
}
