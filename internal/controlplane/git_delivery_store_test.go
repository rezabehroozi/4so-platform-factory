package controlplane

import (
	"context"
	"testing"
)

func TestPullRequestApprovalMergeAndLastKnownGoodAuthority(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	base := repeatGitSHA("0")
	candidate := repeatGitSHA("1")
	pr, err := s.CreateGitPullRequest(ctx, GitPullRequest{
		Organization: "Platform", Repository: "Desired-State", BaseBranch: "main",
		HeadBranch: "platform-revision-1", BaseCommitSHA: base,
		RevisionID: "revision-1", Digest: "sha256:" + repeatHex("a"),
		PublicKeyFingerprint: "sha256:" + repeatHex("b"),
	}, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	if pr.State != GitPullRequestRequested {
		t.Fatalf("state=%s", pr.State)
	}
	pr, err = s.FinalizeGitPullRequest(ctx, pr.ID, pr.Revision, 7, "https://forgejo.test/pr/7", candidate, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	if pr.State != GitPullRequestOpen || pr.CandidateCommitSHA != candidate {
		t.Fatalf("pr=%+v", pr)
	}
	if _, _, err = s.CommitMergedGitPullRequest(ctx, pr.ID, pr.Revision, repeatGitSHA("a"), ManagedGitRevision{}, "admin"); err != ErrInvalidTransition {
		t.Fatalf("merge before approval err=%v", err)
	}
	if _, err = s.ApproveGitPullRequest(ctx, pr.ID, pr.Revision, repeatGitSHA("9"), "approver"); err == nil {
		t.Fatal("approval accepted a head commit different from the durable candidate")
	}
	pr, err = s.ApproveGitPullRequest(ctx, pr.ID, pr.Revision, candidate, "approver")
	if err != nil {
		t.Fatal(err)
	}
	mergeSHA := repeatGitSHA("a")
	pr, r1, err := s.CommitMergedGitPullRequest(ctx, pr.ID, pr.Revision, mergeSHA, ManagedGitRevision{
		Organization: "platform", Repository: "desired-state", Branch: "main",
		RevisionID: "revision-1", Digest: "sha256:" + repeatHex("a"), CommitSHA: mergeSHA,
		PublicKeyFingerprint: "sha256:" + repeatHex("b"), Source: "PLATFORM_PR_MERGED",
		DeliveryMode: GitDeliveryPullRequest, PullRequestID: pr.ID,
	}, "merger")
	if err != nil {
		t.Fatal(err)
	}
	if pr.State != GitPullRequestMerged || pr.MergedCommitSHA != mergeSHA {
		t.Fatalf("pr=%+v", pr)
	}
	if r1.CommitSHA != mergeSHA || r1.PullRequestID != pr.ID {
		t.Fatalf("revision=%+v", r1)
	}
	if _, err = s.MarkManagedGitRevisionSynchronized(ctx, r1.ID, r1.Revision, "sha256:"+repeatHex("c"), true, "observer"); err == nil {
		t.Fatal("mismatched observed digest accepted")
	}
	r1, err = s.MarkManagedGitRevisionSynchronized(ctx, r1.ID, r1.Revision, r1.Digest, true, "observer")
	if err != nil {
		t.Fatal(err)
	}
	if !r1.LastKnownGood {
		t.Fatalf("r1=%+v", r1)
	}
	r2, err := s.RecordManagedGitRevision(ctx, ManagedGitRevision{Organization: "platform", Repository: "desired-state", RevisionID: "revision-2", Digest: "sha256:" + repeatHex("c"), CommitSHA: repeatGitSHA("f"), PublicKeyFingerprint: "sha256:" + repeatHex("b"), Source: "PLATFORM_PUBLISHED", DeliveryMode: GitDeliveryDirectCommit}, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	r2, err = s.MarkManagedGitRevisionSynchronized(ctx, r2.ID, r2.Revision, r2.Digest, true, "observer")
	if err != nil {
		t.Fatal(err)
	}
	lkg, err := s.GetLastKnownGoodGitRevision(ctx, "platform", "desired-state", "main")
	if err != nil {
		t.Fatal(err)
	}
	if lkg.ID != r2.ID || !lkg.LastKnownGood {
		t.Fatalf("lkg=%+v", lkg)
	}
	all, _ := s.ListManagedGitRevisions(ctx, "platform", "desired-state")
	for _, v := range all {
		if v.ID == r1.ID && v.LastKnownGood {
			t.Fatal("previous LKG remained active")
		}
	}
}

func repeatHex(v string) string {
	out := ""
	for i := 0; i < 64; i++ {
		out += v
	}
	return out
}
func repeatGitSHA(v string) string {
	out := ""
	for i := 0; i < 40; i++ {
		out += v
	}
	return out
}
