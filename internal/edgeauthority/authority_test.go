package edgeauthority

import (
	"strings"
	"testing"
	"time"
)

func digest(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }

func policyFixture(t *testing.T) LocalPolicy {
	t.Helper()
	policy, err := CanonicalPolicy(
		"site-helsinki-1", "prj_edge", digest("a"), 7,
		[]Action{ActionCollectDiagnostics, ActionObserve, ActionRestartApprovedWorkload},
		48*time.Hour, 5000, time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
	)
	if err != nil { t.Fatal(err) }
	return policy
}

func TestOfflineMutationIsBoundedByExactCentralRevisionAndPolicy(t *testing.T) {
	policy := policyFixture(t)
	request := MutationRequest{
		SiteID: policy.SiteID, ProjectID: policy.ProjectID, Action: ActionRestartApprovedWorkload,
		TargetRef: "workload:payments/api", BaseRevision: policy.Revision, BaseDesiredDigest: policy.DesiredStateDigest,
		PolicyDigest: policy.PolicyDigest, IdempotencyKey: "edge-op-1", RequestDigest: digest("b"),
	}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	if err := AdmitOfflineMutation(policy, request, now, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	request.Action = Action("DELETE_STORAGE")
	if err := AdmitOfflineMutation(policy, request, now, now.Add(-time.Hour)); err == nil {
		t.Fatal("unadmitted destructive action was accepted")
	}
}

func TestOfflineWindowAndPolicyDriftFailClosed(t *testing.T) {
	policy := policyFixture(t)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	request := MutationRequest{
		SiteID: policy.SiteID, ProjectID: policy.ProjectID, Action: ActionObserve,
		TargetRef: "site:site-helsinki-1", BaseRevision: policy.Revision, BaseDesiredDigest: policy.DesiredStateDigest,
		PolicyDigest: policy.PolicyDigest, IdempotencyKey: "edge-read-1", RequestDigest: digest("c"),
	}
	if err := AdmitOfflineMutation(policy, request, now, now.Add(-49*time.Hour)); err == nil {
		t.Fatal("expired offline window was admitted")
	}
	request.BaseRevision++
	if err := AdmitOfflineMutation(policy, request, now, now.Add(-time.Hour)); err == nil {
		t.Fatal("stale central revision was admitted")
	}
}

func TestReconnectNeverUsesSilentLastWriteWins(t *testing.T) {
	request := MutationRequest{BaseRevision: 3, BaseDesiredDigest: digest("d")}
	got := ResolveReconnect(request, 4, digest("e"))
	if got.State != ConflictReviewRequired || got.AutomaticApply {
		t.Fatalf("central drift must require review: %#v", got)
	}
	got = ResolveReconnect(request, 3, digest("d"))
	if got.State != ConflictNone || !got.AutomaticApply {
		t.Fatalf("same authority should reconcile automatically: %#v", got)
	}
}

func TestBootAttestationRequiresVerifiedQuoteNoncePCRAndEncryption(t *testing.T) {
	claim := BootClaim{
		Authority: BootAttestationAuthority, SiteID: "site-a", NodeID: "node-a",
		ObservedAt: time.Now().UTC(), TPMPresent: true, SecureBootEnabled: true, MeasuredBootPresent: true,
		DiskEncryptionVerified: true, QuoteVerified: true, NonceBound: true, PCRPolicyMatched: true,
		QuoteDigest: digest("1"), EventLogDigest: digest("2"), EvidenceDigest: digest("3"),
	}
	if got := AssessBootClaim(claim); got.State != BootAttested {
		t.Fatalf("valid claim rejected: %#v", got)
	}
	claim.NonceBound = false
	if got := AssessBootClaim(claim); got.State != BootRejected {
		t.Fatalf("unbound quote admitted: %#v", got)
	}
}

func TestDisconnectedLocalAIProfileForbidsExternalAuthority(t *testing.T) {
	profile := LocalAIProfile{
		Authority: LocalAIProfileAuthority, Mode: "disconnected", Runtime: "local-vllm",
		ModelDigest: digest("4"), RuntimeImageDigest: digest("5"),
		MaxPromptBytes: 256 * 1024, MaxOutputBytes: 256 * 1024,
	}
	if err := ValidateLocalAIProfile(profile); err != nil { t.Fatal(err) }
	for _, mutate := range []func(*LocalAIProfile){
		func(v *LocalAIProfile){ v.NetworkEgress = true },
		func(v *LocalAIProfile){ v.RawCredentials = true },
		func(v *LocalAIProfile){ v.ExternalProvider = true },
	} {
		bad := profile
		mutate(&bad)
		if err := ValidateLocalAIProfile(bad); err == nil {
			t.Fatalf("unsafe local AI profile admitted: %#v", bad)
		}
	}
}
