package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMCPControlJobReplayAndExpiredRunningFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC)
	seq := 0
	s := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return prefix + "-id" })
	input := MCPControlJob{ToolName: "api_post_projects", Family: "projects", Action: "create", Method: "POST", Route: "/api/v1/projects", Risk: "medium", ActorID: "user-a", Authentication: "mcp-human", OAuthClientID: "chatgpt", DelegationProfile: "OPERATE", OrganizationID: "org-a", IdempotencyKey: "same", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LeaseOwner: "req-a"}
	job, replay, err := s.CreateMCPControlJob(context.Background(), input, time.Minute, now)
	if err != nil || replay {
		t.Fatalf("create replay=%v err=%v", replay, err)
	}
	completed, err := s.CompleteMCPControlJob(context.Background(), job.ID, job.Revision, job.FenceToken, 201, []byte(`{"id":"project-1"}`), "user-a")
	if err != nil || completed.State != MCPControlJobSucceeded {
		t.Fatalf("complete=%+v err=%v", completed, err)
	}
	got, replay, err := s.CreateMCPControlJob(context.Background(), input, time.Minute, now.Add(10*time.Second))
	if err != nil || !replay || got.State != MCPControlJobSucceeded || string(got.Response) != "{\"id\":\"project-1\"}" {
		t.Fatalf("terminal replay=%+v replay=%v err=%v", got, replay, err)
	}

	input.IdempotencyKey = "expired"
	input.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	running, _, err := s.CreateMCPControlJob(context.Background(), input, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	got, replay, err = s.CreateMCPControlJob(context.Background(), input, time.Minute, now.Add(2*time.Minute))
	if err != nil || !replay || got.ID != running.ID || got.State != MCPControlJobRecoveryRequired {
		t.Fatalf("expired replay=%+v replay=%v err=%v", got, replay, err)
	}
}

func TestMCPControlJobRecoveryResolutionRequiresAuthoritativeReadbackEvidence(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	seq := 0
	s := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { seq++; return prefix + "-recovery" })
	input := MCPControlJob{ToolName: "api_post_projects", Family: "projects", Action: "create", Method: "POST", Route: "/api/v1/projects", Risk: "medium", ActorID: "user-a", Authentication: "mcp-human", OAuthClientID: "chatgpt", DelegationProfile: "OPERATE", OrganizationID: "org-a", IdempotencyKey: "stale-recovery", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LeaseOwner: "req-a"}
	job, _, err := s.CreateMCPControlJob(context.Background(), input, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	job, replay, err := s.CreateMCPControlJob(context.Background(), input, time.Minute, now.Add(2*time.Minute))
	if err != nil || !replay || job.State != MCPControlJobRecoveryRequired {
		t.Fatalf("recovery-required=%+v replay=%v err=%v", job, replay, err)
	}

	if _, err = s.ResolveMCPControlJobRecovery(context.Background(), job.ID, job.Revision, MCPControlJobRecoveryConfirmedSucceeded, "bad", "sha256:"+strings.Repeat("b", 64), "operator-a"); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid readback digest err=%v", err)
	}
	resolved, err := s.ResolveMCPControlJobRecovery(context.Background(), job.ID, job.Revision, MCPControlJobRecoveryConfirmedSucceeded, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "operator-a")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.State != MCPControlJobSucceeded || resolved.RecoveryResolution != MCPControlJobRecoveryConfirmedSucceeded || resolved.RecoveryReadbackDigest == "" || resolved.RecoveryEvidenceDigest == "" || resolved.RecoveredBy != "operator-a" || resolved.RecoveredAt == nil {
		t.Fatalf("resolved=%+v", resolved)
	}
	if len(resolved.Response) == 0 || !strings.Contains(string(resolved.Response), `"recovered":true`) || !strings.Contains(string(resolved.Response), `"automaticRedispatch":false`) {
		t.Fatalf("recovery response=%s", string(resolved.Response))
	}
	replayed, replay, err := s.CreateMCPControlJob(context.Background(), input, time.Minute, now.Add(3*time.Minute))
	if err != nil || !replay || replayed.State != MCPControlJobSucceeded || string(replayed.Response) != string(resolved.Response) {
		t.Fatalf("resolved replay=%+v replay=%v err=%v", replayed, replay, err)
	}
}

func TestMCPControlJobRecoveryResolutionRejectsRunningOrStaleRevision(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 30, 0, 0, time.UTC)
	s := NewMemoryStoreWith(func() time.Time { return now }, func(prefix string) string { return prefix + "-guard" })
	input := MCPControlJob{ToolName: "api_post_projects", Family: "projects", Action: "create", Method: "POST", Route: "/api/v1/projects", Risk: "medium", ActorID: "user-a", Authentication: "mcp-human", OAuthClientID: "chatgpt", DelegationProfile: "OPERATE", OrganizationID: "org-a", IdempotencyKey: "guard", RequestDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", LeaseOwner: "req-a"}
	job, _, err := s.CreateMCPControlJob(context.Background(), input, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	readback := "sha256:" + strings.Repeat("d", 64)
	evidence := "sha256:" + strings.Repeat("e", 64)
	if _, err = s.ResolveMCPControlJobRecovery(context.Background(), job.ID, job.Revision, MCPControlJobRecoveryConfirmedFailed, readback, evidence, "operator-a"); !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("running recovery resolution err=%v", err)
	}
	job, _, err = s.CreateMCPControlJob(context.Background(), input, time.Minute, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ResolveMCPControlJobRecovery(context.Background(), job.ID, job.Revision-1, MCPControlJobRecoveryConfirmedFailed, readback, evidence, "operator-a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision err=%v", err)
	}
}
