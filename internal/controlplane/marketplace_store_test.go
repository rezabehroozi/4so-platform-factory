package controlplane

import (
	"context"
	"testing"
)

func TestMarketplaceRecommendationPersistenceAndIdempotency(t *testing.T) {
	s, ctx, project, cluster, _ := providerFixture(t)
	input := MarketplaceRecommendation{
		ProjectID: project.ID, ClusterID: cluster.ID, Objective: "security", Engine: "policy",
		ContextDigest: digestTenantTest("context"), ResponseDigest: digestTenantTest("response"), RequestDigest: digestTenantTest("request"), IdempotencyKey: "recommend-1",
		Items: []MarketplaceRecommendationItem{{OfferID: "secure-namespace-foundation", OfferVersion: "1.0.0", Score: 90, Reason: "Safe baseline", Risk: "medium"}},
	}
	created, replay, err := s.CreateMarketplaceRecommendation(ctx, input, "operator")
	if err != nil || replay {
		t.Fatalf("created=%#v replay=%v err=%v", created, replay, err)
	}
	got, replay, err := s.CreateMarketplaceRecommendation(ctx, input, "operator")
	if err != nil || !replay || got.ID != created.ID {
		t.Fatalf("replay=%#v replay=%v err=%v", got, replay, err)
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	restored := NewMemoryStore()
	if err = restored.Restore(snap); err != nil {
		t.Fatal(err)
	}
	got, err = restored.GetMarketplaceRecommendation(ctx, created.ID)
	if err != nil || len(got.Items) != 1 {
		t.Fatalf("restored=%#v err=%v", got, err)
	}
}

func TestBaselineFailureRetryPreservesExactAction(t *testing.T) {
	s, ctx, project, cluster, agentToken := providerFixture(t)
	v, _, err := s.CreateBaselineDeployment(ctx, BaselineDeployment{ProjectID: project.ID, ClusterID: cluster.ID, BaselineID: "secure-namespace-foundation", BaselineVersion: "1.0.0", TargetNamespace: "4so-platform-baseline", Risk: "medium", DesiredDigest: digestTenantTest("desired"), RequestDigest: digestTenantTest("request"), IdempotencyKey: "baseline-retry"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.NextBaselineTask(ctx, cluster.ID, digestTenantTest(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	v, err = s.ReportBaselineTask(ctx, cluster.ID, digestTenantTest(agentToken), claimed.Revision, BaselineTaskResult{DeploymentID: v.ID, Action: "PLAN", Success: false, Error: "temporary", TaskFenceToken: claimed.TaskFenceToken})
	if err != nil || v.PendingAction != "PLAN" || v.State != BaselineDeploymentFailed {
		t.Fatalf("failed=%#v err=%v", v, err)
	}
	v, err = s.RetryBaselineDeployment(ctx, v.ID, v.Revision, "operator")
	if err != nil || v.State != BaselineDeploymentPlanning || v.PendingAction != "PLAN" {
		t.Fatalf("retried=%#v err=%v", v, err)
	}
}

func TestBaselineSourceIdentityValidation(t *testing.T) {
	s, ctx, project, cluster, _ := providerFixture(t)
	base := BaselineDeployment{ProjectID: project.ID, ClusterID: cluster.ID, BaselineID: "secure-namespace-foundation", BaselineVersion: "1.0.0", TargetNamespace: "4so-platform-baseline", Risk: "medium", DesiredDigest: digestTenantTest("desired-source"), RequestDigest: digestTenantTest("request-source"), IdempotencyKey: "baseline-source"}
	base.SourceType = BaselineSourceMarketplace
	if _, _, err := s.CreateBaselineDeployment(ctx, base, "operator"); err == nil {
		t.Fatal("partial marketplace source identity unexpectedly accepted")
	}
	base.SourceID, base.SourceVersion = "secure-namespace-foundation", "1.0.0"
	if _, _, err := s.CreateBaselineDeployment(ctx, base, "operator"); err != nil {
		t.Fatalf("complete marketplace source identity rejected: %v", err)
	}
}
