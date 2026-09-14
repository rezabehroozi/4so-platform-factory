package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"platform.4so.io/factory/internal/reliability"
)

func exerciseReliabilityStore(t *testing.T, s ReliabilityStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	obsA := reliability.HealthObservation{OrganizationID: "org-a", ProjectID: "prj-a", ClusterID: "clu-a", Health: "HEALTHY", ObservedAt: now, SourceDigest: "sha256:a"}
	first, created, err := s.CreateHealthObservation(ctx, obsA)
	if err != nil || !created {
		t.Fatalf("create observation: created=%v err=%v", created, err)
	}
	second, created, err := s.CreateHealthObservation(ctx, obsA)
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("observation idempotency: %#v %#v created=%v err=%v", first, second, created, err)
	}
	_, _, err = s.CreateHealthObservation(ctx, reliability.HealthObservation{OrganizationID: "org-b", ProjectID: "prj-b", ClusterID: "clu-b", Health: "CRITICAL", ObservedAt: now, SourceDigest: "sha256:b"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListHealthObservations(ctx, "prj-a", "", now.Add(-time.Minute), now.Add(time.Minute), 20)
	if err != nil || len(rows) != 1 || rows[0].ProjectID != "prj-a" {
		t.Fatalf("project isolation failed: %#v err=%v", rows, err)
	}

	inc, err := s.CreateIncident(ctx, reliability.Incident{OrganizationID: "org-a", ProjectID: "prj-a", ClusterID: "clu-a", Service: "cluster-api", Severity: "CRITICAL", State: reliability.IncidentOpen}, "operator-a")
	if err != nil || inc.Revision != 1 || inc.ID == "" {
		t.Fatalf("create incident: %#v err=%v", inc, err)
	}
	if _, err = s.TransitionIncident(ctx, inc.ID, 99, reliability.IncidentActionAcknowledge, "operator-a", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected revision conflict, got %v", err)
	}
	ack, err := s.TransitionIncident(ctx, inc.ID, 1, reliability.IncidentActionAcknowledge, "operator-a", "")
	if err != nil || ack.Revision != 2 || ack.State != reliability.IncidentAcknowledged {
		t.Fatalf("ack incident: %#v err=%v", ack, err)
	}
	policyInput := reliability.SLOPolicy{OrganizationID: "org-a", ProjectID: "prj-a", ClusterID: "clu-a", Name: "cluster-api", ObjectiveBasisPoints: 9990, WindowSeconds: 3600, ObservationIntervalSeconds: 60}
	policy, err := s.CreateSLOPolicy(ctx, policyInput, "operator-a")
	if err != nil || policy.Revision != 1 || policy.ID == "" {
		t.Fatalf("create SLO policy: %#v err=%v", policy, err)
	}
	if _, err = s.CreateSLOPolicy(ctx, policyInput, "operator-a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate SLO identity must conflict, got %v", err)
	}
	next := policy
	next.ClusterID = "clu-other"
	next.ObjectiveBasisPoints = 9950
	revision, err := s.CreateSLOPolicyRevision(ctx, policy.ID, 1, next, "operator-a")
	if err != nil || revision.Revision != 2 || revision.ID == policy.ID || revision.ClusterID != policy.ClusterID {
		t.Fatalf("create SLO revision: %#v err=%v", revision, err)
	}
	original, err := s.GetSLOPolicy(ctx, policy.ID)
	if err != nil || original.ObjectiveBasisPoints != 9990 || original.Revision != 1 || original.ClusterID != "clu-a" {
		t.Fatalf("SLO immutability failed: %#v err=%v", original, err)
	}
	if _, err = s.CreateSLOPolicyRevision(ctx, policy.ID, 1, next, "operator-a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("non-latest SLO predecessor must conflict, got %v", err)
	}
	if _, err = s.CreateSLOPolicyRevision(ctx, policy.ID, 99, next, "operator-a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected stale SLO revision conflict, got %v", err)
	}
}

func TestMemoryReliabilityStoreContract(t *testing.T) {
	exerciseReliabilityStore(t, NewMemoryStore())
}

func TestFileReliabilityStorePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	exerciseReliabilityStore(t, first)
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := reopened.ListHealthObservations(context.Background(), "prj-a", "", time.Date(2026, 9, 12, 11, 59, 0, 0, time.UTC), time.Date(2026, 9, 12, 12, 1, 0, 0, time.UTC), 20)
	if err != nil || len(rows) != 1 {
		t.Fatalf("file observation persistence: %#v err=%v", rows, err)
	}
	incidents, err := reopened.ListIncidents(context.Background(), "prj-a", "", 20)
	if err != nil || len(incidents) != 1 || incidents[0].Revision != 2 {
		t.Fatalf("file incident persistence: %#v err=%v", incidents, err)
	}
	policies, err := reopened.ListSLOPolicies(context.Background(), "prj-a", "cluster-api", 20)
	if err != nil || len(policies) != 2 || policies[0].ClusterID != "clu-a" || policies[1].ClusterID != "clu-a" {
		t.Fatalf("file SLO persistence: %#v err=%v", policies, err)
	}
}
