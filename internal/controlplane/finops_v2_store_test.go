package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFinOpsBudgetStoreRejectsOverlapAndCrossProjectScope(t *testing.T) {
	store := NewMemoryStore()
	org, project := seedFinOpsProject(t, store)
	otherOrg, err := store.CreateOrganization(context.Background(), Organization{Name: "other-finops", DisplayName: "Other FinOps"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	otherProject, err := store.CreateProject(context.Background(), Project{OrganizationID: otherOrg.ID, Name: "other", DisplayName: "Other"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	base := FinOpsBudgetPolicy{OrganizationID: org.ID, ProjectID: project.ID, Name: "monthly", Version: "1", Currency: "EUR", EffectiveFrom: start, LimitMicros: 100_000_000, WarningBasisPoints: 8000, CriticalBasisPoints: 10000}
	first, err := store.CreateFinOpsBudgetPolicy(context.Background(), base, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.Authority != FinOpsBudgetPolicyAuthority {
		t.Fatalf("unexpected budget: %#v", first)
	}
	overlap := base
	overlap.Name = "other"
	overlap.Version = "2"
	if _, err := store.CreateFinOpsBudgetPolicy(context.Background(), overlap, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected overlap conflict, got %v", err)
	}
	bad := base
	bad.Name = "bad"
	bad.Version = "3"
	bad.ProjectID = otherProject.ID
	if _, err := store.CreateFinOpsBudgetPolicy(context.Background(), bad, "admin"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected scope validation, got %v", err)
	}
	list, err := store.ListFinOpsBudgetPolicies(context.Background(), org.ID, project.ID)
	if err != nil || len(list) != 1 || list[0].ID != first.ID {
		t.Fatalf("unexpected list: %#v %v", list, err)
	}
}

func TestFinOpsBudgetFileStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-plane.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	org, project := seedFinOpsProject(t, store)
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	created, err := store.CreateFinOpsBudgetPolicy(context.Background(), FinOpsBudgetPolicy{OrganizationID: org.ID, ProjectID: project.ID, Name: "monthly", Version: "1", Currency: "EUR", EffectiveFrom: start, LimitMicros: 100_000_000, WarningBasisPoints: 8000, CriticalBasisPoints: 10000}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetFinOpsBudgetPolicy(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != created.Digest || got.ProjectID != project.ID {
		t.Fatalf("file round trip drift: created=%#v got=%#v", created, got)
	}
}
