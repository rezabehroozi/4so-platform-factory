package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func seedFinOpsProject(t *testing.T, store interface {
	CreateOrganization(context.Context, Organization, string) (Organization, error)
	CreateProject(context.Context, Project, string) (Project, error)
}) (Organization, Project) {
	t.Helper()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, Organization{Name: "finops", DisplayName: "FinOps"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "prod", DisplayName: "Production"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return org, project
}

func fullRateCard(orgID string, start time.Time) FinOpsRateCard {
	return FinOpsRateCard{OrganizationID: orgID, Name: "standard", Version: "1", Currency: "EUR", EffectiveFrom: start, Rates: map[FinOpsUsageMetric]int64{FinOpsCPUCoreHour: 1_000_000, FinOpsMemoryGiBHour: 100_000, FinOpsStorageGiBHour: 10_000, FinOpsAcceleratorHour: 5_000_000}}
}

func fullUsage(orgID, projectID, event string, start time.Time) FinOpsUsageMeasurement {
	metrics := allUsageMetrics(0)
	metrics[FinOpsCPUCoreHour] = FinOpsMetricSample{Available: true, QuantityMicros: 1_000_000}
	return FinOpsUsageMeasurement{OrganizationID: orgID, ProjectID: projectID, Source: "meter", SourceEventID: event, WindowStart: start, WindowEnd: start.Add(time.Hour), Metrics: metrics}
}

func TestFinOpsStoreRejectsOverlappingRateCardsAndCrossProjectScope(t *testing.T) {
	store := NewMemoryStore()
	org, project := seedFinOpsProject(t, store)
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	first, err := store.CreateFinOpsRateCard(context.Background(), fullRateCard(org.ID, start), "admin")
	if err != nil {
		t.Fatal(err)
	}
	overlap := fullRateCard(org.ID, start.Add(30*time.Minute))
	overlap.Name = "overlap"
	overlap.Version = "2"
	if _, err = store.CreateFinOpsRateCard(context.Background(), overlap, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("overlap err=%v", err)
	}
	got, err := store.GetFinOpsRateCard(context.Background(), first.ID)
	if err != nil || got.Digest != first.Digest {
		t.Fatalf("get=%+v err=%v", got, err)
	}

	other, err := store.CreateOrganization(context.Background(), Organization{Name: "other", DisplayName: "Other"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	bad := fullUsage(other.ID, project.ID, "cross", start)
	if _, _, err = store.CreateFinOpsUsageMeasurement(context.Background(), bad, "admin"); !errors.Is(err, ErrValidation) {
		t.Fatalf("cross-project usage err=%v", err)
	}
}

func TestFinOpsUsageAndCapacitySourceEventAreIdempotentAndConflictOnChangedDigest(t *testing.T) {
	store := NewMemoryStore()
	org, project := seedFinOpsProject(t, store)
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	usage := fullUsage(org.ID, project.ID, "usage-1", start)
	first, replay, err := store.CreateFinOpsUsageMeasurement(context.Background(), usage, "meter-agent")
	if err != nil || replay {
		t.Fatalf("create replay=%v err=%v", replay, err)
	}
	second, replay, err := store.CreateFinOpsUsageMeasurement(context.Background(), usage, "meter-agent")
	if err != nil || !replay || second.ID != first.ID {
		t.Fatalf("replay=%+v replay=%v err=%v", second, replay, err)
	}
	changed := usage
	changed.Metrics = allUsageMetrics(0)
	changed.Metrics[FinOpsCPUCoreHour] = FinOpsMetricSample{Available: true, QuantityMicros: 2_000_000}
	if _, _, err = store.CreateFinOpsUsageMeasurement(context.Background(), changed, "meter-agent"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotency err=%v", err)
	}

	capacity := FinOpsCapacityObservation{OrganizationID: org.ID, ProjectID: project.ID, Source: "inventory", SourceEventID: "capacity-1", ObservedAt: start, Metrics: allCapacityMetrics(1_000_000)}
	cap1, replay, err := store.CreateFinOpsCapacityObservation(context.Background(), capacity, "meter-agent")
	if err != nil || replay {
		t.Fatalf("capacity create replay=%v err=%v", replay, err)
	}
	cap2, replay, err := store.CreateFinOpsCapacityObservation(context.Background(), capacity, "meter-agent")
	if err != nil || !replay || cap2.ID != cap1.ID {
		t.Fatalf("capacity replay=%+v replay=%v err=%v", cap2, replay, err)
	}
}

func TestFinOpsFileStoreRoundTripPreservesAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	org, project := seedFinOpsProject(t, store)
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	card, err := store.CreateFinOpsRateCard(context.Background(), fullRateCard(org.ID, start), "admin")
	if err != nil {
		t.Fatal(err)
	}
	usage, _, err := store.CreateFinOpsUsageMeasurement(context.Background(), fullUsage(org.ID, project.ID, "usage-file", start), "meter-agent")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.CreateFinOpsCapacityObservation(context.Background(), FinOpsCapacityObservation{OrganizationID: org.ID, ProjectID: project.ID, Source: "inventory", SourceEventID: "cap-file", ObservedAt: start, Metrics: allCapacityMetrics(0)}, "meter-agent")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	gotCard, err := reopened.GetFinOpsRateCard(context.Background(), card.ID)
	if err != nil || gotCard.Digest != card.Digest {
		t.Fatalf("card=%+v err=%v", gotCard, err)
	}
	gotUsage, err := reopened.GetFinOpsUsageMeasurement(context.Background(), usage.ID)
	if err != nil || gotUsage.Digest != usage.Digest {
		t.Fatalf("usage=%+v err=%v", gotUsage, err)
	}
	caps, err := reopened.ListFinOpsCapacityObservations(context.Background(), org.ID, project.ID, time.Time{}, time.Time{}, 100)
	if err != nil || len(caps) != 1 {
		t.Fatalf("capacity len=%d err=%v", len(caps), err)
	}
}
