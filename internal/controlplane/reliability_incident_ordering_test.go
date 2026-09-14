package controlplane

import (
	"context"
	"testing"
	"time"

	"platform.4so.io/factory/internal/reliability"
)

func TestMemoryIncidentOrderingUsesUpdatedAtDescending(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Date(2026, 9, 14, 8, 30, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	first, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: "org-a", ProjectID: "prj-a", Severity: "WARNING"}, "operator")
	if err != nil { t.Fatal(err) }
	if first.CreatedAt.IsZero() || !first.CreatedAt.Equal(first.UpdatedAt) { t.Fatalf("create timestamps=%#v", first) }

	now = now.Add(time.Minute)
	second, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: "org-a", ProjectID: "prj-a", Severity: "CRITICAL"}, "operator")
	if err != nil { t.Fatal(err) }
	rows, err := store.ListIncidents(ctx, "prj-a", "", 10)
	if err != nil { t.Fatal(err) }
	if len(rows) != 2 || rows[0].ID != second.ID || rows[1].ID != first.ID { t.Fatalf("creation ordering=%#v", rows) }

	now = now.Add(time.Minute)
	first, err = store.TransitionIncident(ctx, first.ID, first.Revision, reliability.IncidentActionAcknowledge, "operator", "")
	if err != nil { t.Fatal(err) }
	if !first.UpdatedAt.Equal(now) || !first.CreatedAt.Before(first.UpdatedAt) { t.Fatalf("transition timestamps=%#v", first) }
	rows, err = store.ListIncidents(ctx, "prj-a", "", 10)
	if err != nil { t.Fatal(err) }
	if rows[0].ID != first.ID || rows[1].ID != second.ID { t.Fatalf("transition ordering=%#v", rows) }
}
