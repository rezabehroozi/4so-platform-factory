package controlplane

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestOutboxClaimOrdersByAvailableAtThenIDLikePostgres(t *testing.T) {
	store := NewMemoryStore()
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	store.outbox["evt_z_older"] = OutboxEvent{ResourceMeta: ResourceMeta{ID: "evt_z_older", Revision: 1, CreatedAt: base, UpdatedAt: base}, AggregateType: "test", AggregateID: "agg", EventType: "older", AvailableAt: base}
	store.outbox["evt_a_newer"] = OutboxEvent{ResourceMeta: ResourceMeta{ID: "evt_a_newer", Revision: 1, CreatedAt: base.Add(time.Second), UpdatedAt: base.Add(time.Second)}, AggregateType: "test", AggregateID: "agg", EventType: "newer", AvailableAt: base.Add(time.Second)}
	claimed, err := store.ClaimOutbox(context.Background(), "publisher", 1, time.Minute, base.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].ID != "evt_z_older" {
		t.Fatalf("outbox claim ignored available_at ordering: %+v", claimed)
	}
}

func TestOutboxClaimUsesIDAsStableTieBreakForEqualAvailableAt(t *testing.T) {
	store := NewMemoryStore()
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"evt_z", "evt_a", "evt_m"} {
		store.outbox[id] = OutboxEvent{ResourceMeta: ResourceMeta{ID: id, Revision: 1, CreatedAt: base, UpdatedAt: base}, AggregateType: "test", AggregateID: "agg", EventType: id, AvailableAt: base}
	}
	claimed, err := store.ClaimOutbox(context.Background(), "publisher", 3, time.Minute, base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"evt_a", "evt_m", "evt_z"}
	if len(claimed) != len(want) {
		t.Fatalf("claimed %d events, want %d", len(claimed), len(want))
	}
	for i := range want {
		if claimed[i].ID != want[i] {
			t.Fatalf("claim order=%v, want %v", []string{claimed[0].ID, claimed[1].ID, claimed[2].ID}, want)
		}
	}
}

func TestFileStoreOutboxOrderingSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "control-plane.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	store.outbox["evt_z_older"] = OutboxEvent{ResourceMeta: ResourceMeta{ID: "evt_z_older", Revision: 1, CreatedAt: base, UpdatedAt: base}, AggregateType: "test", AggregateID: "agg", EventType: "older", AvailableAt: base}
	store.outbox["evt_a_newer"] = OutboxEvent{ResourceMeta: ResourceMeta{ID: "evt_a_newer", Revision: 1, CreatedAt: base.Add(time.Second), UpdatedAt: base.Add(time.Second)}, AggregateType: "test", AggregateID: "agg", EventType: "newer", AvailableAt: base.Add(time.Second)}
	if err := store.persist(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := reopened.ClaimOutbox(context.Background(), "publisher", 1, time.Minute, base.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].ID != "evt_z_older" {
		t.Fatalf("restarted FileStore outbox order=%+v", claimed)
	}
}
