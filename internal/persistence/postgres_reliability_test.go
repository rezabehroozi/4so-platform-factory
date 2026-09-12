package persistence

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

var _ controlplane.ReliabilityStore = (*PostgresStore)(nil)

func TestPostgresHealthObservationScopesBeforeLimit(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{kind: "query", contains: "WHERE project_id=$1 AND ($2='' OR cluster_id=$2)", columns: []string{"id", "organization_id", "project_id", "cluster_id", "health", "observed_at", "source_digest"}, rows: [][]driver.Value{{"hob_a", "org_a", "project_a", "cluster_a", "HEALTHY", now, "sha256:a"}}},
	)
	store, _ := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	rows, err := store.ListHealthObservations(context.Background(), "project_a", "", time.Time{}, time.Time{}, 10)
	if err != nil || len(rows) != 1 || rows[0].ProjectID != "project_a" {
		t.Fatalf("project-scoped observations: rows=%#v err=%v", rows, err)
	}
	script.done(t)
}

func TestPostgresIncidentTransitionRejectsStaleRevision(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM incidents WHERE id=$1 FOR UPDATE", columns: []string{"id", "organization_id", "project_id", "cluster_id", "service", "severity", "state", "revision", "acknowledged_by", "resolved_by", "resolution_summary"}, rows: [][]driver.Value{{"inc_a", "org_a", "project_a", "", "api", "critical", reliability.IncidentOpen, int64(2), "", "", ""}}},
		scriptStep{kind: "rollback"},
	)
	store, _ := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	_, err := store.TransitionIncident(context.Background(), "inc_a", 1, reliability.IncidentActionAcknowledge, "operator-a", "")
	if !errors.Is(err, controlplane.ErrConflict) {
		t.Fatalf("expected stale revision conflict, got %v", err)
	}
	script.done(t)
}

func TestPostgresSLOPoliciesScopeBeforeLimit(t *testing.T) {
	db, script := openScriptDB(t,
		scriptStep{kind: "query", contains: "WHERE project_id=$1 AND ($2='' OR name=$2)", columns: []string{"id", "organization_id", "project_id", "name", "revision", "objective_basis_points", "window_seconds", "observation_interval_seconds"}, rows: [][]driver.Value{{"slo_a", "org_a", "project_a", "availability", int64(1), int64(9990), int64(3600), int64(60)}}},
	)
	store, _ := NewPostgresStoreWith(db, time.Now, fixedPGID)
	rows, err := store.ListSLOPolicies(context.Background(), "project_a", "", 10)
	if err != nil || len(rows) != 1 || rows[0].ProjectID != "project_a" {
		t.Fatalf("project-scoped SLO policies: rows=%#v err=%v", rows, err)
	}
	script.done(t)
}
