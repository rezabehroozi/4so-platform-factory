package persistence

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestPostgresCreateOrganizationBudgetRejectsDuplicateNameVersionBeforeInsert(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "exec", contains: "SELECT pg_advisory_xact_lock(hashtext($1))"},
		scriptStep{kind: "query", contains: "COALESCE(project_id,'')=$2 AND lower(name)=lower($3) AND version=$4", columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}},
		scriptStep{kind: "rollback"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateFinOpsBudgetPolicy(context.Background(), controlplane.FinOpsBudgetPolicy{
		OrganizationID: "org_fixed", Name: "Monthly", Version: "1", Currency: "EUR",
		EffectiveFrom: now, LimitMicros: 100_000_000, WarningBasisPoints: 8000, CriticalBasisPoints: 10000,
	}, "actor-1")
	if !errors.Is(err, controlplane.ErrDuplicateName) {
		t.Fatalf("expected duplicate-name rejection, got %v", err)
	}
	script.done(t)
}
