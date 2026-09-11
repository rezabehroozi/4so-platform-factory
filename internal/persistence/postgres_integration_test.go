//go:build integration && cgo && linux

package persistence

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/pgdriver"
)

const postgresIntegrationAuthority = "POSTGRES_BEHAVIORAL_INTEGRATION_V1"

func openPostgresIntegrationStore(t *testing.T) (*PostgresStore, *sql.DB) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("PLATFORM_FACTORY_POSTGRES_TEST_DSN is required for PostgreSQL behavioral integration")
	}
	if !pgdriver.Available() {
		t.Fatalf("%s requires the production libpq driver: %s", postgresIntegrationAuthority, pgdriver.Description())
	}
	db, err := sql.Open(pgdriver.Name(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatalf("connect PostgreSQL integration authority: %v", err)
	}
	// The CI database is dedicated to this test job. Rebuilding public ensures
	// every run proves a fresh migration path rather than inheriting old state.
	if _, err = db.ExecContext(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err = ApplyMigrationsWithCompatibility(ctx, db, MigrationModeRolling, nil); err != nil {
		t.Fatalf("fresh migrations: %v", err)
	}
	store, err := NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store, db
}

func TestPostgresIntegrationAuthorityIdempotencyScopeAndLeaseFencing(t *testing.T) {
	store, db := openPostgresIntegrationStore(t)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "integration-org", DisplayName: "Integration Org"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "project-a", DisplayName: "Project A"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "project-b", DisplayName: "Project B"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	var membershipCount int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM organization_memberships WHERE organization_id=$1 AND subject=$2`, org.ID, "integration-admin").Scan(&membershipCount); err != nil {
		t.Fatal(err)
	}
	if membershipCount != 1 {
		t.Fatalf("organization creation must atomically create admin membership; count=%d", membershipCount)
	}

	request := controlplane.OperationRequest{
		ProjectID:       projectA.ID,
		Kind:            "integration.inspect",
		TargetRef:       "project:" + projectA.ID,
		DesiredRevision: "sha256:" + strings.Repeat("a", 64),
		Risk:            "low",
		Class:           controlplane.OperationClassReadOnly,
	}
	op, replay, err := store.CreateOperation(ctx, request, "integration-idempotency", "integration-admin", "request-1")
	if err != nil || replay {
		t.Fatalf("first operation create replay=%v err=%v", replay, err)
	}
	replayed, replay, err := store.CreateOperation(ctx, request, "integration-idempotency", "integration-admin", "request-2")
	if err != nil || !replay || replayed.ID != op.ID {
		t.Fatalf("idempotent replay id=%q replay=%v err=%v original=%q", replayed.ID, replay, err, op.ID)
	}
	_, _, err = store.CreateOperation(ctx, controlplane.OperationRequest{
		ProjectID:       projectB.ID,
		Kind:            "integration.foreign",
		TargetRef:       "project:" + projectB.ID,
		DesiredRevision: "sha256:" + strings.Repeat("b", 64),
		Risk:            "low",
		Class:           controlplane.OperationClassReadOnly,
	}, "integration-foreign", "integration-admin", "request-foreign")
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.ListOperationsPageByProjects(ctx, []string{projectA.ID}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != op.ID || page[0].ProjectID != projectA.ID {
		t.Fatalf("project-scoped operation page leaked or lost rows: %#v", page)
	}

	now := time.Now().UTC()
	claim, err := store.ClaimOperation(ctx, op.ID, "worker-a", 2*time.Minute, now)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if claim.FenceToken < 1 || claim.LeaseOwner != "worker-a" {
		t.Fatalf("invalid claim: %#v", claim)
	}
	if _, err = store.ClaimOperation(ctx, op.ID, "worker-b", 2*time.Minute, now.Add(time.Second)); err == nil {
		t.Fatal("concurrent worker claim must fail while lease is active")
	} else if !errors.Is(err, controlplane.ErrConflict) && !strings.Contains(strings.ToLower(err.Error()), "lease") {
		t.Fatalf("unexpected competing claim error: %v", err)
	}
	if _, err = store.RenewOperationLease(ctx, op.ID, "worker-a", claim.FenceToken+1, 2*time.Minute, now.Add(2*time.Second)); err == nil {
		t.Fatal("stale/wrong fence token renewed operation lease")
	}
}
