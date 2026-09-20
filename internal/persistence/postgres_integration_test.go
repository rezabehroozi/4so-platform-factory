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
	"platform.4so.io/factory/internal/virtualcluster"
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

	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationPlanning, "", "integration-admin")
	if err != nil {
		t.Fatalf("transition to planning: %v", err)
	}
	op, err = store.TransitionOperation(ctx, op.ID, op.Revision, controlplane.OperationQueued, "", "integration-admin")
	if err != nil {
		t.Fatalf("transition to queued: %v", err)
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


func TestPostgresVirtualClusterWorkspaceAuthorityIsDurableAndIdempotent(t *testing.T) {
	store, db := openPostgresIntegrationStore(t)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "vcluster-integration", DisplayName: "Virtual Cluster Integration"}, "integration-admin")
	if err != nil { t.Fatal(err) }
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "platform", DisplayName: "Platform"}, "integration-admin")
	if err != nil { t.Fatal(err) }

	enrollment := "sha256:" + strings.Repeat("c", 64)
	agent := "sha256:" + strings.Repeat("d", 64)
	imp, err := store.CreateClusterImport(ctx, controlplane.ClusterImport{
		ProjectID: project.ID, Name: "host-a", DisplayName: "Host A",
		TokenDigest: enrollment, ExpiresAt: time.Now().Add(time.Hour),
	}, "integration-admin")
	if err != nil { t.Fatal(err) }
	imp, err = store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "integration-admin")
	if err != nil { t.Fatal(err) }
	_, cluster, err := store.ClaimClusterImport(ctx, imp.ID, enrollment, agent, "uid-vcluster-integration", "0.0.integration")
	if err != nil { t.Fatal(err) }

	workspace, err := store.CreateWorkspace(ctx, controlplane.Workspace{
		ProjectID: project.ID, Name: "developers", DisplayName: "Developers",
	}, "integration-admin")
	if err != nil { t.Fatal(err) }
	binding, err := store.CreateWorkspaceBinding(ctx, controlplane.WorkspaceBinding{
		WorkspaceID: workspace.ID, ClusterID: cluster.ID, Namespace: "developers",
	}, "integration-admin")
	if err != nil { t.Fatal(err) }

	request := controlplane.VirtualClusterCreateRequest{
		WorkspaceID: workspace.ID,
		WorkspaceBindingID: binding.ID,
		Spec: virtualcluster.Request{
			Name: "dev-sandbox", Profile: virtualcluster.ProfileDeveloper,
			KubernetesVersion: "v1.34.2", CPUMilli: 2000, MemoryMiB: 4096,
			StorageGiB: 20, MaxNamespaces: 3, SleepAfterMinutes: 60,
		},
		IdempotencyKey: "vcluster-integration-create",
		RequestDigest: "sha256:" + strings.Repeat("e", 64),
	}
	created, replay, err := store.CreateVirtualCluster(ctx, request, "integration-admin")
	if err != nil || replay {
		t.Fatalf("create virtual cluster replay=%v err=%v record=%#v", replay, err, created)
	}
	if created.ProjectID != project.ID || created.WorkspaceID != workspace.ID || created.WorkspaceBindingID != binding.ID ||
		created.HostClusterID != cluster.ID || created.HostNamespace != binding.Namespace ||
		created.State != virtualcluster.StateRequested || created.PendingAction != virtualcluster.ActionProvision {
		t.Fatalf("workspace-derived authority drift: %#v", created)
	}

	var rows int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM virtual_clusters WHERE id=$1 AND project_id=$2 AND workspace_id=$3 AND workspace_binding_id=$4 AND host_cluster_id=$5 AND host_namespace=$6`,
		created.ID, project.ID, workspace.ID, binding.ID, cluster.ID, binding.Namespace).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("virtual cluster durable row count=%d", rows)
	}

	replayed, replay, err := store.CreateVirtualCluster(ctx, request, "other-actor")
	if err != nil || !replay || replayed.ID != created.ID || replayed.Revision != created.Revision {
		t.Fatalf("idempotent virtual cluster replay=%#v replay=%v err=%v", replayed, replay, err)
	}
	request.RequestDigest = "sha256:" + strings.Repeat("f", 64)
	if _, _, err = store.CreateVirtualCluster(ctx, request, "integration-admin"); !errors.Is(err, controlplane.ErrIdempotencyConflict) {
		t.Fatalf("virtual cluster idempotency conflict not enforced: %v", err)
	}

	list, err := store.ListVirtualClusters(ctx, project.ID, workspace.ID)
	if err != nil || len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("virtual cluster scoped list=%#v err=%v", list, err)
	}
}
