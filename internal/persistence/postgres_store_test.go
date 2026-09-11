package persistence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/migrations"
)

func futureSchemaVersion(t *testing.T) int64 {
	t.Helper()
	all, err := migrations.All()
	if err != nil || len(all) == 0 {
		t.Fatalf("load embedded migrations: %v", err)
	}
	return all[len(all)-1].Version + 1
}

type scriptStep struct {
	kind     string
	contains string
	columns  []string
	rows     [][]driver.Value
	result   driver.Result
	err      error
}

type scriptState struct {
	mu    sync.Mutex
	steps []scriptStep
}

func (s *scriptState) next(kind, query string) (scriptStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.steps) == 0 {
		return scriptStep{}, fmt.Errorf("unexpected %s: %s", kind, query)
	}
	step := s.steps[0]
	s.steps = s.steps[1:]
	if step.kind != kind {
		return scriptStep{}, fmt.Errorf("expected %s, got %s: %s", step.kind, kind, query)
	}
	if step.contains != "" && !strings.Contains(strings.Join(strings.Fields(query), " "), step.contains) {
		return scriptStep{}, fmt.Errorf("query does not contain %q: %s", step.contains, query)
	}
	return step, step.err
}

func (s *scriptState) done(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.steps) != 0 {
		t.Fatalf("%d scripted SQL steps were not consumed; next=%s", len(s.steps), s.steps[0].kind)
	}
}

type scriptDriver struct{ state *scriptState }

func (d scriptDriver) Open(string) (driver.Conn, error) { return &scriptConn{state: d.state}, nil }

type scriptConn struct{ state *scriptState }

func (c *scriptConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not supported")
}
func (c *scriptConn) Close() error { return nil }
func (c *scriptConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *scriptConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	if _, err := c.state.next("begin", ""); err != nil {
		return nil, err
	}
	return &scriptTx{state: c.state}, nil
}
func (c *scriptConn) Ping(context.Context) error { _, err := c.state.next("ping", ""); return err }
func (c *scriptConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	step, err := c.state.next("query", query)
	if err != nil {
		return nil, err
	}
	return &scriptRows{columns: step.columns, rows: step.rows}, nil
}
func (c *scriptConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	step, err := c.state.next("exec", query)
	if err != nil {
		return nil, err
	}
	if step.result == nil {
		return driver.RowsAffected(1), nil
	}
	return step.result, nil
}

type scriptTx struct{ state *scriptState }

func (t *scriptTx) Commit() error { _, err := t.state.next("commit", ""); return err }
func (t *scriptTx) Rollback() error {
	step, err := t.state.next("rollback", "")
	if err != nil && strings.Contains(err.Error(), "unexpected rollback") {
		return nil
	}
	_ = step
	return err
}

type scriptRows struct {
	columns []string
	rows    [][]driver.Value
	idx     int
}

func (r *scriptRows) Columns() []string { return r.columns }
func (r *scriptRows) Close() error      { return nil }
func (r *scriptRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

var scriptedDriverSeq atomic.Uint64

func openScriptDB(t *testing.T, steps ...scriptStep) (*sql.DB, *scriptState) {
	t.Helper()
	state := &scriptState{steps: steps}
	name := fmt.Sprintf("platform-script-%d", scriptedDriverSeq.Add(1))
	sql.Register(name, scriptDriver{state: state})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db, state
}

func fixedPGTime() time.Time         { return time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC) }
func fixedPGID(prefix string) string { return prefix + "_fixed" }

func TestPostgresCreateOrganizationCommitsResourceAuditAndOutboxAtomically(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "INSERT INTO organizations", columns: []string{"id", "revision", "name", "display_name", "created_at", "updated_at"}, rows: [][]driver.Value{{"org_fixed", int64(1), "example", "Example", now, now}}},
		scriptStep{kind: "exec", contains: "INSERT INTO organization_memberships"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "Example", DisplayName: "Example"}, "actor-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "org_fixed" || got.Name != "example" || got.Revision != 1 {
		t.Fatalf("unexpected organization: %#v", got)
	}
	script.done(t)
}

func TestPostgresCreateOrganizationRollsBackWhenOutboxFails(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "INSERT INTO organizations", columns: []string{"id", "revision", "name", "display_name", "created_at", "updated_at"}, rows: [][]driver.Value{{"org_fixed", int64(1), "example", "Example", now, now}}},
		scriptStep{kind: "exec", contains: "INSERT INTO organization_memberships"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO outbox_events", err: errors.New("forced membership outbox failure")},
		scriptStep{kind: "rollback"},
	)
	store, _ := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if _, err := store.CreateOrganization(context.Background(), controlplane.Organization{Name: "example", DisplayName: "Example"}, "actor-1"); err == nil {
		t.Fatal("expected failure")
	}
	script.done(t)
}

func TestPostgresStoreHealthUsesPingAndReadinessQuery(t *testing.T) {
	db, script := openScriptDB(t,
		scriptStep{kind: "ping"},
		scriptStep{kind: "query", contains: "SELECT 1", columns: []string{"one"}, rows: [][]driver.Value{{int64(1)}}},
	)
	store, _ := NewPostgresStoreWith(db, time.Now, fixedPGID)
	if err := store.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	script.done(t)
}

func TestPostgresOrganizationMembershipGrantAndRevoke(t *testing.T) {
	now := fixedPGTime()
	membershipColumns := []string{"id", "organization_id", "revision", "subject", "role", "state", "granted_by", "revoked_by", "revoked_at", "created_at", "updated_at"}
	organizationColumnsForTest := []string{"id", "revision", "name", "display_name", "created_at", "updated_at"}

	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM organizations WHERE id=$1 FOR SHARE", columns: organizationColumnsForTest, rows: [][]driver.Value{{"org_fixed", int64(1), "example", "Example", now, now}}},
		scriptStep{kind: "query", contains: "FROM organization_memberships WHERE organization_id=$1 AND subject=$2 FOR UPDATE", columns: membershipColumns, rows: nil},
		scriptStep{kind: "query", contains: "INSERT INTO organization_memberships", columns: membershipColumns, rows: [][]driver.Value{{"mem_fixed", "org_fixed", int64(1), "user-a", "organization-operator", "ACTIVE", "admin-a", "", nil, now, now}}},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := store.UpsertOrganizationMembership(context.Background(), controlplane.OrganizationMembership{OrganizationID: "org_fixed", Subject: "user-a", Role: controlplane.OrganizationOperator}, 0, "admin-a")
	if err != nil {
		t.Fatal(err)
	}
	if granted.ID != "mem_fixed" || granted.State != controlplane.OrganizationMembershipActive || granted.Role != controlplane.OrganizationOperator {
		t.Fatalf("unexpected granted membership: %#v", granted)
	}
	script.done(t)

	db2, script2 := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM organization_memberships WHERE organization_id=$1 AND subject=$2 FOR UPDATE", columns: membershipColumns, rows: [][]driver.Value{{"mem_fixed", "org_fixed", int64(1), "user-a", "organization-operator", "ACTIVE", "admin-a", "", nil, now, now}}},
		scriptStep{kind: "query", contains: "UPDATE organization_memberships SET revision=revision+1", columns: membershipColumns, rows: [][]driver.Value{{"mem_fixed", "org_fixed", int64(2), "user-a", "organization-operator", "REVOKED", "admin-a", "admin-b", now, now, now}}},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
		scriptStep{kind: "commit"},
	)
	store2, err := NewPostgresStoreWith(db2, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store2.RevokeOrganizationMembership(context.Background(), "org_fixed", "user-a", 1, "admin-b")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Revision != 2 || revoked.State != controlplane.OrganizationMembershipRevoked || revoked.RevokedBy != "admin-b" || revoked.RevokedAt == nil {
		t.Fatalf("unexpected revoked membership: %#v", revoked)
	}
	script2.done(t)
}

func TestPostgresServiceAccountTokenIssueRotateAndRevokeAuthority(t *testing.T) {
	now := fixedPGTime()
	orgCols := []string{"id", "revision", "name", "display_name", "created_at", "updated_at"}
	prjCols := []string{"id", "organization_id", "revision", "name", "display_name", "created_at", "updated_at"}
	saCols := []string{"id", "organization_id", "project_id", "revision", "name", "display_name", "product_role", "state", "created_by", "revoked_by", "revoked_at", "created_at", "updated_at"}
	tokCols := []string{"id", "service_account_id", "organization_id", "project_id", "revision", "token_prefix", "token_digest", "idempotency_key", "permissions", "state", "expires_at", "created_by", "rotated_from_id", "revoked_by", "revoked_at", "created_at", "updated_at"}
	permissions := []byte(`["read","operate"]`)
	expires := now.Add(24 * time.Hour)
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM organizations WHERE id=$1 FOR SHARE", columns: orgCols, rows: [][]driver.Value{{"org_fixed", int64(1), "acme", "Acme", now, now}}},
		scriptStep{kind: "query", contains: "FROM projects WHERE id=$1 FOR SHARE", columns: prjCols, rows: [][]driver.Value{{"prj_fixed", "org_fixed", int64(1), "prod", "Prod", now, now}}},
		scriptStep{kind: "query", contains: "INSERT INTO service_accounts", columns: saCols, rows: [][]driver.Value{{"svc_fixed", "org_fixed", "prj_fixed", int64(1), "automation", "Automation", "platform-operator", "ACTIVE", "admin", "", nil, now, now}}},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"}, scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"}, scriptStep{kind: "commit"},
	)
	store, _ := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	sa, err := store.CreateServiceAccount(context.Background(), controlplane.ServiceAccount{OrganizationID: "org_fixed", ProjectID: "prj_fixed", Name: "automation", DisplayName: "Automation", ProductRole: "platform-operator"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if sa.ID != "svc_fixed" || sa.State != controlplane.ServiceAccountActive {
		t.Fatalf("service account %#v", sa)
	}
	script.done(t)

	db2, script2 := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM service_accounts WHERE id=$1 FOR SHARE", columns: saCols, rows: [][]driver.Value{{"svc_fixed", "org_fixed", "prj_fixed", int64(1), "automation", "Automation", "platform-operator", "ACTIVE", "admin", "", nil, now, now}}},
		scriptStep{kind: "query", contains: "INSERT INTO api_tokens", columns: tokCols, rows: [][]driver.Value{{"tok_a", "svc_fixed", "org_fixed", "prj_fixed", int64(1), "pft.tok_a", "sha256:" + strings.Repeat("a", 64), "issue-a", permissions, "ACTIVE", expires, "admin", "", "", nil, now, now}}},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"}, scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"}, scriptStep{kind: "commit"},
	)
	store2, _ := NewPostgresStoreWith(db2, func() time.Time { return now }, fixedPGID)
	tok, err := store2.CreateAPIToken(context.Background(), controlplane.APIToken{ResourceMeta: controlplane.ResourceMeta{ID: "tok_a"}, ServiceAccountID: "svc_fixed", TokenPrefix: "pft.tok_a", TokenDigest: "sha256:" + strings.Repeat("a", 64), Permissions: []string{"read", "operate"}, ExpiresAt: expires, IdempotencyKey: "issue-a"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if tok.ID != "tok_a" || len(tok.Permissions) != 2 {
		t.Fatalf("token %#v", tok)
	}
	script2.done(t)

	db3, script3 := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM api_tokens WHERE id=$1 FOR UPDATE", columns: tokCols, rows: [][]driver.Value{{"tok_a", "svc_fixed", "org_fixed", "prj_fixed", int64(1), "pft.tok_a", "sha256:" + strings.Repeat("a", 64), "issue-a", permissions, "ACTIVE", expires, "admin", "", "", nil, now, now}}},
		scriptStep{kind: "query", contains: "FROM service_accounts WHERE id=$1 FOR SHARE", columns: saCols, rows: [][]driver.Value{{"svc_fixed", "org_fixed", "prj_fixed", int64(1), "automation", "Automation", "platform-operator", "ACTIVE", "admin", "", nil, now, now}}},
		scriptStep{kind: "query", contains: "SELECT id FROM api_tokens WHERE service_account_id=$1 AND idempotency_key=$2", columns: []string{"id"}, rows: nil},
		scriptStep{kind: "query", contains: "UPDATE api_tokens SET revision=revision+1", columns: tokCols, rows: [][]driver.Value{{"tok_a", "svc_fixed", "org_fixed", "prj_fixed", int64(2), "pft.tok_a", "sha256:" + strings.Repeat("a", 64), "issue-a", permissions, "REVOKED", expires, "admin", "", "admin", now, now, now}}},
		scriptStep{kind: "query", contains: "INSERT INTO api_tokens", columns: tokCols, rows: [][]driver.Value{{"tok_b", "svc_fixed", "org_fixed", "prj_fixed", int64(1), "pft.tok_b", "sha256:" + strings.Repeat("b", 64), "rotate-a", permissions, "ACTIVE", expires, "admin", "tok_a", "", nil, now, now}}},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"}, scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"}, scriptStep{kind: "commit"},
	)
	store3, _ := NewPostgresStoreWith(db3, func() time.Time { return now }, fixedPGID)
	old, next, err := store3.RotateAPIToken(context.Background(), "tok_a", 1, controlplane.APIToken{ResourceMeta: controlplane.ResourceMeta{ID: "tok_b"}, TokenPrefix: "pft.tok_b", TokenDigest: "sha256:" + strings.Repeat("b", 64), Permissions: []string{"read", "operate"}, ExpiresAt: expires, IdempotencyKey: "rotate-a"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if old.State != controlplane.APITokenRevoked || next.RotatedFromID != "tok_a" {
		t.Fatalf("rotation old=%#v next=%#v", old, next)
	}
	script3.done(t)

	db4, script4 := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM service_accounts WHERE id=$1 FOR UPDATE", columns: saCols, rows: [][]driver.Value{{"svc_fixed", "org_fixed", "prj_fixed", int64(1), "automation", "Automation", "platform-operator", "ACTIVE", "admin", "", nil, now, now}}},
		scriptStep{kind: "query", contains: "UPDATE service_accounts SET revision=revision+1", columns: saCols, rows: [][]driver.Value{{"svc_fixed", "org_fixed", "prj_fixed", int64(2), "automation", "Automation", "platform-operator", "REVOKED", "admin", "admin", now, now, now}}},
		scriptStep{kind: "exec", contains: "UPDATE api_tokens SET revision=revision+1"}, scriptStep{kind: "exec", contains: "INSERT INTO audit_events"}, scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"}, scriptStep{kind: "commit"},
	)
	store4, _ := NewPostgresStoreWith(db4, func() time.Time { return now }, fixedPGID)
	revoked, err := store4.RevokeServiceAccount(context.Background(), "svc_fixed", 1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != controlplane.ServiceAccountRevoked {
		t.Fatalf("revoked %#v", revoked)
	}
	script4.done(t)
}

func TestPostgresInventoryCorruptJSONFailsClosed(t *testing.T) {
	now := fixedPGTime()
	columns := []string{"id", "revision", "cluster_id", "observed_at", "distribution", "distribution_evidence_method", "distribution_evidence_uid", "distribution_evidence_version", "kubernetes_version", "nodes", "addons", "storage_classes", "capacity", "certificates", "networking", "workload_explorer", "api_resources", "crds", "api_discovery_complete", "crd_discovery_complete", "schema_discovery_version", "schema_discovery_digest", "schema_discovery_complete", "capabilities", "digest", "created_at", "updated_at"}
	row := []driver.Value{
		"inv_fixed", int64(1), "clu_fixed", now, "rke2", "", "", "", "v1.34.9+rke2r1",
		[]byte("{"), []byte("[]"), []byte("[]"), []byte("{}"), []byte("[]"), []byte("{}"), []byte("{}"), []byte("[]"), []byte("[]"),
		true, true, "v1", "sha256:schema", true, []byte("[]"), "sha256:inventory", now, now,
	}
	db, script := openScriptDB(t, scriptStep{kind: "query", contains: "FROM cluster_inventory_snapshots", columns: columns, rows: [][]driver.Value{row}})
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetLatestClusterInventory(context.Background(), "clu_fixed")
	if err == nil || !strings.Contains(err.Error(), "decode PostgreSQL JSON column") {
		t.Fatalf("expected corrupt JSON to fail closed, got %v", err)
	}
	script.done(t)
}

func fixtureColumns(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("c%d", i)
	}
	return out
}

func TestPostgresCriticalJSONScannersFailClosed(t *testing.T) {
	now := fixedPGTime()
	bad := []byte("{")
	tests := []struct {
		name   string
		values []driver.Value
		scan   func(*sql.Row) error
	}{
		{
			name: "operation retry policy",
			values: []driver.Value{
				"op_fixed", "prj_fixed", int64(1), "APPLY", "cluster-a", "rev-a",
				"FAILED", "high", "mutation", bad, int64(1), nil, "transient", false,
				"", "", "", "", nil, "", "idem", "sha256:req", "actor", "", nil, int64(1), "err",
				"", int64(0), int64(0), nil, nil, "", now, now,
			},
			scan: func(row *sql.Row) error { _, err := scanOperation(row); return err },
		},
		{
			name: "tenant quota",
			values: []driver.Value{
				"ten_fixed", "org_fixed", "prj_fixed", "clu_fixed", int64(1), "tenant-a", "Tenant A", "standard", "tenant-a", "READY",
				bad, nil, nil, nil, nil, "", nil, "sha256:desired", "", nil, "", "", "actor", "idem", "sha256:req", int64(0), int64(0), int64(0), nil, "", "", "", "", nil, "", now, now,
			},
			scan: func(row *sql.Row) error { _, err := scanTenant(row); return err },
		},
		{
			name: "provider kubernetes series",
			values: []driver.Value{
				"pp_fixed", "prj_fixed", "mgmt_fixed", int64(1), "profile", "Profile", "cluster-api", "platform-system", "cc", "worker", "v1.34.0",
				bad, []byte("[]"), []byte("[]"), "unspecified", "", "", int64(10), "READY", "sha256:desired", "sha256:observed", "actor", "idem", "sha256:req", int64(0), int64(0), nil, "", now, now,
			},
			scan: func(row *sql.Row) error { _, err := scanProviderProfile(row); return err },
		},
		{
			name: "runtime verification checks",
			values: []driver.Value{
				"rtv_fixed", "prj_fixed", "clu_fixed", "bld_fixed", int64(1), "FAILED", "sha256:desired", "sha256:observed",
				"registry/probe@sha256:" + strings.Repeat("a", 64), "sha256:req", "idem", "actor", nil, nil, bad, "sha256:report", "err", int64(1), int64(0), nil, now, now,
			},
			scan: func(row *sql.Row) error { _, err := scanRuntimeVerification(row); return err },
		},
		{
			name: "api token permissions",
			values: []driver.Value{
				"tok_fixed", "svc_fixed", "org_fixed", "prj_fixed", int64(1), "pft.fixed", "sha256:" + strings.Repeat("a", 64), "critical-key", bad,
				"ACTIVE", now.Add(time.Hour), "actor", "", "", nil, now, now,
			},
			scan: func(row *sql.Row) error { _, err := scanAPIToken(row); return err },
		},
		{
			name: "notification route event patterns",
			values: []driver.Value{
				"route_fixed", "org_fixed", "prj_fixed", int64(1), "critical", true, bad, "critical", []byte(`[]`), "actor", now, now,
			},
			scan: func(row *sql.Row) error { _, err := scanNotificationRoute(row); return err },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, script := openScriptDB(t, scriptStep{kind: "query", contains: "SELECT fixture", columns: fixtureColumns(len(tc.values)), rows: [][]driver.Value{tc.values}})
			err := tc.scan(db.QueryRowContext(context.Background(), "SELECT fixture"))
			if err == nil || !strings.Contains(err.Error(), "decode PostgreSQL JSON column") {
				t.Fatalf("expected corrupt JSON to fail closed, got %v", err)
			}
			script.done(t)
		})
	}
}

func TestPostgresSerializableRetriesSerializationFailure(t *testing.T) {
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "rollback"},
		scriptStep{kind: "begin"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, time.Now, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	err = store.serializable(context.Background(), func(*sql.Tx) error {
		attempts++
		if attempts == 1 {
			return errors.New("SQLSTATE 40001 serialization failure")
		}
		return nil
	})
	if err != nil || attempts != 2 {
		t.Fatalf("retry err=%v attempts=%d", err, attempts)
	}
	script.done(t)
}

func TestPostgresSerializableRetriesCommitSerializationFailure(t *testing.T) {
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "commit", err: errors.New("SQLSTATE 40001 could not serialize access")},
		scriptStep{kind: "begin"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, time.Now, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	err = store.serializable(context.Background(), func(*sql.Tx) error { attempts++; return nil })
	if err != nil || attempts != 2 {
		t.Fatalf("commit retry err=%v attempts=%d", err, attempts)
	}
	script.done(t)
}

func TestClaimNotificationDeliveriesCommitRetryDoesNotLeakRolledBackResults(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	columns := strings.Split(notificationDeliveryColumns, ",")
	candidate := []driver.Value{"ndl_1", "nte_1", "route_1", "dst_1", int64(1), "PENDING", int64(0), int64(5), now, "", nil, int64(0), "", nil, now, now}
	claimed := []driver.Value{"ndl_1", "nte_1", "route_1", "dst_1", int64(2), "DELIVERING", int64(1), int64(5), now, "worker-a", now.Add(time.Minute), int64(0), "", nil, now, now}
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM notification_deliveries", columns: columns, rows: [][]driver.Value{candidate}},
		scriptStep{kind: "query", contains: "UPDATE notification_deliveries SET", columns: columns, rows: [][]driver.Value{claimed}},
		scriptStep{kind: "commit", err: errors.New("SQLSTATE 40001 could not serialize access")},
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM notification_deliveries", columns: columns, rows: [][]driver.Value{candidate}},
		scriptStep{kind: "query", contains: "UPDATE notification_deliveries SET", columns: columns, rows: [][]driver.Value{claimed}},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	out, err := store.ClaimNotificationDeliveries(context.Background(), "worker-a", 1, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "ndl_1" {
		t.Fatalf("serializable commit retry leaked rolled-back attempt results: %#v", out)
	}
	script.done(t)
}

func TestApplyMigrationsRejectsChecksumDriftAndRollsBackFailedDDL(t *testing.T) {
	workTxSafety := func() []scriptStep {
		return []scriptStep{
			{kind: "query", contains: "set_config('lock_timeout'", columns: []string{"set_config", "set_config"}, rows: [][]driver.Value{{postgresTimeoutSetting(migrationSchemaLockTimeout), postgresTimeoutSetting(migrationStatementTimeout)}}},
		}
	}
	t.Run("checksum drift", func(t *testing.T) {
		steps := []scriptStep{{kind: "query", contains: "SELECT pg_advisory_lock", columns: []string{"pg_advisory_lock"}, rows: [][]driver.Value{{nil}}}, {kind: "begin"}}
		steps = append(steps, workTxSafety()...)
		steps = append(steps, scriptStep{kind: "exec", contains: "CREATE TABLE IF NOT EXISTS schema_migrations"}, scriptStep{kind: "commit"}, scriptStep{kind: "begin"})
		steps = append(steps, workTxSafety()...)
		steps = append(steps, scriptStep{kind: "query", contains: "SELECT checksum FROM schema_migrations", columns: []string{"checksum"}, rows: [][]driver.Value{{"sha256:wrong"}}}, scriptStep{kind: "rollback"}, scriptStep{kind: "query", contains: "SELECT pg_advisory_unlock", columns: []string{"pg_advisory_unlock"}, rows: [][]driver.Value{{true}}})
		db, script := openScriptDB(t, steps...)
		err := ApplyMigrations(context.Background(), db)
		if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("expected migration checksum mismatch, got %v", err)
		}
		script.done(t)
	})
	t.Run("ddl failure rollback", func(t *testing.T) {
		steps := []scriptStep{{kind: "query", contains: "SELECT pg_advisory_lock", columns: []string{"pg_advisory_lock"}, rows: [][]driver.Value{{nil}}}, {kind: "begin"}}
		steps = append(steps, workTxSafety()...)
		steps = append(steps, scriptStep{kind: "exec", contains: "CREATE TABLE IF NOT EXISTS schema_migrations"}, scriptStep{kind: "commit"}, scriptStep{kind: "begin"})
		steps = append(steps, workTxSafety()...)
		steps = append(steps,
			scriptStep{kind: "query", contains: "SELECT checksum FROM schema_migrations", columns: []string{"checksum"}, rows: nil},
			scriptStep{kind: "exec", err: errors.New("forced migration DDL failure")},
			scriptStep{kind: "rollback"},
			scriptStep{kind: "query", contains: "SELECT pg_advisory_unlock", columns: []string{"pg_advisory_unlock"}, rows: [][]driver.Value{{true}}},
		)
		db, script := openScriptDB(t, steps...)
		err := ApplyMigrations(context.Background(), db)
		if err == nil || !strings.Contains(err.Error(), "apply migration") {
			t.Fatalf("expected migration failure, got %v", err)
		}
		script.done(t)
	})
}

func TestApplyMigrationsWithCompatibilityFencesFutureSchemaUnderMigrationLock(t *testing.T) {
	db, script := openScriptDB(t,
		scriptStep{kind: "query", contains: "SELECT pg_advisory_lock", columns: []string{"pg_advisory_lock"}, rows: [][]driver.Value{{nil}}},
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "set_config('lock_timeout'", columns: []string{"set_config", "set_config"}, rows: [][]driver.Value{{postgresTimeoutSetting(migrationSchemaLockTimeout), postgresTimeoutSetting(migrationStatementTimeout)}}},
		scriptStep{kind: "exec", contains: "CREATE TABLE IF NOT EXISTS schema_migrations"},
		scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
		scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{futureSchemaVersion(t), futureSchemaVersion(t)}}},
		scriptStep{kind: "rollback"},
		scriptStep{kind: "query", contains: "SELECT pg_advisory_unlock", columns: []string{"pg_advisory_unlock"}, rows: [][]driver.Value{{true}}},
	)
	err := ApplyMigrationsWithCompatibility(context.Background(), db, MigrationModeRolling, nil)
	if err == nil || !strings.Contains(err.Error(), "schema is newer") {
		t.Fatalf("expected future-schema rollback fence under migration authority, got %v", err)
	}
	script.done(t)
}

func TestBeginMigrationTxFailsClosedWhenSchemaLockSafetyCannotBeApplied(t *testing.T) {
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "set_config('lock_timeout'", err: errors.New("lock timeout GUC unavailable")},
		scriptStep{kind: "rollback"},
	)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = beginMigrationTx(context.Background(), conn); err == nil || !strings.Contains(err.Error(), "configure PostgreSQL migration lock safety") {
		t.Fatalf("expected migration lock safety failure, got %v", err)
	}
	script.done(t)
}

func TestMigrationSQLForManagedTransactionPreservesHistoricalWrapperSemantics(t *testing.T) {
	raw := "BEGIN;\nCREATE TABLE demo(id bigint);\nCOMMIT;\n"
	got, err := migrationSQLForManagedTransaction(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(got), "BEGIN;") || strings.Contains(strings.ToUpper(got), "COMMIT;") {
		t.Fatalf("managed execution retained nested transaction control: %q", got)
	}
	if !strings.Contains(got, "CREATE TABLE demo") {
		t.Fatalf("migration body was lost: %q", got)
	}
	if _, err = migrationSQLForManagedTransaction("BEGIN;\nSELECT 1;\n"); err == nil {
		t.Fatal("unbalanced transaction wrapper was accepted")
	}
	if _, err = migrationSQLForManagedTransaction("SELECT 1;\nCOMMIT;\n"); err == nil {
		t.Fatal("trailing COMMIT without BEGIN was accepted")
	}
	if _, err = migrationSQLForManagedTransaction("BEGIN;\nSAVEPOINT x;\nCOMMIT;\nROLLBACK;\n"); err == nil {
		t.Fatal("nested transaction control was accepted")
	}
}

func TestPostgresResolveOIDCGroupsQueriesOnlyAssertedGroups(t *testing.T) {
	now := fixedPGTime()
	columns := []string{"id", "revision", "group_name", "product_role", "organization_id", "organization_role", "project_id", "project_role", "state", "created_by", "revoked_by", "revoked_at", "created_at", "updated_at"}
	row := []driver.Value{"ogm_fixed", int64(1), "team-a", "platform-viewer", "", "", "", "", "ACTIVE", "admin", "", nil, now, now}
	db, script := openScriptDB(t, scriptStep{kind: "query", contains: "WHERE state='ACTIVE' AND group_name IN ($1,$2)", columns: columns, rows: [][]driver.Value{row}})
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveOIDCGroups(context.Background(), []string{"team-a", "team-b", "team-a", " "})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.ProductRoles) != 1 || resolved.ProductRoles[0] != "platform-viewer" {
		t.Fatalf("unexpected resolution: %#v", resolved)
	}
	script.done(t)
}

func TestPostgresResolveOIDCGroupsEmptyInputAvoidsDatabaseScan(t *testing.T) {
	db, script := openScriptDB(t)
	store, err := NewPostgresStoreWith(db, fixedPGTime, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveOIDCGroups(context.Background(), []string{"", "  "})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.ProductRoles) != 0 || len(resolved.MappingIDs) != 0 {
		t.Fatalf("unexpected empty resolution: %#v", resolved)
	}
	script.done(t)
}

func TestPostgresSecurityAuditBatchCommitsSingleLockedHashChain(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "exec", contains: "SELECT pg_advisory_xact_lock(680068)"},
		scriptStep{kind: "query", contains: "SELECT sequence,event_digest FROM security_audit_events ORDER BY sequence DESC LIMIT 1", columns: []string{"sequence", "event_digest"}},
		scriptStep{kind: "exec", contains: "INSERT INTO security_audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO security_audit_events"},
		scriptStep{kind: "commit"},
	)
	var ids atomic.Int64
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, func(prefix string) string {
		return fmt.Sprintf("%s_%d", prefix, ids.Add(1))
	})
	if err != nil {
		t.Fatal(err)
	}
	req1 := &securityAuditRequest{input: controlplane.SecurityAuditInput{Category: "AUTHENTICATION", Decision: "ALLOW", ActorID: "actor-1"}, result: make(chan securityAuditResult, 1)}
	req2 := &securityAuditRequest{input: controlplane.SecurityAuditInput{Category: "AUTHORIZATION", Decision: "ALLOW", ActorID: "actor-1"}, result: make(chan securityAuditResult, 1)}
	store.securityAuditMu.Lock()
	store.securityAuditQueue = append(store.securityAuditQueue, req1, req2)
	store.securityAuditProcessing = true
	store.securityAuditMu.Unlock()
	go store.processSecurityAuditQueue()

	r1 := <-req1.result
	r2 := <-req2.result
	if r1.err != nil || r2.err != nil {
		t.Fatalf("batch append failed: first=%v second=%v", r1.err, r2.err)
	}
	if r1.event.Sequence != 1 || r2.event.Sequence != 2 {
		t.Fatalf("unexpected sequence allocation: %d %d", r1.event.Sequence, r2.event.Sequence)
	}
	if r2.event.PreviousDigest != r1.event.Digest {
		t.Fatalf("second event does not extend first digest: previous=%s first=%s", r2.event.PreviousDigest, r1.event.Digest)
	}
	if err := controlplane.ValidateSecurityAuditChain([]controlplane.SecurityAuditEvent{r1.event, r2.event}); err != nil {
		t.Fatalf("batched audit chain invalid: %v", err)
	}
	script.done(t)
}

func TestPostgresSecurityAuditBackpressureBoundsPendingQueue(t *testing.T) {
	db, script := openScriptDB(t)
	store, err := NewPostgresStoreWith(db, fixedPGTime, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	store.securityAuditMu.Lock()
	store.securityAuditProcessing = true
	store.securityAuditQueue = make([]*securityAuditRequest, securityAuditQueueMax)
	store.securityAuditMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = store.AppendSecurityAudit(ctx, controlplane.SecurityAuditInput{Category: "AUTHENTICATION", Decision: "ALLOW", ActorID: "actor-overload"})
	if err == nil || !strings.Contains(err.Error(), "security audit backpressure") {
		t.Fatalf("expected bounded audit backpressure error, got %v", err)
	}
	store.securityAuditMu.Lock()
	queued := len(store.securityAuditQueue)
	store.securityAuditQueue = nil
	store.securityAuditProcessing = false
	store.securityAuditMu.Unlock()
	if queued != securityAuditQueueMax {
		t.Fatalf("queue grew beyond bounded capacity: %d", queued)
	}
	script.done(t)
}

func TestPostgresSecurityAuditDrainWaitsForAdmittedBatch(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "exec", contains: "SELECT pg_advisory_xact_lock(680068)"},
		scriptStep{kind: "query", contains: "SELECT sequence,event_digest FROM security_audit_events ORDER BY sequence DESC LIMIT 1", columns: []string{"sequence", "event_digest"}},
		scriptStep{kind: "exec", contains: "INSERT INTO security_audit_events"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	req := &securityAuditRequest{input: controlplane.SecurityAuditInput{Category: "AUTHENTICATION", Decision: "DENY", ActorID: "actor-drain"}, result: make(chan securityAuditResult, 1)}
	store.securityAuditMu.Lock()
	store.securityAuditQueue = append(store.securityAuditQueue, req)
	store.securityAuditProcessing = true
	store.securityAuditMu.Unlock()
	go store.processSecurityAuditQueue()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := store.DrainSecurityAudit(ctx); err != nil {
		t.Fatalf("drain failed: %v", err)
	}
	result := <-req.result
	if result.err != nil || result.event.Sequence != 1 {
		t.Fatalf("unexpected drained result: event=%#v err=%v", result.event, result.err)
	}
	script.done(t)
}

func TestPostgresSecurityAuditDurableFailureRejectsQueuedBacklog(t *testing.T) {
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "exec", contains: "SELECT pg_advisory_xact_lock(680068)", err: errors.New("database unavailable")},
		scriptStep{kind: "rollback"},
	)
	store, err := NewPostgresStoreWith(db, fixedPGTime, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	requests := make([]*securityAuditRequest, securityAuditBatchMax+1)
	store.securityAuditMu.Lock()
	store.securityAuditProcessing = true
	for i := range requests {
		requests[i] = &securityAuditRequest{
			input:  controlplane.SecurityAuditInput{Category: "AUTHENTICATION", Decision: "ALLOW", ActorID: fmt.Sprintf("actor-%d", i)},
			result: make(chan securityAuditResult, 1),
		}
		store.securityAuditQueue = append(store.securityAuditQueue, requests[i])
	}
	store.securityAuditMu.Unlock()
	go store.processSecurityAuditQueue()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i, req := range requests {
		select {
		case result := <-req.result:
			if result.err == nil || !strings.Contains(result.err.Error(), "database unavailable") {
				t.Fatalf("request %d did not fail closed with durable DB error: %v", i, result.err)
			}
		case <-ctx.Done():
			t.Fatalf("request %d remained pinned behind failed audit DB", i)
		}
	}
	if err := store.DrainSecurityAudit(ctx); err != nil {
		t.Fatalf("failed backlog did not drain: %v", err)
	}
	script.done(t)
}

func TestCheckMigrationCompatibilityBlocksUnsafeRollingUpgradeBeforeMutation(t *testing.T) {
	t.Run("fresh database is allowed", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{nil}}},
		)
		if err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil); err != nil {
			t.Fatal(err)
		}
		script.done(t)
	})

	t.Run("rolling upgrade crossing migration 21 is blocked", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(20), int64(20)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "pending migration 21") || !strings.Contains(err.Error(), "quiesced") {
			t.Fatalf("expected mixed-version migration block, got %v", err)
		}
		script.done(t)
	})

	t.Run("quiesced mode explicitly permits legacy crossing", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(20), int64(20)}}},
		)
		if err := CheckMigrationCompatibility(context.Background(), db, MigrationModeQuiesced, map[int64]struct{}{21: {}, 27: {}, 47: {}, 50: {}, 60: {}, 61: {}, 64: {}}); err != nil {
			t.Fatal(err)
		}
		script.done(t)
	})

	t.Run("quiesced mode requires exact migration approval", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(20), int64(20)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeQuiesced, map[int64]struct{}{99: {}})
		if err == nil || !strings.Contains(err.Error(), "not explicitly approved") {
			t.Fatalf("expected exact quiesced approval requirement, got %v", err)
		}
		script.done(t)
	})

	t.Run("past migration 21 still blocks at migration 27", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(21), int64(21)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "pending migration 27") || !strings.Contains(err.Error(), "quiesced") {
			t.Fatalf("expected migration 27 mixed-version block, got %v", err)
		}
		script.done(t)
	})

	t.Run("past migration 27 still blocks at migration 47", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(27), int64(27)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "pending migration 47") || !strings.Contains(err.Error(), "quiesced") {
			t.Fatalf("expected migration 47 mixed-version block, got %v", err)
		}
		script.done(t)
	})

	t.Run("already past migration 47 blocks at migration 50", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(47), int64(47)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "pending migration 50") || !strings.Contains(err.Error(), "quiesced") {
			t.Fatalf("expected migration 50 mixed-version block, got %v", err)
		}
		script.done(t)
	})

	t.Run("already past migration 50 blocks at OS patch semantic boundary 60", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(50), int64(50)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "pending migration 60") || !strings.Contains(err.Error(), "quiesced") {
			t.Fatalf("expected migration 60 mixed-version block, got %v", err)
		}
		script.done(t)
	})

	t.Run("already past migration 60 blocks at provider Machine semantic boundary 61", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(60), int64(60)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "pending migration 61") || !strings.Contains(err.Error(), "quiesced") {
			t.Fatalf("expected migration 61 mixed-version block, got %v", err)
		}
		script.done(t)
	})

	t.Run("already past migration 61 blocks at component lifecycle semantic boundary 64", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(61), int64(61)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "pending migration 64") || !strings.Contains(err.Error(), "quiesced") {
			t.Fatalf("expected migration 64 mixed-version block, got %v", err)
		}
		script.done(t)
	})

	t.Run("future schema blocks binary rollback", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{futureSchemaVersion(t), futureSchemaVersion(t)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "schema is newer") || !strings.Contains(err.Error(), "do not roll back") {
			t.Fatalf("expected future-schema rollback fence, got %v", err)
		}
		script.done(t)
	})

	t.Run("gapped migration history fails before mutation", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "SELECT to_regclass", columns: []string{"to_regclass"}, rows: [][]driver.Value{{"schema_migrations"}}},
			scriptStep{kind: "query", contains: "SELECT COALESCE(MAX(version),0), COUNT(*)", columns: []string{"max", "count"}, rows: [][]driver.Value{{int64(20), int64(19)}}},
		)
		err := CheckMigrationCompatibility(context.Background(), db, MigrationModeRolling, nil)
		if err == nil || !strings.Contains(err.Error(), "not a contiguous prefix") {
			t.Fatalf("expected gapped migration history rejection, got %v", err)
		}
		script.done(t)
	})
}

func TestParseMigrationModeFailsClosed(t *testing.T) {
	for raw, want := range map[string]MigrationMode{"": MigrationModeRolling, "rolling": MigrationModeRolling, "QUIESCED": MigrationModeQuiesced} {
		got, err := ParseMigrationMode(raw)
		if err != nil || got != want {
			t.Fatalf("ParseMigrationMode(%q)=(%q,%v), want %q", raw, got, err, want)
		}
	}
	if _, err := ParseMigrationMode("unsafe"); err == nil {
		t.Fatal("invalid migration mode was accepted")
	}
	approved, err := ParseQuiescedMigrationApprovals("21, 21, 44")
	if err != nil || len(approved) != 2 {
		t.Fatalf("unexpected quiesced approvals: %#v err=%v", approved, err)
	}
	if _, err := ParseQuiescedMigrationApprovals("21,unsafe"); err == nil {
		t.Fatal("invalid quiesced migration approval was accepted")
	}
}

func TestPostgresListOperationsPageByProjectsScopesBeforeLimit(t *testing.T) {
	now := fixedPGTime()
	row := []driver.Value{
		"op_own", "prj_own", int64(7), "APPLY", "cluster-a", "sha256:desired",
		"QUEUED", "medium", "mutation", []byte("{}"), int64(0), nil, "", false,
		"", "", "", "", nil, "", "idem-own", "sha256:req", "actor", "", nil, int64(0), "",
		"", int64(0), int64(0), nil, nil, "", now, now,
	}
	db, script := openScriptDB(t, scriptStep{
		kind:     "query",
		contains: "FROM operations WHERE project_id = ANY(string_to_array($1, chr(31))) ORDER BY updated_at DESC,created_at DESC,id DESC LIMIT $2",
		columns:  fixtureColumns(len(row)),
		rows:     [][]driver.Value{row},
	})
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.ListOperationsPageByProjects(context.Background(), []string{"prj_own", "prj_own", "prj_other"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "op_own" || got[0].ProjectID != "prj_own" {
		t.Fatalf("unexpected scoped operations page: %#v", got)
	}
	script.done(t)
}

func TestPostgresNotificationPagesApplyScopesBeforeLimit(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{
			kind:     "query",
			contains: "FROM notification_events WHERE (project_id = ANY(string_to_array($1, chr(31))) OR (project_id IS NULL AND organization_id = ANY(string_to_array($2, chr(31))))) ORDER BY occurred_at DESC,id DESC LIMIT $3",
			columns:  []string{"id"},
		},
		scriptStep{
			kind:     "query",
			contains: "FROM notification_deliveries d JOIN notification_events e ON e.id=d.event_id WHERE (e.project_id = ANY(string_to_array($1, chr(31))) OR (e.project_id IS NULL AND e.organization_id = ANY(string_to_array($2, chr(31))))) AND d.state=$3 ORDER BY d.created_at DESC,d.id DESC LIMIT $4",
			columns:  []string{"id"},
		},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.ListNotificationEventsPageByScopes(context.Background(), []string{"org_own", "org_own"}, []string{"prj_own", "prj_own"}, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("unexpected events: %#v", events)
	}
	deliveries, err := store.ListNotificationDeliveriesPageByScopes(context.Background(), []string{"org_own"}, []string{"prj_own"}, controlplane.NotificationDeliveryDeadLetter, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 0 {
		t.Fatalf("unexpected deliveries: %#v", deliveries)
	}
	script.done(t)
}

func TestPostgresAuditPageByScopesScopesBeforeLimit(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t, scriptStep{
		kind:     "query",
		contains: "WITH allowed_resources(id) AS (SELECT id FROM organizations WHERE id = ANY(string_to_array($1, chr(31)))",
		columns:  []string{"id"},
	})
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	values, err := store.ListAuditPageByScopes(context.Background(), []string{"org_own", "org_own"}, []string{"prj_own", "prj_own"}, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 0 {
		t.Fatalf("unexpected scoped audit values: %#v", values)
	}
	script.done(t)
}

func TestPostgresSecurityAuditTailPreservesChainOrder(t *testing.T) {
	now := fixedPGTime()
	row := func(sequence int64, id, previous, digest string) []driver.Value {
		return []driver.Value{
			sequence, id, now.Add(time.Duration(sequence) * time.Second), controlplane.SecurityAuditMethod,
			"AUTHORIZATION", "ALLOW", "actor", "oidc", "GET", "/api/v1/projects", int64(200), "PRODUCT_RBAC_ALLOWED", "req", "project", "prj", "viewer", "mapping", previous, digest,
		}
	}
	db, script := openScriptDB(t, scriptStep{
		kind:     "query",
		contains: "FROM security_audit_events ORDER BY sequence DESC LIMIT $1",
		columns:  fixtureColumns(19),
		rows: [][]driver.Value{
			row(2, "sau-2", "digest-1", "digest-2"),
			row(1, "sau-1", "", "digest-1"),
		},
	})
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.ListSecurityAudit(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("security audit events=%d want=2", len(got))
	}
	if got[0].Sequence != 1 || got[1].Sequence != 2 {
		t.Fatalf("security audit ordering=%v want chain order [1 2]", []int64{got[0].Sequence, got[1].Sequence})
	}
	script.done(t)
}

func TestPostgresClaimOutboxReturnsCandidateOrderDeterministically(t *testing.T) {
	now := fixedPGTime()
	older := now.Add(-2 * time.Minute)
	newer := now.Add(-time.Minute)
	lease := now.Add(time.Minute)
	columns := []string{"id", "revision", "aggregate_type", "aggregate_id", "event_type", "payload", "available_at", "claimed_by", "claimed_until", "attempt", "published_at", "created_at", "updated_at"}
	db, script := openScriptDB(t, scriptStep{kind: "query", contains: "ORDER BY available_at,id", columns: columns, rows: [][]driver.Value{
		{"evt_z_newer", int64(2), "test", "agg", "newer", []byte(`{}`), newer, "publisher", lease, int64(1), nil, newer, now},
		{"evt_a_older", int64(2), "test", "agg", "older", []byte(`{}`), older, "publisher", lease, int64(1), nil, older, now},
	}})
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), "publisher", 2, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 2 || claimed[0].ID != "evt_a_older" || claimed[1].ID != "evt_z_newer" {
		t.Fatalf("postgres outbox return order=%+v", claimed)
	}
	script.done(t)
}

func TestPostgresNextBaselineTaskRejectsStaleInventoryAuthority(t *testing.T) {
	now := fixedPGTime()
	stale := now.Add(-(controlplane.ClusterInventoryAuthorityFreshness + time.Second))
	token := "sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	clusterColumns := strings.Split(managedClusterColumns, ",")
	clusterRow := []driver.Value{
		"clu_fixed", int64(1), "prj_fixed", "imp_fixed", "prod", "Prod", "cluster-uid-1",
		"CONNECTED", "rke2", "v1.33.2+rke2r1", "0.0.205", stale, stale, stale,
		[]byte(`{}`), []byte(`["target-mutation-rbac-active","target-mutation-rbac-activation-issued","target-cluster-uid-attested"]`), digest, digest, digest, "", nil, "", now, now,
	}
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "SELECT ci.agent_token_digest FROM cluster_imports", columns: []string{"agent_token_digest"}, rows: [][]driver.Value{{token}}},
		scriptStep{kind: "query", contains: "FROM managed_clusters WHERE id=$1", columns: clusterColumns, rows: [][]driver.Value{clusterRow}},
		scriptStep{kind: "query", contains: "FROM managed_clusters WHERE id=$1", columns: clusterColumns, rows: [][]driver.Value{clusterRow}},
		scriptStep{kind: "rollback"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.NextBaselineTask(context.Background(), "clu_fixed", token); !errors.Is(err, controlplane.ErrPrerequisite) {
		t.Fatalf("stale inventory authority was admitted for a new PostgreSQL baseline task: %v", err)
	}
	script.done(t)
}

func TestPostgresCreateClusterImportPersistsImportScopedAgentPrincipal(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM cluster_imports WHERE project_id=$1 AND lower(name)=lower($2)", columns: []string{"id", "revision", "project_id", "name", "display_name", "state", "token_digest", "agent_token_digest", "agent_service_account", "expires_at", "approved_at", "claimed_at", "cluster_id", "requested_by", "approved_by", "created_at", "updated_at"}},
		scriptStep{kind: "exec", contains: "INSERT INTO cluster_imports(id,project_id,revision,name,display_name,state,token_digest,agent_service_account"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateClusterImport(context.Background(), controlplane.ClusterImport{ProjectID: "prj_fixed", Name: "edge", DisplayName: "Edge", TokenDigest: "sha256:" + strings.Repeat("a", 64), ExpiresAt: now.Add(time.Hour)}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if created.AgentServiceAccount != controlplane.FleetAgentServiceAccountName(created.ID) {
		t.Fatalf("postgres cluster import principal=%q want=%q", created.AgentServiceAccount, controlplane.FleetAgentServiceAccountName(created.ID))
	}
	script.done(t)
}

func TestPostgresClusterImportExpiryParity(t *testing.T) {
	now := fixedPGTime()
	cols := []string{"id", "revision", "project_id", "name", "display_name", "state", "token_digest", "agent_token_digest", "agent_service_account", "expires_at", "approved_at", "claimed_at", "cluster_id", "requested_by", "approved_by", "created_at", "updated_at"}
	expiredRow := []driver.Value{
		"imp_old", int64(3), "prj_fixed", "edge", "Edge old", "PENDING_APPROVAL",
		"sha256:" + strings.Repeat("a", 64), "", "4so-platform-agent-old", now.Add(-time.Minute), nil, nil, "", "operator", "", now.Add(-time.Hour), now.Add(-time.Hour),
	}

	t.Run("reject-create-already-expired", func(t *testing.T) {
		db, script := openScriptDB(t)
		store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.CreateClusterImport(context.Background(), controlplane.ClusterImport{ProjectID: "prj_fixed", Name: "edge", DisplayName: "Edge", TokenDigest: "sha256:" + strings.Repeat("b", 64), ExpiresAt: now}, "operator")
		if !errors.Is(err, controlplane.ErrValidation) {
			t.Fatalf("postgres accepted already-expired cluster import: %v", err)
		}
		script.done(t)
	})

	t.Run("get-renders-effective-expiry", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "query", contains: "FROM cluster_imports WHERE id=$1", columns: cols, rows: [][]driver.Value{expiredRow}},
		)
		store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.GetClusterImport(context.Background(), "imp_old")
		if err != nil {
			t.Fatal(err)
		}
		if got.State != controlplane.ClusterImportExpired || got.TokenDigest != "sha256:expired" {
			t.Fatalf("postgres rendered stale expired import: %+v", got)
		}
		script.done(t)
	})

	t.Run("replacement-materializes-expiry-and-releases-name", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "begin"},
			scriptStep{kind: "query", contains: "FROM cluster_imports WHERE project_id=$1 AND lower(name)=lower($2)", columns: cols, rows: [][]driver.Value{expiredRow}},
			scriptStep{kind: "exec", contains: "UPDATE cluster_imports SET revision=$2,state='EXPIRED',token_digest=$3"},
			scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
			scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
			scriptStep{kind: "exec", contains: "INSERT INTO cluster_imports(id,project_id,revision,name,display_name,state,token_digest,agent_service_account"},
			scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
			scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
			scriptStep{kind: "commit"},
		)
		store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
		if err != nil {
			t.Fatal(err)
		}
		created, err := store.CreateClusterImport(context.Background(), controlplane.ClusterImport{ProjectID: "prj_fixed", Name: "edge", DisplayName: "Edge replacement", TokenDigest: "sha256:" + strings.Repeat("c", 64), ExpiresAt: now.Add(time.Hour)}, "operator")
		if err != nil {
			t.Fatalf("replacement after expiry: %v", err)
		}
		if created.State != controlplane.ClusterImportPendingApproval {
			t.Fatalf("replacement state=%s", created.State)
		}
		script.done(t)
	})

	t.Run("revoke-logically-expired-is-rejected", func(t *testing.T) {
		approved := append([]driver.Value(nil), expiredRow...)
		approved[5] = "APPROVED"
		db, script := openScriptDB(t,
			scriptStep{kind: "begin"},
			scriptStep{kind: "query", contains: "FROM cluster_imports WHERE id=$1 FOR UPDATE", columns: cols, rows: [][]driver.Value{approved}},
			scriptStep{kind: "rollback"},
		)
		store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.RevokeClusterImport(context.Background(), "imp_old", 3, "operator")
		if !errors.Is(err, controlplane.ErrInvalidTransition) {
			t.Fatalf("postgres revoked logically-expired import: %v", err)
		}
		script.done(t)
	})
}

func TestPostgresClaimClusterImportRejectsInvalidPhysicalIdentityBeforeDatabaseMutation(t *testing.T) {
	db, script := openScriptDB(t)
	store, err := NewPostgresStoreWith(db, fixedPGTime, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.ClaimClusterImport(context.Background(), "imp_fixed", "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "   ", "0.0.207"); !errors.Is(err, controlplane.ErrValidation) {
		t.Fatalf("postgres accepted empty physical cluster UID: %v", err)
	}
	if _, _, err = store.ClaimClusterImport(context.Background(), "imp_fixed", "sha256:"+strings.Repeat("a", 64), "not-a-digest", "uid-valid", "0.0.207"); !errors.Is(err, controlplane.ErrValidation) {
		t.Fatalf("postgres accepted malformed agent credential digest: %v", err)
	}
	script.done(t)
}

func TestPostgresStoreOwnsClusterIdentityContinuity(t *testing.T) {
	now := fixedPGTime()
	token := "sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	clusterColumns := strings.Split(managedClusterColumns, ",")
	clusterRow := []driver.Value{
		"clu_fixed", int64(1), "prj_fixed", "imp_fixed", "prod", "Prod", "cluster-uid-1",
		"CONNECTED", "rke2", "v1.33.2+rke2r1", "0.0.205", now, now, now,
		[]byte(`{}`), []byte(`[]`), digest, "", "", "", nil, "", now, now,
	}

	t.Run("inventory-mismatch", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "begin"},
			scriptStep{kind: "query", contains: "SELECT ci.agent_token_digest FROM cluster_imports", columns: []string{"agent_token_digest"}, rows: [][]driver.Value{{token}}},
			scriptStep{kind: "query", contains: "FROM managed_clusters WHERE id=$1", columns: clusterColumns, rows: [][]driver.Value{clusterRow}},
			scriptStep{kind: "rollback"},
		)
		store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = store.UpsertClusterInventory(context.Background(), "clu_fixed", token, "different-cluster-uid", controlplane.ClusterInventory{ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2"})
		if !errors.Is(err, controlplane.ErrValidation) {
			t.Fatalf("postgres accepted inventory from a different physical cluster: %v", err)
		}
		script.done(t)
	})

	t.Run("legacy-heartbeat-does-not-refresh", func(t *testing.T) {
		db, script := openScriptDB(t,
			scriptStep{kind: "begin"},
			scriptStep{kind: "query", contains: "SELECT ci.agent_token_digest FROM cluster_imports", columns: []string{"agent_token_digest"}, rows: [][]driver.Value{{token}}},
			scriptStep{kind: "query", contains: "FROM managed_clusters WHERE id=$1", columns: clusterColumns, rows: [][]driver.Value{clusterRow}},
			scriptStep{kind: "commit"},
		)
		store, err := NewPostgresStoreWith(db, func() time.Time { return now.Add(time.Minute) }, fixedPGID)
		if err != nil {
			t.Fatal(err)
		}
		cluster, err := store.HeartbeatCluster(context.Background(), "clu_fixed", token, "", "legacy-agent")
		if err != nil {
			t.Fatal(err)
		}
		if cluster.LastSeenAt == nil || !cluster.LastSeenAt.Equal(now) {
			t.Fatalf("legacy heartbeat refreshed PostgreSQL liveness: got=%v want=%v", cluster.LastSeenAt, now)
		}
		script.done(t)
	})
}

func TestPostgresInventoryCannotSelfAuthorizeMutationRBACBeforeServerIssuance(t *testing.T) {
	now := fixedPGTime()
	token := "sha256:" + strings.Repeat("a", 64)
	clusterColumns := strings.Split(managedClusterColumns, ",")
	clusterRow := []driver.Value{
		"clu_fixed", int64(1), "prj_fixed", "imp_fixed", "prod", "Prod", "cluster-uid-1",
		"CONNECTED", "rke2", "v1.33.2+rke2r1", "0.0.208", now, now, now,
		[]byte(`{}`), []byte(`[]`), "sha256:" + strings.Repeat("b", 64), "", "", "", nil, "", now, now,
	}
	importColumns := []string{"id", "revision", "project_id", "name", "display_name", "state", "token_digest", "agent_token_digest", "agent_service_account", "expires_at", "approved_at", "claimed_at", "cluster_id", "requested_by", "approved_by", "created_at", "updated_at"}
	importRow := []driver.Value{
		"imp_fixed", int64(3), "prj_fixed", "prod", "Prod", string(controlplane.ClusterImportClaimed),
		"sha256:" + strings.Repeat("c", 64), token, controlplane.FleetAgentServiceAccountName("imp_fixed"), now.Add(time.Hour), now, now, "clu_fixed", "operator", "approver", now, now,
	}
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "SELECT ci.agent_token_digest FROM cluster_imports", columns: []string{"agent_token_digest"}, rows: [][]driver.Value{{token}}},
		scriptStep{kind: "query", contains: "FROM managed_clusters WHERE id=$1 FOR UPDATE", columns: clusterColumns, rows: [][]driver.Value{clusterRow}},
		scriptStep{kind: "query", contains: "FROM cluster_imports WHERE id=$1", columns: importColumns, rows: [][]driver.Value{importRow}},
		scriptStep{kind: "exec", contains: "INSERT INTO cluster_inventory_snapshots"},
		scriptStep{kind: "exec", contains: "UPDATE managed_clusters SET revision"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	cluster, stored, err := store.UpsertClusterInventory(context.Background(), "clu_fixed", token, "cluster-uid-1", controlplane.ClusterInventory{
		ObservedAt: now, Distribution: "rke2", KubernetesVersion: "v1.33.2+rke2r1",
		Capabilities: []string{controlplane.TargetEnrollmentPrincipalIsolatedCapability, controlplane.TargetMutationRBACActiveCapability, controlplane.TargetMutationRBACActivationIssuedCapability, "controlled-baseline-deployment"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if controlplane.ClusterHasCapability(cluster, controlplane.TargetMutationRBACActiveCapability) || controlplane.ClusterHasCapability(cluster, controlplane.TargetMutationRBACActivationIssuedCapability) || controlplane.ClusterTaskAdmitted(cluster) {
		t.Fatalf("postgres accepted agent-created mutation authority: cluster=%v inventory=%v", cluster.Capabilities, stored.Capabilities)
	}
	script.done(t)
}

func TestPostgresInventoryDriftInvalidatesDigestBoundMutationIssuance(t *testing.T) {
	now := fixedPGTime()
	token := "sha256:" + strings.Repeat("a", 64)
	issued := "sha256:" + strings.Repeat("d", 64)
	clusterColumns := strings.Split(managedClusterColumns, ",")
	clusterRow := []driver.Value{
		"clu_fixed", int64(9), "prj_fixed", "imp_fixed", "prod", "Prod", "cluster-uid-1",
		"CONNECTED", "rke2", "v1.33.2+rke2r1", "0.0.208", now, now, now,
		[]byte(`{}`), []byte(`["controlled-baseline-deployment","target-cluster-uid-attested","target-enrollment-principal-isolated","target-mutation-rbac-active","target-mutation-rbac-activation-issued"]`),
		"sha256:" + strings.Repeat("e", 64), issued, issued, "", nil, "", now, now,
	}
	importColumns := []string{"id", "revision", "project_id", "name", "display_name", "state", "token_digest", "agent_token_digest", "agent_service_account", "expires_at", "approved_at", "claimed_at", "cluster_id", "requested_by", "approved_by", "created_at", "updated_at"}
	importRow := []driver.Value{
		"imp_fixed", int64(3), "prj_fixed", "prod", "Prod", string(controlplane.ClusterImportClaimed),
		"sha256:" + strings.Repeat("c", 64), token, controlplane.FleetAgentServiceAccountName("imp_fixed"), now.Add(time.Hour), now, now, "clu_fixed", "operator", "approver", now, now,
	}
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "SELECT ci.agent_token_digest FROM cluster_imports", columns: []string{"agent_token_digest"}, rows: [][]driver.Value{{token}}},
		scriptStep{kind: "query", contains: "FROM managed_clusters WHERE id=$1 FOR UPDATE", columns: clusterColumns, rows: [][]driver.Value{clusterRow}},
		scriptStep{kind: "query", contains: "FROM cluster_imports WHERE id=$1", columns: importColumns, rows: [][]driver.Value{importRow}},
		scriptStep{kind: "exec", contains: "INSERT INTO cluster_inventory_snapshots"},
		scriptStep{kind: "exec", contains: "UPDATE managed_clusters SET revision"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now.Add(time.Minute) }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err := store.UpsertClusterInventory(context.Background(), "clu_fixed", token, "cluster-uid-1", controlplane.ClusterInventory{
		ObservedAt: now.Add(time.Minute), Distribution: "rke2", KubernetesVersion: "v1.33.3+rke2r1",
		Capabilities: []string{controlplane.TargetEnrollmentPrincipalIsolatedCapability, controlplane.TargetMutationRBACActiveCapability, "controlled-baseline-deployment"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cluster.MutationRBACBasisDigest == issued || cluster.MutationRBACIssuedForDigest != "" || controlplane.ClusterHasCapability(cluster, controlplane.TargetMutationRBACActivationIssuedCapability) || controlplane.ClusterHasCapability(cluster, controlplane.TargetMutationRBACActiveCapability) || controlplane.ClusterTaskAdmitted(cluster) {
		t.Fatalf("postgres retained stale digest-bound mutation authority after inventory drift: %+v", cluster)
	}
	script.done(t)
}

func TestPostgresMutationRBACActivationIssuanceIsServerOwned(t *testing.T) {
	now := fixedPGTime()
	clusterColumns := strings.Split(managedClusterColumns, ",")
	caps := []byte(`["target-cluster-uid-attested","target-enrollment-principal-isolated","target-read-only-admission"]`)
	clusterRow := []driver.Value{
		"clu_fixed", int64(7), "prj_fixed", "imp_fixed", "prod", "Prod", "cluster-uid-1",
		"CONNECTED", "rke2", "v1.33.2+rke2r1", "0.0.208", now, now, now,
		[]byte(`{}`), caps, "sha256:" + strings.Repeat("d", 64), "sha256:" + strings.Repeat("d", 64), "", "", nil, "", now, now,
	}
	importColumns := []string{"id", "revision", "project_id", "name", "display_name", "state", "token_digest", "agent_token_digest", "agent_service_account", "expires_at", "approved_at", "claimed_at", "cluster_id", "requested_by", "approved_by", "created_at", "updated_at"}
	importRow := []driver.Value{
		"imp_fixed", int64(3), "prj_fixed", "prod", "Prod", string(controlplane.ClusterImportClaimed),
		"sha256:" + strings.Repeat("c", 64), "sha256:" + strings.Repeat("a", 64), controlplane.FleetAgentServiceAccountName("imp_fixed"), now.Add(time.Hour), now, now, "clu_fixed", "operator", "approver", now, now,
	}
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM managed_clusters WHERE id=$1 FOR UPDATE", columns: clusterColumns, rows: [][]driver.Value{clusterRow}},
		scriptStep{kind: "query", contains: "FROM cluster_imports WHERE id=$1", columns: importColumns, rows: [][]driver.Value{importRow}},
		scriptStep{kind: "query", contains: "FROM managed_clusters WHERE external_uid=$1 AND connection_state='REVOKED'", columns: clusterColumns, rows: nil},
		scriptStep{kind: "exec", contains: "UPDATE managed_clusters SET revision"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	cluster, imp, err := store.AuthorizeClusterMutationRBACActivation(context.Background(), "clu_fixed", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if imp.ID != "imp_fixed" || !controlplane.ClusterHasCapability(cluster, controlplane.TargetMutationRBACActivationIssuedCapability) || controlplane.ClusterHasCapability(cluster, controlplane.TargetMutationRBACActiveCapability) {
		t.Fatalf("postgres issuance authority invalid: cluster=%v import=%+v", cluster.Capabilities, imp)
	}
	script.done(t)
}

func TestPostgresInventoryRejectsStaleObservationBeforeAuthorityMutation(t *testing.T) {
	now := fixedPGTime()
	token := "sha256:" + strings.Repeat("a", 64)
	clusterColumns := strings.Split(managedClusterColumns, ",")
	clusterRow := []driver.Value{
		"clu_fixed", int64(1), "prj_fixed", "imp_fixed", "prod", "Prod", "cluster-uid-1",
		"CONNECTED", "rke2", "v1.33.2+rke2r1", "0.0.214", now, now, nil,
		[]byte(`{}`), []byte(`[]`), "sha256:" + strings.Repeat("b", 64), "", "", "", nil, "", now, now,
	}
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "SELECT ci.agent_token_digest FROM cluster_imports", columns: []string{"agent_token_digest"}, rows: [][]driver.Value{{token}}},
		scriptStep{kind: "query", contains: "FROM managed_clusters WHERE id=$1 FOR UPDATE", columns: clusterColumns, rows: [][]driver.Value{clusterRow}},
		scriptStep{kind: "rollback"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.UpsertClusterInventory(context.Background(), "clu_fixed", token, "cluster-uid-1", controlplane.ClusterInventory{
		ObservedAt:        now.Add(-(controlplane.ClusterInventoryAuthorityFreshness + time.Second)),
		Distribution:      "rke2",
		KubernetesVersion: "v1.33.2+rke2r1",
	})
	if !errors.Is(err, controlplane.ErrPrerequisite) {
		t.Fatalf("postgres accepted stale observation as fresh inventory authority: %v", err)
	}
	script.done(t)
}

func TestPostgresFinalizeAIExecutionCommitsRunAndClaimInOneTransaction(t *testing.T) {
	now := fixedPGTime()
	requestDigest := "sha256:" + strings.Repeat("b", 64)
	output := json.RawMessage(`{"classification":"environment"}`)
	outputDigest, err := controlplane.AIRunOutputDigest(output)
	if err != nil {
		t.Fatal(err)
	}
	claimRow := []driver.Value{"aic_existing", "project-1", int64(1), "operator-diagnosis", "ai-key", requestDigest, "DISPATCHED", "", "", "operator", now, now}
	db, script := openScriptDB(t,
		scriptStep{kind: "begin"},
		scriptStep{kind: "query", contains: "FROM ai_execution_claims WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE", columns: strings.Split(aiExecutionColumns, ","), rows: [][]driver.Value{claimRow}},
		scriptStep{kind: "query", contains: "FROM ai_runs WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE", columns: strings.Split(aiRunColumns, ",")},
		scriptStep{kind: "query", contains: "SELECT EXISTS(SELECT 1 FROM projects", columns: []string{"exists"}, rows: [][]driver.Value{{true}}},
		scriptStep{kind: "query", contains: "SELECT project_id FROM operations", columns: []string{"project_id"}, rows: [][]driver.Value{{"project-1"}}},
		scriptStep{kind: "exec", contains: "INSERT INTO ai_runs"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "exec", contains: "INSERT INTO outbox_events"},
		scriptStep{kind: "exec", contains: "UPDATE ai_execution_claims SET revision=$3,state='COMPLETED'"},
		scriptStep{kind: "exec", contains: "INSERT INTO audit_events"},
		scriptStep{kind: "commit"},
	)
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	run := controlplane.AIRun{ProjectID: "project-1", Purpose: "operator-diagnosis", Provider: "openai-responses", Model: "test", PromptID: "operator.failure-diagnosis.v1", PromptDigest: requestDigest, ContextDigest: requestDigest, OutputDigest: outputDigest, Output: output, LinkedResourceType: "operation", LinkedResourceID: "op-1", IdempotencyKey: "ai-key", RequestDigest: requestDigest, AdvisoryOnly: true}
	created, replay, claim, err := store.FinalizeAIExecution(context.Background(), run, "operator")
	if err != nil || replay || created.ID != "air_fixed" || claim.State != controlplane.AIExecutionCompleted || claim.AIRunID != created.ID {
		t.Fatalf("run=%+v replay=%v claim=%+v err=%v", created, replay, claim, err)
	}
	script.done(t)
}

func TestPostgresControlPlaneAttentionScopesBeforeLimit(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t, scriptStep{
		kind:     "query",
		contains: "WITH selected_projects AS (",
		columns:  []string{"kind", "id", "project_id", "display_name", "state", "message", "page", "updated_at"},
		rows:     [][]driver.Value{{"tenant", "tenant-failed", "prj_own", "Tenant Failed", "FAILED", "boom", "tenants", now}},
	})
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	items, err := store.ControlPlaneAttention(context.Background(), []string{"prj_own", "prj_own"}, false, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "tenant-failed" || items[0].ProjectID != "prj_own" {
		t.Fatalf("unexpected attention items: %#v", items)
	}
	script.done(t)
}

func TestPostgresOperatorCollectionCursorAppliesBeforeLimit(t *testing.T) {
	now := fixedPGTime()
	db, script := openScriptDB(t, scriptStep{
		kind:     "query",
		contains: "FROM managed_clusters WHERE 1=1 AND (updated_at < $1 OR (updated_at = $1 AND id < $2)) ORDER BY updated_at DESC,id DESC LIMIT $3",
		columns:  []string{"id"},
	})
	store, err := NewPostgresStoreWith(db, func() time.Time { return now }, fixedPGID)
	if err != nil {
		t.Fatal(err)
	}
	cursor := &controlplane.CollectionCursor{UpdatedAt: now.Add(-time.Minute), ID: "cls_cursor"}
	values, err := store.ListManagedClustersPage(context.Background(), nil, true, cursor, 101)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 0 {
		t.Fatalf("unexpected values: %#v", values)
	}
	script.done(t)
}
