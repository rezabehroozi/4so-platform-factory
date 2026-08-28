package persistence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/migrations"
)

// migrationAdvisoryLockKey serializes the complete migration session across
// concurrently starting platform-api replicas. Runtime migration startup holds
// a session-level advisory lock on one dedicated sql.Conn from compatibility
// admission through final verification, then explicitly unlocks it before the
// connection returns to the pool. PostgreSQL releases the lock automatically if
// the process/connection dies; failed explicit unlock marks the connection bad.
const migrationAdvisoryLockKey int64 = 3770437216469231943

const (
	migrationSchemaLockTimeout = 5 * time.Second
	migrationStatementTimeout  = 5 * time.Minute
)

type MigrationMode string

const (
	MigrationModeRolling  MigrationMode = "rolling"
	MigrationModeQuiesced MigrationMode = "quiesced"
)

func ParseMigrationMode(raw string) (MigrationMode, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return MigrationModeRolling, nil
	}
	switch MigrationMode(raw) {
	case MigrationModeRolling, MigrationModeQuiesced:
		return MigrationMode(raw), nil
	default:
		return "", fmt.Errorf("invalid PostgreSQL migration mode %q: expected rolling or quiesced", raw)
	}
}

func ParseQuiescedMigrationApprovals(raw string) (map[int64]struct{}, error) {
	out := map[int64]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		version, err := strconv.ParseInt(part, 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid quiesced migration approval %q: expected positive migration versions", part)
		}
		out[version] = struct{}{}
	}
	return out, nil
}

// CheckMigrationCompatibility refuses to cross a migration that is known to be
// unsafe for mixed old/new application writers during a rolling deployment.
// Fresh databases are exempt because no old application replica can be writing.
// Quiesced mode is an explicit operator assertion that old writers have been
// removed before schema mutation begins.
func CheckMigrationCompatibility(ctx context.Context, db *sql.DB, mode MigrationMode, quiescedApprovals map[int64]struct{}) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	all, err := migrations.All()
	if err != nil {
		return err
	}
	return checkMigrationCompatibilityAuthority(ctx, db, all, mode, quiescedApprovals)
}

type migrationQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func checkMigrationCompatibilityAuthority(ctx context.Context, q migrationQueryRower, all []migrations.Migration, mode MigrationMode, quiescedApprovals map[int64]struct{}) error {
	if mode != MigrationModeRolling && mode != MigrationModeQuiesced {
		return fmt.Errorf("invalid PostgreSQL migration mode %q", mode)
	}
	if len(all) == 0 {
		return fmt.Errorf("no embedded PostgreSQL migrations are available")
	}
	var relation sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT to_regclass('public.schema_migrations')`).Scan(&relation); err != nil {
		return fmt.Errorf("inspect PostgreSQL migration authority: %w", err)
	}
	if !relation.Valid || strings.TrimSpace(relation.String) == "" {
		return nil
	}
	var maxVersion, appliedCount int64
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0), COUNT(*) FROM schema_migrations`).Scan(&maxVersion, &appliedCount); err != nil {
		return fmt.Errorf("inspect applied PostgreSQL migrations: %w", err)
	}
	if appliedCount == 0 {
		return nil
	}
	latestEmbeddedVersion := all[len(all)-1].Version
	if maxVersion > latestEmbeddedVersion {
		return fmt.Errorf("database schema is newer than this platform-api binary: database migration %d is applied but this binary only knows through migration %d; do not roll back application binaries across an already-applied schema boundary", maxVersion, latestEmbeddedVersion)
	}
	// Migration versions are a monotonic authority starting at 1. A non-empty
	// schema_migrations table must therefore be an exact contiguous prefix of
	// the migrations embedded in this binary. Refuse gaps/extra rows before any
	// pending mutation: applying an older missing migration after later schema
	// changes is not a valid recovery strategy and can corrupt upgraded state.
	if appliedCount != maxVersion {
		return fmt.Errorf("PostgreSQL migration history is not a contiguous prefix: max applied version=%d applied rows=%d; restore a consistent schema_migrations authority before startup", maxVersion, appliedCount)
	}
	for _, migration := range all {
		if migration.Version <= maxVersion {
			continue
		}
		if migration.Compatibility == migrations.CompatibilityQuiescedRequired {
			if mode == MigrationModeQuiesced {
				if _, approved := quiescedApprovals[migration.Version]; approved {
					continue
				}
				return fmt.Errorf("quiesced migration blocked before schema mutation: pending migration %d (%s) is not explicitly approved; after stopping old platform-api writers set PLATFORM_FACTORY_POSTGRES_QUIESCED_MIGRATIONS to include %d", migration.Version, migration.Name, migration.Version)
			}
			return fmt.Errorf("rolling migration blocked before schema mutation: pending migration %d (%s) requires quiesced mode: %s; stop old platform-api writers, set PLATFORM_FACTORY_POSTGRES_MIGRATION_MODE=quiesced and explicitly approve migration %d with PLATFORM_FACTORY_POSTGRES_QUIESCED_MIGRATIONS", migration.Version, migration.Name, migration.CompatibilityReason, migration.Version)
		}
	}
	return nil
}

func postgresTimeoutSetting(d time.Duration) string {
	// PostgreSQL GUC time values accept explicit unit suffixes. Milliseconds are
	// used instead of Go's Duration.String() so values like "5m0s" never depend
	// on PostgreSQL accepting Go-specific duration syntax.
	return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
}

func acquireMigrationSessionAuthority(ctx context.Context, conn *sql.Conn) (func() error, error) {
	if conn == nil {
		return nil, fmt.Errorf("PostgreSQL migration connection is nil")
	}
	var lockResult any
	if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey).Scan(&lockResult); err != nil {
		return nil, fmt.Errorf("acquire PostgreSQL migration session authority: %w", err)
	}
	released := false
	return func() error {
		if released {
			return nil
		}
		released = true
		// Release uses a detached bounded context so request/startup cancellation
		// cannot return a pooled connection while it still owns the session lock.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		err := conn.QueryRowContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey).Scan(&unlocked)
		if err == nil && unlocked {
			return nil
		}
		// A failed unlock must never return this physical session to the pool with
		// the authority still held. Mark it bad so database/sql discards it.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		if err != nil {
			return fmt.Errorf("release PostgreSQL migration session authority: %w", err)
		}
		return fmt.Errorf("release PostgreSQL migration session authority: pg_advisory_unlock returned false")
	}, nil
}

func beginMigrationTx(ctx context.Context, conn *sql.Conn) (*sql.Tx, error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin migration transaction: %w", err)
	}
	// The dedicated connection holds the session-wide migration authority.
	// Individual migration transactions only apply bounded live-schema waits.
	var appliedLockTimeout, appliedStatementTimeout string
	if err = tx.QueryRowContext(ctx, `SELECT set_config('lock_timeout',$1,true), set_config('statement_timeout',$2,true)`, postgresTimeoutSetting(migrationSchemaLockTimeout), postgresTimeoutSetting(migrationStatementTimeout)).Scan(&appliedLockTimeout, &appliedStatementTimeout); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("configure PostgreSQL migration lock safety: %w", err)
	}
	_ = appliedLockTimeout
	_ = appliedStatementTimeout
	return tx, nil
}

func migrationSQLForManagedTransaction(raw string) (string, error) {
	lines := strings.Split(raw, "\n")
	first, last := -1, -1
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			if first == -1 {
				first = i
			}
			last = i
		}
	}
	if first == -1 {
		return "", fmt.Errorf("migration SQL is empty")
	}
	isBegin := strings.EqualFold(strings.TrimSpace(lines[first]), "BEGIN;")
	isCommit := strings.EqualFold(strings.TrimSpace(lines[last]), "COMMIT;")
	if isBegin != isCommit {
		return "", fmt.Errorf("migration transaction wrapper must contain both leading BEGIN and trailing COMMIT")
	}
	if isBegin && isCommit {
		lines = append(append([]string{}, lines[:first]...), lines[first+1:last]...)
	}
	for _, line := range lines {
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch upper {
		case "BEGIN;", "COMMIT;", "ROLLBACK;":
			return "", fmt.Errorf("nested migration transaction control %q is not allowed", strings.TrimSpace(line))
		}
	}
	execSQL := strings.TrimSpace(strings.Join(lines, "\n"))
	if execSQL == "" {
		return "", fmt.Errorf("migration SQL is empty after removing managed transaction wrapper")
	}
	return execSQL, nil
}

// ApplyMigrationsWithCompatibility is the runtime migration entry point. It
// performs the schema-version/rollback fence and mixed-version admission while
// holding the same PostgreSQL advisory migration authority used for schema
// mutation. Keeping admission under that lock closes the check/apply race
// between concurrently starting binaries of different versions.
func ApplyMigrationsWithCompatibility(ctx context.Context, db *sql.DB, mode MigrationMode, quiescedApprovals map[int64]struct{}) (retErr error) {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	all, err := migrations.All()
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire PostgreSQL migration connection: %w", err)
	}
	defer conn.Close()
	releaseAuthority, err := acquireMigrationSessionAuthority(ctx, conn)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := releaseAuthority(); releaseErr != nil {
			retErr = errors.Join(retErr, releaseErr)
		}
	}()

	tx, err := beginMigrationTx(ctx, conn)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now(), checksum text NOT NULL)`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	if err = checkMigrationCompatibilityAuthority(ctx, tx, all, mode, quiescedApprovals); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migration compatibility admission: %w", err)
	}
	if err = applyEmbeddedMigrations(ctx, conn, all); err != nil {
		return err
	}
	// Verify the exact schema authority again before releasing the session-wide
	// lock. No concurrently starting runtime using this authority can interleave
	// a future-schema mutation between admission and this final fence.
	verifyTx, err := beginMigrationTx(ctx, conn)
	if err != nil {
		return err
	}
	if err = checkMigrationCompatibilityAuthority(ctx, verifyTx, all, mode, quiescedApprovals); err != nil {
		_ = verifyTx.Rollback()
		return fmt.Errorf("verify PostgreSQL migration authority after apply: %w", err)
	}
	if err = verifyTx.Commit(); err != nil {
		return fmt.Errorf("commit PostgreSQL migration authority verification: %w", err)
	}
	return nil
}

func applyEmbeddedMigrations(ctx context.Context, conn *sql.Conn, all []migrations.Migration) error {
	for _, m := range all {
		tx, err := beginMigrationTx(ctx, conn)
		if err != nil {
			return err
		}
		var checksum string
		err = tx.QueryRowContext(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, m.Version).Scan(&checksum)
		if err == nil {
			if checksum != m.Checksum {
				_ = tx.Rollback()
				return fmt.Errorf("migration %d checksum mismatch", m.Version)
			}
			if err = tx.Commit(); err != nil {
				return fmt.Errorf("commit migration %d verification: %w", m.Version, err)
			}
			continue
		}
		if err != sql.ErrNoRows {
			_ = tx.Rollback()
			return fmt.Errorf("read migration %d: %w", m.Version, err)
		}
		execSQL, normalizeErr := migrationSQLForManagedTransaction(m.SQL)
		if normalizeErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("normalize migration %d transaction boundary: %w", m.Version, normalizeErr)
		}
		if _, err = tx.ExecContext(ctx, execSQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", m.Version, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)`, m.Version, m.Checksum); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.Version, err)
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.Version, err)
		}
	}
	return nil
}

// ApplyMigrations applies the exact PostgreSQL schema shipped with the binary.
// The dedicated migration connection holds one PostgreSQL advisory session
// authority across bootstrap and every migration transaction so concurrently
// starting replicas cannot interleave separate migration sessions.
func ApplyMigrations(ctx context.Context, db *sql.DB) (retErr error) {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	all, err := migrations.All()
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire PostgreSQL migration connection: %w", err)
	}
	defer conn.Close()
	releaseAuthority, err := acquireMigrationSessionAuthority(ctx, conn)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := releaseAuthority(); releaseErr != nil {
			retErr = errors.Join(retErr, releaseErr)
		}
	}()
	tx, err := beginMigrationTx(ctx, conn)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now(), checksum text NOT NULL)`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit schema_migrations bootstrap: %w", err)
	}
	return applyEmbeddedMigrations(ctx, conn, all)
}
