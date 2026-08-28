# PostgreSQL runtime certification

This runbook is retained because PostgreSQL is the production control-plane authority and live database certification cannot be replaced by static/unit checks.

`Contract PASS != Runtime PASS` and `BLOCKED != PASS`.

`scripts/postgresql_runtime_certify.py` returns:

- `0 / PASS` only after all required checks for the selected mode pass;
- `1 / FAIL` when prerequisites are present but an invariant fails;
- `2 / BLOCKED` when live PostgreSQL/restart/backup prerequisites are unavailable.

Linux CGO builds include the built-in `4so-libpq` database/sql adapter and require the system PostgreSQL client headers/library at build time.

## Contract-only check

```bash
python3 scripts/postgresql_runtime_certify.py \
  --contract-only \
  --evidence /tmp/postgresql-runtime-contract.json
```

Contract-only evidence never sets `runtimeCertified=true`.

## Live disposable-database certification

Use only a disposable database/profile. Inject credentials through an approved secret mechanism rather than committing or logging them.

```bash
export ALLOW_DESTRUCTIVE_POSTGRES_CERTIFICATION=1
export POSTGRES_CERT_DSN='postgresql://certifier:***@db.example/platform_cert?sslmode=verify-full'
export POSTGRES_CERT_ADMIN_DSN='postgresql://admin:***@db.example/postgres?sslmode=verify-full'
export POSTGRES_CERT_RESTART_COMMAND='/approved/runbook/restart-postgresql'

python3 scripts/postgresql_runtime_certify.py \
  --evidence /secure/evidence/postgresql-runtime-certification.json
```

The live matrix verifies supported PostgreSQL version/TLS admission, fresh migrations, transactional authority invariants, revision/idempotency concurrency, leasing/fencing, append-only audit/evidence protections, actual PostgreSQL restart, backup/restore and post-restore invariant re-checks. The generated evidence redacts DSN secrets, but the command environment still requires controlled secret injection.
