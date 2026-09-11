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


## Phase-C Lab-owned M03

For the canonical `production-ha` Lab path, do **not** provide an arbitrary external PostgreSQL DSN. `scripts/lab_runner.py run` executes M03 only after the same run has completed M02 HA recovery, and binds certification to that exact installed CloudNativePG `platform-postgresql` cluster.

The runner discovers the current CNPG primary, RW service ClusterIP and the operator-reported server CA through strict root SSH to the management primary. It creates a unique ephemeral `pf_cert_<id>` role/database inside that runtime, keeps the generated password private to the current process, writes only the public CA certificate into the run state directory, and reaches PostgreSQL through a strict local SSH tunnel with `sslmode=verify-full`. The certifier performs fresh/replay migrations, authority and concurrency checks, an actual primary-pod restart/failover with postmaster-identity verification, backup/restore and post-restore immutable-invariant checks. The runner then requires full three-node PostgreSQL/API recovery.

Cleanup is part of PASS: every database owned by the unique certifier identity is dropped and then the role is removed. A cleanup failure makes M03 fail. The private bootstrap stage explicitly strips `M03_PASSWORD` and CA payloads from public stage output, and the sealed certifier evidence is independently rejected if it contains an unredacted DSN credential or an invalid digest. Missing local PostgreSQL client tools make `production-ha` preflight `BLOCKED`.

M03 PASS is row-level runtime evidence only. It does not infer Source Semantics, Generated/Installed Runtime Semantics, Runtime-Realism Negative Controls, or the independent Exact-SHA Physical Runtime release gate as a whole.
