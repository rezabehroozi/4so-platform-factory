#!/usr/bin/env python3
"""Run evidence-bearing PostgreSQL authority certification using official CLI tools.

This harness never reports PASS when PostgreSQL, restart control, or backup/restore
prerequisites are missing. It uses an isolated schema and requires an explicitly
approved disposable certification database.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "certification" / "postgresql-runtime-profile.json"
MIGRATIONS_DIR = ROOT / "migrations"
POSTMASTER_IDENTITY_SQL = "SELECT concat_ws('|', coalesce(inet_server_addr()::text,'local'), coalesce(inet_server_port()::text,'local'), pg_postmaster_start_time()::text)"
AI_RUN_POSTGRES_DURABILITY_AUTHORITY = "AI_RUN_POSTGRES_DURABILITY_RUNTIME_AUTHORITY_V1"
M03_EXACT_RELEASE_EVIDENCE_AUTHORITY = "LAB_M03_EXACT_RELEASE_EVIDENCE_AUTHORITY_V1"
AI_RUN_POSTGRES_MANDATORY_CHECKS = (
    "ai-run-atomic-result-commit",
    "ai-run-post-restart-durability",
    "ai-run-post-restore-durability",
)


class CertificationError(RuntimeError):
    pass


@dataclasses.dataclass
class Check:
    name: str
    status: str
    detail: str
    duration_ms: int = 0


def schema_identity_guard_sql(schema: str, expected_oid: str) -> str:
    value = str(expected_oid).strip()
    if not value:
        return ""
    if not value.isdigit() or int(value) <= 0:
        raise CertificationError(f"invalid certification schema OID: {value}")
    schema_literal = schema.replace("'", "''")
    return (
        "DO $$ BEGIN "
        f"IF coalesce((SELECT oid::text FROM pg_catalog.pg_namespace WHERE nspname='{schema_literal}'),'') <> '{value}' "
        "THEN RAISE EXCEPTION 'certification schema identity changed'; END IF; "
        "END $$; "
    )


class Runner:
    def __init__(self, dsn: str, schema: str, timeout: int = 60):
        self.dsn, self.env = subprocess_postgres_connection(dsn, os.environ)
        self.schema = schema
        self.timeout = timeout
        self.expected_schema_oid: str | None = None
        self.env["PGOPTIONS"] = f"-c search_path={schema}"

    def bind_schema_oid(self, oid: str) -> None:
        value = str(oid).strip()
        if not value.isdigit() or int(value) <= 0:
            raise CertificationError(f"invalid certification schema OID: {value or 'empty'}")
        self.expected_schema_oid = value

    def schema_identity_guard(self) -> str:
        return schema_identity_guard_sql(self.schema, self.expected_schema_oid or "")

    def run(self, sql: str, *, tuples: bool = False, check: bool = True, dsn: str | None = None,
            env: dict[str, str] | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        command = ["psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1"]
        if tuples:
            command += ["--tuples-only", "--no-align"]
        guarded_sql = self.schema_identity_guard() + sql
        command_env = dict(env or self.env)
        command_dsn = self.dsn
        if dsn is not None:
            command_dsn, command_env = subprocess_postgres_connection(dsn, command_env)
        command += [command_dsn, "--command", guarded_sql]
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            env=command_env,
            timeout=timeout or self.timeout,
            check=False,
        )
        if check and result.returncode:
            raise CertificationError(redact_text(f"psql failed: {result.stderr.strip()}"))
        return result

    def file(self, path: Path) -> None:
        command = ["psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", self.dsn]
        guard = self.schema_identity_guard()
        if guard:
            command += ["--command", guard]
        command += ["--file", str(path)]
        result = subprocess.run(command, text=True, capture_output=True, env=self.env, timeout=self.timeout, check=False)
        if result.returncode:
            raise CertificationError(redact_text(f"migration {path.name} failed: {result.stderr.strip()}"))


def utcnow(*, reproducible: bool = False) -> str:
    source_date_epoch = os.getenv("SOURCE_DATE_EPOCH", "").strip() if reproducible else ""
    if source_date_epoch:
        try:
            value = dt.datetime.fromtimestamp(int(source_date_epoch), tz=dt.timezone.utc)
        except ValueError as exc:
            raise CertificationError("SOURCE_DATE_EPOCH must be an integer") from exc
        return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def canonical_json_digest(value) -> tuple[str, str]:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return raw, sha256_bytes(raw.encode())


def verify_ai_run_durable_pair(runner, *, run_id: str = "air-cert", claim_id: str = "aic-cert") -> str:
    row = runner.run(
        "SELECT c.state || '|' || c.ai_run_id || '|' || r.id || '|' || "
        "c.request_digest || '|' || r.request_digest || '|' || c.idempotency_key || '|' || "
        "r.idempotency_key || '|' || r.output_digest "
        "FROM ai_execution_claims c JOIN ai_runs r ON r.id=c.ai_run_id "
        f"WHERE c.id={sql_literal(claim_id)} AND r.id={sql_literal(run_id)}",
        tuples=True,
    ).stdout.strip()
    parts = row.split("|", 7)
    if len(parts) != 8:
        raise CertificationError(f"durable AI execution pair is missing or malformed: {row or 'empty'}")
    state, linked_run, persisted_run, claim_request, run_request, claim_key, run_key, output_digest = parts
    if state != "COMPLETED" or linked_run != run_id or persisted_run != run_id:
        raise CertificationError(f"durable AI execution claim is not terminally bound to {run_id}: {row}")
    if claim_request != run_request or claim_key != run_key:
        raise CertificationError("durable AI execution claim/run request authority diverged")
    output_text = runner.run(
        f"SELECT output::text FROM ai_runs WHERE id={sql_literal(run_id)}", tuples=True
    ).stdout.strip()
    try:
        output_value = json.loads(output_text)
    except json.JSONDecodeError as exc:
        raise CertificationError("durable AI run output is not valid JSON") from exc
    _, recomputed = canonical_json_digest(output_value)
    if output_digest != recomputed:
        raise CertificationError(
            f"durable AI run output digest mismatch expected={recomputed} actual={output_digest}"
        )
    return f"claim={claim_id} state=COMPLETED aiRun={run_id} outputDigest={output_digest}"




def subprocess_postgres_connection(dsn: str, base_env: dict[str, str] | None = None) -> tuple[str, dict[str, str]]:
    """Return a credential-free argv DSN plus child env for libpq tools.

    M03 runs on shared operator/lab hosts where process argv may be observable.
    Password material therefore never travels in psql/pg_dump/pg_restore/createdb/
    dropdb argv. URL-format DSNs are preserved semantically while credentials are
    moved to PGPASSWORD. Keyword DSNs must already keep password out of argv.
    """
    raw = str(dsn).strip()
    if not raw:
        raise CertificationError("PostgreSQL DSN is required")
    env = dict(base_env or os.environ)
    if raw.startswith(("postgres://", "postgresql://")):
        parsed = urlsplit(raw)
        password: str | None = None
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo, hostpart = netloc.rsplit("@", 1)
            if ":" in userinfo:
                userpart, passwordpart = userinfo.split(":", 1)
                password = unquote(passwordpart)
                netloc = userpart + "@" + hostpart
        clean_query: list[tuple[str, str]] = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() == "password":
                if password is not None and password != value:
                    raise CertificationError("PostgreSQL DSN contains conflicting password authorities")
                password = value
                continue
            clean_query.append((key, value))
        if password is not None:
            if "\x00" in password or "\r" in password or "\n" in password:
                raise CertificationError("PostgreSQL DSN password contains forbidden control characters")
            env["PGPASSWORD"] = password
        sanitized = urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(clean_query, doseq=True), ""))
        return sanitized, env
    if re.search(r"(?i)(?:^|\s)password\s*=", raw):
        raise CertificationError("password-bearing keyword PostgreSQL DSN is forbidden on process argv; use PGPASSWORD")
    return raw, env


def redact_dsn(dsn: str) -> str:
    if dsn.startswith(("postgres://", "postgresql://")):
        parsed = urlsplit(dsn)
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        user = parsed.username or ""
        auth = f"{user}:***@" if parsed.password is not None else (f"{user}@" if user else "")
        query = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            query.append((key, "***" if key.lower() == "password" else value))
        return urlunsplit((parsed.scheme, auth + host + port, parsed.path, urlencode(query, doseq=True, safe="*"), ""))
    return re.sub(r"(?i)(password\s*=\s*)[^\s]+", r"\1***", dsn)


def redact_text(text: str) -> str:
    text = re.sub(r"(?i)(password=)[^\s&]+", r"\1***", text)
    text = re.sub(r"(postgres(?:ql)?://[^:/\s]+:)[^@/\s]+@", r"\1***@", text)
    return text


def load_profile() -> dict:
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    required = {
        "supportedMajors", "minimumSecureMinor", "requiredClientTools", "requiredTLSMode",
        "securityBaselinePublishedAt", "securityBaselineMaxAgeDays", "securityBaselineSource",
        "mandatoryChecks", "certificationRules",
    }
    missing = required - set(profile)
    if missing:
        raise CertificationError(f"profile missing fields: {sorted(missing)}")
    return profile


def compare_version(actual: str, minimum: str) -> bool:
    def parts(value: str) -> tuple[int, ...]:
        return tuple(int(x) for x in re.findall(r"\d+", value)[:2])
    return parts(actual) >= parts(minimum)


def security_baseline_check(profile: dict, now: dt.datetime | None = None) -> str:
    raw_date = str(profile.get("securityBaselinePublishedAt", "")).strip()
    source = str(profile.get("securityBaselineSource", "")).strip()
    try:
        published = dt.datetime.strptime(raw_date, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise CertificationError("security baseline publication date must be YYYY-MM-DD") from exc
    try:
        max_age = int(profile.get("securityBaselineMaxAgeDays", 0))
    except (TypeError, ValueError) as exc:
        raise CertificationError("security baseline max age must be an integer") from exc
    if max_age <= 0:
        raise CertificationError("security baseline max age must be positive")
    if not source.startswith("https://"):
        raise CertificationError("security baseline source must be an HTTPS authority")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    age = (current.astimezone(dt.timezone.utc).date() - published.date()).days
    if age < 0:
        raise CertificationError("security baseline publication date is in the future")
    if age > max_age:
        raise CertificationError(f"security baseline expired: age={age}d max={max_age}d")
    return f"security baseline age={age}d max={max_age}d source={source}"


def configured_sslmode(dsn: str, env: dict[str, str] | None = None) -> str:
    if dsn.startswith(("postgres://", "postgresql://")):
        values = parse_qs(urlsplit(dsn).query).get("sslmode", [])
        if values:
            return values[-1].strip().lower()
    match = re.search(r"(?i)(?:^|\s)sslmode\s*=\s*([^\s]+)", dsn)
    if match:
        return match.group(1).strip("'\"").lower()
    return (env or os.environ).get("PGSSLMODE", "").strip().lower()


def verify_tls_session(runner, dsn: str, required_mode: str) -> str:
    mode = configured_sslmode(dsn, getattr(runner, "env", None))
    if mode != required_mode.lower():
        raise CertificationError(f"certification DSN must use sslmode={required_mode}; got {mode or 'unset'}")
    row = runner.run(
        "SELECT ssl::text || '|' || coalesce(version,'') || '|' || coalesce(cipher,'') FROM pg_stat_ssl WHERE pid=pg_backend_pid()",
        tuples=True,
    ).stdout.strip()
    parts = row.split("|", 2)
    if len(parts) != 3 or parts[0].lower() not in {"t", "true", "on"} or not parts[1] or not parts[2]:
        raise CertificationError(f"current certification session is not proven TLS: {row or 'no pg_stat_ssl row'}")
    return f"sslmode={required_mode} tls={parts[1]} cipher={parts[2]}"



def verify_schema_isolation(runner) -> str:
    row = runner.run(
        "SELECT coalesce(current_schema(),'') || '|' || coalesce(array_to_string(current_schemas(false), ','),'')",
        tuples=True,
    ).stdout.strip()
    parts = row.split("|", 1)
    if len(parts) != 2:
        raise CertificationError(f"could not prove certification schema isolation: {row or 'empty result'}")
    current, visible = parts[0].strip(), [item.strip() for item in parts[1].split(',') if item.strip()]
    if current != runner.schema or visible != [runner.schema]:
        raise CertificationError(
            f"certification session is not isolated to {runner.schema}: current_schema={current or 'none'} visible={visible}"
        )
    return f"current_schema={current} visible_search_path={','.join(visible)}"


def schema_oid(runner, schema: str | None = None) -> str:
    target = (schema or runner.schema).replace("'", "''")
    result = runner.run(
        f"SELECT coalesce((SELECT oid::text FROM pg_catalog.pg_namespace WHERE nspname='{target}'),'')",
        tuples=True,
    ).stdout.strip()
    if not result or not result.isdigit() or int(result) <= 0:
        raise CertificationError(f"could not bind certification schema identity for {schema or runner.schema}")
    return result


def database_oid(admin_dsn: str, database: str) -> str:
    target = database.replace("'", "''")
    admin_arg, admin_env = subprocess_postgres_connection(admin_dsn, os.environ)
    command = [
        "psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--tuples-only", "--no-align",
        admin_arg, "--command",
        f"SELECT coalesce((SELECT oid::text FROM pg_catalog.pg_database WHERE datname='{target}'),'')",
    ]
    result = subprocess.run(command, text=True, capture_output=True, env=admin_env, timeout=30, check=False)
    if result.returncode:
        raise CertificationError(redact_text(f"could not inspect restore database identity: {result.stderr.strip()}"))
    value = result.stdout.strip()
    if not value or not value.isdigit() or int(value) <= 0:
        raise CertificationError(f"restore database {database} has no durable database identity")
    return value


def require_database_oid(admin_dsn: str, database: str, expected_oid: str) -> None:
    actual = database_oid(admin_dsn, database)
    if actual != str(expected_oid):
        raise CertificationError(
            f"restore database identity changed for {database}: expected_oid={expected_oid} actual_oid={actual}"
        )


def create_restore_database(admin_dsn: str, database: str) -> str:
    admin_arg, admin_env = subprocess_postgres_connection(admin_dsn, os.environ)
    create = subprocess.run(
        ["createdb", "--maintenance-db", admin_arg, database],
        text=True, capture_output=True, env=admin_env, timeout=30, check=False,
    )
    if create.returncode:
        raise CertificationError(f"createdb failed without deleting any pre-existing database: {create.stderr.strip()}")
    return database_oid(admin_dsn, database)


def drop_owned_restore_database(admin_dsn: str, database: str, expected_oid: str) -> None:
    require_database_oid(admin_dsn, database, expected_oid)
    admin_arg, admin_env = subprocess_postgres_connection(admin_dsn, os.environ)
    result = subprocess.run(
        ["dropdb", "--maintenance-db", admin_arg, database],
        text=True, capture_output=True, env=admin_env, timeout=30, check=False,
    )
    if result.returncode:
        raise CertificationError("restored database cleanup failed: " + result.stderr.strip())


def require_schema_ready(ready: bool) -> None:
    if not ready:
        raise CertificationError(
            "isolated certification schema did not complete migration; refusing any fallback mutation against production authority"
        )

def database_dsn(dsn: str, database: str) -> str:
    parsed = urlsplit(dsn)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise CertificationError("backup/restore requires URL-format PostgreSQL DSN")
    return urlunsplit((parsed.scheme, parsed.netloc, "/" + database, parsed.query, ""))


def check_tools(names: list[str]) -> list[str]:
    return [name for name in names if shutil.which(name) is None]


def terminate_process_group(process: subprocess.Popen[str], grace_seconds: float = 2.0) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace_seconds
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=max(1.0, grace_seconds))
    except subprocess.TimeoutExpired:
        pass


def run_shell_command(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        terminate_process_group(process)
        stdout, stderr = process.communicate()
        raise CertificationError(f"command timed out after {timeout}s: {redact_text(command)}") from exc
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


def terminate_concurrent_workers(processes: list[subprocess.Popen[str]]) -> None:
    for worker in processes:
        terminate_process_group(worker)
    for worker in processes:
        try:
            worker.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            terminate_process_group(worker, grace_seconds=0.2)
            worker.communicate()


def run_concurrent(commands: list[list[str]], env: dict[str, str], timeout: int = 30) -> list[subprocess.CompletedProcess[str]]:
    processes: list[subprocess.Popen[str]] = []
    try:
        for cmd in commands:
            processes.append(
                subprocess.Popen(
                    cmd,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    start_new_session=True,
                )
            )
    except OSError as exc:
        terminate_concurrent_workers(processes)
        raise CertificationError("failed to start concurrent PostgreSQL check") from exc
    results = []
    deadline = time.monotonic() + timeout
    for process in processes:
        remaining = max(0.05, deadline - time.monotonic())
        try:
            stdout, stderr = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            terminate_concurrent_workers(processes)
            raise CertificationError("concurrent PostgreSQL check timed out") from exc
        results.append(subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr))
    return results


def run_restart_check(runner, restart_command: str, deadline_seconds: float = 90, poll_seconds: float = 2) -> str:
    before = runner.run(POSTMASTER_IDENTITY_SQL, tuples=True).stdout.strip()
    if not before:
        raise CertificationError("could not capture PostgreSQL postmaster identity before restart")
    result = run_shell_command(restart_command, 120)
    if result.returncode:
        raise CertificationError(f"restart command failed: {result.stderr.strip()}")
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        probe = runner.run(POSTMASTER_IDENTITY_SQL, tuples=True, check=False, timeout=5)
        if probe.returncode == 0:
            after = probe.stdout.strip()
            if after and after != before:
                count = runner.run("SELECT count(*) FROM organizations WHERE id='atomic-ok'", tuples=True).stdout.strip()
                if count != "1":
                    raise CertificationError("authority row missing after restart")
                return f"postmaster identity changed {before} -> {after}; durable authority row remained"
        time.sleep(poll_seconds)
    raise CertificationError("restart command completed but PostgreSQL postmaster identity did not change")


def cleanup_certification_artifacts(
    runner, admin_dsn: str, restored_database: str, backup_file: Path, keep_schema: bool,
    *, schema_created: bool, schema_oid_value: str, restored_database_created: bool, restored_database_oid: str,
) -> str:
    failures: list[str] = []
    if keep_schema:
        failures.append("--keep-schema is diagnostic mode and cannot produce runtime certification PASS")
    elif schema_created:
        try:
            if not schema_oid_value:
                raise CertificationError("created certification schema has no bound OID; refusing name-only cleanup")
            runner.bind_schema_oid(schema_oid_value)
            dropped = runner.run(f'DROP SCHEMA "{runner.schema}" CASCADE', check=False)
            if dropped.returncode != 0:
                failures.append("certification schema cleanup failed: " + dropped.stderr.strip())
            else:
                runner.expected_schema_oid = None
        except CertificationError as exc:
            failures.append(str(exc))
    if restored_database_created:
        try:
            if not restored_database_oid:
                raise CertificationError("created restore database has no bound OID; refusing name-only cleanup")
            drop_owned_restore_database(admin_dsn, restored_database, restored_database_oid)
        except CertificationError as exc:
            failures.append(str(exc))
    try:
        backup_file.unlink(missing_ok=True)
    except OSError as exc:
        failures.append(f"backup file cleanup failed: {exc}")
    if failures:
        raise CertificationError("; ".join(failures))
    return "owned certification schema, owned restored database and backup artifact removed"


def psql_command(
    dsn: str, sql: str, tuples: bool = True, *, schema: str = "", expected_schema_oid: str = "",
) -> list[str]:
    command = ["psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1"]
    if tuples:
        command += ["--tuples-only", "--no-align"]
    guarded_sql = schema_identity_guard_sql(schema, expected_schema_oid) + sql if expected_schema_oid else sql
    safe_dsn, _ = subprocess_postgres_connection(dsn, os.environ)
    return command + [safe_dsn, "--command", guarded_sql]


def _strict_json_object(raw: str, *, label: str) -> dict[str, object]:
    def pairs(values):
        out = {}
        for key, value in values:
            if key in out:
                raise CertificationError(f"{label} contains duplicate JSON key {key!r}")
            out[key] = value
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise CertificationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise CertificationError(f"{label} must be a JSON object")
    return value


def read_connection_json_stdin(stream) -> tuple[str, str]:
    max_bytes = 16 * 1024
    raw = stream.read(max_bytes + 1)
    if len(raw.encode("utf-8")) > max_bytes:
        raise CertificationError("PostgreSQL private connection stdin exceeds 16384-byte limit")
    value = _strict_json_object(raw, label="PostgreSQL private connection stdin")
    if set(value) != {"dsn", "adminDsn"}:
        raise CertificationError("PostgreSQL private connection stdin must contain exactly dsn and adminDsn")
    dsn = value.get("dsn")
    admin = value.get("adminDsn")
    if not isinstance(dsn, str) or not dsn.strip() or not isinstance(admin, str) or not admin.strip():
        raise CertificationError("PostgreSQL private connection stdin requires non-empty string dsn and adminDsn")
    return dsn.strip(), admin.strip()


def add_check(checks: list[Check], name: str, fn) -> None:
    start = time.monotonic()
    try:
        detail = fn() or "pass"
        status = "PASS"
    except CertificationError as exc:
        detail = str(exc)
        status = "FAIL"
    except Exception as exc:  # defensive boundary for evidence completeness
        detail = f"unexpected: {type(exc).__name__}: {exc}"
        status = "FAIL"
    checks.append(Check(name, status, redact_text(detail), int((time.monotonic() - start) * 1000)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default=os.getenv("POSTGRES_CERT_DSN", ""))
    parser.add_argument("--admin-dsn", default=os.getenv("POSTGRES_CERT_ADMIN_DSN", ""))
    parser.add_argument("--connection-json-stdin", action="store_true")
    parser.add_argument("--restart-command", default=os.getenv("POSTGRES_CERT_RESTART_COMMAND", ""))
    parser.add_argument("--evidence", default=str(ROOT / "evidence" / "postgresql-runtime-certification.json"))
    parser.add_argument("--release-artifact-digest", default=os.getenv("POSTGRES_CERT_RELEASE_ARTIFACT_DIGEST", ""))
    parser.add_argument("--contract-only", action="store_true")
    parser.add_argument("--keep-schema", action="store_true")
    args = parser.parse_args()
    if args.connection_json_stdin:
        if str(args.dsn).strip() or str(args.admin_dsn).strip():
            raise CertificationError("--connection-json-stdin cannot be combined with --dsn/--admin-dsn or POSTGRES_CERT_DSN/POSTGRES_CERT_ADMIN_DSN")
        args.dsn, args.admin_dsn = read_connection_json_stdin(sys.stdin)

    started = utcnow(reproducible=args.contract_only)
    profile = load_profile()
    profile_digest = sha256_file(PROFILE_PATH)
    migrations = sorted(MIGRATIONS_DIR.glob("*.sql"))
    migration_digests = {path.name: sha256_file(path) for path in migrations}
    checks: list[Check] = []
    schema = "pf_cert_" + secrets.token_hex(6)
    evidence_path = Path(args.evidence)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if args.contract_only:
        missing = check_tools(["python3"])
        checks.append(Check("contract-profile", "PASS" if not missing else "FAIL", profile_digest))
        checks.append(Check("contract-migrations", "PASS" if len(migrations) >= 2 else "FAIL", json.dumps(migration_digests, sort_keys=True)))
        add_check(checks, "security-baseline", lambda: security_baseline_check(profile))
        status = "PASS" if all(c.status == "PASS" for c in checks) else "FAIL"
        evidence = {
            "schemaVersion": 1,
            "mode": "contract-only",
            "status": status,
            "runtimeCertified": False,
            "aiRunPostgresDurabilityAuthority": AI_RUN_POSTGRES_DURABILITY_AUTHORITY,
            "aiRunPostgresDurabilityCertified": False,
            "startedAt": started,
            "finishedAt": utcnow(reproducible=True),
            "profileDigest": profile_digest,
            "migrationDigests": migration_digests,
            "checks": [dataclasses.asdict(c) for c in checks],
            "truth": "Contract validation is not PostgreSQL runtime certification."
        }
        evidence["evidenceDigest"] = sha256_bytes(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode())
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("POSTGRESQL_CERTIFICATION_CONTRACT_PASS", evidence_path)
        return 0 if status == "PASS" else 1

    prerequisites = []
    release_artifact_digest = str(args.release_artifact_digest).strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", release_artifact_digest):
        prerequisites.append("--release-artifact-digest must be the exact lowercase sha256 release digest")
    if os.getenv("ALLOW_DESTRUCTIVE_POSTGRES_CERTIFICATION") != "1":
        prerequisites.append("ALLOW_DESTRUCTIVE_POSTGRES_CERTIFICATION=1 is required")
    if not args.dsn:
        prerequisites.append("POSTGRES_CERT_DSN is required")
    missing_tools = check_tools(profile["requiredClientTools"])
    if missing_tools:
        prerequisites.append("missing tools: " + ", ".join(missing_tools))
    if not args.admin_dsn:
        prerequisites.append("POSTGRES_CERT_ADMIN_DSN is required for backup/restore")
    if not args.restart_command:
        prerequisites.append("POSTGRES_CERT_RESTART_COMMAND is required for restart evidence")

    if prerequisites:
        checks.append(Check("prerequisites", "BLOCKED", "; ".join(prerequisites)))
        evidence = {
            "schemaVersion": 2,
            "mode": "runtime",
            "status": "BLOCKED",
            "releaseEvidenceAuthority": M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,
            "releaseArtifactDigest": release_artifact_digest,
            "runtimeCertified": False,
            "aiRunPostgresDurabilityAuthority": AI_RUN_POSTGRES_DURABILITY_AUTHORITY,
            "aiRunPostgresDurabilityCertified": False,
            "startedAt": started,
            "finishedAt": utcnow(),
            "target": redact_dsn(args.dsn),
            "profileDigest": profile_digest,
            "migrationDigests": migration_digests,
            "checks": [dataclasses.asdict(c) for c in checks],
            "truth": "Missing prerequisites are blockers and never count as PASS."
        }
        evidence["evidenceDigest"] = sha256_bytes(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode())
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("POSTGRESQL_RUNTIME_CERTIFICATION_BLOCKED", evidence_path)
        return 2

    runner = Runner(args.dsn, schema)
    server_version = ""
    restored_database = "pf_restore_" + secrets.token_hex(5)
    backup_file = Path(tempfile.gettempdir()) / f"{schema}.dump"
    schema_ready = False
    schema_created = False
    schema_oid_value = ""
    restored_database_created = False
    restored_database_oid = ""

    def prerequisites_check():
        runner.run("SELECT 1")
        return "PostgreSQL reachable and required CLI tools available"
    add_check(checks, "prerequisites", prerequisites_check)

    add_check(checks, "security-baseline", lambda: security_baseline_check(profile))

    def version_check():
        nonlocal server_version
        server_version = runner.run("SHOW server_version", tuples=True).stdout.strip()
        major = int(server_version.split(".")[0])
        if major not in profile["supportedMajors"]:
            raise CertificationError(f"unsupported PostgreSQL major {major}: {server_version}")
        minimum = profile["minimumSecureMinor"][str(major)]
        if not compare_version(server_version, minimum):
            raise CertificationError(f"PostgreSQL {server_version} is below secure minimum {minimum}")
        return f"PostgreSQL {server_version} >= {minimum}"
    add_check(checks, "server-version", version_check)

    def tls_check():
        ssl = runner.run("SHOW ssl", tuples=True).stdout.strip().lower()
        if ssl != "on":
            raise CertificationError("PostgreSQL ssl must be on")
        return verify_tls_session(runner, args.dsn, profile["requiredTLSMode"])
    add_check(checks, "tls-policy", tls_check)

    def migration_fresh():
        nonlocal schema_ready, schema_created, schema_oid_value
        runner.run(f'CREATE SCHEMA "{schema}"')
        schema_created = True
        schema_oid_value = schema_oid(runner)
        runner.bind_schema_oid(schema_oid_value)
        before = verify_schema_isolation(runner)
        for migration in migrations:
            runner.file(migration)
        after = verify_schema_isolation(runner)
        schema_ready = True
        return (
            f"applied {len(migrations)} migrations in isolated schema {schema} "
            f"oid={schema_oid_value}; {before}; post-migration {after}"
        )
    add_check(checks, "migration-fresh", migration_fresh)

    def migration_replay():
        require_schema_ready(schema_ready)
        # The application migration runner is checksum-aware; direct SQL replay must fail safely
        # instead of silently creating divergent objects.
        result = runner.run(migrations[0].read_text(encoding="utf-8"), check=False)
        if result.returncode == 0:
            raise CertificationError("raw migration replay unexpectedly succeeded")
        return "duplicate raw migration rejected; checksum runner remains required"
    add_check(checks, "migration-replay", migration_replay)

    def schema_invariants():
        require_schema_ready(schema_ready)
        tables = runner.run("SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema()", tuples=True).stdout.strip()
        triggers = runner.run("SELECT count(*) FROM information_schema.triggers WHERE trigger_schema=current_schema()", tuples=True).stdout.strip()
        if int(tables) < 9 or int(triggers) < 6:
            raise CertificationError(f"insufficient schema objects: tables={tables}, triggers={triggers}")
        return f"tables={tables}, triggers={triggers}"
    add_check(checks, "schema-invariants", schema_invariants)

    def atomicity():
        require_schema_ready(schema_ready)
        failed = runner.run("BEGIN; INSERT INTO organizations(id,revision,name,display_name,created_at,updated_at) VALUES('atomic-fail',1,'atomic-fail','Atomic Fail',now(),now()); INSERT INTO audit_events(id,occurred_at,actor_id,action,resource_type,resource_id,resource_revision,metadata) VALUES('aud-fail',now(),'certifier','create','organization','atomic-fail',1,'{}'); SELECT 1/0; COMMIT;", check=False)
        if failed.returncode == 0:
            raise CertificationError("forced transaction failure unexpectedly succeeded")
        count = runner.run("SELECT count(*) FROM organizations WHERE id='atomic-fail'", tuples=True).stdout.strip()
        if count != "0":
            raise CertificationError("resource survived failed transaction")
        runner.run("BEGIN; INSERT INTO organizations(id,revision,name,display_name,created_at,updated_at) VALUES('atomic-ok',1,'atomic-ok','Atomic OK',now(),now()); INSERT INTO audit_events(id,occurred_at,actor_id,action,resource_type,resource_id,resource_revision,metadata) VALUES('aud-ok',now(),'certifier','create','organization','atomic-ok',1,'{}'); INSERT INTO outbox_events(id,revision,aggregate_type,aggregate_id,event_type,payload,available_at,created_at,updated_at) VALUES('evt-ok',1,'organization','atomic-ok','organization.created','{}',now(),now(),now()); COMMIT;")
        result = runner.run("SELECT (SELECT count(*) FROM organizations WHERE id='atomic-ok')::text || ':' || (SELECT count(*) FROM audit_events WHERE resource_id='atomic-ok')::text || ':' || (SELECT count(*) FROM outbox_events WHERE aggregate_id='atomic-ok')::text", tuples=True).stdout.strip()
        if result != "1:1:1":
            raise CertificationError(f"atomic success set incomplete: {result}")
        return result
    add_check(checks, "atomic-resource-audit-outbox", atomicity)

    def revision_contention():
        require_schema_ready(schema_ready)
        runner.run("INSERT INTO organizations(id,revision,name,display_name,created_at,updated_at) VALUES('revision-race',1,'revision-race','Revision Race',now(),now()) ON CONFLICT DO NOTHING")
        sql = "UPDATE organizations SET revision=revision+1,display_name='winner',updated_at=now() WHERE id='revision-race' AND revision=1 RETURNING revision;"
        results = run_concurrent([psql_command(args.dsn, sql, schema=schema, expected_schema_oid=schema_oid_value), psql_command(args.dsn, sql, schema=schema, expected_schema_oid=schema_oid_value)], runner.env)
        outputs = [r.stdout.strip() for r in results if r.returncode == 0]
        winners = sum(1 for output in outputs if output == "2")
        if winners != 1:
            raise CertificationError(f"expected exactly one revision winner, got {winners}: {outputs}")
        return "one winner, one stale writer rejected"
    add_check(checks, "optimistic-revision-contention", revision_contention)

    def idempotency_contention():
        require_schema_ready(schema_ready)
        runner.run("INSERT INTO projects(id,organization_id,revision,name,display_name,created_at,updated_at) VALUES('project-cert','atomic-ok',1,'project-cert','Project Cert',now(),now()) ON CONFLICT DO NOTHING")
        base = "INSERT INTO operations(id,project_id,revision,kind,target_ref,desired_revision,state,risk,idempotency_key,request_digest,actor_id,created_at,updated_at) VALUES(%s,'project-cert',1,'certify','target','rev','DRAFT','low','same-key','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','certifier',now(),now());"
        results = run_concurrent([
            psql_command(args.dsn, base % "'op-idem-a'", tuples=False, schema=schema, expected_schema_oid=schema_oid_value),
            psql_command(args.dsn, base % "'op-idem-b'", tuples=False, schema=schema, expected_schema_oid=schema_oid_value),
        ], runner.env)
        success = sum(1 for r in results if r.returncode == 0)
        if success != 1:
            raise CertificationError(f"expected one idempotency winner, got {success}")
        count = runner.run("SELECT count(*) FROM operations WHERE project_id='project-cert' AND idempotency_key='same-key'", tuples=True).stdout.strip()
        if count != "1":
            raise CertificationError(f"idempotency row count {count}")
        return "unique idempotency authority enforced under contention"
    add_check(checks, "idempotency-contention", idempotency_contention)

    def ai_run_atomic_result_commit():
        require_schema_ready(schema_ready)
        runner.run("INSERT INTO projects(id,organization_id,revision,name,display_name,created_at,updated_at) VALUES('project-cert','atomic-ok',1,'project-cert','Project Cert',now(),now()) ON CONFLICT DO NOTHING")
        request_digest = "sha256:" + "d" * 64
        prompt_digest = "sha256:" + "a" * 64
        context_digest = "sha256:" + "b" * 64
        output_raw, output_digest = canonical_json_digest({"classification": "environment"})

        rollback_sql = f"""BEGIN;
INSERT INTO ai_execution_claims(id,project_id,revision,purpose,idempotency_key,request_digest,state,ai_run_id,failure_code,requested_by,created_at,updated_at) VALUES('aic-rollback','project-cert',1,'operator-diagnosis','ai-cert-rollback',{sql_literal(request_digest)},'DISPATCHED','','','certifier',now(),now());
INSERT INTO ai_runs(id,project_id,revision,purpose,provider,model,prompt_id,prompt_digest,context_digest,output_digest,redaction_count,input_bytes,input_tokens,cached_tokens,output_tokens,output,linked_resource_type,linked_resource_id,requested_by,idempotency_key,request_digest,advisory_only,created_at,updated_at) VALUES('air-rollback','project-cert',1,'operator-diagnosis','runtime-certifier','cert-model','operator-diagnosis',{sql_literal(prompt_digest)},{sql_literal(context_digest)},{sql_literal(output_digest)},0,32,4,0,2,{sql_literal(output_raw)}::jsonb,'','','certifier','ai-cert-rollback',{sql_literal(request_digest)},true,now(),now());
SELECT 1/0;
UPDATE ai_execution_claims SET revision=2,state='COMPLETED',ai_run_id='air-rollback',updated_at=now() WHERE id='aic-rollback';
COMMIT;"""
        failed = runner.run(rollback_sql, check=False)
        if failed.returncode == 0:
            raise CertificationError("forced AI result transaction rollback unexpectedly succeeded")
        rollback_count = runner.run(
            "SELECT (SELECT count(*) FROM ai_execution_claims WHERE id='aic-rollback')::text || ':' || "
            "(SELECT count(*) FROM ai_runs WHERE id='air-rollback')::text", tuples=True
        ).stdout.strip()
        if rollback_count != "0:0":
            raise CertificationError(f"AI result transaction leaked split state after rollback: {rollback_count}")

        commit_sql = f"""BEGIN;
INSERT INTO ai_execution_claims(id,project_id,revision,purpose,idempotency_key,request_digest,state,ai_run_id,failure_code,requested_by,created_at,updated_at) VALUES('aic-cert','project-cert',1,'operator-diagnosis','ai-cert-main',{sql_literal(request_digest)},'DISPATCHED','','','certifier',now(),now());
INSERT INTO ai_runs(id,project_id,revision,purpose,provider,model,prompt_id,prompt_digest,context_digest,output_digest,redaction_count,input_bytes,input_tokens,cached_tokens,output_tokens,output,linked_resource_type,linked_resource_id,requested_by,idempotency_key,request_digest,advisory_only,created_at,updated_at) VALUES('air-cert','project-cert',1,'operator-diagnosis','runtime-certifier','cert-model','operator-diagnosis',{sql_literal(prompt_digest)},{sql_literal(context_digest)},{sql_literal(output_digest)},0,32,4,0,2,{sql_literal(output_raw)}::jsonb,'','','certifier','ai-cert-main',{sql_literal(request_digest)},true,now(),now());
INSERT INTO audit_events(id,occurred_at,actor_id,action,resource_type,resource_id,resource_revision,metadata) VALUES('aud-ai-cert',now(),'certifier','ai_run.created','aiRun','air-cert',1,'{{"projectId":"project-cert"}}'::jsonb);
INSERT INTO outbox_events(id,revision,aggregate_type,aggregate_id,event_type,payload,available_at,created_at,updated_at) VALUES('evt-ai-cert',1,'aiRun','air-cert','ai_run.created','{{}}'::jsonb,now(),now(),now());
UPDATE ai_execution_claims SET revision=2,state='COMPLETED',ai_run_id='air-cert',failure_code='',updated_at=now() WHERE id='aic-cert';
COMMIT;"""
        runner.run(commit_sql)
        detail = verify_ai_run_durable_pair(runner)
        side_effects = runner.run(
            "SELECT (SELECT count(*) FROM audit_events WHERE resource_type='aiRun' AND resource_id='air-cert')::text || ':' || "
            "(SELECT count(*) FROM outbox_events WHERE aggregate_type='aiRun' AND aggregate_id='air-cert')::text",
            tuples=True,
        ).stdout.strip()
        if side_effects != "1:1":
            raise CertificationError(f"AI result commit missing audit/outbox atomic side effects: {side_effects}")

        concurrent = []
        for suffix in ("a", "b"):
            concurrent.append(psql_command(
                args.dsn,
                "INSERT INTO ai_execution_claims(id,project_id,revision,purpose,idempotency_key,request_digest,state,ai_run_id,failure_code,requested_by,created_at,updated_at) "
                f"VALUES('aic-race-{suffix}','project-cert',1,'operator-diagnosis','ai-cert-race',{sql_literal(request_digest)},'DISPATCHED','','','certifier',now(),now())",
                tuples=False, schema=schema, expected_schema_oid=schema_oid_value,
            ))
        results = run_concurrent(concurrent, runner.env)
        if sum(1 for result in results if result.returncode == 0) != 1:
            raise CertificationError("AI pre-egress idempotency claim did not produce exactly one dispatch winner")
        return detail + "; rollback=0:0 audit/outbox=1:1 dispatchWinners=1"
    add_check(checks, "ai-run-atomic-result-commit", ai_run_atomic_result_commit)

    def lease_contention():
        require_schema_ready(schema_ready)
        runner.run("INSERT INTO operations(id,project_id,revision,kind,target_ref,desired_revision,state,risk,idempotency_key,request_digest,actor_id,created_at,updated_at) VALUES('op-lease','project-cert',1,'certify','target','rev','QUEUED','low','lease-key','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','certifier',now(),now()) ON CONFLICT DO NOTHING")
        sql_a = "UPDATE operations SET revision=revision+1,lease_owner='worker-a',lease_expires_at=now()+interval '30 seconds',fence_token=fence_token+1,updated_at=now() WHERE id='op-lease' AND (lease_expires_at IS NULL OR lease_expires_at<=now()) RETURNING fence_token;"
        sql_b = sql_a.replace("worker-a", "worker-b")
        results = run_concurrent([psql_command(args.dsn, sql_a, schema=schema, expected_schema_oid=schema_oid_value), psql_command(args.dsn, sql_b, schema=schema, expected_schema_oid=schema_oid_value)], runner.env)
        winners = [r.stdout.strip() for r in results if r.returncode == 0 and r.stdout.strip()]
        if winners != ["1"] and sorted(winners) != ["1"]:
            raise CertificationError(f"expected one fence token winner: {winners}")
        stale = runner.run("UPDATE operations SET revision=revision+1,fence_token=0,updated_at=now() WHERE id='op-lease'", check=False)
        if stale.returncode == 0:
            raise CertificationError("stale fence update unexpectedly succeeded")
        return "exclusive lease and monotonic fence enforced"
    add_check(checks, "lease-fencing-contention", lease_contention)

    def outbox_skip_locked():
        require_schema_ready(schema_ready)
        runner.run("INSERT INTO outbox_events(id,revision,aggregate_type,aggregate_id,event_type,payload,available_at,created_at,updated_at) VALUES('evt-lock-a',1,'cert','a','event','{}',now(),now(),now()),('evt-lock-b',1,'cert','b','event','{}',now(),now(),now()) ON CONFLICT DO NOTHING")
        sql = "BEGIN; SELECT id FROM outbox_events WHERE id LIKE 'evt-lock-%' AND published_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1; SELECT pg_sleep(1); COMMIT;"
        results = run_concurrent([psql_command(args.dsn, sql, schema=schema, expected_schema_oid=schema_oid_value), psql_command(args.dsn, sql, schema=schema, expected_schema_oid=schema_oid_value)], runner.env, timeout=10)
        ids = []
        for result in results:
            ids.extend(line.strip() for line in result.stdout.splitlines() if line.strip().startswith("evt-lock-"))
        if len(set(ids)) != 2:
            raise CertificationError(f"SKIP LOCKED workers did not claim distinct rows: {ids}")
        return ",".join(sorted(set(ids)))
    add_check(checks, "outbox-skip-locked-contention", outbox_skip_locked)

    def append_only_audit():
        require_schema_ready(schema_ready)
        result = runner.run("UPDATE audit_events SET action='tampered' WHERE id='aud-ok'", check=False)
        if result.returncode == 0:
            raise CertificationError("audit update unexpectedly succeeded")
        return "audit update rejected by trigger"
    add_check(checks, "append-only-audit", append_only_audit)

    def immutable_evidence():
        require_schema_ready(schema_ready)
        operation_id = runner.run("SELECT id FROM operations WHERE project_id='project-cert' AND idempotency_key='same-key'", tuples=True).stdout.strip()
        if not operation_id:
            raise CertificationError("idempotent operation row not found")
        runner.run(f"INSERT INTO evidence_metadata(id,operation_id,kind,digest,media_type,location,size_bytes,created_at,updated_at) VALUES('evidence-cert','{operation_id}','runtime','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','application/json','s3://evidence/example',1,now(),now())")
        result = runner.run("DELETE FROM evidence_metadata WHERE id='evidence-cert'", check=False)
        if result.returncode == 0:
            raise CertificationError("evidence delete unexpectedly succeeded")
        return "evidence delete rejected by trigger"
    add_check(checks, "immutable-evidence", immutable_evidence)

    def restart_check():
        require_schema_ready(schema_ready)
        return run_restart_check(runner, args.restart_command)
    add_check(checks, "postgres-restart", restart_check)

    def ai_run_post_restart():
        require_schema_ready(schema_ready)
        return verify_ai_run_durable_pair(runner) + "; survived PostgreSQL postmaster restart"
    add_check(checks, "ai-run-post-restart-durability", ai_run_post_restart)

    def backup_restore():
        nonlocal restored_database_created, restored_database_oid
        require_schema_ready(schema_ready)
        restored_database_oid = create_restore_database(args.admin_dsn, restored_database)
        restored_database_created = True
        require_database_oid(args.admin_dsn, restored_database, restored_database_oid)
        dump_dsn, dump_env = subprocess_postgres_connection(args.dsn, runner.env)
        dump = subprocess.run(["pg_dump", "--format=custom", "--schema", schema, "--file", str(backup_file), dump_dsn], text=True, capture_output=True, env=dump_env, timeout=120, check=False)
        if dump.returncode:
            raise CertificationError(f"pg_dump failed: {dump.stderr.strip()}")
        restore_dsn = database_dsn(args.admin_dsn, restored_database)
        require_database_oid(args.admin_dsn, restored_database, restored_database_oid)
        restore_arg, restore_env = subprocess_postgres_connection(restore_dsn, os.environ)
        restore = subprocess.run(["pg_restore", "--no-owner", "--no-privileges", "--dbname", restore_arg, str(backup_file)], text=True, capture_output=True, env=restore_env, timeout=120, check=False)
        if restore.returncode:
            raise CertificationError(f"pg_restore failed: {restore.stderr.strip()}")
        require_database_oid(args.admin_dsn, restored_database, restored_database_oid)
        restored_runner = Runner(restore_dsn, schema)
        restored_runner.bind_schema_oid(schema_oid(restored_runner))
        count = restored_runner.run("SELECT count(*) FROM organizations WHERE id='atomic-ok'", tuples=True).stdout.strip()
        if count != "1":
            raise CertificationError(f"restored authority row count {count}")
        return f"backup restored into {restored_database} oid={restored_database_oid}"
    add_check(checks, "backup-restore", backup_restore)

    def post_restore_invariants():
        require_schema_ready(schema_ready)
        if not restored_database_created or not restored_database_oid:
            raise CertificationError("backup/restore did not establish durable restore database identity")
        require_database_oid(args.admin_dsn, restored_database, restored_database_oid)
        restore_dsn = database_dsn(args.admin_dsn, restored_database)
        restored = Runner(restore_dsn, schema)
        restored.bind_schema_oid(schema_oid(restored))
        audit = restored.run("UPDATE audit_events SET action='tampered' WHERE id='aud-ok'", check=False)
        evidence = restored.run("DELETE FROM evidence_metadata WHERE id='evidence-cert'", check=False)
        if audit.returncode == 0 or evidence.returncode == 0:
            raise CertificationError("immutable triggers not preserved after restore")
        return "post-restore immutable invariants preserved"
    add_check(checks, "post-restore-invariants", post_restore_invariants)

    def ai_run_post_restore():
        require_schema_ready(schema_ready)
        if not restored_database_created or not restored_database_oid:
            raise CertificationError("backup/restore did not establish durable restore database identity")
        require_database_oid(args.admin_dsn, restored_database, restored_database_oid)
        restored = Runner(database_dsn(args.admin_dsn, restored_database), schema)
        restored.bind_schema_oid(schema_oid(restored))
        return verify_ai_run_durable_pair(restored) + "; survived backup/restore"
    add_check(checks, "ai-run-post-restore-durability", ai_run_post_restore)

    add_check(
        checks, "cleanup",
        lambda: cleanup_certification_artifacts(
            runner, args.admin_dsn, restored_database, backup_file, args.keep_schema,
            schema_created=schema_created, schema_oid_value=schema_oid_value,
            restored_database_created=restored_database_created, restored_database_oid=restored_database_oid,
        ),
    )

    mandatory = set(profile["mandatoryChecks"])
    observed = {c.name: c.status for c in checks}
    missing_checks = sorted(mandatory - set(observed))
    all_pass = not missing_checks and all(observed.get(name) == "PASS" for name in mandatory)
    status = "PASS" if all_pass else "FAIL"
    ai_run_postgres_certified = all(observed.get(name) == "PASS" for name in AI_RUN_POSTGRES_MANDATORY_CHECKS)
    evidence = {
        "schemaVersion": 2,
        "mode": "runtime",
        "status": status,
        "releaseEvidenceAuthority": M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,
        "releaseArtifactDigest": release_artifact_digest,
        "runtimeCertified": all_pass,
        "aiRunPostgresDurabilityAuthority": AI_RUN_POSTGRES_DURABILITY_AUTHORITY,
        "aiRunPostgresDurabilityCertified": ai_run_postgres_certified,
        "startedAt": started,
        "finishedAt": utcnow(),
        "target": redact_dsn(args.dsn),
        "serverVersion": server_version,
        "profileDigest": profile_digest,
        "migrationDigests": migration_digests,
        "checks": [dataclasses.asdict(c) for c in checks],
        "missingMandatoryChecks": missing_checks,
        "truth": "PASS requires every mandatory runtime check; blocked/skipped checks never pass."
    }
    evidence["evidenceDigest"] = sha256_bytes(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode())
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"POSTGRESQL_RUNTIME_CERTIFICATION_{status}", evidence_path)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
