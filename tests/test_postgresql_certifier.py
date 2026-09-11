from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys
import time
import datetime as dt
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pgcert", ROOT / "scripts" / "postgresql_runtime_certify.py")
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class PostgreSQLCertifierTests(unittest.TestCase):
    def test_redact_url_dsn(self):
        value = mod.redact_dsn("postgresql://admin:supersecret@db.example:5432/platform?sslmode=verify-full")
        self.assertNotIn("supersecret", value)
        self.assertIn("admin:***@db.example", value)

    def test_version_comparison(self):
        self.assertTrue(mod.compare_version("18.6", "18.6"))
        self.assertTrue(mod.compare_version("17.12", "17.11"))
        self.assertFalse(mod.compare_version("16.14", "16.15"))


    def test_postgres_subprocess_connection_removes_password_from_argv(self):
        secret = "s3cr%40et:@/?#%"
        encoded = "s3cr%2540et%3A%40%2F%3F%23%25"
        dsn = f"postgresql://cert:{encoded}@db.example:5432/platform?sslmode=verify-full&application_name=cert"
        safe, env = mod.subprocess_postgres_connection(dsn, {"BASE": "1"})
        self.assertNotIn(encoded, safe)
        self.assertNotIn(secret, safe)
        self.assertEqual(env["PGPASSWORD"], secret)
        self.assertIn("cert@db.example:5432", safe)
        self.assertIn("sslmode=verify-full", safe)
        self.assertEqual(env["BASE"], "1")

    def test_runner_and_concurrent_psql_never_expose_password_in_argv(self):
        dsn = "postgresql://cert:supersecret@db.example:5432/platform?sslmode=verify-full"
        calls = []
        original = mod.subprocess.run
        try:
            def fake_run(command, **kwargs):
                calls.append((command, kwargs.get("env", {})))
                return subprocess.CompletedProcess(command, 0, "1\n", "")
            mod.subprocess.run = fake_run
            runner = mod.Runner(dsn, "pf_cert_safe")
            runner.run("SELECT 1")
        finally:
            mod.subprocess.run = original
        command, env = calls[0]
        self.assertFalse(any("supersecret" in str(arg) for arg in command))
        self.assertEqual(env.get("PGPASSWORD"), "supersecret")
        concurrent = mod.psql_command(dsn, "SELECT 1")
        self.assertFalse(any("supersecret" in str(arg) for arg in concurrent))

    def test_keyword_dsn_password_is_rejected_from_argv_boundary(self):
        with self.assertRaisesRegex(mod.CertificationError, "PGPASSWORD"):
            mod.subprocess_postgres_connection("host=db.example dbname=platform user=cert password=supersecret")

    def test_conflicting_uri_password_authorities_fail_closed(self):
        with self.assertRaisesRegex(mod.CertificationError, "conflicting password authorities"):
            mod.subprocess_postgres_connection("postgresql://cert:first@db.example/platform?password=second&sslmode=verify-full")

    def test_redact_url_dsn_masks_query_password(self):
        value = mod.redact_dsn("postgresql://admin@db.example:5432/platform?password=fixture-query-3P8&sslmode=verify-full")
        self.assertNotIn("fixture-query-3P8", value)
        self.assertIn("password=***", value)
        self.assertIn("sslmode=verify-full", value)

    def test_private_connection_stdin_is_bounded_strict_and_conflict_free(self):
        import io
        primary = "postgresql://cert:fixture-alpha-7K2@db.example/platform"
        admin = "postgresql://admin:fixture-beta-9M4@db.example/postgres"
        dsn, admin_dsn = mod.read_connection_json_stdin(io.StringIO(json.dumps({"dsn": primary, "adminDsn": admin})))
        self.assertEqual(primary, dsn)
        self.assertEqual(admin, admin_dsn)
        for raw in (
            '{"dsn":"a","dsn":"b","adminDsn":"c"}',
            '{"dsn":"a","adminDsn":"b","extra":true}',
            '[]',
        ):
            with self.assertRaises(mod.CertificationError):
                mod.read_connection_json_stdin(io.StringIO(raw))
        with self.assertRaisesRegex(mod.CertificationError, "16384-byte limit"):
            mod.read_connection_json_stdin(io.StringIO(json.dumps({"dsn": "x" * 17000, "adminDsn": "y"})))

    def test_admin_restore_credentials_are_distinct_and_never_exposed_on_argv(self):
        primary = mod.Runner("postgresql://cert:fixture-alpha-7K2@db.example/platform?sslmode=verify-full", "pf_cert_safe")
        restore_dsn = mod.database_dsn("postgresql://admin:fixture-beta-9M4@db.example/postgres?sslmode=verify-full", "pf_restore_safe")
        restored = mod.Runner(restore_dsn, "pf_cert_safe")
        self.assertEqual("fixture-alpha-7K2", primary.env.get("PGPASSWORD"))
        self.assertEqual("fixture-beta-9M4", restored.env.get("PGPASSWORD"))
        self.assertNotIn("fixture-alpha-7K2", primary.dsn)
        self.assertNotIn("fixture-beta-9M4", restored.dsn)

        calls = []
        original = mod.subprocess.run
        try:
            def fake_run(command, **kwargs):
                calls.append((list(command), dict(kwargs.get("env") or {})))
                if command[0] == "createdb":
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[0] == "psql":
                    return subprocess.CompletedProcess(command, 0, "4242\n", "")
                raise AssertionError(command)
            mod.subprocess.run = fake_run
            oid = mod.create_restore_database("postgresql://admin:fixture-beta-9M4@db.example/postgres", "pf_restore_safe")
        finally:
            mod.subprocess.run = original
        self.assertEqual("4242", oid)
        self.assertEqual(["fixture-beta-9M4", "fixture-beta-9M4"], [env.get("PGPASSWORD") for _, env in calls])
        self.assertTrue(all("fixture-beta-9M4" not in " ".join(command) for command, _ in calls))
        self.assertTrue(all("fixture-alpha-7K2" not in " ".join(command) for command, _ in calls))

    def test_runtime_runner_never_falls_back_to_public_schema(self):
        runner = mod.Runner("postgresql://db.example/platform?sslmode=verify-full", "pf_cert_isolated")
        self.assertEqual(runner.env["PGOPTIONS"], "-c search_path=pf_cert_isolated")
        self.assertNotIn("public", runner.env["PGOPTIONS"].lower())

    def test_schema_isolation_rejects_public_or_missing_schema(self):
        class FakeRunner:
            schema = "pf_cert_isolated"
            def __init__(self, row):
                self.row = row
            def run(self, *args, **kwargs):
                return subprocess.CompletedProcess(["psql"], 0, self.row + "\n", "")
        detail = mod.verify_schema_isolation(FakeRunner("pf_cert_isolated|pf_cert_isolated"))
        self.assertIn("current_schema=pf_cert_isolated", detail)
        for row in ("public|public", "pf_cert_isolated|pf_cert_isolated,public", "|public"):
            with self.assertRaises(mod.CertificationError):
                mod.verify_schema_isolation(FakeRunner(row))

    def test_bound_schema_oid_is_injected_into_all_runner_sql(self):
        calls = []
        original = mod.subprocess.run
        try:
            def fake_run(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, "1\n", "")
            mod.subprocess.run = fake_run
            runner = mod.Runner("postgresql://db.example/platform?sslmode=verify-full", "pf_cert_bound")
            runner.bind_schema_oid("4242")
            runner.run("SELECT 1")
        finally:
            mod.subprocess.run = original
        sql = calls[0][-1]
        self.assertIn("pg_catalog.pg_namespace", sql)
        self.assertIn("4242", sql)
        self.assertIn("certification schema identity changed", sql)
        self.assertTrue(sql.endswith("SELECT 1"))

    def test_concurrent_psql_commands_are_schema_oid_guarded(self):
        command = mod.psql_command(
            "postgresql://db.example/platform?sslmode=verify-full",
            "UPDATE organizations SET revision=revision+1",
            schema="pf_cert_bound",
            expected_schema_oid="4242",
        )
        sql = command[-1]
        self.assertIn("pg_catalog.pg_namespace", sql)
        self.assertIn("4242", sql)
        self.assertIn("UPDATE organizations", sql)

    def test_restore_database_creation_never_predeletes_same_name_database(self):
        calls = []
        original = mod.subprocess.run
        try:
            def fake_run(command, **kwargs):
                calls.append(command)
                if command[0] == "createdb":
                    return subprocess.CompletedProcess(command, 1, "", "already exists")
                raise AssertionError(f"unexpected command after failed create: {command}")
            mod.subprocess.run = fake_run
            with self.assertRaises(mod.CertificationError) as ctx:
                mod.create_restore_database("postgresql://admin/db", "pf_restore_collision")
        finally:
            mod.subprocess.run = original
        self.assertIn("without deleting any pre-existing database", str(ctx.exception))
        self.assertEqual([call[0] for call in calls], ["createdb"])

    def test_restore_database_cleanup_refuses_oid_replacement_before_drop(self):
        calls = []
        original = mod.subprocess.run
        try:
            def fake_run(command, **kwargs):
                calls.append(command)
                if command[0] == "psql":
                    return subprocess.CompletedProcess(command, 0, "9002\n", "")
                if command[0] == "dropdb":
                    raise AssertionError("foreign replacement must not be dropped")
                raise AssertionError(command)
            mod.subprocess.run = fake_run
            with self.assertRaises(mod.CertificationError) as ctx:
                mod.drop_owned_restore_database("postgresql://admin/db", "pf_restore_bound", "9001")
        finally:
            mod.subprocess.run = original
        self.assertIn("identity changed", str(ctx.exception))
        self.assertEqual([call[0] for call in calls], ["psql"])

    def test_cleanup_does_not_delete_uncreated_random_schema_or_database(self):
        class NoMutationRunner:
            schema = "pf_cert_collision"
            expected_schema_oid = None
            def bind_schema_oid(self, oid):
                raise AssertionError("uncreated schema must not be bound for cleanup")
            def run(self, *args, **kwargs):
                raise AssertionError("uncreated schema must not be dropped")
        original = mod.subprocess.run
        try:
            mod.subprocess.run = lambda *a, **k: (_ for _ in ()).throw(AssertionError("uncreated database must not be dropped"))
            with tempfile.TemporaryDirectory() as td:
                detail = mod.cleanup_certification_artifacts(
                    NoMutationRunner(), "postgresql://admin/db", "pf_restore_collision", Path(td) / "backup.dump", False,
                    schema_created=False, schema_oid_value="",
                    restored_database_created=False, restored_database_oid="",
                )
        finally:
            mod.subprocess.run = original
        self.assertIn("owned certification schema", detail)

    def test_failed_migration_blocks_all_follow_on_authority_mutations(self):
        with self.assertRaises(mod.CertificationError) as ctx:
            mod.require_schema_ready(False)
        self.assertIn("refusing any fallback mutation", str(ctx.exception))

    def test_restart_requires_postmaster_identity_change(self):
        class FakeRunner:
            env = {}
            def run(self, sql, **kwargs):
                if sql == mod.POSTMASTER_IDENTITY_SQL:
                    return subprocess.CompletedProcess(["psql"], 0, "node|5432|2026-08-17 10:00:00+00\n", "")
                return subprocess.CompletedProcess(["psql"], 0, "1\n", "")
        with self.assertRaises(mod.CertificationError) as ctx:
            mod.run_restart_check(FakeRunner(), "true", deadline_seconds=0.05, poll_seconds=0.01)
        self.assertIn("identity did not change", str(ctx.exception))

    def test_concurrent_timeout_terminates_all_workers(self):
        commands = [[sys.executable, "-c", "import time; time.sleep(60)"] for _ in range(2)]
        launched = []
        original = mod.subprocess.Popen
        try:
            def tracking_popen(*args, **kwargs):
                process = original(*args, **kwargs)
                launched.append(process)
                return process
            mod.subprocess.Popen = tracking_popen
            with self.assertRaises(mod.CertificationError):
                mod.run_concurrent(commands, os.environ.copy(), timeout=1)
        finally:
            mod.subprocess.Popen = original
        self.assertEqual(len(launched), 2)
        self.assertTrue(all(process.poll() is not None for process in launched))

    def test_concurrent_partial_launch_failure_terminates_started_workers(self):
        class FakeWorker:
            args = ["first"]
            returncode = None
            def communicate(self, timeout=None):
                return "", ""

        worker = FakeWorker()
        launched = 0
        terminated = []
        original_popen = mod.subprocess.Popen
        original_terminate = mod.terminate_process_group
        try:
            def fake_popen(*args, **kwargs):
                nonlocal launched
                launched += 1
                if launched == 1:
                    return worker
                raise FileNotFoundError("synthetic launch failure")
            mod.subprocess.Popen = fake_popen
            mod.terminate_process_group = lambda process, grace_seconds=2.0: terminated.append(process)
            with self.assertRaisesRegex(mod.CertificationError, "failed to start concurrent PostgreSQL check"):
                mod.run_concurrent([["first"], ["missing"]], os.environ.copy(), timeout=1)
        finally:
            mod.subprocess.Popen = original_popen
            mod.terminate_process_group = original_terminate
        self.assertEqual(terminated, [worker])


    def test_ai_run_postgres_durability_checks_are_mandatory(self):
        profile = mod.load_profile()
        for name in mod.AI_RUN_POSTGRES_MANDATORY_CHECKS:
            self.assertIn(name, profile["mandatoryChecks"])

    def test_ai_run_pair_verification_recomputes_output_digest(self):
        output = {"classification": "environment"}
        raw, digest = mod.canonical_json_digest(output)
        request = "sha256:" + "d" * 64
        class FakeRunner:
            def __init__(self, bad_digest=False):
                self.bad_digest = bad_digest
            def run(self, sql, **kwargs):
                if "FROM ai_execution_claims c JOIN ai_runs" in sql:
                    used = ("sha256:" + "e" * 64) if self.bad_digest else digest
                    row = f"COMPLETED|air-cert|air-cert|{request}|{request}|ai-cert-main|ai-cert-main|{used}\n"
                    return subprocess.CompletedProcess(["psql"], 0, row, "")
                if "SELECT output::text FROM ai_runs" in sql:
                    return subprocess.CompletedProcess(["psql"], 0, raw + "\n", "")
                raise AssertionError(sql)
        detail = mod.verify_ai_run_durable_pair(FakeRunner())
        self.assertIn("state=COMPLETED", detail)
        with self.assertRaises(mod.CertificationError):
            mod.verify_ai_run_durable_pair(FakeRunner(bad_digest=True))

    def test_cleanup_is_mandatory_certification_check(self):
        profile = mod.load_profile()
        self.assertIn("cleanup", profile["mandatoryChecks"])
        class FakeRunner:
            schema = "pf_cert_test"
            expected_schema_oid = None
            def bind_schema_oid(self, oid):
                self.expected_schema_oid = str(oid)
            def run(self, *args, **kwargs):
                return subprocess.CompletedProcess(["psql"], 1, "", "synthetic drop failure")
        original = mod.subprocess.run
        try:
            mod.subprocess.run = lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", "")
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(mod.CertificationError):
                    mod.cleanup_certification_artifacts(
                        FakeRunner(), "postgresql://admin/db", "restore_db", Path(td) / "backup.dump", False,
                        schema_created=True, schema_oid_value="42",
                        restored_database_created=False, restored_database_oid="",
                    )
        finally:
            mod.subprocess.run = original
        with tempfile.TemporaryDirectory() as td:
            class GoodRunner:
                schema = "pf_cert_test"
                def run(self, *args, **kwargs):
                    return subprocess.CompletedProcess(["psql"], 0, "", "")
            original = mod.subprocess.run
            try:
                mod.subprocess.run = lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", "")
                with self.assertRaises(mod.CertificationError) as ctx:
                    mod.cleanup_certification_artifacts(
                        GoodRunner(), "postgresql://admin/db", "restore_db", Path(td) / "backup.dump", True,
                        schema_created=False, schema_oid_value="",
                        restored_database_created=False, restored_database_oid="",
                    )
                self.assertIn("cannot produce runtime certification PASS", str(ctx.exception))
            finally:
                mod.subprocess.run = original

    def test_tls_policy_requires_verified_live_session(self):
        class FakeRunner:
            env = {}
            def run(self, *args, **kwargs):
                return subprocess.CompletedProcess(["psql"], 0, "t|TLSv1.3|TLS_AES_256_GCM_SHA384\n", "")
        detail = mod.verify_tls_session(FakeRunner(), "postgresql://db.example/platform?sslmode=verify-full", "verify-full")
        self.assertIn("TLSv1.3", detail)
        with self.assertRaises(mod.CertificationError):
            mod.verify_tls_session(FakeRunner(), "postgresql://db.example/platform?sslmode=disable", "verify-full")
        class PlainRunner(FakeRunner):
            def run(self, *args, **kwargs):
                return subprocess.CompletedProcess(["psql"], 0, "f||\n", "")
        with self.assertRaises(mod.CertificationError):
            mod.verify_tls_session(PlainRunner(), "postgresql://db.example/platform?sslmode=verify-full", "verify-full")

    def test_security_baseline_expires_closed(self):
        profile = mod.load_profile()
        self.assertIn("security-baseline", profile["mandatoryChecks"])
        fresh = dt.datetime(2026, 8, 17, tzinfo=dt.timezone.utc)
        self.assertIn("age=4d", mod.security_baseline_check(profile, fresh))
        expired = dt.datetime(2026, 11, 12, tzinfo=dt.timezone.utc)
        with self.assertRaises(mod.CertificationError):
            mod.security_baseline_check(profile, expired)

    def test_runtime_timestamp_ignores_source_date_epoch(self):
        old = os.environ.get("SOURCE_DATE_EPOCH")
        os.environ["SOURCE_DATE_EPOCH"] = "946684800"
        try:
            reproducible = mod.utcnow(reproducible=True)
            runtime = mod.utcnow()
        finally:
            if old is None:
                os.environ.pop("SOURCE_DATE_EPOCH", None)
            else:
                os.environ["SOURCE_DATE_EPOCH"] = old
        self.assertTrue(reproducible.startswith("2000-01-01"))
        self.assertFalse(runtime.startswith("2000-01-01"))

    def test_contract_only_writes_non_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "evidence.json"
            original = mod.sys.argv
            try:
                mod.sys.argv = ["postgresql_runtime_certify.py", "--contract-only", "--evidence", str(output)]
                rc = mod.main()
            finally:
                mod.sys.argv = original
            self.assertEqual(rc, 0)
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["status"], "PASS")
            self.assertFalse(evidence["runtimeCertified"])
            self.assertEqual(evidence["mode"], "contract-only")

    def test_runtime_without_prerequisites_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "blocked.json"
            original = mod.sys.argv
            try:
                mod.sys.argv = ["postgresql_runtime_certify.py", "--evidence", str(output), "--release-artifact-digest", "sha256:" + "7" * 64]
                rc = mod.main()
            finally:
                mod.sys.argv = original
            self.assertEqual(rc, 2)
            evidence = json.loads(output.read_text())
            self.assertEqual(evidence["status"], "BLOCKED")
            self.assertFalse(evidence["runtimeCertified"])
            self.assertEqual(evidence["schemaVersion"], 2)
            self.assertEqual(evidence["releaseEvidenceAuthority"], mod.M03_EXACT_RELEASE_EVIDENCE_AUTHORITY)
            self.assertEqual(evidence["releaseArtifactDigest"], "sha256:" + "7" * 64)

    def test_runtime_requires_exact_release_digest_before_certification(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "blocked.json"
            original = mod.sys.argv
            try:
                mod.sys.argv = ["postgresql_runtime_certify.py", "--evidence", str(output)]
                rc = mod.main()
            finally:
                mod.sys.argv = original
            self.assertEqual(rc, 2)
            evidence = json.loads(output.read_text())
            prereq = next(row for row in evidence["checks"] if row["name"] == "prerequisites")
            self.assertIn("release-artifact-digest", prereq["detail"])


if __name__ == "__main__":
    unittest.main()
