import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import sys
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("codex_autopilot", ROOT / "scripts" / "codex_autopilot.py")
AUTOPILOT = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = AUTOPILOT
SPEC.loader.exec_module(AUTOPILOT)


class ExactSHARealTestPreflight(unittest.TestCase):
    def make_release(self, root: Path) -> tuple[Path, str, str]:
        release = root / "release.zip"
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        installer_body = b"installer-runtime-fixture"
        installer_sha = hashlib.sha256(installer_body).hexdigest()
        version_body = (version + "\n").encode()
        release_name = "test"
        release_name_body = (release_name + "\n").encode()
        manifest = {
            "schemaVersion": 2,
            "product": "4SO Platform Factory",
            "version": version,
            "releaseName": release_name,
            "fileCount": 3,
            "files": [
                {"path": "VERSION", "sha256": hashlib.sha256(version_body).hexdigest(), "size": len(version_body), "mode": "0o644"},
                {"path": "RELEASE-NAME", "sha256": hashlib.sha256(release_name_body).hexdigest(), "size": len(release_name_body), "mode": "0o644"},
                {"path": "bin/linux-amd64/platform-installer", "sha256": installer_sha, "size": len(installer_body), "mode": "0o755"},
            ],
        }
        release_root = f"4so-platform-factory-{version}-{release_name}"
        with zipfile.ZipFile(release, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(f"{release_root}/VERSION", version_body)
            archive.writestr(f"{release_root}/RELEASE-NAME", release_name_body)
            archive.writestr(f"{release_root}/bin/linux-amd64/platform-installer", installer_body)
            archive.writestr(f"{release_root}/ARTIFACT-MANIFEST.json", json.dumps(manifest, sort_keys=True))
        release_digest = "sha256:" + hashlib.sha256(release.read_bytes()).hexdigest()
        return release, release_digest, "sha256:" + installer_sha

    def base_env(self, state: Path, release: Path) -> dict[str, str]:
        return {
            "POSTGRES_CERT_DSN": "postgres://cert",
            "POSTGRES_CERT_ADMIN_DSN": "postgres://admin",
            "POSTGRES_CERT_RESTART_COMMAND": "true",
            "ALLOW_DESTRUCTIVE_POSTGRES_CERTIFICATION": "1",
            "PLATFORM_FACTORY_AUTOPILOT_FIELD_CAMPAIGN_STATE": str(state),
            "PLATFORM_INSTALLER_TOKEN": "token",
            "PLATFORM_FACTORY_AUTOPILOT_RELEASE_ARTIFACT": str(release),
        }

    def test_real_test_requires_exact_sha_and_runtime_binary_bound_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, digest, installer_digest = self.make_release(root)
            state = root / "campaign.json"
            state.write_text(json.dumps({
                "apiVersion": "platform.4so.io/v1alpha1",
                "kind": "FieldExecutionCampaign",
                "schemaVersion": 3,
                "releaseArtifactDigest": digest,
                "installerBinaryDigest": installer_digest,
            }), encoding="utf-8")
            with mock.patch.dict(os.environ, self.base_env(state, release), clear=True), mock.patch.object(AUTOPILOT, "unresolved_components", return_value=[]):
                missing, resolved = AUTOPILOT._real_test_preflight(ROOT)
            self.assertEqual(resolved, state.resolve())
            self.assertNotIn("PLATFORM_FACTORY_AUTOPILOT_RELEASE_ARTIFACT", missing)
            self.assertNotIn("FIELD_CAMPAIGN_EXACT_SHA_BINDING", missing)

            state.write_text(json.dumps({
                "apiVersion": "platform.4so.io/v1alpha1",
                "kind": "FieldExecutionCampaign",
                "schemaVersion": 3,
                "releaseArtifactDigest": digest,
                "installerBinaryDigest": "sha256:" + "0" * 64,
            }), encoding="utf-8")
            with mock.patch.dict(os.environ, self.base_env(state, release), clear=True), mock.patch.object(AUTOPILOT, "unresolved_components", return_value=[]):
                missing, _ = AUTOPILOT._real_test_preflight(ROOT)
            self.assertIn("FIELD_CAMPAIGN_EXACT_SHA_BINDING", missing)

    def test_exact_release_inspection_rejects_manifest_installer_self_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, _, _ = self.make_release(root)
            with zipfile.ZipFile(release, "r") as source:
                members = {name: source.read(name) for name in source.namelist()}
            manifest_name = next(name for name in members if name.endswith("/ARTIFACT-MANIFEST.json"))
            manifest = json.loads(members[manifest_name])
            for row in manifest["files"]:
                if row["path"] == "bin/linux-amd64/platform-installer":
                    row["sha256"] = "f" * 64
            members[manifest_name] = json.dumps(manifest, sort_keys=True).encode()
            with zipfile.ZipFile(release, "w", compression=zipfile.ZIP_STORED) as target:
                for name, raw in members.items():
                    target.writestr(name, raw)
            with self.assertRaisesRegex(ValueError, "does not match archive bytes"):
                AUTOPILOT._inspect_exact_release(release)

    def test_exact_release_inspection_rejects_release_name_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, _, _ = self.make_release(root)
            with zipfile.ZipFile(release, "r") as source:
                members = {name: source.read(name) for name in source.namelist()}
            manifest_name = next(name for name in members if name.endswith("/ARTIFACT-MANIFEST.json"))
            manifest = json.loads(members[manifest_name])
            manifest["releaseName"] = "forged"
            members[manifest_name] = json.dumps(manifest, sort_keys=True).encode()
            with zipfile.ZipFile(release, "w", compression=zipfile.ZIP_STORED) as target:
                for name, raw in members.items():
                    target.writestr(name, raw)
            with self.assertRaisesRegex(ValueError, "identity contract"):
                AUTOPILOT._inspect_exact_release(release)

    def test_exact_release_inspection_rejects_duplicate_manifest_json_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, _, _ = self.make_release(root)
            with zipfile.ZipFile(release, "r") as source:
                members = [(info.filename, source.read(info)) for info in source.infolist()]
            with zipfile.ZipFile(release, "w", compression=zipfile.ZIP_STORED) as target:
                for name, raw in members:
                    if name.endswith("/ARTIFACT-MANIFEST.json"):
                        text = raw.decode()
                        marker = '"releaseName": "test"'
                        self.assertIn(marker, text)
                        raw = text.replace(marker, '"releaseName": "forged", "releaseName": "test"', 1).encode()
                    target.writestr(name, raw)
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                AUTOPILOT._inspect_exact_release(release)

    def test_exact_release_inspection_rejects_noncanonical_archive_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, _, _ = self.make_release(root)
            with zipfile.ZipFile(release, "r") as source:
                members = [(info.filename, source.read(info)) for info in source.infolist()]
            with zipfile.ZipFile(release, "w", compression=zipfile.ZIP_STORED) as target:
                for name, raw in members:
                    if name.endswith("/VERSION"):
                        name = name.removesuffix("/VERSION") + "/meta/../VERSION"
                    target.writestr(name, raw)
            with self.assertRaisesRegex(ValueError, "not canonical"):
                AUTOPILOT._inspect_exact_release(release)

    def test_exact_release_inspection_rejects_symlink_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, _, _ = self.make_release(root)
            link = root / "release-link.zip"
            link.symlink_to(release)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                AUTOPILOT._inspect_exact_release(link)

    def test_real_test_exact_artifact_full_stage_uses_physical_release_path(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "physical-exact-sha.zip"
            release.write_bytes(b"fixture")
            stage = AUTOPILOT._exact_artifact_full_stage(release)
            self.assertEqual(stage.name, "artifact-full-verify")
            self.assertEqual(stage.command, ("python3", "scripts/verify_release.py", str(AUTOPILOT._absolute_path_no_symlink_resolution(str(release))), "--full"))

    def test_real_test_rejects_schema_v2_campaign_even_with_release_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, digest, _ = self.make_release(root)
            state = root / "campaign.json"
            state.write_text(json.dumps({
                "apiVersion": "platform.4so.io/v1alpha1",
                "kind": "FieldExecutionCampaign",
                "schemaVersion": 2,
                "releaseArtifactDigest": digest,
            }), encoding="utf-8")
            with mock.patch.dict(os.environ, self.base_env(state, release), clear=True), mock.patch.object(AUTOPILOT, "unresolved_components", return_value=[]):
                missing, _ = AUTOPILOT._real_test_preflight(ROOT)
            self.assertIn("FIELD_CAMPAIGN_EXACT_SHA_BINDING", missing)

    def test_failed_campaign_without_confirmation_diagnoses_but_does_not_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "VERSION").write_text((ROOT / "VERSION").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "bin").mkdir()
            (root / "bin" / "platformctl").write_text("placeholder", encoding="utf-8")
            release, digest, installer_digest = self.make_release(root)
            state = root / "campaign.json"
            state.write_text(json.dumps({
                "apiVersion": "platform.4so.io/v1alpha1", "kind": "FieldExecutionCampaign", "schemaVersion": 3,
                "state": "FAILED", "runState": "FAILED", "simulation": False,
                "releaseArtifactDigest": digest, "installerBinaryDigest": installer_digest,
                "id": "campaign-failed", "lastError": "fixture failure",
            }), encoding="utf-8")
            commands = []
            def fake_run_logged(command, *, root, timeout):
                commands.append(list(command))
                return 0, "diagnostic collected"
            with mock.patch.dict(os.environ, self.base_env(state, release), clear=True), mock.patch.object(AUTOPILOT, "_run_logged", side_effect=fake_run_logged):
                result = AUTOPILOT._run_field_campaign_real(root, state, root / "evidence", 600)
            self.assertEqual(result.status, "FAIL")
            self.assertIn("FIELD_CAMPAIGN_RESUME_CONFIRMATION_REQUIRED", result.output_tail)
            self.assertTrue(any(cmd[1:3] == ["field-campaign", "diagnose"] for cmd in commands), commands)
            self.assertFalse(any(cmd[1:3] == ["field-campaign", "resume"] for cmd in commands), commands)

    def test_interrupted_campaign_with_confirmation_resumes_watches_and_reverifies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "VERSION").write_text((ROOT / "VERSION").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "bin").mkdir()
            (root / "bin" / "platformctl").write_text("placeholder", encoding="utf-8")
            release, digest, installer_digest = self.make_release(root)
            state = root / "campaign.json"
            campaign = {
                "apiVersion": "platform.4so.io/v1alpha1", "kind": "FieldExecutionCampaign", "schemaVersion": 3,
                "state": "INTERRUPTED", "runState": "RUNNING", "simulation": False,
                "releaseArtifactDigest": digest, "installerBinaryDigest": installer_digest,
                "id": "campaign-interrupted",
            }
            state.write_text(json.dumps(campaign), encoding="utf-8")
            commands = []
            def fake_run_logged(command, *, root, timeout):
                commands.append(list(command))
                if command[1:3] == ["field-campaign", "resume"]:
                    campaign["state"] = "RUNNING"
                    state.write_text(json.dumps(campaign), encoding="utf-8")
                elif command[1:3] == ["field-campaign", "watch"]:
                    campaign.update({"state":"SUCCEEDED", "runState":"SUCCEEDED", "evidenceVerified":False})
                    state.write_text(json.dumps(campaign), encoding="utf-8")
                elif command[1:3] == ["field-campaign", "collect"]:
                    campaign.update({"evidenceVerified":True, "evidenceDigest":"sha256:" + "9" * 64})
                    state.write_text(json.dumps(campaign), encoding="utf-8")
                return 0, "ok"
            env = self.base_env(state, release)
            env["PLATFORM_FACTORY_AUTOPILOT_FIELD_RESUME_CONFIRMATION"] = "RESUME"
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(AUTOPILOT, "_run_logged", side_effect=fake_run_logged):
                result = AUTOPILOT._run_field_campaign_real(root, state, root / "evidence", 600)
            self.assertEqual(result.status, "PASS", result.output_tail)
            verbs = [cmd[1:3] for cmd in commands]
            self.assertIn(["field-campaign", "resume"], verbs)
            self.assertLess(verbs.index(["field-campaign", "resume"]), verbs.index(["field-campaign", "watch"]))
            self.assertIn(["field-campaign", "collect"], verbs)
            self.assertIn(["field-evidence", "verify-report"], verbs)

    def test_real_test_always_refreshes_and_reverifies_field_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "VERSION").write_text((ROOT / "VERSION").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "bin").mkdir()
            (root / "bin" / "platformctl").write_text("placeholder", encoding="utf-8")
            release, digest, installer_digest = self.make_release(root)
            state = root / "campaign.json"
            state.write_text(json.dumps({
                "apiVersion": "platform.4so.io/v1alpha1",
                "kind": "FieldExecutionCampaign",
                "schemaVersion": 3,
                "state": "SUCCEEDED",
                "runState": "SUCCEEDED",
                "simulation": False,
                "evidenceVerified": True,
                "releaseArtifactDigest": digest,
                "installerBinaryDigest": installer_digest,
                "evidenceDigest": "sha256:" + "8" * 64,
                "id": "campaign-1",
            }), encoding="utf-8")
            commands: list[list[str]] = []

            def fake_run_logged(command, *, root, timeout):
                commands.append(list(command))
                return 0, "ok"

            env = self.base_env(state, release)
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(AUTOPILOT, "_run_logged", side_effect=fake_run_logged):
                result = AUTOPILOT._run_field_campaign_real(root, state, root / "evidence", 600)
            self.assertEqual(result.status, "PASS", result.output_tail)
            collect = next(cmd for cmd in commands if cmd[1:3] == ["field-campaign", "collect"])
            self.assertIn("--release-artifact", collect)
            self.assertIn(str(AUTOPILOT._absolute_path_no_symlink_resolution(str(release))), collect)
            self.assertTrue(any(cmd[1:3] == ["field-evidence", "verify-report"] for cmd in commands), commands)


if __name__ == "__main__":
    unittest.main()

class BrowserTriagePrerequisiteTests(unittest.TestCase):
    def test_operator_console_repair_ensures_browser_prerequisites(self):
        stage = AUTOPILOT.Stage("smoke-ui-live", ("python3", "scripts/smoke_ui_live.py"), 10)
        fake = type("R", (), {"returncode": 0, "stdout": '{"ready":true,"os":"linux"}\n'})()
        with mock.patch.object(AUTOPILOT, "_run", return_value=fake) as run:
            ok, detail = AUTOPILOT._ensure_browser_triage_for_stage(ROOT, stage)
        self.assertTrue(ok)
        self.assertIn('"ready":true', detail)
        command = run.call_args.args[0]
        self.assertIn("browser_triage_bootstrap.py", command[1])
        self.assertIn("--ensure", command)

    def test_non_console_repair_does_not_install_browser_prerequisites(self):
        stage = AUTOPILOT.Stage("go-tests", ("go", "test", "./..."), 10)
        with mock.patch.object(AUTOPILOT, "_run") as run:
            ok, detail = AUTOPILOT._ensure_browser_triage_for_stage(ROOT, stage)
        self.assertTrue(ok)
        self.assertEqual(detail, "")
        run.assert_not_called()

class AutopilotReportTests(unittest.TestCase):
    def test_report_is_machine_readable_and_excludes_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = AUTOPILOT.Stage("smoke-ui-live", ("true",), 10)
            result = AUTOPILOT.StageResult("smoke-ui-live", "FAIL", 1, 0.25, "fp-1", "password=super-secret")
            summarized = AUTOPILOT._report_result(stage, result)
            AUTOPILOT._write_autopilot_report(root, stages=[stage], graph_signature="graph", repair=True, phase="deterministic", next_index=0, repair_count=1, status="REPAIRING", current_stage="smoke-ui-live", stage_results=[summarized], last_failure={"stage":"ui-live","specialist":"operator-console","status":"FAIL","fingerprint":"fp-1","reason":"bounded failure"})
            raw = (root / ".state" / "codex-autopilot-report.json").read_text(encoding="utf-8")
            self.assertNotIn("super-secret", raw)
            data = json.loads(raw)
            self.assertEqual(data["authority"], "AUTOPILOT_CAMPAIGN_REPORT_V1")
            self.assertTrue(data["notProductAuthority"])
            self.assertEqual(data["stageResults"][0]["specialist"], "operator-console")
            self.assertNotIn("output_tail", data["stageResults"][0])
            self.assertIn("workspaceFingerprint", data)
            self.assertIn("gitHead", data)
            self.assertEqual(data["nextStage"], "smoke-ui-live")
            self.assertTrue(data["invocation"])
            self.assertIn("rerun the same invocation", data["resumeHint"])

class ProcessTreeTimeoutTests(unittest.TestCase):
    def test_timeout_terminates_descendant_process_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            orphan = root / "orphan-marker"
            child = "import pathlib,time;time.sleep(1.5);pathlib.Path('orphan-marker').write_text('alive')"
            parent = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',%r]);time.sleep(10)" % child
            result = AUTOPILOT.run_stage(root, AUTOPILOT.Stage("timeout-tree-regression", (sys.executable, "-c", parent), 1))
            self.assertEqual(result.status, "TIMEOUT")
            import time
            time.sleep(1.0)
            self.assertFalse(orphan.exists(), "timed-out stage left a descendant process alive")

class CheckpointRetentionTests(unittest.TestCase):
    def test_timeout_retains_checkpoint_for_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = AUTOPILOT.Stage("timeout-stage", ("true",), 1)
            timed_out = AUTOPILOT.StageResult("timeout-stage", "TIMEOUT", 124, 1.0, "fp-timeout", "timed out")
            with mock.patch.object(AUTOPILOT, "run_stage", return_value=timed_out):
                code = AUTOPILOT._execute_stages(root, [stage], repair=False, max_repairs=0, codex_timeout=1, enforce_supply_chain=False, emit_ready_result=False)
            self.assertEqual(code, 3)
            checkpoint = AUTOPILOT._checkpoint_path(root)
            self.assertTrue(checkpoint.is_file(), "timeout erased resumable checkpoint")
            state = json.loads(checkpoint.read_text(encoding="utf-8"))
            self.assertEqual(state["phase"], "forward")
            self.assertEqual(state["nextIndex"], 0)
            self.assertIn("workspaceFingerprint", state)
            self.assertIn("gitHead", state)
            self.assertTrue(state["invocation"])
            self.assertTrue(state["updatedAt"].endswith("Z"))
            self.assertEqual(state["currentStage"], "timeout-stage")

    def test_pass_clears_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = AUTOPILOT.Stage("pass-stage", ("true",), 1)
            passed = AUTOPILOT.StageResult("pass-stage", "PASS", 0, 0.01, "fp-pass", "ok")
            with mock.patch.object(AUTOPILOT, "run_stage", return_value=passed):
                code = AUTOPILOT._execute_stages(root, [stage], repair=False, max_repairs=0, codex_timeout=1, enforce_supply_chain=False, emit_ready_result=False)
            self.assertEqual(code, 0)
            self.assertFalse(AUTOPILOT._checkpoint_path(root).exists())

class CheckpointSafeStageTests(unittest.TestCase):
    def test_canonical_go_stages_are_checkpoint_safe_shards(self):
        stages = AUTOPILOT.canonical_stages(ROOT)
        names = {stage.name for stage in stages}
        for prefix in ("go-unit-", "go-vet-", "go-race-"):
            self.assertTrue(all(f"{prefix}{i}" in names for i in range(1, 5)))
        self.assertNotIn("go-tests", names)
        source = (ROOT / "scripts" / "run_go_package_shard.py").read_text(encoding="utf-8")
        self.assertIn("AUTOPILOT_STAGE_SHARD_AUTHORITY_V2", source)


class AutopilotEventLogTests(unittest.TestCase):
    def test_event_log_is_append_only_and_summarizes_last_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = AUTOPILOT._AutopilotEventLog(root, "run-test")
            log.append("run-start", phase="forward", status="RUNNING", nextIndex=0)
            log.append("stage-result", phase="forward", stage="unit", specialist="go-runtime", status="PASS", returncode=0, fingerprint="fp-pass", nextIndex=1)
            log.append("terminal", phase="forward", stage="smoke", specialist="operator-console", status="CODE_DEFECT", fingerprint="fp-fail", reason="NO_PROGRESS", nextIndex=1)
            summary = AUTOPILOT._summarize_event_log(root)
            self.assertEqual(summary["runId"], "run-test")
            self.assertEqual(summary["eventCount"], 3)
            self.assertEqual(summary["status"], "CODE_DEFECT")
            self.assertEqual(summary["nextIndex"], 1)
            self.assertEqual(summary["passedStages"], ["unit"])
            self.assertEqual(summary["lastFailure"]["stage"], "smoke")
            raw = AUTOPILOT._event_log_path(root, "run-test").read_text(encoding="utf-8")
            self.assertEqual(len([line for line in raw.splitlines() if line.strip()]), 3)

    def test_checkpoint_preserves_run_id_for_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            AUTOPILOT._checkpoint_forward(root, graph_signature="graph", repair=True, next_index=2, repair_count=1, seen_failures={}, run_id="run-resume")
            state = json.loads(AUTOPILOT._checkpoint_path(root).read_text(encoding="utf-8"))
            self.assertEqual(state["runId"], "run-resume")

    def test_report_links_run_id_and_event_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = AUTOPILOT._AutopilotEventLog(root, "run-report")
            log.append("run-start", status="RUNNING", nextIndex=0)
            stage = AUTOPILOT.Stage("unit", ("true",), 1)
            AUTOPILOT._write_autopilot_report(root, stages=[stage], graph_signature="graph", repair=False, phase="forward", next_index=0, repair_count=0, status="RUNNING", current_stage="unit", stage_results=[], run_id="run-report")
            report = json.loads(AUTOPILOT._report_path(root).read_text(encoding="utf-8"))
            self.assertEqual(report["runId"], "run-report")
            self.assertEqual(Path(report["eventLog"]), AUTOPILOT._event_log_path(root, "run-report"))

    def test_event_summary_cli_prints_latest_structured_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = AUTOPILOT._AutopilotEventLog(root, "run-cli")
            log.append("terminal", status="PASS", nextIndex=3)
            with mock.patch.object(AUTOPILOT, "ROOT", root), mock.patch.object(sys, "argv", ["codex_autopilot.py", "--event-summary"]), mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                code = AUTOPILOT.main()
            self.assertEqual(code, 0)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["runId"], "run-cli")
            self.assertEqual(payload["status"], "PASS")


class AutopilotRunLockTests(unittest.TestCase):
    def test_live_owner_blocks_second_run_and_release_allows_next(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = AUTOPILOT._AutopilotRunLock(root)
            first.acquire()
            try:
                second = AUTOPILOT._AutopilotRunLock(root)
                with self.assertRaisesRegex(RuntimeError, "RUN_ALREADY_ACTIVE"):
                    second.acquire()
            finally:
                first.release()
            second = AUTOPILOT._AutopilotRunLock(root)
            second.acquire()
            second.release()

    def test_stale_owner_lock_is_reclaimed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / ".state"
            state.mkdir()
            (state / "codex-autopilot.lock").write_text(
                json.dumps({"pid": 99999999, "startTicks": "dead"}), encoding="utf-8"
            )
            lock = AUTOPILOT._AutopilotRunLock(root)
            lock.acquire()
            self.assertEqual(json.loads((state / "codex-autopilot.lock").read_text())["pid"], os.getpid())
            lock.release()

    def test_run_autopilot_rejects_concurrent_owner_before_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = AUTOPILOT._AutopilotRunLock(root)
            lock.acquire()
            try:
                with mock.patch.object(
                    AUTOPILOT, "print_environment_preflight", side_effect=AssertionError("run body entered")
                ) as preflight:
                    code = AUTOPILOT.run_autopilot(
                        root, repair=False, max_repairs=0, codex_timeout=1
                    )
                    self.assertEqual(code, 3)
                    preflight.assert_not_called()
            finally:
                lock.release()


class StageAwareEnvironmentPreflightTests(unittest.TestCase):
    def unavailable(self, name):
        return None

    def test_python_only_stage_does_not_require_unrelated_toolchains(self):
        stage = AUTOPILOT.Stage("repository-validation", ("python3", "scripts/validate_repository.py", "."), 180)
        with mock.patch.object(AUTOPILOT.shutil, "which", side_effect=self.unavailable), \
             mock.patch.object(AUTOPILOT, "_python_module_available", return_value=True), \
             mock.patch.object(AUTOPILOT, "_codex_command", return_value=None):
            missing, _ = AUTOPILOT.environment_preflight(require_codex=False, stages=[stage])
        self.assertEqual(missing, [])

    def test_go_race_stage_requires_go_c_toolchain_and_libpq_not_browser(self):
        stage = AUTOPILOT.Stage("go-race-1", ("python3", "scripts/run_go_package_shard.py", "--race", "--shard", "1"), 900)
        with mock.patch.object(AUTOPILOT.shutil, "which", side_effect=self.unavailable), \
             mock.patch.object(AUTOPILOT, "_python_module_available", return_value=True), \
             mock.patch.object(AUTOPILOT, "_codex_command", return_value=None):
            missing, _ = AUTOPILOT.environment_preflight(require_codex=False, stages=[stage])
        self.assertEqual(set(missing), {"go", "c-compiler", "libpq-dev"})

    def test_ui_stage_requires_browser_and_playwright_only(self):
        stage = AUTOPILOT.Stage("smoke-ui-live", ("python3", "scripts/smoke_ui_live.py"), 900)
        with mock.patch.object(AUTOPILOT.shutil, "which", side_effect=self.unavailable), \
             mock.patch.object(AUTOPILOT, "_playwright_browser_executable", return_value=None), \
             mock.patch.object(AUTOPILOT, "_python_module_available", return_value=False), \
             mock.patch.object(AUTOPILOT, "_codex_command", return_value=None):
            missing, _ = AUTOPILOT.environment_preflight(require_codex=False, stages=[stage])
        self.assertEqual(set(missing), {"chromium-or-chrome", "python-module:playwright"})

    def test_full_run_preserves_strict_environment_contract(self):
        with mock.patch.object(AUTOPILOT.shutil, "which", side_effect=self.unavailable), \
             mock.patch.object(AUTOPILOT, "_playwright_browser_executable", return_value=None), \
             mock.patch.object(AUTOPILOT, "_python_module_available", return_value=False), \
             mock.patch.object(AUTOPILOT, "_codex_command", return_value=None):
            missing, _ = AUTOPILOT.environment_preflight(require_codex=False)
        self.assertEqual(set(missing), {
            "go", "make", "c-compiler", "libpq-dev", "chromium-or-chrome",
            "python-module:yaml", "python-module:playwright",
        })

class StageSlicingPreflightOrderTests(unittest.TestCase):
    def test_sliced_run_preflights_only_selected_stages(self):
        stages = [
            AUTOPILOT.Stage("first", ("python3", "first.py"), 10),
            AUTOPILOT.Stage("selected", ("python3", "selected.py"), 10),
            AUTOPILOT.Stage("last", ("python3", "last.py"), 10),
        ]
        with mock.patch.object(AUTOPILOT, "canonical_stages", return_value=stages), \
             mock.patch.object(AUTOPILOT, "print_environment_preflight", return_value=3) as preflight:
            code = AUTOPILOT._run_autopilot_locked(
                Path("."), repair=False, max_repairs=0, codex_timeout=1,
                start_stage="selected", stop_stage="selected",
            )
        self.assertEqual(code, 3)
        selected = preflight.call_args.kwargs["stages"]
        self.assertEqual([stage.name for stage in selected], ["selected"])

class StageAwarePreflightCLITests(unittest.TestCase):
    def test_preflight_cli_honors_stage_slice(self):
        stages = [
            AUTOPILOT.Stage("first", ("python3", "first.py"), 10),
            AUTOPILOT.Stage("selected", ("python3", "selected.py"), 10),
            AUTOPILOT.Stage("last", ("python3", "last.py"), 10),
        ]
        argv = ["codex_autopilot.py", "--preflight", "--start-stage", "selected", "--stop-stage", "selected"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(AUTOPILOT, "canonical_stages", return_value=stages), \
             mock.patch.object(AUTOPILOT, "print_environment_preflight", return_value=0) as preflight:
            self.assertEqual(AUTOPILOT.main(), 0)
        selected = preflight.call_args.kwargs["stages"]
        self.assertEqual([stage.name for stage in selected], ["selected"])
