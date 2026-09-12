import hashlib
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
