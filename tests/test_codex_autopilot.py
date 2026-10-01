import hashlib
import io
import importlib.util
import json
import os
import signal
import subprocess
import time
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
            self.assertEqual(data["failureCapsuleAuthority"], "AUTOPILOT_FAILURE_CAPSULE_V1")
            self.assertEqual(data["selectiveConvergenceAuthority"], "AUTOPILOT_OWNER_SCOPED_CONVERGENCE_V1")
            self.assertEqual(data["repairScopeFenceAuthority"], "AUTOPILOT_REPAIR_SCOPE_FENCE_V1")
            self.assertEqual(data["structuredTriageAuthority"], "AUTOPILOT_STRUCTURED_TRIAGE_V1")
            self.assertEqual(data["repairGitBoundaryAuthority"], "AUTOPILOT_REPAIR_GIT_BOUNDARY_V1")
            self.assertEqual(data["dirtyDeltaAuthority"], "AUTOPILOT_DIRTY_DELTA_V1")
            self.assertEqual(data["workspaceFingerprintAuthority"], "AUTOPILOT_GIT_WORKSPACE_FINGERPRINT_V1")
            self.assertEqual(data["installerOwnerStageAuthority"], "AUTOPILOT_INSTALLER_OWNER_STAGE_V1")
            self.assertEqual(data["agentOwnerProofAuthority"], "AUTOPILOT_AGENT_OWNER_PROOF_V1")
            self.assertTrue(data["notProductAuthority"])
            self.assertEqual(data["stageResults"][0]["specialist"], "operator-console")
            self.assertNotIn("output_tail", data["stageResults"][0])
            self.assertIn("workspaceFingerprint", data)
            self.assertIn("gitHead", data)
            self.assertEqual(data["nextStage"], "smoke-ui-live")
            self.assertTrue(data["invocation"])
            self.assertIn("rerun the same invocation", data["resumeHint"])


class LiveCheckpointProcessResumeTests(unittest.TestCase):
    def test_live_checkpoint_process_is_rejoined_not_terminated(self):
        if os.name != "posix":
            self.skipTest("process identity regression uses /proc on POSIX")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.txt").write_text("stable\n")
            stage = AUTOPILOT.Stage("live-stage", (sys.executable, "-c", "pass"), 10)
            graph = AUTOPILOT._stage_graph_signature([stage], repair=False)
            AUTOPILOT._checkpoint_forward(
                root, graph_signature=graph, repair=False, next_index=0,
                repair_count=0, seen_failures={}, current_stage="live-stage",
                run_id="run-live",
            )
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time;time.sleep(30)"],
                cwd=root, start_new_session=True,
            )
            try:
                for _ in range(50):
                    if AUTOPILOT._process_start_ticks(proc.pid):
                        break
                    time.sleep(0.01)
                AUTOPILOT._mark_active_process(root, proc.pid, "live-stage-child")
                state = AUTOPILOT._load_checkpoint(root, graph_signature=graph, repair=False)
                self.assertIsNotNone(state)
                self.assertTrue(state.pop("_activeProcessLive"))
                self.assertIsNone(proc.poll(), "resume observer killed live stage process")
                with mock.patch.object(AUTOPILOT, "run_stage") as run:
                    code = AUTOPILOT._execute_stages(
                        root, [stage], repair=False, max_repairs=0,
                        codex_timeout=10, enforce_supply_chain=False,
                        emit_ready_result=False,
                    )
                    self.assertEqual(4, code)
                    run.assert_not_called()
                self.assertIsNone(proc.poll(), "rejoin path killed live stage process")
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)

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


class AutopilotAgentContextTests(unittest.TestCase):
    def test_agent_context_is_compact_and_omits_raw_stage_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".state").mkdir()
            report = {
                "schemaVersion": 1,
                "authority": "AUTOPILOT_CAMPAIGN_REPORT_V1",
                "runId": "run-context",
                "status": "CODE_DEFECT",
                "phase": "forward",
                "currentStage": "installer-remote-smoke",
                "currentSpecialist": "installer-runtime",
                "currentCommand": ["python3", "scripts/smoke_installer_remote.py", "./bin/platformctl", "./bin/platform-installer"],
                "currentTimeoutSeconds": 900,
                "nextStage": "installer-remote-smoke",
                "repairCount": 1,
                "resumeEligible": True,
                "invocation": ["python3", "scripts/codex_autopilot.py", "--repair"],
                "lastFailure": {
                    "stage": "installer-remote-smoke",
                    "specialist": "installer-runtime",
                    "status": "FAIL",
                    "fingerprint": "fp-compact",
                    "reason": "NO_PROGRESS",
                    "output_tail": "secret raw output must not escape",
                },
            }
            AUTOPILOT._report_path(root).write_text(json.dumps(report), encoding="utf-8")
            AUTOPILOT._checkpoint_path(root).write_text(json.dumps({
                "lastFailureCapsule": "ERROR owner mismatch token=[REDACTED]"
            }), encoding="utf-8")
            with mock.patch.object(AUTOPILOT, "_git_head", return_value="a" * 40):
                context = AUTOPILOT._agent_context(root)
            raw = json.dumps(context)
            self.assertEqual(context["authority"], "AUTOPILOT_AGENT_CONTEXT_V1")
            self.assertTrue(context["notProductAuthority"])
            self.assertEqual(context["lastFailure"]["fingerprint"], "fp-compact")
            self.assertNotIn("output_tail", raw)
            self.assertNotIn("secret raw output", raw)
            self.assertEqual(context["failureCapsuleAuthority"], "AUTOPILOT_AGENT_FAILURE_CAPSULE_V2")
            self.assertEqual(context["ownerProofAuthority"], "AUTOPILOT_AGENT_OWNER_PROOF_V1")
            self.assertEqual(context["installerOwnerStageAuthority"], "AUTOPILOT_INSTALLER_OWNER_STAGE_V1")
            self.assertEqual(context["installerOwnerContractStageAuthority"], "AUTOPILOT_INSTALLER_OWNER_CONTRACT_STAGE_V1")
            self.assertEqual(context["agentRepairBudgetAuthority"], "AUTOPILOT_AGENT_REPAIR_BUDGET_V1")
            self.assertEqual(context["failurePathHintsAuthority"], "AUTOPILOT_FAILURE_PATH_HINTS_V1")
            self.assertEqual(context["defaultAgentRepairBudget"], 8)
            self.assertEqual(context["failureCapsuleMaxChars"], 3200)
            self.assertEqual(context["failureCapsule"], "ERROR owner mismatch token=[REDACTED]")
            self.assertLessEqual(len(context["failureCapsule"]), 3200)
            self.assertEqual(context["proofCommand"][:2], ["python3", "scripts/smoke_installer_remote.py"])
            self.assertEqual(context["proofTimeoutSeconds"], 900)
            self.assertEqual(context["resumeInvocation"][-1], "--repair")
            self.assertIn("AGENTS.md", context["sourceContext"]["agentInstructions"])

    def test_checkpoint_failure_capsule_is_redacted_before_agent_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".state").mkdir()
            AUTOPILOT._write_checkpoint(root, {
                "graphSignature": "graph",
                "repair": True,
                "phase": "forward",
                "nextIndex": 0,
                "repairCount": 0,
                "seenFailures": [],
            })
            failure = AUTOPILOT.StageResult(
                "installer-remote-smoke", "FAIL", 1, 0.1, "fp",
                "ERROR remote bootstrap password=hunter2 token=qwerty\nTraceback: owner failure",
            )
            with mock.patch.object(AUTOPILOT, "_workspace_fingerprint", return_value="workspace"), \
                 mock.patch.object(AUTOPILOT, "_git_head", return_value="a" * 40):
                AUTOPILOT._record_failure_capsule(root, failure)
                context = AUTOPILOT._agent_context(root)
            self.assertIn("ERROR remote bootstrap", context["failureCapsule"])
            self.assertIn("[REDACTED]", context["failureCapsule"])
            self.assertNotIn("hunter2", context["failureCapsule"])
            self.assertNotIn("qwerty", context["failureCapsule"])

    def test_agent_context_cli_prints_one_json_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(AUTOPILOT, "ROOT", root), \
                 mock.patch.object(AUTOPILOT, "_agent_context", return_value={"authority": "AUTOPILOT_AGENT_CONTEXT_V1", "status": "IDLE"}), \
                 mock.patch.object(sys, "argv", ["codex_autopilot.py", "--agent-context"]), \
                 mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                code = AUTOPILOT.main()
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["authority"], "AUTOPILOT_AGENT_CONTEXT_V1")


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
    def test_custom_codex_command_arguments_are_not_exposed_by_preflight(self):
        stage = AUTOPILOT.Stage("repository-validation", ("python3", "scripts/validate_repository.py", "."), 180)
        command = ["codex", "exec", "--token", "super-secret-token", "--sandbox", "workspace-write"]
        with mock.patch.object(AUTOPILOT.shutil, "which", return_value="/usr/bin/codex"), \
             mock.patch.object(AUTOPILOT, "_python_module_available", return_value=True), \
             mock.patch.object(AUTOPILOT, "_codex_command", return_value=command), \
             mock.patch.dict(os.environ, {"PLATFORM_FACTORY_CODEX_COMMAND": "secret override"}, clear=False):
            missing, details = AUTOPILOT.environment_preflight(require_codex=True, stages=[stage])
        self.assertEqual(missing, [])
        raw = json.dumps(details, sort_keys=True)
        self.assertNotIn("super-secret-token", raw)
        self.assertNotIn("secret override", raw)
        self.assertNotIn("--token", raw)
        self.assertEqual(details["codex-command-source"], "override")
        self.assertEqual(details["codex-command-argv-count"], str(len(command)))
        self.assertEqual(details["codex-executable"], "/usr/bin/codex")

    def test_blocked_environment_preflight_creates_compact_agent_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = AUTOPILOT.Stage("installer-remote-smoke", ("python3", "scripts/smoke_installer_remote.py"), 900)
            missing = ["python-module:playwright", "chromium-or-chrome"]
            details = {"optional:node": "unavailable"}
            with mock.patch.object(AUTOPILOT, "_select_stages", return_value=[stage]), \
                 mock.patch.object(AUTOPILOT, "environment_preflight", return_value=(missing, details)), \
                 mock.patch.object(AUTOPILOT, "_git_head", return_value="a" * 40), \
                 mock.patch.object(AUTOPILOT, "_workspace_fingerprint", return_value="workspace"):
                code = AUTOPILOT._run_autopilot_locked(
                    root,
                    repair=True,
                    max_repairs=3,
                    codex_timeout=10,
                    start_stage="installer-remote-smoke",
                )
                context = AUTOPILOT._agent_context(root)
            self.assertEqual(code, 3)
            self.assertEqual(context["status"], "ENVIRONMENT_BLOCKED")
            self.assertEqual(context["environmentPreflight"]["authority"], "AUTOPILOT_ENVIRONMENT_PREFLIGHT_HANDOFF_V1")
            self.assertEqual(context["environmentPreflight"]["missing"], sorted(missing))
            self.assertEqual(context["lastFailure"]["stage"], "environment-preflight")
            self.assertEqual(context["lastFailure"]["specialist"], "environment")
            self.assertIn("do not edit product source", context["nextAction"])
            self.assertNotIn("super-secret", json.dumps(context))
            self.assertFalse((root / ".state" / "codex-autopilot-run.json").exists())


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



class TokenEfficientAutopilotTests(unittest.TestCase):
    def test_repair_prompt_forbids_git_history_mutation(self):
        stage = AUTOPILOT.Stage("smoke-4", ("true",), 10)
        result = AUTOPILOT.StageResult("smoke-4", "FAIL", 1, 0.1, "fp", "failed")
        prompt = AUTOPILOT._repair_prompt(stage, result, 1, "CLASSIFICATION=CODE_DEFECT")
        self.assertIn("Do not commit", prompt)
        self.assertIn("mutate Git refs/index/history", prompt)

    def test_git_workspace_fingerprint_hashes_only_dirty_paths_when_available(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "clean.txt").write_text("clean\n", encoding="utf-8")
            (root / "dirty.txt").write_text("dirty\n", encoding="utf-8")
            with mock.patch.object(AUTOPILOT, "_git_head", return_value="a" * 40), \
                 mock.patch.object(AUTOPILOT, "_git_dirty_paths", return_value=["dirty.txt"]), \
                 mock.patch.object(AUTOPILOT, "_full_workspace_fingerprint", side_effect=AssertionError("full tree fallback used")):
                first = AUTOPILOT._workspace_fingerprint(root)
                (root / "clean.txt").write_text("changed but not declared dirty\n", encoding="utf-8")
                second = AUTOPILOT._workspace_fingerprint(root)
                self.assertEqual(first, second)
                (root / "dirty.txt").write_text("changed dirty\n", encoding="utf-8")
                third = AUTOPILOT._workspace_fingerprint(root)
                self.assertNotEqual(second, third)

    def test_workspace_fingerprint_falls_back_when_git_enumeration_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.txt").write_text("source\n", encoding="utf-8")
            with mock.patch.object(AUTOPILOT, "_git_head", return_value=""), \
                 mock.patch.object(AUTOPILOT, "_git_dirty_paths", return_value=None):
                self.assertEqual(AUTOPILOT._workspace_fingerprint(root), AUTOPILOT._full_workspace_fingerprint(root))

    def test_failure_capsule_is_bounded_redacted_and_signal_first(self):
        raw = "\n".join(
            [f"noise line {i}" for i in range(80)]
            + ["ERROR owner mismatch password=hunter2", "Traceback: important frame", "token=qwerty"]
            + [f"tail line {i}" for i in range(20)]
        )
        capsule = AUTOPILOT._failure_capsule(raw, max_lines=20, max_chars=1200)
        self.assertLessEqual(len(capsule), 1240)
        self.assertNotIn("hunter2", capsule)
        self.assertNotIn("qwerty", capsule)
        self.assertIn("ERROR owner mismatch", capsule)
        self.assertIn("Traceback: important frame", capsule)
        self.assertIn("tail line 19", capsule)

    def test_operator_console_repair_uses_selective_convergence_family(self):
        stages = AUTOPILOT.canonical_stages(ROOT)
        selected = AUTOPILOT._select_convergence_stages(stages, {"smoke-ui-quality"})
        names = [stage.name for stage in selected]
        self.assertIn("smoke-ui-quality", names)
        self.assertIn("smoke-ui-live", names)
        self.assertIn("build-release", names)
        self.assertIn("artifact-quick-verify", names)
        self.assertNotIn("lab-runner-tests", names)
        self.assertLess(len(selected), len(stages))

    def test_installer_smokes_are_independent_checkpoint_stages(self):
        stages = AUTOPILOT.canonical_stages(ROOT)
        names = [stage.name for stage in stages]
        self.assertNotIn("smoke-4", names)
        self.assertIn("installer-entrypoint-contracts", names)
        self.assertIn("installer-go-owner-tests", names)
        self.assertLess(names.index("installer-entrypoint-contracts"), names.index("installer-core-smoke"))
        self.assertLess(names.index("installer-go-owner-tests"), names.index("installer-core-smoke"))
        self.assertLess(names.index("installer-core-smoke"), names.index("installer-host-smoke"))
        self.assertLess(names.index("installer-host-smoke"), names.index("installer-remote-smoke"))

    def test_installer_repair_uses_installer_and_package_convergence(self):
        stages = AUTOPILOT.canonical_stages(ROOT)
        selected = AUTOPILOT._select_convergence_stages(stages, {"installer-remote-smoke"})
        names = [stage.name for stage in selected]
        self.assertIn("installer-entrypoint-contracts", names)
        self.assertIn("installer-go-owner-tests", names)
        self.assertIn("installer-core-smoke", names)
        self.assertIn("installer-host-smoke", names)
        self.assertIn("installer-remote-smoke", names)
        self.assertIn("smoke-ui-workflow-e2e", names)
        self.assertIn("package", names)
        self.assertNotIn("lab-runner-tests", names)

    def test_installer_go_owner_contract_stage_declares_go_preflight_only(self):
        stages = AUTOPILOT.canonical_stages(ROOT)
        stage = next(item for item in stages if item.name == "installer-go-owner-tests")
        requirements = AUTOPILOT._environment_requirements([stage])
        self.assertEqual(requirements, {"go"})
        self.assertEqual(AUTOPILOT.INSTALLER_OWNER_CONTRACT_STAGE_AUTHORITY, "AUTOPILOT_INSTALLER_OWNER_CONTRACT_STAGE_V1")

    def test_cross_owner_repair_forces_full_convergence(self):
        stage = AUTOPILOT.Stage("smoke-ui-quality", ("true",), 10)
        self.assertFalse(AUTOPILOT._repair_requires_full_convergence(stage, ["webconsole/static/app.js"]))
        self.assertTrue(AUTOPILOT._repair_requires_full_convergence(stage, ["internal/persistence/postgres.go"]))
        self.assertTrue(AUTOPILOT._repair_requires_full_convergence(stage, []))

    def test_structured_triage_parser_accepts_wrapper_lines_but_rejects_ambiguity(self):
        self.assertEqual(AUTOPILOT._parse_triage_classification("CLASSIFICATION=CODE_DEFECT\nowner=api"), "CODE_DEFECT")
        self.assertEqual(AUTOPILOT._parse_triage_classification("codex progress...\n  CLASSIFICATION=TEST_DEFECT  \nproof=x"), "TEST_DEFECT")
        self.assertEqual(AUTOPILOT._parse_triage_classification("CLASSIFICATION=CODE_DEFECT\nCLASSIFICATION=ENVIRONMENT"), "UNKNOWN")
        self.assertEqual(AUTOPILOT._parse_triage_classification("no structured classification"), "UNKNOWN")

    def test_environment_triage_never_opens_repair_writer(self):
        stage = AUTOPILOT.Stage("smoke-4", ("true",), 10)
        result = AUTOPILOT.StageResult("smoke-4", "FAIL", 1, 0.1, "fp", "connection refused")
        with mock.patch.object(AUTOPILOT, "invoke_codex_triage", return_value=(True, "ENVIRONMENT", "CLASSIFICATION=ENVIRONMENT\nnetwork unavailable")), \
             mock.patch.object(AUTOPILOT, "_codex_command", side_effect=AssertionError("writer command requested")):
            ok, detail = AUTOPILOT.invoke_codex(ROOT, stage, result, 1, 10)
        self.assertFalse(ok)
        self.assertIn("classification=ENVIRONMENT", detail)

    def test_timeout_in_repair_mode_is_triaged_and_can_be_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "internal").mkdir()
            marker = root / "internal" / "installer-fix.go"
            marker.write_text("before\n", encoding="utf-8")
            stage = AUTOPILOT.Stage("smoke-4", ("true",), 10)
            timed_out = AUTOPILOT.StageResult("smoke-4", "TIMEOUT", 124, 10.0, "fp-timeout", "test timeout")
            passed = AUTOPILOT.StageResult("smoke-4", "PASS", 0, 0.1, "fp-pass", "ok")
            calls = {"repair": 0}
            def fake_repair(*_args, **_kwargs):
                calls["repair"] += 1
                marker.write_text("after\n", encoding="utf-8")
                return True, "repaired"
            with mock.patch.object(AUTOPILOT, "run_stage", side_effect=[timed_out, passed, passed]), \
                 mock.patch.object(AUTOPILOT, "invoke_codex", side_effect=fake_repair):
                code = AUTOPILOT._execute_stages(
                    root, [stage], repair=True, max_repairs=1, codex_timeout=10,
                    enforce_supply_chain=False, emit_ready_result=False,
                )
            self.assertEqual(code, 0)
            self.assertEqual(calls["repair"], 1)

    def test_full_convergence_requirement_survives_forward_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.txt").write_text("stable\n", encoding="utf-8")
            AUTOPILOT._checkpoint_forward(
                root,
                graph_signature="graph",
                repair=True,
                next_index=3,
                repair_count=1,
                seen_failures={("smoke-ui-quality", "fp"): 1},
                current_stage="smoke-ui-quality",
                full_convergence_required=True,
                run_id="run-full",
            )
            state = json.loads(AUTOPILOT._checkpoint_path(root).read_text(encoding="utf-8"))
            self.assertTrue(state["fullConvergenceRequired"])
            self.assertEqual(state["runId"], "run-full")


class AgentEntrypointContractTests(unittest.TestCase):
    def test_agent_run_defaults_to_multi_defect_budget_without_unbounded_loop(self):
        argv = ["codex_autopilot.py", "--agent-run"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(AUTOPILOT, "run_autopilot", return_value=0) as run:
            self.assertEqual(AUTOPILOT.main(), 0)
        self.assertEqual(run.call_args.kwargs["max_repairs"], AUTOPILOT.DEFAULT_AGENT_REPAIR_BUDGET)
        self.assertEqual(AUTOPILOT.DEFAULT_AGENT_REPAIR_BUDGET, 8)
        self.assertEqual(AUTOPILOT.AGENT_REPAIR_BUDGET_AUTHORITY, "AUTOPILOT_AGENT_REPAIR_BUDGET_V1")

    def test_normal_repair_keeps_conservative_default_budget(self):
        argv = ["codex_autopilot.py", "--repair"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(AUTOPILOT, "run_autopilot", return_value=0) as run:
            self.assertEqual(AUTOPILOT.main(), 0)
        self.assertEqual(run.call_args.kwargs["max_repairs"], AUTOPILOT.DEFAULT_REPAIR_BUDGET)
        self.assertEqual(AUTOPILOT.DEFAULT_REPAIR_BUDGET, 3)

    def test_agent_run_enables_bounded_repair_without_manual_orchestration_flags(self):
        argv = ["codex_autopilot.py", "--agent-run", "--max-repairs", "2"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(AUTOPILOT, "run_autopilot", return_value=0) as run:
            self.assertEqual(AUTOPILOT.main(), 0)
        kwargs = run.call_args.kwargs
        self.assertTrue(kwargs["repair"])
        self.assertEqual(kwargs["max_repairs"], 2)
        self.assertIsNone(kwargs["start_stage"])
        self.assertIsNone(kwargs["stop_stage"])

    def test_agent_context_recommends_single_durable_entrypoint_when_idle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(AUTOPILOT, "_git_head", return_value="a" * 40):
                context = AUTOPILOT._agent_context(root)
        self.assertEqual(context["authority"], "AUTOPILOT_AGENT_CONTEXT_V1")
        self.assertIn("make autopilot-agent", context["nextAction"])
        self.assertTrue(any("owner-scoped convergence" in rule for rule in context["continuationRules"]))

    def test_failure_path_hints_are_bounded_existing_and_owner_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "install.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "internal" / "hostdeployment").mkdir(parents=True)
            (root / "internal" / "hostdeployment" / "deploy.go").write_text("package hostdeployment\n", encoding="utf-8")
            (root / "internal" / "persistence").mkdir(parents=True)
            (root / "internal" / "persistence" / "postgres.go").write_text("package persistence\n", encoding="utf-8")
            stage = AUTOPILOT.Stage("installer-host-smoke", ("python3", "scripts/smoke_installer_host.py"), 30)
            hints = AUTOPILOT._failure_path_hints(
                root,
                stage,
                "install.sh:12 failed\ninternal/hostdeployment/deploy.go:44 mismatch\ninternal/persistence/postgres.go:8 unrelated\nmissing/file.go:9 absent",
            )
        self.assertEqual(hints, ["install.sh", "internal/hostdeployment/deploy.go"])
        self.assertEqual(AUTOPILOT.FAILURE_PATH_HINTS_AUTHORITY, "AUTOPILOT_FAILURE_PATH_HINTS_V1")

    def test_owner_context_is_shared_by_prompt_scope_and_report(self):
        stage = AUTOPILOT.Stage("installer-host-smoke", ("python3", "scripts/smoke_installer_host.py"), 30)
        owner_paths = AUTOPILOT._owner_context_paths(stage)
        self.assertIn("install.sh", owner_paths)
        self.assertIn("internal/hostdeployment/", owner_paths)
        self.assertTrue(AUTOPILOT._repair_path_in_owner_scope(stage, "install.sh"))
        self.assertTrue(AUTOPILOT._repair_path_in_owner_scope(stage, "internal/hostdeployment/deploy.go"))
        self.assertFalse(AUTOPILOT._repair_path_in_owner_scope(stage, "internal/persistence/postgres.go"))
        failed = AUTOPILOT.StageResult(stage.name, "FAIL", 1, 0.1, "fp", "failure")
        prompt = AUTOPILOT._repair_prompt(stage, failed, 1, "CLASSIFICATION=CODE_DEFECT")
        self.assertIn("Start with these owner paths", prompt)
        self.assertIn("internal/hostdeployment/", prompt)
        self.assertEqual(AUTOPILOT.OWNER_CONTEXT_AUTHORITY, "AUTOPILOT_OWNER_CONTEXT_PATHS_V1")

    def test_prompt_budgets_keep_failure_context_compact(self):
        stage = AUTOPILOT.Stage("installer-host-smoke", ("false",), 30)
        noisy = "\n".join(["ERROR owner failure " + ("x" * 200) for _ in range(80)])
        result = AUTOPILOT.StageResult(stage.name, "FAIL", 1, 0.1, "fp-budget", noisy)
        triage_prompt = AUTOPILOT._triage_prompt(stage, result, 1)
        repair_prompt = AUTOPILOT._repair_prompt(stage, result, 1, "CLASSIFICATION=CODE_DEFECT\n" + ("triage " * 1000))
        self.assertLess(len(triage_prompt), 7000)
        self.assertLess(len(repair_prompt), 9000)
        self.assertIn("Start with these owner paths", repair_prompt)
        self.assertEqual(AUTOPILOT.PROMPT_BUDGET_AUTHORITY, "AUTOPILOT_PROMPT_BUDGET_V1")
        self.assertLessEqual(AUTOPILOT.REPAIR_FAILURE_CAPSULE_MAX_CHARS, 3200)
        self.assertLessEqual(AUTOPILOT.REPAIR_TRIAGE_MAX_CHARS, 2400)

if __name__ == "__main__":
    unittest.main()
