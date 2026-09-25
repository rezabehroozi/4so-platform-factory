import importlib.util
import json
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("supply_chain_handoff", ROOT / "scripts" / "supply_chain_handoff.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SupplyChainHandoffTests(unittest.TestCase):
    def test_plan_derives_current_s1_truth_without_promotion(self):
        plan = mod.build(ROOT)
        spec = plan["spec"]
        self.assertEqual(mod.AUTHORITY, spec["authority"])
        self.assertTrue(spec["truthModel"]["derivedEvidenceOnly"])
        self.assertTrue(spec["truthModel"]["stagingNeverPromotesSourceResolution"])
        self.assertTrue(spec["truthModel"]["stagingNeverPromotesRuntimeCertification"])
        self.assertTrue(spec["truthModel"]["physicalPassInferenceForbidden"])
        components = mod._component_docs(ROOT)
        admission = mod._json(ROOT / "catalog" / "upstream-admission.json")
        admission_rows = (admission.get("spec") or {}).get("components") or []
        expected_ready = {row["component"] for row in admission_rows if row.get("status") == "ready-for-acquisition"}
        expected_review = {row["component"] for row in admission_rows if row.get("status") != "ready-for-acquisition"}
        expected_locked = {
            name for name, doc in components.items()
            if ((doc.get("spec") or {}).get("source") or {}).get("resolved") is True
        }
        ca = spec["componentAcquisition"]
        self.assertEqual(expected_ready, {row["component"] for row in ca["ready"]})
        self.assertEqual(expected_review, {row["component"] for row in ca["reviewBlocked"]})
        self.assertEqual(expected_locked, {row["component"] for row in ca["alreadySourceLocked"]})
        self.assertEqual(set(components), expected_ready | expected_review | expected_locked)
        self.assertEqual("RUNTIME_DEPENDENCY_TRANSITION_V1", spec["runtimeDependencyTransition"]["authority"])
        self.assertEqual(4, len(spec["managementWorkloads"]["externalImages"]))
        self.assertIn("lab/management-workload-external-image-receipt.json", spec["truthModel"]["canonicalAuthorities"])
        self.assertTrue(spec["managementWorkloads"]["externalReceipt"]["offlineVerified"])
        self.assertFalse(spec["managementWorkloads"]["externalReceipt"]["archiveReady"])
        self.assertEqual("36115673607", spec["managementWorkloads"]["externalReceipt"]["sourceRunId"])
        for row in spec["managementWorkloads"]["externalImages"]:
            self.assertEqual("ready", row["effectiveState"])
            self.assertTrue(row["evidence"]["offlineVerified"])
            self.assertIn("@sha256:", row["evidence"]["exactReference"])
        self.assertIn("MANAGEMENT_IMAGE_DIGEST_LOCKS_PENDING", spec["openBlockers"])
        self.assertIn("MANAGEMENT_WORKLOAD_OCI_ARCHIVE_PENDING", spec["openBlockers"])
        self.assertEqual(4, len(spec["managementWorkloads"]["manifestImageResolution"]))
        self.assertEqual(20, len(spec["componentUpgradePairRequirements"]))
        pair_rows = spec["componentUpgradePairRequirements"]
        self.assertEqual(
            sum(1 for row in pair_rows if row["targetSourceLockPresent"] and row["previousExactSourceLocks"]),
            sum(1 for row in pair_rows if row["pairState"] == "pair-present"),
        )
        self.assertEqual("admitted", spec["releaseToolchain"]["admissionStatus"])
        self.assertEqual("go1.27.1", spec["releaseToolchain"]["version"])
        self.assertEqual(
            "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445",
            spec["releaseToolchain"]["archiveSha256"],
        )

    def test_runtime_holds_remain_exact_and_do_not_leave_ready_set(self):
        plan = mod.build(ROOT)
        ca = plan["spec"]["componentAcquisition"]
        ready = {row["component"] for row in ca["ready"]}
        holds = {row["component"] for row in ca["runtimeHolds"]}
        registry = mod._json(ROOT / "catalog" / "component-runtime-certification.json")
        expected_holds = {
            row["component"] for row in (registry.get("spec") or {}).get("runtimeSuitabilityHolds") or []
        }
        locked = {row["component"] for row in ca["alreadySourceLocked"]}
        self.assertEqual(expected_holds, holds)
        self.assertTrue(holds.issubset(ready | locked))
        for row in ca["runtimeHolds"]:
            self.assertIn(row["status"], {"ready-for-acquisition","source-acquired"})
            self.assertIn(row["runtimeStatus"], {"dependency-transition-required","review-required"})
            self.assertTrue(row["runtimeAuthority"])
            self.assertTrue(row["evidenceURL"].startswith("https://"))
        for row in ca["runtimeHolds"]:
            self.assertRegex(row["selectedVersion"], r"^\d+\.\d+\.\d+$")
            self.assertNotEqual("eligible-after-source-resolution", row["runtimeStatus"])

    def test_reviewed_predecessor_lock_is_the_only_pair_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "catalog" / "runtime" / "demo"
            unreviewed = base / "1.8.0"
            reviewed = base / "1.9.9"
            unreviewed.mkdir(parents=True)
            reviewed.mkdir(parents=True)
            (unreviewed / "source-lock.json").write_text(json.dumps({
                "component": "demo", "version": "1.8.0", "marker": "unreviewed",
            }))
            admission = {
                "component": "demo",
                "targetRelease": "2.0.0",
                "status": "admitted-for-acquisition",
                "previousVersion": "1.9.9",
            }
            self.assertEqual([], mod._reviewed_previous_locks(root, "demo", "2.0.0", admission))
            (reviewed / "source-lock.json").write_text(json.dumps({
                "component": "demo", "version": "1.9.9", "marker": "reviewed",
            }))
            rows = mod._reviewed_previous_locks(root, "demo", "2.0.0", admission)
            self.assertEqual(["1.9.9"], [row["release"] for row in rows])

    def test_reviewed_predecessor_binding_rejects_target_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / "catalog" / "runtime" / "demo" / "1.9.9"
            p.mkdir(parents=True)
            (p / "source-lock.json").write_text(json.dumps({
                "component": "demo", "version": "1.9.9",
            }))
            admission = {
                "component": "demo",
                "targetRelease": "2.1.0",
                "status": "admitted-for-acquisition",
                "previousVersion": "1.9.9",
            }
            self.assertEqual([], mod._reviewed_previous_locks(root, "demo", "2.0.0", admission))

    def test_management_archive_blocker_can_reach_ready_from_authority(self):
        lock = {
            "authority": "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8",
            "schemaVersion": 8,
            "releaseVersion": "9.9.9",
            "status": "ready",
            "missingAuthorities": [],
            "partialAuthorities": [],
            "resolvedAuthorities": [{"id": "management-workload-oci-archive"}],
        }
        state = mod._management_archive_state(lock, "9.9.9")
        self.assertTrue(state["resolved"])
        self.assertEqual("ready", state["status"])
        lock["status"] = "incomplete"
        state = mod._management_archive_state(lock, "9.9.9")
        self.assertFalse(state["resolved"])
        self.assertEqual("pending", state["status"])

    def test_management_archive_partial_authority_never_reports_ready(self):
        lock = {
            "authority": "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8",
            "schemaVersion": 8,
            "releaseVersion": "9.9.9",
            "status": "ready",
            "missingAuthorities": [],
            "partialAuthorities": [{"id": "management-workload-oci-archive"}],
            "resolvedAuthorities": [{"id": "management-workload-oci-archive"}],
        }
        state = mod._management_archive_state(lock, "9.9.9")
        self.assertFalse(state["resolved"])
        self.assertEqual("pending", state["status"])

    def test_management_archive_authority_rejects_release_drift(self):
        lock = {
            "authority": "LAB_APPLIANCE_BUNDLE_ACQUISITION_LOCK_V8",
            "schemaVersion": 8,
            "releaseVersion": "9.9.8",
            "status": "incomplete",
            "missingAuthorities": ["management-workload-oci-archive"],
            "partialAuthorities": [],
            "resolvedAuthorities": [],
        }
        with self.assertRaisesRegex(RuntimeError, "RELEASE_DRIFT"):
            mod._management_archive_state(lock, "9.9.9")

    def test_plan_rejects_truth_model_tamper(self):
        plan = mod.build(ROOT)
        plan["spec"]["truthModel"]["physicalPassInferenceForbidden"] = False
        errors = mod.validate(plan, ROOT)
        self.assertTrue(any("truth model" in err for err in errors))

    def test_plan_rejects_toolchain_digest_tamper(self):
        plan = mod.build(ROOT)
        plan["spec"]["releaseToolchain"]["archiveSha256"] = "0" * 64
        errors = mod.validate(plan, ROOT)
        self.assertTrue(any("handoff plan drift" in err for err in errors))

    def test_stage_audit_fails_closed_on_toolchain_digest_mismatch(self):
        plan = mod.build(ROOT)
        tc = plan["spec"]["releaseToolchain"]
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td)
            p = stage / tc["stagePath"]
            p.parent.mkdir(parents=True)
            p.write_bytes(b"bad")
            missing, invalid = mod.stage_audit(stage, plan)
            self.assertIn(tc["stagePath"] + ":size", invalid)
            self.assertIn(plan["spec"]["componentAcquisition"]["stageManifestPath"], missing)

    def test_stage_audit_requires_management_batch_manifest(self):
        plan = mod.build(ROOT)
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td)
            missing, invalid = mod.stage_audit(stage, plan)
            self.assertEqual([], invalid)
            self.assertIn("management/external/stage-manifest.json", missing)

    def test_stage_entrypoint_preserves_symlink_identity(self):
        plan = mod.build(ROOT)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "real-stage"
            real.mkdir()
            link = root / "stage-link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            self.assertEqual(["stage-directory"], mod.stage_audit(mod._absolute_no_follow(link), plan)[0])

    def test_stage_audit_rejects_symlinked_toolchain(self):
        plan = mod.build(ROOT)
        tc = plan["spec"]["releaseToolchain"]
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td)
            real = stage / "real"
            real.write_bytes(b"x")
            p = stage / tc["stagePath"]
            p.parent.mkdir(parents=True)
            p.symlink_to(real)
            _, invalid = mod.stage_audit(stage, plan)
            self.assertIn(tc["stagePath"] + ":not-regular", invalid)

    def test_stage_seal_detects_byte_tamper(self):
        plan = mod.build(ROOT)
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td)
            payload = stage / "payload.bin"
            payload.write_bytes(b"exact")
            mod._atomic_json(stage / mod.SEAL_FILE, mod.build_stage_seal(stage, plan))
            self.assertEqual([], mod.verify_stage_seal(stage, plan))
            payload.write_bytes(b"tampered")
            errors = mod.verify_stage_seal(stage, plan)
            self.assertTrue(any("tamper" in err or "drift" in err for err in errors))

    def test_stage_inventory_rejects_symlink(self):
        plan = mod.build(ROOT)
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td)
            real = stage / "real.bin"
            real.write_bytes(b"x")
            (stage / "link.bin").symlink_to(real)
            with self.assertRaisesRegex(RuntimeError, "SYMLINK_FORBIDDEN"):
                mod.build_stage_seal(stage, plan)

    def test_command_plan_keeps_online_and_offline_authorities_separate(self):
        commands = mod.command_plan(mod.build(ROOT))
        connected = "\n".join(commands["connected"])
        self.assertIn("--stage-out", connected)
        self.assertIn("acquire_management_workload_batch.py --stage-out STAGE/management/external", connected)
        offline = "\n".join(commands["offline"])
        self.assertIn("--install-staged", offline)
        self.assertIn("acquire_management_workload_batch.py --verify-staged STAGE/management/external", offline)
        self.assertIn("acquire_release_build_toolchain.py --install", offline)
        self.assertIn("component_runtime_upgrade_matrix.py --write --check", offline)
        self.assertNotIn("# acquire each management external image", connected)

    def test_generated_repository_paths_use_posix_separators(self):
        plan = mod.build(ROOT)
        bad = []
        def walk(value, trail="root"):
            if isinstance(value, dict):
                for key, item in value.items():
                    walk(item, f"{trail}.{key}")
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, f"{trail}[{index}]")
            elif isinstance(value, str) and "\\" in value:
                bad.append((trail, value))
        walk(plan)
        self.assertEqual([], bad)

    def test_committed_plan_matches_canonical_authorities(self):
        path = ROOT / "lab" / "supply-chain-handoff-plan.json"
        plan = json.loads(path.read_text())
        self.assertEqual([], mod.validate(plan, ROOT))


if __name__ == "__main__":
    unittest.main()
