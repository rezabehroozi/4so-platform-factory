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
        self.assertEqual(17, len(spec["componentAcquisition"]["ready"]))
        self.assertEqual(0, len(spec["componentAcquisition"]["reviewBlocked"]))
        self.assertEqual(3, len(spec["componentAcquisition"]["runtimeHolds"]))
        self.assertEqual("RUNTIME_DEPENDENCY_TRANSITION_V1", spec["runtimeDependencyTransition"]["authority"])
        self.assertEqual(3, len(spec["componentAcquisition"]["alreadySourceLocked"]))
        self.assertEqual(4, len(spec["managementWorkloads"]["externalImages"]))
        self.assertEqual(4, len(spec["managementWorkloads"]["manifestImageResolution"]))
        self.assertEqual(20, len(spec["componentUpgradePairRequirements"]))
        self.assertEqual(0, sum(1 for row in spec["componentUpgradePairRequirements"] if row["pairState"] == "pair-present"))
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
        self.assertEqual({"cilium", "kyverno", "metallb"}, holds)
        self.assertTrue(holds.issubset(ready))
        for row in ca["runtimeHolds"]:
            self.assertRegex(row["selectedVersion"], r"^\d+\.\d+\.\d+$")
            self.assertNotEqual("eligible-after-source-resolution", row["runtimeStatus"])

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
        self.assertIn("--stage-out", "\n".join(commands["connected"]))
        offline = "\n".join(commands["offline"])
        self.assertIn("--install-staged", offline)
        self.assertIn("acquire_release_build_toolchain.py --install", offline)
        self.assertIn("component_runtime_upgrade_matrix.py --write --check", offline)

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
