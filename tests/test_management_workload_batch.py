import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("acquire_management_workload_batch", ROOT / "scripts" / "acquire_management_workload_batch.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

class ManagementWorkloadBatchTests(unittest.TestCase):
    def test_queue_is_exact_and_complete(self):
        _, rows = mod.load_plan(ROOT)
        self.assertEqual(["forgejo", "keycloak", "postgresql", "zot"], [r["role"] for r in rows])
        self.assertEqual({"15.0.7", "26.7.3", "17.11", "2.1.20"}, {r["version"] for r in rows})
        self.assertTrue(all(r["tag"] != "latest" for r in rows))

    def test_diagnose_reports_current_missing_authority_without_fake_readiness(self):
        result = mod.diagnose(ROOT)
        self.assertEqual(mod.DIAGNOSTIC_AUTHORITY, result["authority"])
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual(["management-workload-oci-archive"], result["missingAuthorities"])
        self.assertFalse(result["managementWorkloadArchiveResolved"])
        self.assertTrue(result["canStartExternalAcquisition"])
        self.assertEqual([], result["pending"]["externalImages"])
        self.assertEqual(["forgejo", "keycloak", "postgresql", "zot"], result["externalReceipt"]["readyRoles"])
        self.assertTrue(result["externalReceipt"]["offlineVerified"])
        self.assertEqual("36115673607", result["externalReceipt"]["sourceRunId"])
        self.assertEqual(["api-runtime-base", "maintenance-toolchain-base", "static-runtime-base"], result["pending"]["baseImages"])
        self.assertEqual(["maintenance", "platform-agent", "platform-api", "platform-probe"], result["pending"]["productImages"])
        self.assertEqual(4, len(result["pending"]["manifestResolutions"]))
        self.assertGreaterEqual(len(result["blockers"]), 10)
        self.assertFalse(any(row["stage"] == "external-image" for row in result["blockers"]))
        self.assertEqual("resolve-base-product-and-manifest-images-then-assemble-management-workload-oci", result["nextAction"])
        self.assertNotIn("sha256:", json.dumps(result).lower())

    def test_tree_digest_is_deterministic_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/"a").write_bytes(b"a"); (root/"d").mkdir(); (root/"d"/"b").write_bytes(b"b")
            first = mod.tree_digest(root); second = mod.tree_digest(root)
            self.assertEqual(first, second)
            (root/"link").symlink_to(root/"a")
            with self.assertRaisesRegex(RuntimeError, "SYMLINK"):
                mod.tree_digest(root)

    def test_manifest_binds_release_digest_and_offline_network_policy(self):
        with tempfile.TemporaryDirectory() as td:
            release = Path(td)/"r.zip"; release.write_bytes(b"release")
            doc = mod.manifest([], release)
            self.assertEqual(mod.AUTHORITY, doc["spec"]["authority"])
            self.assertFalse(doc["spec"]["networkFetchRequiredForOfflineVerify"])
            self.assertEqual(mod.sha256_file(release), doc["spec"]["releaseFileSha256"])

    def test_validate_manifest_rejects_release_drift_before_owner_verify(self):
        _, rows = mod.load_plan(ROOT)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); release = root/"r.zip"; release.write_bytes(b"one")
            doc = mod.manifest([], release)
            release.write_bytes(b"two")
            with self.assertRaisesRegex(RuntimeError, "RELEASE_DRIFT"):
                mod.validate_manifest(root, doc, release, rows)

    def test_prepare_role_stage_dir_recovers_empty_failed_attempt_but_rejects_nonempty(self):
        with tempfile.TemporaryDirectory() as td:
            role = Path(td) / "forgejo"
            role.mkdir()
            mod.prepare_role_stage_dir(role)
            self.assertTrue(role.is_dir())
            self.assertEqual([], list(role.iterdir()))
            (role / "unknown.partial").write_text("do-not-delete")
            with self.assertRaisesRegex(RuntimeError, "ROLE_ALREADY_EXISTS"):
                mod.prepare_role_stage_dir(role)
            self.assertEqual("do-not-delete", (role / "unknown.partial").read_text())

    def test_acquire_parallelizes_missing_roles_and_reuses_verified_completed_role(self):
        rows = [
            {"role":"forgejo","repository":"codeberg.org/forgejo/forgejo","tag":"15.0.7","version":"15.0.7","selectionChannel":"forgejo-lts","selectionEvidenceURL":"https://forgejo.org/releases/"},
            {"role":"zot","repository":"ghcr.io/project-zot/zot-linux-amd64","tag":"v2.1.20","version":"2.1.20","selectionChannel":"zot-stable","selectionEvidenceURL":"https://github.com/project-zot/zot/releases/tag/v2.1.20"},
            {"role":"keycloak","repository":"quay.io/keycloak/keycloak","tag":"26.7.3","version":"26.7.3","selectionChannel":"keycloak-current-security","selectionEvidenceURL":"https://www.keycloak.org/2026/08/keycloak-2673-released"},
        ]
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td) / "stage"
            stage.mkdir()
            complete = stage / "forgejo"
            (complete / "layout").mkdir(parents=True)
            (complete / "acquisition-lock.json").write_text("{}")
            release = Path(td) / "release.zip"
            release.write_bytes(b"release")
            ctl = Path(td) / "platformctl"
            ctl.write_bytes(b"ctl")
            active = 0
            max_active = 0
            lock = threading.Lock()
            acquired = []
            verified = []

            def fake_run(cmd, timeout=1800):
                nonlocal active, max_active
                role = cmd[cmd.index("--role") + 1]
                if "acquire-external" in cmd:
                    acquired.append(role)
                    with lock:
                        active += 1
                        max_active = max(max_active, active)
                    time.sleep(0.08)
                    with lock:
                        active -= 1
                    return {"acquired": True}
                verified.append(role)
                return {"verified": True, "result": {"exactReference": rows[[r["role"] for r in rows].index(role)]["repository"] + "@sha256:" + "a"*64}}

            def fake_stage_entry(row, role_dir, verify_result):
                return {**row, "manifestDigest":"sha256:"+"a"*64, "exactReference":row["repository"]+"@sha256:"+"a"*64, "layoutPath":f"{row['role']}/layout", "lockPath":f"{row['role']}/acquisition-lock.json", "lockDigest":"sha256:"+"b"*64, "layoutTreeDigest":"sha256:"+"c"*64, "layoutFileCount":1, "layoutBytes":1}

            with mock.patch.object(mod, "load_plan", return_value=({}, rows)), mock.patch.object(mod, "run_json", side_effect=fake_run), mock.patch.object(mod, "stage_entry", side_effect=fake_stage_entry):
                mod.acquire(stage, release, ctl)

            self.assertNotIn("forgejo", acquired)
            self.assertEqual({"zot", "keycloak"}, set(acquired))
            self.assertEqual({"forgejo", "zot", "keycloak"}, set(verified))
            self.assertGreaterEqual(max_active, 2)
            doc = json.loads((stage / mod.MANIFEST).read_text())
            self.assertEqual(["forgejo", "keycloak", "zot"], [row["role"] for row in doc["spec"]["entries"]])

    def test_stage_entry_rejects_mutable_or_wrong_exact_reference(self):
        _, rows = mod.load_plan(ROOT); row = rows[0]
        with tempfile.TemporaryDirectory() as td:
            role = Path(td); (role/"layout").mkdir(); (role/"layout"/"index.json").write_text("{}")
            lock = {"authority":"MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2", "role":row["role"], "sourceRepository":row["repository"], "selectedVersion":row["version"], "sourceTag":row["tag"], "selectionChannel":row["selectionChannel"], "manifestDigest":"sha256:"+"a"*64, "exactReference":row["repository"]+":"+row["tag"]}
            (role/"acquisition-lock.json").write_text(json.dumps(lock))
            with self.assertRaisesRegex(RuntimeError, "EXACT_REFERENCE_INVALID"):
                mod.stage_entry(row, role, {"verified":True,"result":{"exactReference":lock["exactReference"]}})

    def test_management_stage_and_platformctl_reject_direct_symlinks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real_stage = root / "stage"
            real_stage.mkdir()
            stage_link = root / "stage-link"
            real_ctl = root / "platformctl"
            real_ctl.write_text("#!/bin/sh\\nexit 0\\n")
            real_ctl.chmod(0o755)
            ctl_link = root / "platformctl-link"
            release = root / "release.zip"
            release.write_bytes(b"release")
            try:
                stage_link.symlink_to(real_stage, target_is_directory=True)
                ctl_link.symlink_to(real_ctl)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "PLATFORMCTL_NOT_REAL_FILE"):
                mod.platformctl(str(ctl_link))
            with self.assertRaisesRegex(RuntimeError, "MANAGEMENT_STAGE_NOT_REAL_DIRECTORY"):
                mod.acquire(stage_link, release, real_ctl)

    def test_management_archive_output_rejects_direct_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "archive.tar"
            real.write_bytes(b"archive")
            link = root / "archive-link.tar"
            try:
                link.symlink_to(real)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "MANAGEMENT_ARCHIVE_OUTPUT_INVALID"):
                mod.output_archive_path(link)

if __name__ == "__main__": unittest.main()
