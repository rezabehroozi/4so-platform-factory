import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

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
        self.assertEqual(["forgejo", "keycloak", "postgresql", "zot"], result["pending"]["externalImages"])
        self.assertEqual(["api-runtime-base", "maintenance-toolchain-base", "static-runtime-base"], result["pending"]["baseImages"])
        self.assertEqual(["maintenance", "platform-agent", "platform-api", "platform-probe"], result["pending"]["productImages"])
        self.assertEqual(3, len(result["pending"]["manifestResolutions"]))
        self.assertGreaterEqual(len(result["blockers"]), 14)
        self.assertEqual("seal-and-verify-management-workload-oci-archive", result["nextAction"])
        self.assertNotIn("digest", json.dumps(result).lower())

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

    def test_stage_entry_rejects_mutable_or_wrong_exact_reference(self):
        _, rows = mod.load_plan(ROOT); row = rows[0]
        with tempfile.TemporaryDirectory() as td:
            role = Path(td); (role/"layout").mkdir(); (role/"layout"/"index.json").write_text("{}")
            lock = {"authority":"MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_ACQUISITION_V2", "role":row["role"], "sourceRepository":row["repository"], "selectedVersion":row["version"], "sourceTag":row["tag"], "selectionChannel":row["selectionChannel"], "manifestDigest":"sha256:"+"a"*64, "exactReference":row["repository"]+":"+row["tag"]}
            (role/"acquisition-lock.json").write_text(json.dumps(lock))
            with self.assertRaisesRegex(RuntimeError, "EXACT_REFERENCE_INVALID"):
                mod.stage_entry(row, role, {"verified":True,"result":{"exactReference":lock["exactReference"]}})

if __name__ == "__main__": unittest.main()
