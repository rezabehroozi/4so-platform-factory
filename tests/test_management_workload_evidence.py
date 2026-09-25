import json
import shutil
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from management_workload_evidence import AUTHORITY, external_receipt_evidence


class ManagementWorkloadEvidenceTests(unittest.TestCase):
    def test_current_receipt_is_exact_plan_bound_external_evidence_only(self):
        plan = json.loads((ROOT / "lab" / "management-workload-image-build-plan.json").read_text())
        evidence = external_receipt_evidence(ROOT, plan)
        self.assertEqual(AUTHORITY, evidence["authority"])
        self.assertEqual("36115673607", evidence["sourceRunId"])
        self.assertEqual({"forgejo", "keycloak", "postgresql", "zot"}, set(evidence["byRole"]))
        self.assertTrue(evidence["offlineVerified"])
        self.assertFalse(evidence["archiveReady"])
        self.assertFalse(evidence["runtimeCertified"])
        self.assertFalse(evidence["physicalCertified"])

    def test_receipt_plan_digest_tamper_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lab").mkdir()
            for name in ("management-workload-image-build-plan.json", "management-workload-external-image-receipt.json"):
                shutil.copy2(ROOT / "lab" / name, root / "lab" / name)
            receipt_path = root / "lab" / "management-workload-external-image-receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["planDigest"] = "sha256:" + "0" * 64
            receipt_path.write_text(json.dumps(receipt))
            plan = json.loads((root / "lab" / "management-workload-image-build-plan.json").read_text())
            with self.assertRaisesRegex(RuntimeError, "PLAN_DIGEST_DRIFT"):
                external_receipt_evidence(root, plan)

    def test_receipt_scope_inflation_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lab").mkdir()
            for name in ("management-workload-image-build-plan.json", "management-workload-external-image-receipt.json"):
                shutil.copy2(ROOT / "lab" / name, root / "lab" / name)
            receipt_path = root / "lab" / "management-workload-external-image-receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["archiveReady"] = True
            receipt_path.write_text(json.dumps(receipt))
            plan = json.loads((root / "lab" / "management-workload-image-build-plan.json").read_text())
            with self.assertRaisesRegex(RuntimeError, "SCOPE_INFLATION"):
                external_receipt_evidence(root, plan)


if __name__ == "__main__":
    unittest.main()
