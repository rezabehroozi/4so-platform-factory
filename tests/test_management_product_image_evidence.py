import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "management_product_image_evidence",
    ROOT / "scripts" / "management_product_image_evidence.py",
)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(mod)


class ManagementProductImageEvidenceTests(unittest.TestCase):
    def test_self_test(self):
        self.assertEqual(0, mod.self_test())

    def test_maintenance_toolset_authority_matches_product_runtime_contract(self):
        doc = json.loads((ROOT / "catalog" / "management-maintenance-toolset.json").read_text())
        self.assertEqual("MANAGEMENT_MAINTENANCE_TOOLSET_AUTHORITY_V1", doc["authority"])
        self.assertEqual("65532:65532", doc["defaultRuntimeUser"])
        self.assertTrue(doc["rootOverrideRequired"])
        self.assertFalse(doc["networkPackageInstallationAllowed"])
        self.assertEqual(
            {
                "aws","cat","cmp","cp","createdb","cut","dropdb","find","gunzip","gzip",
                "mkdir","pg_dump","pg_restore","psql","rm","sha256sum","tar","tr","wc",
            },
            set(doc["requiredExecutables"]),
        )

    def test_mutable_image_reference_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "REFERENCE_INVALID"):
            mod.exact_ref("platform.4so.local/management/platform-api:latest", "TEST")

    def test_false_runtime_probe_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "PROBE_INCOMPLETE"):
            mod.validate_probe({"execution": False}, {"execution"}, "TEST")

    def test_current_authorities_bind_external_receipt_to_plan(self):
        plan, external, toolset = mod.authorities(ROOT)
        self.assertEqual("MANAGEMENT_WORKLOAD_IMAGE_BUILD_PLAN_V5", plan["authority"])
        self.assertEqual("MANAGEMENT_WORKLOAD_EXTERNAL_IMAGE_RECEIPT_V1", external["authority"])
        self.assertEqual("MANAGEMENT_MAINTENANCE_TOOLSET_AUTHORITY_V1", toolset["authority"])


if __name__ == "__main__":
    unittest.main()
