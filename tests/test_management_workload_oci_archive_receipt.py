import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "seal_management_workload_oci_archive",
    ROOT / "scripts" / "seal_management_workload_oci_archive.py",
)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(mod)


class ManagementWorkloadOCIArchiveReceiptTests(unittest.TestCase):
    def test_self_test(self):
        self.assertEqual(0, mod.self_test())

    def test_current_evidence_resolves_exact_twenty_runtime_images(self):
        external, manifest, product, images = mod.expected_images(ROOT)
        self.assertEqual(4, len(external["byRole"]))
        self.assertEqual(4, len(product["byRole"]))
        self.assertEqual(4, len(manifest["byAuthority"]))
        self.assertEqual(20, len(images))
        self.assertEqual(images, sorted(images))
        self.assertEqual(len(images), len(set(images)))
        for ref in images:
            self.assertRegex(ref, r"^[^\s@]+@sha256:[0-9a-f]{64}$")

    def test_base_images_are_not_runtime_archive_addresses(self):
        _, _, product, images = mod.expected_images(ROOT)
        bases = {row["exactReference"] for row in product["byBaseRole"].values()}
        self.assertTrue(bases)
        self.assertTrue(bases.isdisjoint(images))


if __name__ == "__main__":
    unittest.main()
