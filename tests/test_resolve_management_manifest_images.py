import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("resolve_management_manifest_images", ROOT / "scripts" / "resolve_management_manifest_images.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ResolveManagementManifestImagesTests(unittest.TestCase):
    def test_canonical_repository_strips_only_tag_or_digest(self):
        self.assertEqual("quay.io/example/controller", mod.canonical_repository("quay.io/example/controller:v1.2.3"))
        self.assertEqual("registry.example:5000/team/image", mod.canonical_repository("registry.example:5000/team/image:latest"))
        self.assertEqual("ghcr.io/team/image", mod.canonical_repository("ghcr.io/team/image@sha256:" + "a" * 64))

    def test_canonical_repository_rejects_unqualified_or_ambiguous(self):
        for value in ("busybox:latest", " no.example/team/image:tag", "example.com/"):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    mod.canonical_repository(value)


if __name__ == "__main__":
    unittest.main()
