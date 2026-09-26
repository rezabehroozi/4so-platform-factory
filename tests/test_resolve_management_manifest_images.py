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

    def test_platform_digest_resolution_is_linux_amd64(self):
        calls = []
        original = mod.run
        try:
            mod.run = lambda cmd, timeout=900: calls.append((cmd, timeout)) or ("sha256:" + "b" * 64)
            got = mod.resolve_platform_digest(Path("/tmp/crane"), "registry.example/team/image:v1")
        finally:
            mod.run = original
        self.assertEqual("sha256:" + "b" * 64, got)
        self.assertEqual(
            ["/tmp/crane", "digest", "--platform", "linux/amd64", "registry.example/team/image:v1"],
            calls[0][0],
        )
        self.assertEqual(600, calls[0][1])

    def test_platform_digest_resolution_rejects_non_digest_output(self):
        original = mod.run
        try:
            mod.run = lambda cmd, timeout=900: "latest"
            with self.assertRaisesRegex(RuntimeError, "MANIFEST_IMAGE_DIGEST_INVALID"):
                mod.resolve_platform_digest(Path("/tmp/crane"), "registry.example/team/image:v1")
        finally:
            mod.run = original

    def test_canonical_repository_rejects_unqualified_or_ambiguous(self):
        for value in ("busybox:latest", " no.example/team/image:tag", "example.com/"):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    mod.canonical_repository(value)


if __name__ == "__main__":
    unittest.main()
