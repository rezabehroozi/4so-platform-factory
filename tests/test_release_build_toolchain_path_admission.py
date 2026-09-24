import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "acquire_release_build_toolchain",
    ROOT / "scripts" / "acquire_release_build_toolchain.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ReleaseBuildToolchainPathAdmissionTests(unittest.TestCase):
    def test_verify_archive_rejects_direct_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "go.tar.gz"
            real.write_bytes(b"compiler")
            link = root / "go-link.tar.gz"
            try:
                link.symlink_to(real)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            candidate = {
                "archiveSize": real.stat().st_size,
                "archiveSha256": mod.sha256_file(real),
            }
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                mod.verify_archive(link, candidate)


if __name__ == "__main__":
    unittest.main()
