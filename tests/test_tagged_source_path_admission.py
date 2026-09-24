import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("acquire_upstream_tagged_source", ROOT / "scripts" / "acquire_upstream_tagged_source.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class TaggedSourcePathAdmissionTests(unittest.TestCase):
    def test_platformctl_rejects_direct_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "platformctl"
            real.write_text("#!/bin/sh\nexit 0\n")
            real.chmod(0o755)
            link = root / "platformctl-link"
            try:
                link.symlink_to(real)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "PLATFORMCTL_NOT_EXECUTABLE"):
                mod._platformctl(str(link))

    def test_absolute_no_follow_preserves_output_symlink_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "bundle.zip"
            real.write_bytes(b"x")
            link = root / "bundle-link.zip"
            try:
                link.symlink_to(real)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            candidate = mod._absolute_no_follow(link)
            self.assertTrue(candidate.is_symlink())


if __name__ == "__main__":
    unittest.main()
