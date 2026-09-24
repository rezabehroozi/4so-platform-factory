import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("acquire_upstream_helm", ROOT / "scripts" / "acquire_upstream_helm.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class UpstreamAcquisitionPathAdmissionTests(unittest.TestCase):
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
            with self.assertRaisesRegex(RuntimeError, "PLATFORMCTL_NOT_REGULAR_EXECUTABLE"):
                mod.platformctl_prefix(str(link))

    def test_values_input_rejects_direct_symlink_even_inside_repository(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            real = root / "values.yaml"
            real.write_text("replicas: 1\n")
            link = root / "values-link.yaml"
            try:
                link.symlink_to(real)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "VALUES_FILE_NOT_REGULAR"):
                mod.repo_value_inputs([link])

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
