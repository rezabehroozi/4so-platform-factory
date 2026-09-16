import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_release", ROOT / "scripts" / "build_release.py")
BUILD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = BUILD
SPEC.loader.exec_module(BUILD)


class ReleaseSourceTreeBoundary(unittest.TestCase):
    def test_source_tree_symlink_is_rejected_instead_of_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repo"
            root.mkdir()
            outside = base / "outside-secret.txt"
            outside.write_text("must-not-be-packaged\n", encoding="utf-8")
            (root / "external-link.txt").symlink_to(outside)
            with self.assertRaisesRegex(SystemExit, "SOURCE_TREE_SYMLINK_FORBIDDEN"):
                BUILD.source_files(root, apply_excludes=True)


    def test_product_owned_durable_temp_is_rejected_from_release_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            (root / "catalog" / "components").mkdir(parents=True)
            residue = root / "catalog" / "components" / ".durable-crash-residue"
            residue.write_text("interrupted replacement\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "SOURCE_TREE_STALE_DURABLE_TEMP_FORBIDDEN"):
                BUILD.source_files(root, apply_excludes=True)

    def test_go_toolchain_version_uses_explicit_go_authority_from_environment(self):
        completed = mock.Mock(stdout="go version go1.27.1 linux/amd64\n")
        with mock.patch.dict(BUILD.os.environ, {"GO": "/opt/4so/go1.27.1/bin/go"}, clear=False):
            with mock.patch.object(BUILD.subprocess, "run", return_value=completed) as run:
                self.assertEqual("go version go1.27.1 linux/amd64", BUILD.go_toolchain_version())
        run.assert_called_once_with(["/opt/4so/go1.27.1/bin/go", "version"], capture_output=True, text=True, check=True)


if __name__ == "__main__":
    unittest.main()
