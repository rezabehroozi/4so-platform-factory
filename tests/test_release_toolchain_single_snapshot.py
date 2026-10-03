import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class ReleaseToolchainSingleSnapshotTests(unittest.TestCase):
    def test_native_builder_reuses_one_toolchain_snapshot_for_go_and_cgo(self):
        source=(ROOT/"scripts"/"build_release_binaries.py").read_text(encoding="utf-8")
        start=source.index("def build(root:")
        end=source.index("\ndef main",start)
        block=source[start:end]
        self.assertEqual(1,block.count("admitted_toolchain_spec(root)"))
        self.assertIn("require_go_binary_identity(root,go_binary,base_env,toolchain_spec)",block)
        self.assertIn("require_cgo_toolchain_identity(root,base_env,toolchain_spec)",block)

    def test_exact_packager_reuses_one_toolchain_snapshot_for_go_and_cgo(self):
        source=(ROOT/"scripts"/"package_release_exact.py").read_text(encoding="utf-8")
        start=source.index("def require_exact_toolchain")
        end=source.index("\ndef ",start+1)
        block=source[start:end]
        self.assertEqual(1,block.count("admitted_toolchain_spec(root)"))
        self.assertIn("require_go_binary_identity(root,go_binary,env,toolchain_spec)",block)
        self.assertIn("require_cgo_toolchain_identity(root,env,toolchain_spec)",block)


if __name__=="__main__":
    unittest.main()
