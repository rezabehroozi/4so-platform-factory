import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_preflight_invalid_root",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WPreflightInvalidRootTests(unittest.TestCase):
    def test_git_source_commit_maps_missing_root_to_canonical_error(self):
        with tempfile.TemporaryDirectory() as td:
            missing=Path(td)/"missing-root"
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_SOURCE_REPOSITORY_INVALID"):
                mod.git_source_commit(missing)


if __name__=="__main__":
    unittest.main()
