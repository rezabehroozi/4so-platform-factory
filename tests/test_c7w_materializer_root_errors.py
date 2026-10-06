import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def load(rel,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


execution=load("scripts/c7w_execution_bindings.py","c7w_execution_bindings_root_errors")
oauth=load("scripts/prepare_c7w_oauth_bindings.py","c7w_oauth_bindings_root_errors")


class C7WMaterializerRootErrorTests(unittest.TestCase):
    def test_execution_binding_invalid_root_uses_canonical_error(self):
        with tempfile.TemporaryDirectory() as td:
            missing=Path(td)/"missing-root"
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_EXECUTION_BINDINGS_GIT_ROOT_INVALID"):
                execution.git_head(missing)

    def test_oauth_binding_invalid_root_uses_canonical_error(self):
        with tempfile.TemporaryDirectory() as td:
            missing=Path(td)/"missing-root"
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_OAUTH_BINDINGS_REPOSITORY_ROOT_INVALID"):
                oauth.require_repository_root(missing)


if __name__=="__main__":
    unittest.main()
