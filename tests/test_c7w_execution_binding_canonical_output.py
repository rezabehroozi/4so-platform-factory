import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_execution_binding_canonical_output",ROOT/"scripts"/"c7w_execution_bindings.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WExecutionBindingCanonicalOutputTests(unittest.TestCase):
    def test_only_canonical_private_output_is_admitted(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            expected=(root/mod.DEFAULT_OUTPUT).resolve()
            self.assertEqual(expected,mod.canonical_output_path(root,mod.DEFAULT_OUTPUT))
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_PATH_INVALID"):
                mod.canonical_output_path(root,Path(".state/private/custom-bindings.json"))


if __name__=="__main__":
    unittest.main()
