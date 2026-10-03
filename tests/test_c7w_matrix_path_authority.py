import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop",ROOT/"scripts"/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WMatrixPathAuthorityTests(unittest.TestCase):
    def test_canonical_matrix_path_is_required(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            canonical=root/"lab"/"mcp-external-client-interop-matrix.json"
            canonical.parent.mkdir(); canonical.write_text("{}\n")
            self.assertEqual(canonical,mod.require_canonical_matrix(root,Path("lab/mcp-external-client-interop-matrix.json")))
            self.assertEqual(canonical,mod.require_canonical_matrix(root,canonical))

    def test_alternate_matrix_copy_is_rejected_before_external_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            canonical=root/"lab"/"mcp-external-client-interop-matrix.json"
            canonical.parent.mkdir(); canonical.write_text("{}\n")
            alternate=root/"lab"/"alternate-matrix.json"; alternate.write_text(canonical.read_text())
            with self.assertRaisesRegex(RuntimeError,"MATRIX_PATH_INVALID"):
                mod.require_canonical_matrix(root,alternate)

    def test_matrix_symlink_is_rejected_even_when_it_resolves_to_canonical_file(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            canonical=root/"lab"/"mcp-external-client-interop-matrix.json"
            canonical.parent.mkdir(); canonical.write_text("{}\n")
            link=root/"matrix-link.json"
            try:
                link.symlink_to(canonical)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"MATRIX_PATH_INVALID"):
                mod.require_canonical_matrix(root,link)


if __name__=="__main__":
    unittest.main()
