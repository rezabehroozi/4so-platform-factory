import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location(
    "fetch_mcp_external_audit_window_output_parent_race_test",
    ROOT/"scripts"/"fetch_mcp_external_audit_window.py",
)
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WAuditOutputParentRaceTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os,"symlink"),"symlink unavailable")
    def test_atomic_write_rejects_parent_swap_after_precheck(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            parent=root/"audits"; parent.mkdir()
            target=parent/"chatgpt.json"
            outside=Path(td)/"outside"; outside.mkdir()
            parked=root/"parked-audits"
            original=mod.core._prepare_output_parent
            swapped=False

            def prepare_then_swap(path,label):
                nonlocal swapped
                prepared=original(path,label)
                if not swapped:
                    parent.rename(parked)
                    parent.symlink_to(outside,target_is_directory=True)
                    swapped=True
                return prepared

            with (
                mock.patch.object(mod.core,"_prepare_output_parent",side_effect=prepare_then_swap),
                mock.patch.object(mod.core,"verify_server_audit",return_value={"auditExportSha256":"sha256:"+"0"*64}),
            ):
                with self.assertRaisesRegex(RuntimeError,r"MCP_EXTERNAL_AUDIT_OUTPUT_PARENT_(?:INVALID|CHANGED)"):
                    mod.atomic_write(target,b"[]\n",{},"chatgpt")

            self.assertFalse((outside/target.name).exists())


if __name__=="__main__":
    unittest.main()
