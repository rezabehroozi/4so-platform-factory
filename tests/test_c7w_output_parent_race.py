import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location(
    "seal_mcp_external_interop_output_parent_race_test",
    ROOT/"scripts"/"seal_mcp_external_interop.py",
)
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WOutputParentRaceTests(unittest.TestCase):
    def _assert_parent_swap_rejected(self,writer):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            parent=root/"state"; parent.mkdir()
            target=parent/"evidence.json"
            outside=Path(td)/"outside"; outside.mkdir()
            parked=root/"parked-state"
            original=mod._prepare_output_parent
            swapped=False

            def prepare_then_swap(path,label):
                nonlocal swapped
                prepared=original(path,label)
                if not swapped:
                    parent.rename(parked)
                    parent.symlink_to(outside,target_is_directory=True)
                    swapped=True
                return prepared

            with mock.patch.object(mod,"_prepare_output_parent",side_effect=prepare_then_swap):
                with self.assertRaisesRegex(RuntimeError,r"TEST_OUTPUT_OUTPUT_PARENT_(?:INVALID|CHANGED)"):
                    writer(target,{"value":1},"TEST_OUTPUT")

            self.assertFalse((outside/target.name).exists())

    @unittest.skipUnless(hasattr(os,"symlink"),"symlink unavailable")
    def test_once_or_identical_rejects_parent_swap_after_precheck(self):
        self._assert_parent_swap_rejected(mod.write_json_once_or_identical)

    @unittest.skipUnless(hasattr(os,"symlink"),"symlink unavailable")
    def test_atomic_replace_rejects_parent_swap_after_precheck(self):
        self._assert_parent_swap_rejected(mod.write_json_atomic_replace)


if __name__=="__main__":
    unittest.main()
