import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/"scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0,str(SCRIPTS))
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_state_dir",SCRIPTS/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WStateDirBrokenSymlinkTests(unittest.TestCase):
    def make_broken_dir_symlink(self,link:Path,target:Path):
        try:
            os.symlink(target,link,target_is_directory=True)
        except (OSError,NotImplementedError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")

    def test_broken_parent_symlink_fails_with_canonical_state_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            broken=root/"broken-parent"
            self.make_broken_dir_symlink(broken,root/"missing-target")
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_STATE_PARENT_INVALID"):
                mod.secure_state_dir(broken/"state")

    def test_broken_state_symlink_fails_with_canonical_state_dir_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            state=root/"state"
            self.make_broken_dir_symlink(state,root/"missing-state-target")
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_STATE_DIR_INVALID"):
                mod.secure_state_dir(state)

    def test_broken_child_symlink_fails_with_canonical_child_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/"state"
            state.mkdir()
            broken=state/"packets"
            self.make_broken_dir_symlink(broken,state/"missing-packets-target")
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_STATE_CHILD_INVALID packets"):
                mod.secure_state_dir(state)


if __name__=="__main__":
    unittest.main()
