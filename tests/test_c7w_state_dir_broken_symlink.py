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
    def test_broken_parent_symlink_fails_with_canonical_state_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            broken=root/"broken-parent"
            try:
                os.symlink(root/"missing-target",broken,target_is_directory=True)
            except (OSError,NotImplementedError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_STATE_PARENT_INVALID"):
                mod.secure_state_dir(broken/"state")


if __name__=="__main__":
    unittest.main()
