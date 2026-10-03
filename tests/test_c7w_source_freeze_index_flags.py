import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_source_freeze_test",ROOT/"scripts/run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WSourceFreezeIndexFlagTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def repo(self,root):
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        tracked=root/"source.txt"; tracked.write_text("exact\n",encoding="utf-8")
        self.git(root,"add","source.txt"); self.git(root,"commit","-m","initial")
        return tracked

    def test_assume_unchanged_cannot_hide_c7w_source_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); tracked=self.repo(root)
            mod.require_c7w_source_freeze(root)
            self.git(root,"update-index","--assume-unchanged","source.txt")
            tracked.write_text("masked-drift\n",encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"GIT_INDEX_FLAGS_FORBIDDEN"):
                mod.require_c7w_source_freeze(root)

    def test_skip_worktree_cannot_hide_c7w_source_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); tracked=self.repo(root)
            self.git(root,"update-index","--skip-worktree","source.txt")
            tracked.write_text("masked-drift\n",encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"GIT_INDEX_FLAGS_FORBIDDEN"):
                mod.require_c7w_source_freeze(root)


if __name__=="__main__":
    unittest.main()
