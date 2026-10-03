import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop",ROOT/"scripts"/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WGitRootAuthorityTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_source_freeze_rejects_subdirectory_as_repository_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("seed\n")
            self.git(root,"add","seed.txt"); self.git(root,"commit","-m","seed")
            child=root/"child"; child.mkdir()
            with self.assertRaisesRegex(RuntimeError,"GIT_ROOT_INVALID"):
                mod.require_c7w_source_freeze(child)

    def test_source_freeze_accepts_exact_repository_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("seed\n")
            self.git(root,"add","seed.txt"); self.git(root,"commit","-m","seed")
            mod.require_c7w_source_freeze(root)


if __name__=="__main__":
    unittest.main()
