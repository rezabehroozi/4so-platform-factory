import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("prepare_c7w_oauth_root",ROOT/"scripts"/"prepare_c7w_oauth_bindings.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WOAuthRepositoryRootTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_repository_root_rejects_subdirectory_and_inherited_git_authority(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as other_td:
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test"); (root/"seed").write_text("x\n"); self.git(root,"add","seed"); self.git(root,"commit","-m","seed")
            other=Path(other_td); self.git(other,"init","-b","main")
            with mock.patch.dict(os.environ,{"GIT_DIR":str(other/".git"),"GIT_WORK_TREE":str(other)},clear=False):
                self.assertEqual(root.resolve(),mod.require_repository_root(root))
            child=root/"child"; child.mkdir()
            with self.assertRaisesRegex(RuntimeError,"REPOSITORY_ROOT_INVALID"):
                mod.require_repository_root(child)

    def test_followup_preflight_is_bound_to_same_repository_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve(); out=root/".state/private/c7w-oauth-client-bindings.json"
            command=mod.followup_preflight_command(root,out,"https://mcp.example.test/mcp","TOKEN")
        root_index=command.index("--root")+1
        self.assertEqual(str(root),command[root_index])
        self.assertIn(str(out),command)


if __name__=="__main__":
    unittest.main()
