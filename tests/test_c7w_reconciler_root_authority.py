import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("reconcile_c7w_trusted_clients_root_authority",ROOT/"scripts"/"reconcile_c7w_trusted_clients.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WReconcilerRootAuthorityTests(unittest.TestCase):
    def git(self,root:Path,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def repo(self,root:Path)->None:
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        (root/"tracked.txt").write_text("tracked\n",encoding="utf-8")
        self.git(root,"add","tracked.txt")
        self.git(root,"commit","-m","initial")

    def test_repository_root_rejects_subdirectory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir(); self.repo(root)
            nested=root/"nested"; nested.mkdir()
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_TRUSTED_CLIENT_REPOSITORY_ROOT_INVALID"):
                mod.require_repository_root(nested)

    def test_repository_root_ignores_inherited_git_environment(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)
            root=base/"repo"; root.mkdir(); self.repo(root)
            decoy=base/"decoy"; decoy.mkdir(); self.repo(decoy)
            injected={"GIT_DIR":str(decoy/".git"),"GIT_WORK_TREE":str(decoy)}
            with mock.patch.dict(os.environ,injected,clear=False):
                self.assertEqual(root.resolve(),mod.require_repository_root(root))

    def test_followup_preflight_uses_canonical_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir(); self.repo(root)
            resolved=mod.require_repository_root(root)
            command=mod.preflight_command(resolved,"https://example.invalid/mcp",resolved/".state/private/c7w-oauth-client-bindings.json","TOKEN")
            index=command.index("--root")
            self.assertEqual(str(root.resolve()),command[index+1])


if __name__=="__main__":
    unittest.main()
