import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("c7w_preflight",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class C7WPreflightRootAuthorityTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_git_source_identity_comes_from_explicit_root_not_module_repo(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("root-authority\n")
            self.git(root,"add","seed.txt")
            self.git(root,"commit","-m","root authority")
            expected=self.git(root,"rev-parse","HEAD")
            self.assertEqual(expected,mod.git_source_commit(root))
            self.assertNotEqual("",expected)

    def test_private_oauth_path_must_live_under_ignored_state_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            private=root/".state"/"private"; private.mkdir(parents=True)
            oauth=private/"oauth.json"; oauth.write_text("{}")
            self.assertEqual(oauth,mod.private_input_path(root,Path(".state/private/oauth.json")))
            unsafe=root/"private"; unsafe.mkdir(); unsafe_oauth=unsafe/"oauth.json"; unsafe_oauth.write_text("{}")
            with self.assertRaisesRegex(RuntimeError,"PRIVATE_INPUT_PATH_INVALID"):
                mod.private_input_path(root,unsafe_oauth)
            outside=Path(td).parent/"outside.json"
            with self.assertRaisesRegex(RuntimeError,"PRIVATE_INPUT_PATH_INVALID"):
                mod.private_input_path(root,outside)

    def test_preflight_rejects_noncanonical_matrix_before_live_readback(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("root-authority\n")
            self.git(root,"add","seed.txt"); self.git(root,"commit","-m","root authority")
            (root/"lab").mkdir(); alternate=root/"lab"/"alternate.json"; alternate.write_text("{}")
            private=root/".state"/"private"; private.mkdir(parents=True); oauth=private/"oauth.json"; oauth.write_text("{}")
            with mock.patch.dict(os.environ,{"TOKEN":"secret"},clear=False), \
                 mock.patch.object(mod.campaign,"live_preflight",side_effect=AssertionError("live readback must not start for noncanonical matrix")):
                out=mod.preflight(root,Path("lab/alternate.json"),"https://mcp.example.test/mcp",Path(".state/private/oauth.json"),"TOKEN")
            self.assertFalse(out["ready"])
            self.assertEqual(["MCP_EXTERNAL_LOCAL_MATRIX_PATH_INVALID"],out["blockers"])
            self.assertEqual("RESTORE_C7W_SOURCE_FREEZE",out["nextActionCode"])

    def test_ready_command_uses_canonical_matrix_private_input_and_exact_root_sha(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("root-authority\n")
            self.git(root,"add","seed.txt")
            self.git(root,"commit","-m","root authority")
            source_sha=self.git(root,"rev-parse","HEAD")
            matrix=root/"lab"/"mcp-external-client-interop-matrix.json"; matrix.parent.mkdir(); matrix.write_text("{}")
            private=root/".state"/"private"; private.mkdir(parents=True); oauth=private/"oauth.json"; oauth.write_text("{}")
            bindings={c:c+"-oauth" for c in mod.core.CLIENTS}
            trusted={c:{"trustedClientId":"trusted-"+c} for c in mod.core.CLIENTS}
            runtime={"authority":"MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1","product":"4SO Platform Factory","version":"0.0.unit","sourceCommitSHA":source_sha}
            with (
                mock.patch.dict(os.environ,{"TOKEN":"secret"},clear=False),
                mock.patch.object(mod.runner,"require_c7w_source_freeze"),
                mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),
                mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(mod.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),
                mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=(bindings,"sha256:"+"b"*64)),
                mock.patch.object(mod.campaign,"live_preflight",return_value={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY}),
                mock.patch.object(mod.campaign,"runtime_identity_readback",return_value=runtime),
                mock.patch.object(mod.campaign,"trusted_client_readback",return_value=trusted),
            ):
                out=mod.preflight(root,Path("lab/mcp-external-client-interop-matrix.json"),"https://mcp.example.test/mcp",Path(".state/private/oauth.json"),"TOKEN")
            self.assertEqual(source_sha,out["sourceCommitSHA"])
            self.assertEqual(str(matrix),out["matrixPath"])
            self.assertEqual(str(oauth),out["oauthClientMapPath"])
            self.assertIn(str(oauth),out["nextCommand"])
            self.assertIn(str(matrix),out["nextCommand"])
            self.assertNotIn("secret",json.dumps(out))


if __name__=="__main__":
    unittest.main()
