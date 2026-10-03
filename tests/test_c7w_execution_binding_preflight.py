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
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WExecutionBindingPreflightTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def repo(self,root:Path)->str:
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        (root/"seed.txt").write_text("seed\n")
        self.git(root,"add","seed.txt"); self.git(root,"commit","-m","seed")
        return self.git(root,"rev-parse","HEAD")

    def test_missing_execution_bindings_blocks_before_live_network(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{"TOKEN":"admin-token"},clear=True):
            root=Path(td); source_sha=self.repo(root)
            private=root/".state/private"; private.mkdir(parents=True)
            oauth=private/"oauth.json"; oauth.write_text("{}")
            canonical=ROOT/"lab/mcp-external-client-interop-matrix.json"
            with (
                mock.patch.object(mod.runner,"require_canonical_matrix",return_value=canonical),
                mock.patch.object(mod.runner,"require_c7w_source_freeze"),
                mock.patch.object(mod,"git_source_commit",return_value=source_sha),
                mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=({c:c+"-oauth" for c in mod.core.CLIENTS},"sha256:"+"b"*64)),
                mock.patch.object(mod.campaign,"live_preflight",side_effect=AssertionError("network must not run before execution bindings")),
            ):
                out=mod.preflight(root,canonical,"https://mcp.example.test/mcp",oauth,"TOKEN")
        self.assertFalse(out["ready"])
        self.assertEqual("PREPARE_C7W_EXECUTION_BINDINGS",out["nextActionCode"])
        self.assertEqual([
            "C7W_FOREIGN_PROJECT_ID","C7W_SAME_PROJECT_OPERATION_ID","C7W_SELF_APPROVAL_REQUEST_ID",
        ],out["requiredInputs"])
        self.assertIn("scripts/c7w_execution_bindings.py",out["nextCommand"])
        self.assertIn(".state/private/c7w-execution-bindings.json",out["nextCommand"])
        self.assertNotIn("admin-token",str(out))

    def test_ready_preflight_reports_exact_execution_binding_digest(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{"TOKEN":"admin-token"},clear=True):
            root=Path(td); source_sha=self.repo(root)
            private=root/".state/private"; private.mkdir(parents=True)
            oauth=private/"oauth.json"; oauth.write_text("{}")
            execution=private/"c7w-execution-bindings.json"; execution.write_text("{}")
            canonical=ROOT/"lab/mcp-external-client-interop-matrix.json"
            bindings={c:c+"-oauth" for c in mod.core.CLIENTS}
            trusted={c:{"trustedClientId":"trusted-"+c} for c in mod.core.CLIENTS}
            runtime={"authority":"MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1","product":"4SO Platform Factory","version":"0.0.unit","sourceCommitSHA":source_sha}
            live={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY,"protocol":"2026-07-28"}
            execution_doc={
                "authority":"MCP_EXTERNAL_EXECUTION_BINDINGS_V1",
                "sourceCommitSHA":source_sha,
                "resources":{"foreignProjectId":"project-foreign","sameProjectOperationId":"operation-1","selfApprovalRequestId":"approval-1"},
                "credentialProfileContractAuthority":"MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1",
                "credentialProfileContractSha256":"sha256:"+"c"*64,
            }
            with (
                mock.patch.object(mod.runner,"require_canonical_matrix",return_value=canonical),
                mock.patch.object(mod.runner,"require_c7w_source_freeze"),
                mock.patch.object(mod,"git_source_commit",return_value=source_sha),
                mock.patch.object(mod.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),
                mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=(bindings,"sha256:"+"b"*64)),
                mock.patch.object(mod.execution_bindings,"load",return_value=(execution_doc,"sha256:"+"d"*64)),
                mock.patch.object(mod.campaign,"live_preflight",return_value=live),
                mock.patch.object(mod.campaign,"runtime_identity_readback",return_value=runtime),
                mock.patch.object(mod.campaign,"trusted_client_readback",return_value=trusted),
            ):
                out=mod.preflight(root,canonical,"https://mcp.example.test/mcp",oauth,"TOKEN")
        self.assertTrue(out["ready"])
        self.assertEqual("sha256:"+"d"*64,out["executionBindingsSha256"])
        self.assertEqual(str(execution),out["executionBindingsPath"])
        self.assertIn("RUN_C7W_PREPARE",out["nextActionCode"])
        self.assertNotIn("admin-token",str(out))


if __name__=="__main__": unittest.main()
