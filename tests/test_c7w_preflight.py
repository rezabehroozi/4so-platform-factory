import importlib.util
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

class C7WPreflightTests(unittest.TestCase):
    def git(self,root,*args): return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()
    def execution_doc(self,source_sha):
        return {"authority":mod.execution_bindings.AUTHORITY,"sourceCommitSHA":source_sha,"resources":{"foreignProjectId":"project-foreign","sameProjectOperationId":"operation-1","selfApprovalRequestId":"approval-1"},"credentialProfileContractAuthority":mod.execution_bindings.credential_contract()["authority"],"credentialProfileContractSha256":mod.execution_bindings.credential_contract_digest()}

    def test_missing_inputs_are_machine_actionable_without_network(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{},clear=True): out=mod.preflight(Path(td),ROOT/"lab/mcp-external-client-interop-matrix.json","",None,"C7W_PLATFORM_ADMIN_TOKEN")
        self.assertFalse(out["ready"]); self.assertEqual("PROVIDE_C7W_INPUTS",out["nextActionCode"]); self.assertEqual(["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],out["requiredInputs"]); self.assertEqual([],out["nextCommand"]); self.assertFalse(out["physicalCertified"])

    def test_missing_oauth_map_with_other_inputs_ready_returns_private_materializer_handoff(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{"TOKEN":"admin-token"},clear=True):
            root=Path(td).resolve(); out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","https://mcp.example.test/mcp",None,"TOKEN")
        self.assertFalse(out["ready"]); self.assertEqual("PREPARE_C7W_OAUTH_BINDINGS",out["nextActionCode"]); self.assertEqual(["C7W_CHATGPT_OAUTH_CLIENT_ID","C7W_CLAUDE_OAUTH_CLIENT_ID","C7W_GEMINI_OAUTH_CLIENT_ID","C7W_GROK_OAUTH_CLIENT_ID"],out["requiredInputs"]); self.assertIn("scripts/prepare_c7w_oauth_bindings.py",out["nextCommand"]); self.assertNotIn("admin-token",str(out)); self.assertEqual(str(root),out["workingDirectory"]); root_arg=out["nextCommand"].index("--root")+1; self.assertEqual(str(root),out["nextCommand"][root_arg])

    def test_existing_source_state_routes_to_status_without_secrets_or_network(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{},clear=True):
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test"); (root/"seed.txt").write_text("seed\n"); self.git(root,"add","seed.txt"); self.git(root,"commit","-m","seed"); source_sha=self.git(root,"rev-parse","HEAD"); state=root/f".state/c7w-external-interop-{source_sha[:12]}"; state.mkdir(parents=True)
            with mock.patch.object(mod.campaign,"live_preflight",side_effect=AssertionError("network must not run before status recovery")): out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","",None,"C7W_PLATFORM_ADMIN_TOKEN")
        self.assertFalse(out["ready"]); self.assertEqual("RUN_C7W_STATUS",out["nextActionCode"]); self.assertEqual([],out["requiredInputs"]); self.assertEqual(source_sha,out["sourceCommitSHA"]); self.assertEqual("status",out["nextCommand"][-1]); self.assertNotIn("C7W_PLATFORM_ADMIN_TOKEN",str(out))

    def test_missing_local_state_with_canonical_progress_stops_before_new_inputs(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{},clear=True):
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test"); (root/"seed.txt").write_text("seed\n"); self.git(root,"add","seed.txt"); self.git(root,"commit","-m","seed"); source_sha=self.git(root,"rev-parse","HEAD"); lab=root/"lab"; lab.mkdir(); (lab/"mcp-external-client-interop-progress.json").write_text("{}\n")
            with mock.patch.object(mod.campaign,"live_preflight",side_effect=AssertionError("network must not run when canonical progress outlives local state")): out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","",None,"C7W_PLATFORM_ADMIN_TOKEN")
        self.assertFalse(out["ready"]); self.assertEqual("RESTORE_C7W_LOCAL_STATE",out["nextActionCode"]); self.assertEqual(source_sha,out["sourceCommitSHA"]); self.assertIn("lab/mcp-external-client-interop-progress.json",out["nextCommand"])

    def test_source_freeze_failure_is_not_misclassified_as_environment_input(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private=root/".state/private"; private.mkdir(parents=True); oauth=private/"oauth.json"; oauth.write_text("{}")
            with mock.patch.dict(os.environ,{"TOKEN":"secret"},clear=False), mock.patch.object(mod.runner,"require_c7w_source_freeze",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")): out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","https://mcp.example.test/mcp",oauth,"TOKEN")
        self.assertEqual("RESTORE_C7W_SOURCE_FREEZE",out["nextActionCode"]); self.assertEqual(["git","status","--short"],out["nextCommand"])

    def test_runtime_source_drift_gets_deployment_action_not_generic_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private=root/".state/private"; private.mkdir(parents=True); oauth=private/"oauth.json"; oauth.write_text("{}"); execution=private/"c7w-execution-bindings.json"; execution.write_text("{}")
            canonical=ROOT/"lab/mcp-external-client-interop-matrix.json"; source_sha="a"*40
            with (mock.patch.dict(os.environ,{"TOKEN":"secret"},clear=False),mock.patch.object(mod.runner,"require_c7w_source_freeze"),mock.patch.object(mod.runner,"require_canonical_matrix",return_value=canonical),mock.patch.object(mod,"git_source_commit",return_value=source_sha),mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),mock.patch.object(mod.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=({c:c+"-oauth" for c in mod.core.CLIENTS},"sha256:"+"b"*64)),mock.patch.object(mod.execution_bindings,"load",return_value=(self.execution_doc(source_sha),"sha256:"+"d"*64)),mock.patch.object(mod.campaign,"live_preflight",return_value={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY}),mock.patch.object(mod.campaign,"runtime_identity_readback",side_effect=RuntimeError("MCP_EXTERNAL_RUNTIME_SOURCE_DRIFT expected=a observed=b"))): out=mod.preflight(root,canonical,"https://mcp.example.test/mcp",oauth,"TOKEN")
        self.assertEqual("DEPLOY_C7W_CURRENT_SOURCE",out["nextActionCode"]); self.assertEqual(source_sha,out["requiredSourceCommitSHA"]); self.assertNotIn("secret",str(out))

    def test_ready_preflight_returns_exact_prepare_command_without_secret(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private=root/".state/private"; private.mkdir(parents=True); oauth=private/"oauth.json"; oauth.write_text("{}"); execution=private/"c7w-execution-bindings.json"; execution.write_text("{}")
            canonical=ROOT/"lab/mcp-external-client-interop-matrix.json"; source_sha="a"*40; bindings={c:c+"-oauth" for c in mod.core.CLIENTS}; trusted={c:{"trustedClientId":"trusted-"+c} for c in mod.core.CLIENTS}; runtime={"authority":"MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1","product":"4SO Platform Factory","version":"0.0.unit","sourceCommitSHA":source_sha}; live={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY,"protocol":"2026-07-28"}
            with (mock.patch.dict(os.environ,{"TOKEN":"super-secret"},clear=False),mock.patch.object(mod.runner,"require_c7w_source_freeze"),mock.patch.object(mod.runner,"require_canonical_matrix",return_value=canonical),mock.patch.object(mod,"git_source_commit",return_value=source_sha),mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),mock.patch.object(mod.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=(bindings,"sha256:"+"b"*64)),mock.patch.object(mod.execution_bindings,"load",return_value=(self.execution_doc(source_sha),"sha256:"+"d"*64)),mock.patch.object(mod.campaign,"live_preflight",return_value=live),mock.patch.object(mod.campaign,"runtime_identity_readback",return_value=runtime),mock.patch.object(mod.campaign,"trusted_client_readback",return_value=trusted)): out=mod.preflight(root,canonical,"https://mcp.example.test/mcp",oauth,"TOKEN")
        self.assertTrue(out["ready"]); self.assertEqual("RUN_C7W_PREPARE",out["nextActionCode"]); self.assertEqual(source_sha,out["sourceCommitSHA"]); self.assertEqual(4,out["trustedClientCount"]); self.assertEqual("sha256:"+"b"*64,out["oauthClientBindingsSha256"]); self.assertEqual("sha256:"+"d"*64,out["executionBindingsSha256"]); self.assertEqual(str(execution),out["executionBindingsPath"]); self.assertIn("scripts/run_mcp_external_interop.py",out["nextCommand"]); self.assertNotIn("super-secret",str(out)); self.assertFalse(out["physicalCertified"])

if __name__=="__main__": unittest.main()