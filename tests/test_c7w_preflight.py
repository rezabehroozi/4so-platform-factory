import importlib.util
import os
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


class C7WPreflightTests(unittest.TestCase):
    def test_missing_inputs_are_machine_actionable_without_network(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{},clear=True):
            out=mod.preflight(Path(td),ROOT/"lab/mcp-external-client-interop-matrix.json","",None,"C7W_PLATFORM_ADMIN_TOKEN")
        self.assertFalse(out["ready"])
        self.assertEqual("PROVIDE_C7W_INPUTS",out["nextActionCode"])
        self.assertEqual(["C7W_MCP_ENDPOINT","C7W_OAUTH_CLIENT_MAP","C7W_PLATFORM_ADMIN_TOKEN"],out["requiredInputs"])
        self.assertEqual([],out["nextCommand"])
        self.assertFalse(out["physicalCertified"])

    def test_source_freeze_failure_is_not_misclassified_as_environment_input(self):
        with tempfile.TemporaryDirectory() as td:
            oauth=Path(td)/"oauth.json"; oauth.write_text("{}")
            with mock.patch.dict(os.environ,{"TOKEN":"secret"},clear=False), mock.patch.object(mod.runner,"require_c7w_source_freeze",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")):
                out=mod.preflight(Path(td),ROOT/"lab/mcp-external-client-interop-matrix.json","https://mcp.example.test/mcp",oauth,"TOKEN")
        self.assertFalse(out["ready"])
        self.assertEqual("RESTORE_C7W_SOURCE_FREEZE",out["nextActionCode"])
        self.assertEqual(["git","status","--short"],out["nextCommand"])
        self.assertEqual([],out["requiredInputs"])

    def test_runtime_source_drift_gets_deployment_action_not_generic_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); oauth=root/"oauth.json"; oauth.write_text("{}")
            with (
                mock.patch.dict(os.environ,{"TOKEN":"secret"},clear=False),
                mock.patch.object(mod.runner,"require_c7w_source_freeze"),
                mock.patch.object(mod.campaign,"source_commit_sha",return_value="a"*40),
                mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),
                mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(mod.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),
                mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=({c:c+"-oauth" for c in mod.core.CLIENTS},"sha256:"+"b"*64)),
                mock.patch.object(mod.campaign,"live_preflight",return_value={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY}),
                mock.patch.object(mod.campaign,"runtime_identity_readback",side_effect=RuntimeError("MCP_EXTERNAL_RUNTIME_SOURCE_DRIFT expected=a observed=b")),
            ):
                out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","https://mcp.example.test/mcp",oauth,"TOKEN")
        self.assertEqual("DEPLOY_C7W_CURRENT_SOURCE",out["nextActionCode"])
        self.assertEqual("a"*40,out["requiredSourceCommitSHA"])
        self.assertNotIn("secret",str(out))

    def test_ready_preflight_returns_exact_prepare_command_without_secret(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); oauth=root/"oauth.json"; oauth.write_text("{}")
            bindings={c:c+"-oauth" for c in mod.core.CLIENTS}
            trusted={c:{"trustedClientId":"trusted-"+c} for c in mod.core.CLIENTS}
            runtime={"authority":"MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1","product":"4SO Platform Factory","version":"0.0.unit","sourceCommitSHA":"a"*40}
            live={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY,"protocol":"2026-07-28"}
            with (
                mock.patch.dict(os.environ,{"TOKEN":"super-secret"},clear=False),
                mock.patch.object(mod.runner,"require_c7w_source_freeze"),
                mock.patch.object(mod.campaign,"source_commit_sha",return_value="a"*40),
                mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),
                mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(mod.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),
                mock.patch.object(mod.campaign,"load_oauth_bindings",return_value=(bindings,"sha256:"+"b"*64)),
                mock.patch.object(mod.campaign,"live_preflight",return_value=live),
                mock.patch.object(mod.campaign,"runtime_identity_readback",return_value=runtime),
                mock.patch.object(mod.campaign,"trusted_client_readback",return_value=trusted),
            ):
                out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","https://mcp.example.test/mcp",oauth,"TOKEN")
        self.assertTrue(out["ready"])
        self.assertEqual("RUN_C7W_PREPARE",out["nextActionCode"])
        self.assertEqual("a"*40,out["sourceCommitSHA"])
        self.assertEqual(4,out["trustedClientCount"])
        self.assertEqual("sha256:"+"b"*64,out["oauthClientBindingsSha256"])
        self.assertIn("scripts/run_mcp_external_interop.py",out["nextCommand"])
        self.assertIn("--endpoint",out["nextCommand"])
        self.assertIn("--oauth-client-map",out["nextCommand"])
        self.assertIn("--token-env",out["nextCommand"])
        self.assertNotIn("super-secret",str(out))
        self.assertFalse(out["physicalCertified"])


if __name__=="__main__":
    unittest.main()
