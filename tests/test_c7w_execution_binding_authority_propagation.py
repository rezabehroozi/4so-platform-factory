import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))

import c7w_preflight as preflight


class C7WExecutionBindingAuthorityPropagationTests(unittest.TestCase):
    def test_ready_preflight_uses_single_canonical_execution_binding_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            private=root/".state/private"; private.mkdir(parents=True)
            oauth=private/"oauth.json"; oauth.write_text("{}",encoding="utf-8")
            execution=root/preflight.DEFAULT_EXECUTION_BINDING_REL; execution.write_text("{}",encoding="utf-8")
            source_sha="a"*40
            execution_doc={
                "authority":preflight.execution_bindings.AUTHORITY,
                "sourceCommitSHA":source_sha,
                "resources":{"foreignProjectId":"p2","sameProjectOperationId":"op1","selfApprovalRequestId":"ap1"},
                "credentialProfileContractAuthority":"MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1",
                "credentialProfileContractSha256":"sha256:"+"d"*64,
            }
            with (
                mock.patch.dict("os.environ",{"TOKEN":"admin-token"},clear=False),
                mock.patch.object(preflight.runner,"require_canonical_matrix",return_value=ROOT/"lab/mcp-external-client-interop-matrix.json"),
                mock.patch.object(preflight.runner,"require_c7w_source_freeze"),
                mock.patch.object(preflight,"git_source_commit",return_value=source_sha),
                mock.patch.object(preflight.campaign,"endpoint",return_value="https://mcp.example.test/mcp"),
                mock.patch.object(preflight.core,"load",return_value={"authority":preflight.core.MATRIX_AUTHORITY,"kind":"MCPExternalClientInteropMatrix","spec":{}}),
                mock.patch.object(preflight.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(preflight.campaign,"load_oauth_bindings",return_value=({c:c+"-oauth" for c in preflight.core.CLIENTS},"sha256:"+"b"*64)),
                mock.patch.object(preflight.execution_bindings,"load",return_value=(execution_doc,"sha256:"+"c"*64)),
                mock.patch.object(preflight.campaign,"live_preflight",return_value={"authority":preflight.core.CAMPAIGN_PREFLIGHT_AUTHORITY}),
                mock.patch.object(preflight.campaign,"runtime_identity_readback",return_value={"version":"0.0.unit","sourceCommitSHA":source_sha}),
                mock.patch.object(preflight.campaign,"trusted_client_readback",return_value={c:{} for c in preflight.core.CLIENTS}),
            ):
                out=preflight.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","https://mcp.example.test/mcp",oauth,"TOKEN",preflight.DEFAULT_EXECUTION_BINDING_REL)
        self.assertTrue(out["ready"])
        self.assertEqual(str(execution),out["executionBindingsPath"])
        self.assertNotIn("--execution-bindings",out["nextCommand"])

    def test_noncanonical_execution_binding_path_is_rejected_before_live_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            private=root/".state/private"; private.mkdir(parents=True)
            oauth=private/"oauth.json"; oauth.write_text("{}",encoding="utf-8")
            custom=private/"custom-execution-bindings.json"; custom.write_text("{}",encoding="utf-8")
            with mock.patch.dict("os.environ",{"TOKEN":"admin-token"},clear=False):
                out=preflight.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","https://mcp.example.test/mcp",oauth,"TOKEN",custom)
        self.assertFalse(out["ready"])
        self.assertEqual("REPAIR_C7W_EXECUTION_BINDINGS",out["nextActionCode"])
        self.assertIn("MCP_EXTERNAL_EXECUTION_BINDINGS_PATH_INVALID",out["blockers"])


if __name__=="__main__":
    unittest.main()
