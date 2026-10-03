import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))

import c7w_preflight as preflight
import run_mcp_external_interop as runner


class C7WExecutionBindingAuthorityPropagationTests(unittest.TestCase):
    def test_ready_preflight_passes_exact_execution_binding_path_to_runner(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            private=root/".state/private"; private.mkdir(parents=True)
            oauth=private/"oauth.json"; oauth.write_text("{}",encoding="utf-8")
            execution=private/"custom-execution-bindings.json"; execution.write_text("{}",encoding="utf-8")
            source_sha="a"*40
            execution_doc={
                "authority":preflight.execution_bindings.AUTHORITY,
                "sourceCommitSHA":source_sha,
                "resources":{"foreignProjectId":"p2","sameProjectOperationId":"op1","selfApprovalRequestId":"ap1"},
                "credentialProfileContractAuthority":"MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1",
                "credentialProfileContractSha256":"sha256:"+"d"*64,
            }
            with (
                mock.patch.object(preflight.runner,"require_canonical_matrix",return_value=ROOT/"lab/mcp-external-client-interop-matrix.json"),
                mock.patch.object(preflight,"private_input_path",side_effect=lambda r,p: Path(p)),
                mock.patch.object(preflight,"private_path",side_effect=lambda r,p,require_file: Path(p)),
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
                out=preflight.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","https://mcp.example.test/mcp",oauth,"TOKEN",execution)
        self.assertTrue(out["ready"])
        self.assertIn("--execution-bindings",out["nextCommand"])
        index=out["nextCommand"].index("--execution-bindings")
        self.assertEqual(str(execution),out["nextCommand"][index+1])

    def test_prepare_embeds_exact_execution_binding_snapshot_in_campaign(self):
        source_sha="b"*40
        binding_doc={
            "authority":"MCP_EXTERNAL_EXECUTION_BINDINGS_V1",
            "sourceCommitSHA":source_sha,
            "resources":{"foreignProjectId":"p2","sameProjectOperationId":"op1","selfApprovalRequestId":"ap1"},
            "credentialProfileContractAuthority":"MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1",
            "credentialProfileContractSha256":"sha256:"+"e"*64,
        }
        binding_sha="sha256:"+"f"*64
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"state"
            execution=Path(td)/"custom-bindings.json"; execution.write_text("{}",encoding="utf-8")
            args=SimpleNamespace(
                state_dir=state,
                matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
                endpoint="https://mcp.example.test/mcp",
                oauth_client_map=Path(td)/"oauth.json",
                token_env="TOKEN",
                source_commit_sha=source_sha,
                execution_bindings=execution,
                progress_out=Path(td)/"progress.json",
                evidence_out=Path(td)/"evidence.json",
            )
            args.oauth_client_map.write_text("{}",encoding="utf-8")
            campaign={
                "campaignId":"mcp-interop-unit",
                "sourceCommitSHA":source_sha,
                "runtimeVersion":"0.0.unit",
                "clients":[],
            }
            with (
                mock.patch.object(runner,"require_c7w_source_freeze"),
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda r,p:p),
                mock.patch.object(runner.campaign_builder,"source_commit_sha",return_value=source_sha),
                mock.patch.object(runner.core,"load",return_value={"authority":runner.core.MATRIX_AUTHORITY,"spec":{}}),
                mock.patch.object(runner.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(runner.campaign_builder,"load_oauth_bindings",return_value=({c:c+"-oauth" for c in runner.core.CLIENTS},"sha256:"+"a"*64)),
                mock.patch.object(runner.campaign_builder,"runtime_identity_readback",return_value={"sourceCommitSHA":source_sha,"version":"0.0.unit"}),
                mock.patch.object(runner.campaign_builder,"trusted_client_readback",return_value={c:{} for c in runner.core.CLIENTS}),
                mock.patch.object(runner.campaign_builder,"live_preflight",return_value={}),
                mock.patch.object(runner.campaign_builder,"prepare",return_value=campaign),
                mock.patch.object(runner.execution_bindings,"load",return_value=(binding_doc,binding_sha)),
                mock.patch.object(runner.packet_builder,"packet",side_effect=RuntimeError("STOP_AFTER_CAMPAIGN")),
            ):
                with self.assertRaisesRegex(RuntimeError,"STOP_AFTER_CAMPAIGN"):
                    runner.prepare(args)
            persisted=json.loads((state/"campaign.json").read_text(encoding="utf-8"))
        self.assertEqual(binding_doc["resources"],persisted["executionBindings"])
        self.assertEqual(binding_sha,persisted["executionBindingsSha256"])
        self.assertEqual(binding_doc["credentialProfileContractSha256"],persisted["credentialProfileContractSha256"])


if __name__=="__main__":
    unittest.main()
