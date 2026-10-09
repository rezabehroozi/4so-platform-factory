import argparse
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_prepare_source_freeze",ROOT/"scripts"/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WPrepareSourceFreezeTests(unittest.TestCase):
    def args(self,root:Path,source_sha:str)->argparse.Namespace:
        private=root/"private"; private.mkdir()
        oauth=private/"oauth.json"; oauth.write_text("{}\n",encoding="utf-8")
        return argparse.Namespace(
            matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
            state_dir=root/"state",
            source_commit_sha=source_sha,
            oauth_client_map=oauth,
            endpoint="https://mcp.example.test/mcp",
            token_env="TOKEN",
            progress_out=root/"progress.json",
            evidence_out=root/"evidence.json",
        )

    def patches(self,source_sha:str,freeze_side_effect):
        campaign={"campaignId":"mcp-interop-test","sourceCommitSHA":source_sha,"runtimeVersion":"0.0.unit"}
        bindings={client:client+"-oauth" for client in mod.core.CLIENTS}
        trusted={client:{"trustedClientId":"trusted-"+client} for client in mod.core.CLIENTS}
        runtime={"sourceCommitSHA":source_sha,"version":"0.0.unit"}
        return (
            mock.patch.object(mod,"require_c7w_source_freeze",side_effect=freeze_side_effect),
            mock.patch.object(mod,"require_canonical_matrix",side_effect=lambda root,path:path),
            mock.patch.object(mod.campaign_builder,"source_commit_sha",return_value=source_sha),
            mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),
            mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),
            mock.patch.object(mod.campaign_builder,"load_oauth_bindings",return_value=(bindings,"sha256:"+"b"*64)),
            mock.patch.object(mod.campaign_builder,"runtime_identity_readback",return_value=runtime),
            mock.patch.object(mod.campaign_builder,"trusted_client_readback",return_value=trusted),
            mock.patch.object(mod.campaign_builder,"live_preflight",return_value={"authority":mod.core.CAMPAIGN_PREFLIGHT_AUTHORITY}),
            mock.patch.object(mod.campaign_builder,"prepare",return_value=campaign),
            mock.patch.object(mod.packet_builder,"packet",side_effect=lambda matrix,path,client:{"clientId":client}),
            mock.patch.object(mod,"capture_template",return_value={}),
            mock.patch.object(mod,"replacement_campaign_supersede_handoff",return_value={}),
            mock.patch.object(mod,"client_execution_handoff",side_effect=lambda state,client:{"clientId":client}),
            mock.patch.object(mod,"external_client_action",return_value={"nextActionCode":"RUN_EXTERNAL_CLIENT","nextCommand":[]}),
        )

    def test_source_unfreezes_during_live_readback_before_campaign_write(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source_sha="a"*40; args=self.args(root,source_sha)
            write=mock.patch.object(mod.core,"write_json_once_or_identical").start()
            self.addCleanup(mock.patch.stopall)
            with self.patches(source_sha,[None,RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")])[0] as freeze:
                remaining=self.patches(source_sha,[None])
            mock.patch.stopall()
            patches=self.patches(source_sha,[None,RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")])
            with patches[0],patches[1],patches[2],patches[3],patches[4],patches[5],patches[6],patches[7],patches[8],patches[9],patches[10],patches[11],patches[12],patches[13],patches[14],mock.patch.object(mod.core,"write_json_once_or_identical") as write:
                with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN"):
                    mod.prepare(args)
            write.assert_not_called()

    def test_source_unfreezes_after_packet_materialization_before_external_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source_sha="a"*40; args=self.args(root,source_sha)
            patches=self.patches(source_sha,[None,None,RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")])
            with patches[0],patches[1],patches[2],patches[3],patches[4],patches[5],patches[6],patches[7],patches[8],patches[9],patches[10],patches[11],patches[12],patches[13],patches[14],mock.patch.object(mod.core,"write_json_once_or_identical") as write:
                with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN"):
                    mod.prepare(args)
            self.assertGreater(write.call_count,0)


if __name__=="__main__":
    unittest.main()
