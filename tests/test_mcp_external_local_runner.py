import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import run_mcp_external_interop as mod


class LocalC7WRunnerTests(unittest.TestCase):
    def test_capture_template_preserves_runtime_identity_and_exact_check_shape(self):
        packet={
            "clientId":"chatgpt",
            "clientSurface":"ChatGPT custom MCP",
            "campaignId":"mcp-interop-unit",
            "challengeSha256":"sha256:"+"a"*64,
            "endpoint":"https://mcp.example.test/mcp",
            "sourceCommitSHA":"b"*40,
            "runtimeVersion":"0.0.unit",
            "receiptRequirements":{"requestIds":list(mod.core.AUDITED_CHECKS)},
            "checks":[{"id":name} for name in mod.core.REQUIRED_CHECKS],
        }
        out=mod.capture_template(packet)
        self.assertEqual("MCP_EXTERNAL_CLIENT_CAPTURE_V1",out["authority"])
        self.assertEqual(packet["sourceCommitSHA"],out["sourceCommitSHA"])
        self.assertEqual(packet["runtimeVersion"],out["runtimeVersion"])
        self.assertEqual("",out["executedAt"])
        self.assertFalse(out["externalExecution"])
        self.assertFalse(out["credentialedExecution"])
        self.assertEqual(list(mod.core.REQUIRED_CHECKS),list(out["checks"]))
        for name,row in out["checks"].items():
            if name in mod.core.AUDITED_CHECKS:
                self.assertEqual({"passed":False,"requestId":""},row)
            else:
                self.assertEqual({"passed":False},row)

    def test_prepare_resume_avoids_live_registry_and_identity_calls(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"state"
            state.mkdir()
            campaign_path=state/"campaign.json"
            campaign_path.write_text("{}")
            source_sha="c"*40
            campaign={
                "campaignId":"mcp-interop-resume",
                "sourceCommitSHA":source_sha,
                "runtimeVersion":"0.0.unit",
            }
            args=SimpleNamespace(
                state_dir=state,
                matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
                endpoint="https://mcp.example.test/mcp",
                oauth_client_map=None,
                token_env="C7W_PLATFORM_ADMIN_TOKEN",
                source_commit_sha=source_sha,
            )
            def packet(_,__,client):
                return {
                    "clientId":client,
                    "clientSurface":mod.core.CLIENT_SURFACES[client],
                    "campaignId":campaign["campaignId"],
                    "challengeSha256":"sha256:"+("a"*64),
                    "endpoint":args.endpoint,
                    "sourceCommitSHA":source_sha,
                    "runtimeVersion":"0.0.unit",
                    "receiptRequirements":{"requestIds":list(mod.core.AUDITED_CHECKS)},
                    "checks":[{"id":name} for name in mod.core.REQUIRED_CHECKS],
                }
            with (
                mock.patch.object(mod.campaign_builder,"source_commit_sha",return_value=source_sha),
                mock.patch.object(mod.core,"load",return_value={"authority":mod.core.MATRIX_AUTHORITY,"spec":{}}),
                mock.patch.object(mod.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(mod.campaign_builder,"resume_existing",return_value=campaign),
                mock.patch.object(mod.campaign_builder,"runtime_identity_readback",side_effect=AssertionError("runtime readback must not run on resume")),
                mock.patch.object(mod.campaign_builder,"trusted_client_readback",side_effect=AssertionError("registry readback must not run on resume")),
                mock.patch.object(mod.campaign_builder,"live_preflight",side_effect=AssertionError("preflight must not run on resume")),
                mock.patch.object(mod.packet_builder,"packet",side_effect=packet),
            ):
                out=mod.prepare(args)
            self.assertTrue(out["resumed"])
            self.assertEqual(source_sha,out["sourceCommitSHA"])
            for client in mod.core.CLIENTS:
                self.assertTrue((state/"packets"/f"{client}.json").is_file())
                capture=json.loads((state/"capture-templates"/f"{client}.json").read_text())
                self.assertEqual(source_sha,capture["sourceCommitSHA"])
                self.assertEqual("0.0.unit",capture["runtimeVersion"])

    def test_status_without_campaign_is_explicitly_pending(self):
        with tempfile.TemporaryDirectory() as td:
            state=mod.secure_state_dir(Path(td)/"state")
            out=mod.progress_status(ROOT/"lab/mcp-external-client-interop-matrix.json",state)
            self.assertFalse(out["campaignPrepared"])
            self.assertFalse(out["complete"])
            self.assertEqual("chatgpt",out["nextClient"])
            self.assertEqual(list(mod.core.CLIENTS),out["missing"])


if __name__=="__main__":
    unittest.main()
