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

    def test_admit_revalidates_existing_audit_with_normalized_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            state=mod.secure_state_dir(Path(td)/"state")
            p=mod.paths(state)
            client="chatgpt"
            packet_path=p["packets"]/(client+".json"); packet_path.write_text("{}")
            capture=Path(td)/"capture.json"; capture.write_text("{}")
            audit_path=p["audits"]/(client+".json"); audit_path.write_text("[]")
            raw_receipt={"authority":mod.core.RECEIPT_AUTHORITY,"clientId":client}
            normalized={"clientId":client,"requestIds":{},"executedAt":"2026-10-01T00:00:00Z","campaignCreatedAt":"2026-10-01T00:00:00Z","campaignExpiresAt":"2026-10-02T00:00:00Z","executionAuditWindowSeconds":60}
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",client=client,capture=capture,token_env="TOKEN",attempts=1,interval_seconds=0.0,progress_out=Path(td)/"progress.json",evidence_out=Path(td)/"evidence.json")
            with (
                mock.patch.object(mod.finalizer,"finalize",return_value=raw_receipt),
                mock.patch.object(mod.core,"write_json_once_or_identical"),
                mock.patch.object(mod.admission,"matrix_contract",return_value=({"protocol":"2026-07-28"},list(mod.core.REQUIRED_CHECKS),{})),
                mock.patch.object(mod.core,"verify_receipt",return_value=normalized) as verify_receipt,
                mock.patch.object(mod.core,"verify_server_audit",return_value={}) as verify_audit,
                mock.patch.object(mod.admission,"progress_lock"),
                mock.patch.object(mod.admission,"merge",return_value={"clients":[],"certifiedClientCount":0,"complete":False}),
                mock.patch.object(mod.core,"write_json_atomic_replace"),
                mock.patch.object(mod,"progress_status",return_value={"certified":[],"complete":False,"nextClient":"chatgpt"}),
            ):
                mod.admit(args)
            verify_receipt.assert_called_once()
            verify_audit.assert_called_once_with(audit_path,normalized,client)

    def test_status_without_state_is_explicitly_pending_and_read_only(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"missing-state"
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=Path(td)/"progress.json",evidence_out=Path(td)/"evidence.json")
            out=mod.status(args)
            self.assertFalse(state.exists())
            self.assertFalse(out["campaignPrepared"])
            self.assertFalse(out["complete"])
            self.assertEqual("chatgpt",out["nextClient"])
            self.assertEqual(list(mod.core.CLIENTS),out["missing"])


if __name__=="__main__":
    unittest.main()
