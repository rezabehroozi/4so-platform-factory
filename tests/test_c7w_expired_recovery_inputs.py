import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_expired_inputs",ROOT/"scripts/run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class C7WExpiredRecoveryInputTests(unittest.TestCase):
    def test_expired_campaign_replacement_declares_prepare_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state=mod.secure_state_dir(root/"state")
            (state/"campaign.json").write_text('{"campaignId":"mcp-interop-expired-inputs"}',encoding="utf-8")
            progress=root/"progress.json"
            progress.write_text("{}",encoding="utf-8")
            args=SimpleNamespace(
                state_dir=state,
                matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
                progress_out=progress,
                evidence_out=root/"evidence.json",
            )
            with mock.patch.object(mod,"progress_status",side_effect=RuntimeError("MCP_EXTERNAL_CAMPAIGN_EXPIRED")):
                out=mod.status(args)
        self.assertEqual("PREPARE_REPLACEMENT_C7W_CAMPAIGN",out["nextActionCode"])
        self.assertEqual([
            "C7W_MCP_ENDPOINT",
            "C7W_OAUTH_CLIENT_MAP",
            "C7W_PLATFORM_ADMIN_TOKEN",
        ],out["requiredInputs"])
        self.assertEqual("prepare",out["nextCommand"][-1])

    def test_supersede_recovery_environment_enables_first_replacement_admit(self):
        argv=[
            "--state-dir",".state/replacement",
            "admit",
            "--client","chatgpt",
            "--capture",".state/replacement/captures/chatgpt.capture.json",
        ]
        with mock.patch.dict("os.environ",{"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"true"},clear=False):
            args=mod.parser().parse_args(argv)
        self.assertTrue(args.allow_campaign_supersede)

    def test_supersede_recovery_environment_is_fail_closed_by_default(self):
        argv=[
            "--state-dir",".state/replacement",
            "admit",
            "--client","chatgpt",
            "--capture",".state/replacement/captures/chatgpt.capture.json",
        ]
        with mock.patch.dict("os.environ",{"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"false"},clear=False):
            args=mod.parser().parse_args(argv)
        self.assertFalse(args.allow_campaign_supersede)

    def test_stale_source_rerun_preserves_incomplete_progress_supersede_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state=mod.secure_state_dir(root/"state")
            (state/"campaign.json").write_text('{"sourceCommitSHA":"1111111111111111111111111111111111111111"}',encoding="utf-8")
            progress=root/"progress.json"
            progress.write_text("{}",encoding="utf-8")
            args=SimpleNamespace(
                state_dir=state,
                matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
                progress_out=progress,
                evidence_out=root/"evidence.json",
            )
            current="2"*40
            with (
                mock.patch.object(mod,"progress_status",return_value={
                    "complete":False,
                    "certified":["chatgpt"],
                    "missing":["claude","gemini","grok"],
                    "nextClient":"claude",
                    "campaignPrepared":True,
                }),
                mock.patch.object(mod,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
                mock.patch.object(mod.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout=current+"\n")),
            ):
                out=mod.status(args)
        self.assertEqual("RERUN_C7W_ON_CURRENT_SOURCE",out["nextActionCode"])
        self.assertTrue(out["replacementAdmitRequiresCampaignSupersede"])
        self.assertEqual({"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"true"},out["followupAdmitEnvironment"])
        self.assertEqual("prepare",out["nextCommand"][-1])


if __name__=="__main__":
    unittest.main()
