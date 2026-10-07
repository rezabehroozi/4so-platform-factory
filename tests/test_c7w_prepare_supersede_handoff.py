import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_prepare_supersede",ROOT/"scripts/run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class C7WPrepareSupersedeHandoffTests(unittest.TestCase):
    def test_replacement_campaign_carries_first_admit_supersede_fence(self):
        with tempfile.TemporaryDirectory() as td:
            progress=Path(td)/"progress.json"
            progress.write_text(json.dumps({
                "campaignId":"old-campaign",
                "certifiedClientCount":1,
                "complete":False,
                "clients":[{"clientId":"chatgpt"}],
            }),encoding="utf-8")
            out=mod.replacement_campaign_supersede_handoff(progress,{"campaignId":"new-campaign"},resumed=False)
        self.assertTrue(out["replacementAdmitRequiresCampaignSupersede"])
        self.assertEqual({"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"true"},out["followupAdmitEnvironment"])
        self.assertEqual({"C7W_ALLOW_CAMPAIGN_SUPERSEDE":"true"},out["postExternalExecutionEnvironment"])

    def test_machine_actionable_first_admit_command_carries_supersede_flag(self):
        command=["python","scripts/run_mcp_external_interop.py","admit","--client","chatgpt"]
        result={
            "nextClientHandoff":{"admitCommand":list(command)},
            "postExternalExecutionCommand":list(command),
        }
        mod.apply_replacement_campaign_supersede_command(result,{
            "replacementAdmitRequiresCampaignSupersede":True,
        })
        expected=command+["--allow-campaign-supersede"]
        self.assertEqual(expected,result["nextClientHandoff"]["admitCommand"])
        self.assertEqual(expected,result["postExternalExecutionCommand"])

    def test_non_replacement_action_command_remains_unchanged(self):
        command=["python","scripts/run_mcp_external_interop.py","admit"]
        result={
            "nextClientHandoff":{"admitCommand":list(command)},
            "postExternalExecutionCommand":list(command),
        }
        mod.apply_replacement_campaign_supersede_command(result,{})
        self.assertEqual(command,result["nextClientHandoff"]["admitCommand"])
        self.assertEqual(command,result["postExternalExecutionCommand"])

    def test_fresh_or_resumed_campaign_never_requests_supersede(self):
        with tempfile.TemporaryDirectory() as td:
            progress=Path(td)/"progress.json"
            self.assertEqual({},mod.replacement_campaign_supersede_handoff(progress,{"campaignId":"new"},resumed=False))
            progress.write_text(json.dumps({"campaignId":"same","certifiedClientCount":1,"complete":False,"clients":[{"clientId":"chatgpt"}]}),encoding="utf-8")
            self.assertEqual({},mod.replacement_campaign_supersede_handoff(progress,{"campaignId":"same"},resumed=True))

    def test_complete_prior_progress_is_never_reintroduced_as_supersedable(self):
        with tempfile.TemporaryDirectory() as td:
            progress=Path(td)/"progress.json"
            progress.write_text(json.dumps({
                "campaignId":"old-campaign",
                "certifiedClientCount":len(mod.core.CLIENTS),
                "complete":True,
                "clients":[{"clientId":client} for client in mod.core.CLIENTS],
            }),encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"REPLACEMENT_PROGRESS_COMPLETE_FORBIDDEN"):
                mod.replacement_campaign_supersede_handoff(progress,{"campaignId":"new-campaign"},resumed=False)


if __name__=="__main__":
    unittest.main()
