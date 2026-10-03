import importlib.util
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("prepare_mcp_external_interop_campaign_git_env",ROOT/"scripts"/"prepare_mcp_external_interop_campaign.py")
campaign=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(campaign)


class C7WCampaignGitEnvironmentTests(unittest.TestCase):
    def test_source_commit_probe_never_inherits_git_overrides(self):
        expected="a"*40
        observed={}
        def fake_run(command,**kwargs):
            observed["env"]=kwargs.get("env")
            return SimpleNamespace(returncode=0,stdout=expected+"\n",stderr="")
        with (
            mock.patch.dict(os.environ,{"GIT_DIR":"/tmp/attacker","GIT_INDEX_FILE":"/tmp/index","PATH":os.environ.get("PATH","")},clear=True),
            mock.patch.object(campaign.subprocess,"run",side_effect=fake_run),
        ):
            self.assertEqual(expected,campaign.source_commit_sha())
        env=observed["env"]
        self.assertIsNotNone(env)
        self.assertFalse(any(key.startswith("GIT_") for key in env),env)


if __name__=="__main__":
    unittest.main()
