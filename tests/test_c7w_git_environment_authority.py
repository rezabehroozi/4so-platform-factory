import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_git_env",ROOT/"scripts"/"run_mcp_external_interop.py")
runner=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runner)


class C7WGitEnvironmentAuthorityTests(unittest.TestCase):
    def test_source_freeze_never_inherits_git_environment_overrides(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            responses=[
                SimpleNamespace(returncode=0,stdout=str(root)+"\n",stderr=""),
                SimpleNamespace(returncode=0,stdout="main\n",stderr=""),
                SimpleNamespace(returncode=0,stdout="a"*40+"\n",stderr=""),
                SimpleNamespace(returncode=0,stdout=b"H tracked.txt\x00",stderr=b""),
                SimpleNamespace(returncode=0,stdout=b"",stderr=b""),
                SimpleNamespace(returncode=0,stdout=b"",stderr=b""),
            ]
            with (
                mock.patch.dict(os.environ,{"GIT_INDEX_FILE":"/tmp/attacker-index","GIT_DIR":"/tmp/attacker-git","PATH":os.environ.get("PATH","")},clear=True),
                mock.patch.object(runner.subprocess,"run",side_effect=responses) as run,
            ):
                runner.require_c7w_source_freeze(root)
            self.assertEqual(6,run.call_count)
            for call in run.call_args_list:
                env=call.kwargs.get("env")
                self.assertIsNotNone(env)
                self.assertFalse(any(key.startswith("GIT_") for key in env),env)

    def test_source_freeze_rejects_missing_or_invalid_head(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            responses=[
                SimpleNamespace(returncode=0,stdout=str(root)+"\n",stderr=""),
                SimpleNamespace(returncode=0,stdout="main\n",stderr=""),
                SimpleNamespace(returncode=128,stdout="",stderr="fatal: ambiguous argument HEAD"),
            ]
            with mock.patch.object(runner.subprocess,"run",side_effect=responses):
                with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_GIT_HEAD_INVALID"):
                    runner.require_c7w_source_freeze(root)

    def test_active_campaign_head_probe_uses_clean_git_environment(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            source_sha="a"*40
            observed=[]
            def fake_run(command,**kwargs):
                observed.append(kwargs.get("env"))
                return SimpleNamespace(returncode=0,stdout=source_sha+"\n",stderr="")
            with (
                mock.patch.dict(os.environ,{"GIT_INDEX_FILE":"/tmp/attacker-index","PATH":os.environ.get("PATH","")},clear=True),
                mock.patch.object(runner,"require_c7w_source_freeze"),
                mock.patch.object(runner.core,"validate_evidence_only_source_lineage"),
                mock.patch.object(runner.subprocess,"run",side_effect=fake_run),
            ):
                self.assertEqual(source_sha,runner.require_active_campaign_source(root,{"sourceCommitSHA":source_sha}))
            self.assertEqual(1,len(observed))
            self.assertIsNotNone(observed[0])
            self.assertFalse(any(key.startswith("GIT_") for key in observed[0]),observed[0])


if __name__=="__main__":
    unittest.main()
