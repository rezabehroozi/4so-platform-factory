import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("codex_autopilot_git_environment_authority",ROOT/"scripts"/"codex_autopilot.py")
mod=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=mod
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class CodexAutopilotGitEnvironmentAuthorityTests(unittest.TestCase):
    def test_git_head_ignores_inherited_repository_selection_authority(self):
        observed=SimpleNamespace(returncode=0,stdout="a"*40+"\n",stderr="")
        with mock.patch.dict(os.environ,{"GIT_DIR":"/tmp/decoy.git","GIT_WORK_TREE":"/tmp/decoy","KEEP_ME":"yes"},clear=False):
            with mock.patch.object(mod.subprocess,"run",return_value=observed) as run:
                self.assertEqual("a"*40,mod._git_head(ROOT))
        env=run.call_args.kwargs.get("env")
        self.assertIsInstance(env,dict)
        self.assertNotIn("GIT_DIR",env)
        self.assertNotIn("GIT_WORK_TREE",env)
        self.assertEqual("yes",env.get("KEEP_ME"))

    def test_git_dirty_paths_ignore_inherited_repository_selection_authority(self):
        tracked=SimpleNamespace(returncode=0,stdout=b"tracked.txt\0",stderr=b"")
        untracked=SimpleNamespace(returncode=0,stdout=b"new.txt\0",stderr=b"")
        with mock.patch.dict(os.environ,{"GIT_INDEX_FILE":"/tmp/decoy-index","GIT_WORK_TREE":"/tmp/decoy","KEEP_ME":"yes"},clear=False):
            with mock.patch.object(mod.subprocess,"run",side_effect=[tracked,untracked]) as run:
                self.assertEqual(["new.txt","tracked.txt"],mod._git_dirty_paths(ROOT))
        self.assertEqual(2,run.call_count)
        for call in run.call_args_list:
            env=call.kwargs.get("env")
            self.assertIsInstance(env,dict)
            self.assertNotIn("GIT_INDEX_FILE",env)
            self.assertNotIn("GIT_WORK_TREE",env)
            self.assertEqual("yes",env.get("KEEP_ME"))

    def test_run_strips_repository_selection_authority_but_preserves_other_environment(self):
        with tempfile.TemporaryDirectory() as td:
            script='import json,os; print(json.dumps({k:os.environ.get(k) for k in ("GIT_DIR","GIT_WORK_TREE","GIT_ASKPASS","KEEP_ME","CUSTOM")}))'
            with mock.patch.dict(os.environ,{"GIT_DIR":"/tmp/decoy.git","GIT_ASKPASS":"/tmp/askpass","KEEP_ME":"yes"},clear=False):
                result=mod._run(
                    [sys.executable,"-c",script],
                    cwd=Path(td),
                    timeout=10,
                    env={"GIT_WORK_TREE":"/tmp/decoy","CUSTOM":"ok"},
                )
        self.assertEqual(0,result.returncode,result.stdout)
        payload=json.loads(result.stdout.strip())
        self.assertIsNone(payload["GIT_DIR"])
        self.assertIsNone(payload["GIT_WORK_TREE"])
        self.assertEqual("/tmp/askpass",payload["GIT_ASKPASS"])
        self.assertEqual("yes",payload["KEEP_ME"])
        self.assertEqual("ok",payload["CUSTOM"])


if __name__=="__main__":
    unittest.main()
