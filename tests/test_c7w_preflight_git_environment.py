import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_preflight_git_environment",ROOT/"scripts"/"c7w_preflight.py")
preflight=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(preflight)


class C7WPreflightGitEnvironmentTests(unittest.TestCase):
    def test_git_source_commit_uses_runner_clean_git_environment(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            expected="a"*40
            observed={}
            def fake_run(command,**kwargs):
                observed["env"]=kwargs.get("env")
                return SimpleNamespace(returncode=0,stdout=expected+"\n",stderr="")
            with (
                mock.patch.dict(os.environ,{"GIT_DIR":"/tmp/attacker","GIT_INDEX_FILE":"/tmp/index","PATH":os.environ.get("PATH","")},clear=True),
                mock.patch.object(preflight.subprocess,"run",side_effect=fake_run),
            ):
                self.assertEqual(expected,preflight.git_source_commit(root))
            env=observed["env"]
            self.assertIsNotNone(env)
            self.assertFalse(any(key.startswith("GIT_") for key in env),env)


if __name__=="__main__":
    unittest.main()
