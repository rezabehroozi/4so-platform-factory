import importlib.util
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_execution_bindings_git_env",ROOT/"scripts"/"c7w_execution_bindings.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WExecutionBindingsGitEnvironmentTests(unittest.TestCase):
    def test_binding_source_head_ignores_inherited_git_authority(self):
        seen=[]
        def fake_run(command,**kwargs):
            seen.append(kwargs)
            return SimpleNamespace(returncode=0,stdout="a"*40+"\n")
        injected={"GIT_DIR":"/tmp/evil.git","GIT_WORK_TREE":"/tmp/evil-tree","GIT_INDEX_FILE":"/tmp/evil-index"}
        with mock.patch.dict(os.environ,injected,clear=False), mock.patch.object(mod.subprocess,"run",side_effect=fake_run):
            self.assertEqual("a"*40,mod.git_head(Path("/repo")))
        self.assertEqual(1,len(seen))
        self.assertIn("env",seen[0])
        self.assertFalse(any(key.startswith("GIT_") for key in seen[0]["env"]))


if __name__=="__main__":
    unittest.main()
