import importlib.util
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("final_exact_release_admission_git_env",ROOT/"scripts"/"final_exact_release_admission.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9AdmissionGitEnvironmentAuthorityTests(unittest.TestCase):
    def test_git_head_ignores_inherited_git_authority(self):
        seen=[]
        def fake_run(command,**kwargs):
            seen.append(kwargs)
            return SimpleNamespace(returncode=0,stdout="a"*40+"\n")
        with mock.patch.dict(os.environ,{"GIT_DIR":"/tmp/evil.git","GIT_INDEX_FILE":"/tmp/evil-index"},clear=False), mock.patch.object(mod.subprocess,"run",side_effect=fake_run):
            self.assertEqual("a"*40,mod.git_head(Path("/repo")))
        self.assertEqual(1,len(seen))
        self.assertIn("env",seen[0])
        self.assertFalse(any(key.startswith("GIT_") for key in seen[0]["env"]))

    def test_exact_source_workspace_probes_ignore_inherited_git_authority(self):
        wanted="b"*40
        root=Path("/repo").resolve()
        seen=[]
        def fake_run(command,**kwargs):
            seen.append((command,kwargs))
            if command[1:]==["rev-parse","--show-toplevel"]:
                return SimpleNamespace(returncode=0,stdout=str(root)+"\n")
            if command[1:]==["rev-parse","HEAD"]:
                return SimpleNamespace(returncode=0,stdout=wanted+"\n")
            if command[1:]==["ls-files","-v","-z"]:
                return SimpleNamespace(returncode=0,stdout=b"H tracked.txt\x00")
            if command[1:4]==["status","--porcelain=v1","-z"]:
                return SimpleNamespace(returncode=0,stdout=b"")
            raise AssertionError(command)
        injected={"GIT_DIR":"/tmp/evil.git","GIT_WORK_TREE":"/tmp/evil-tree","GIT_INDEX_FILE":"/tmp/evil-index"}
        with mock.patch.dict(os.environ,injected,clear=False), mock.patch.object(mod.subprocess,"run",side_effect=fake_run):
            self.assertEqual(wanted,mod.require_exact_source_workspace(root,wanted))
        self.assertEqual(4,len(seen))
        for command,kwargs in seen:
            self.assertEqual("git",command[0])
            self.assertIn("env",kwargs)
            self.assertFalse(any(key.startswith("GIT_") for key in kwargs["env"]))


if __name__=="__main__":
    unittest.main()
