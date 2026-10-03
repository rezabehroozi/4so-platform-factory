import importlib.util
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c9_sealer_git_env",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9SealerGitEnvironmentAuthorityTests(unittest.TestCase):
    def test_git_source_probes_ignore_inherited_git_authority(self):
        root=Path("/repo").resolve()
        head="a"*40
        seen=[]
        def fake_run(command,**kwargs):
            seen.append((command,kwargs))
            args=command[1:]
            if args==["rev-parse","--show-toplevel"]:
                return SimpleNamespace(returncode=0,stdout=str(root)+"\n")
            if args==["symbolic-ref","--quiet","--short","HEAD"]:
                return SimpleNamespace(returncode=0,stdout="main\n")
            if args==["rev-parse","HEAD"]:
                return SimpleNamespace(returncode=0,stdout=head+"\n")
            if args==["ls-files","-v","-z"]:
                return SimpleNamespace(returncode=0,stdout=b"H tracked.txt\x00")
            if args==["status","--porcelain","--untracked-files=all"]:
                return SimpleNamespace(returncode=0,stdout="")
            raise AssertionError(command)
        injected={
            "GIT_DIR":"/tmp/evil.git",
            "GIT_WORK_TREE":"/tmp/evil-tree",
            "GIT_INDEX_FILE":"/tmp/evil-index",
            "GIT_OBJECT_DIRECTORY":"/tmp/evil-objects",
        }
        with mock.patch.dict(os.environ,injected,clear=False), mock.patch.object(mod.subprocess,"run",side_effect=fake_run):
            self.assertEqual(head,mod.git_source(root))
        self.assertEqual(5,len(seen))
        for command,kwargs in seen:
            self.assertEqual("git",command[0])
            self.assertIn("env",kwargs)
            self.assertFalse(any(key.startswith("GIT_") for key in kwargs["env"]))


if __name__=="__main__":
    unittest.main()
