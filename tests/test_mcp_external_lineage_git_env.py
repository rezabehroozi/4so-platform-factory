import importlib.util
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("mcpseal_lineage_git_env",ROOT/"scripts"/"seal_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class MCPExternalLineageGitEnvironmentTests(unittest.TestCase):
    def test_lineage_git_probes_ignore_inherited_git_authority(self):
        calls=[]

        def fake_run(command,**kwargs):
            calls.append((command,kwargs))
            if command[1]=="merge-base":
                return SimpleNamespace(returncode=0,stdout=b"")
            if command[1]=="diff":
                return SimpleNamespace(
                    returncode=0,
                    stdout=b"lab/mcp-external-client-interop-progress.json\x00",
                )
            raise AssertionError(command)

        injected={
            "GIT_DIR":"/tmp/attacker.git",
            "GIT_WORK_TREE":"/tmp/attacker-worktree",
            "GIT_INDEX_FILE":"/tmp/attacker-index",
            "GIT_OBJECT_DIRECTORY":"/tmp/attacker-objects",
        }
        with mock.patch.dict(os.environ,injected,clear=False), mock.patch.object(mod.subprocess,"run",side_effect=fake_run):
            mod.validate_evidence_only_source_lineage(Path("/repo"),"a"*40,"b"*40,"TEST_C7W")

        self.assertEqual(2,len(calls))
        for command,kwargs in calls:
            self.assertEqual("git",command[0])
            self.assertIn("env",kwargs)
            self.assertFalse(any(key.startswith("GIT_") for key in kwargs["env"]))


if __name__=="__main__":
    unittest.main()
