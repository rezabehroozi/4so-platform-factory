import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)
SPEC=importlib.util.spec_from_file_location("c7w_handoff_lineage_before_commit",ROOT/"scripts/run_mcp_external_interop.py")
runner=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(runner)


class C7WHandoffLineageBeforeCommitTests(unittest.TestCase):
    def git(self,root:Path,*args:str)->str:
        completed=subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True)
        return completed.stdout.strip()

    def init_repo(self,root:Path)->str:
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","c7w-test@example.invalid")
        self.git(root,"config","user.name","C7W Test")
        (root/"source.txt").write_text("v1\n",encoding="utf-8")
        self.git(root,"add","source.txt")
        self.git(root,"commit","-m","base")
        return self.git(root,"rev-parse","HEAD")

    def write_untracked_evidence(self,root:Path,certified_sha:str)->tuple[Path,Path]:
        lab=root/"lab"
        lab.mkdir(exist_ok=True)
        progress=lab/"mcp-external-client-interop-progress.json"
        evidence=lab/"mcp-external-client-interoperability-evidence.json"
        progress.write_text("{}\n",encoding="utf-8")
        evidence.write_text(json.dumps({"sourceCommitSHA":certified_sha})+"\n",encoding="utf-8")
        return progress,evidence

    def test_valid_untracked_evidence_still_requests_commit(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            current=self.init_repo(root)
            progress,evidence=self.write_untracked_evidence(root,current)
            out=runner.git_handoff(root,evidence,progress)
        self.assertEqual("COMMIT_C7W_EVIDENCE",out["nextActionCode"])
        self.assertEqual([
            "git","add",
            "lab/mcp-external-client-interop-progress.json",
            "lab/mcp-external-client-interoperability-evidence.json",
        ],out["nextCommand"])

    def test_stale_untracked_evidence_is_retired_before_any_commit(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            certified=self.init_repo(root)
            (root/"source.txt").write_text("v2\n",encoding="utf-8")
            self.git(root,"add","source.txt")
            self.git(root,"commit","-m","source drift")
            progress,evidence=self.write_untracked_evidence(root,certified)
            out=runner.git_handoff(root,evidence,progress)
        self.assertEqual("RETIRE_STALE_C7W_EVIDENCE",out["nextActionCode"])
        self.assertEqual([
            "git","clean","-f","--",
            "lab/mcp-external-client-interop-progress.json",
            "lab/mcp-external-client-interoperability-evidence.json",
        ],out["nextCommand"])
        self.assertNotIn("COMMIT_C7W_EVIDENCE",json.dumps(out,sort_keys=True))
        self.assertEqual(certified,out["certifiedSourceCommitSHA"])


if __name__=="__main__":
    unittest.main()
