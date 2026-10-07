import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_git_handoff_lineage_order",ROOT/"scripts/run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class C7WGitHandoffLineageOrderTests(unittest.TestCase):
    def git(self,root:Path,*args:str)->str:
        proc=subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True)
        return proc.stdout.strip()

    def init_repo(self,root:Path)->str:
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        (root/"source.txt").write_text("base\n",encoding="utf-8")
        self.git(root,"add","source.txt")
        self.git(root,"commit","-m","base")
        return self.git(root,"rev-parse","HEAD")

    def test_untracked_stale_evidence_is_never_told_to_commit(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve(); certified=self.init_repo(root)
            (root/"source.txt").write_text("drift\n",encoding="utf-8")
            self.git(root,"add","source.txt"); self.git(root,"commit","-m","source drift")
            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            evidence=lab/"mcp-external-client-interoperability-evidence.json"
            progress.write_text(json.dumps({"sourceCommitSHA":certified})+"\n",encoding="utf-8")
            evidence.write_text(json.dumps({"sourceCommitSHA":certified})+"\n",encoding="utf-8")
            out=mod.git_handoff(root,evidence,progress)
        self.assertEqual("INSPECT_STALE_C7W_EVIDENCE_GIT_STATE",out["nextActionCode"])
        self.assertNotEqual("COMMIT_C7W_EVIDENCE",out["nextActionCode"])
        self.assertEqual(certified,out["certifiedSourceCommitSHA"])
        self.assertIn("SOURCE_DELTA_NOT_EVIDENCE_ONLY",out["detail"])
        self.assertIn("do not commit",out["detail"])


if __name__=="__main__":
    unittest.main()
