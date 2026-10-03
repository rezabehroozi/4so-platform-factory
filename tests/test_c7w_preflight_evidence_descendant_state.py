import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_preflight_descendant_state",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WPreflightEvidenceDescendantStateTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_committed_progress_descendant_reuses_original_source_bound_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("seed\n",encoding="utf-8")
            self.git(root,"add","seed.txt"); self.git(root,"commit","-m","seed")
            certified=self.git(root,"rev-parse","HEAD")
            state=root/f".state/c7w-external-interop-{certified[:12]}"
            state.mkdir(parents=True)
            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            progress.write_text(json.dumps({"sourceCommitSHA":certified})+"\n",encoding="utf-8")
            self.git(root,"add",progress.relative_to(root).as_posix()); self.git(root,"commit","-m","evidence progress")
            current=self.git(root,"rev-parse","HEAD")
            self.assertNotEqual(certified,current)

            out=mod._existing_state_handoff(root)

        self.assertEqual("RUN_C7W_STATUS",out["nextActionCode"])
        self.assertEqual(str(Path(f".state/c7w-external-interop-{certified[:12]}")),out["stateDir"])
        self.assertEqual(current,out["sourceCommitSHA"])
        self.assertEqual(certified,out["certifiedSourceCommitSHA"])


if __name__=="__main__":
    unittest.main()
