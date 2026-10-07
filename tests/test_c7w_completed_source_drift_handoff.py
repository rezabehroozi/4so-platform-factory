import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_completed_drift",ROOT/"scripts/run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class C7WCompletedSourceDriftHandoffTests(unittest.TestCase):
    def test_completed_certification_is_retired_before_current_source_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.run(["git","init","-b","main"],cwd=root,check=True,capture_output=True)
            subprocess.run(["git","config","user.email","test@example.invalid"],cwd=root,check=True)
            subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
            (root/"source.txt").write_text("v1\n",encoding="utf-8")
            subprocess.run(["git","add","source.txt"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","source"],cwd=root,check=True,capture_output=True)
            certified=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,check=True,capture_output=True).stdout.strip()

            lab=root/"lab"
            lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            evidence=lab/"mcp-external-client-interoperability-evidence.json"
            progress.write_text(json.dumps({"sourceCommitSHA":certified})+"\n",encoding="utf-8")
            evidence.write_text(json.dumps({"sourceCommitSHA":certified})+"\n",encoding="utf-8")
            subprocess.run(["git","add","lab"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","evidence"],cwd=root,check=True,capture_output=True)

            (root/"source.txt").write_text("v2\n",encoding="utf-8")
            subprocess.run(["git","add","source.txt"],cwd=root,check=True)
            subprocess.run(["git","commit","-m","source drift"],cwd=root,check=True,capture_output=True)
            current=subprocess.run(["git","rev-parse","HEAD"],cwd=root,text=True,check=True,capture_output=True).stdout.strip()

            out=mod.git_handoff(root,evidence,progress)

        self.assertEqual("RETIRE_STALE_C7W_EVIDENCE",out["nextActionCode"])
        self.assertEqual([
            "git","rm","--",
            "lab/mcp-external-client-interop-progress.json",
            "lab/mcp-external-client-interoperability-evidence.json",
        ],out["nextCommand"])
        self.assertEqual(["git","commit","-m","evidence: retire stale external MCP interoperability"],out["followupCommand"])
        self.assertEqual([sys.executable,"scripts/c7w_preflight.py","--root",str(root.resolve())],out["rerunCommand"])
        self.assertEqual(certified,out["certifiedSourceCommitSHA"])
        self.assertEqual(current,out["currentSourceCommitSHA"])
        self.assertNotIn("C7W_ALLOW_CAMPAIGN_SUPERSEDE",json.dumps(out))


if __name__=="__main__":
    unittest.main()
