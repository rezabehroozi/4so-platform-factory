import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("c7w_preflight",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class C7WPostEvidencePreflightTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_final_evidence_without_private_state_requires_revalidation_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("seed\n",encoding="utf-8")
            self.git(root,"add","seed.txt")
            self.git(root,"commit","-m","seed")
            source_sha=self.git(root,"rev-parse","HEAD")
            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            evidence=lab/"mcp-external-client-interoperability-evidence.json"
            progress.write_text(json.dumps({"sourceCommitSHA":source_sha})+"\n",encoding="utf-8")
            evidence.write_text(json.dumps({"sourceCommitSHA":source_sha})+"\n",encoding="utf-8")
            with (
                mock.patch.object(mod.runner,"git_handoff",side_effect=AssertionError("final handoff must not bypass private-state bulk revalidation")),
                mock.patch.object(mod.campaign,"live_preflight",side_effect=AssertionError("network must not run while recovering persisted final evidence")),
            ):
                out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","",None,"C7W_PLATFORM_ADMIN_TOKEN")
            self.assertFalse(out["ready"])
            self.assertEqual("RESTORE_C7W_LOCAL_STATE",out["nextActionCode"])
            self.assertEqual(str(root.resolve()),out["workingDirectory"])
            self.assertEqual(source_sha,out["sourceCommitSHA"])
            self.assertIn("mcp-external-client-interop-progress.json",out["nextCommand"])
            self.assertIn("mcp-external-client-interoperability-evidence.json",out["nextCommand"])
            self.assertIn("MCP_EXTERNAL_LOCAL_STATE_MISSING_WITH_CANONICAL_EVIDENCE",out["blockers"])
            self.assertFalse(out["physicalCertified"])

    def test_partial_progress_without_final_evidence_still_requires_local_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("seed\n",encoding="utf-8")
            self.git(root,"add","seed.txt")
            self.git(root,"commit","-m","seed")
            source_sha=self.git(root,"rev-parse","HEAD")
            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            progress.write_text(json.dumps({"sourceCommitSHA":source_sha})+"\n",encoding="utf-8")
            with mock.patch.object(mod.runner,"git_handoff",side_effect=AssertionError("final handoff must not run for progress-only state")):
                out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","",None,"C7W_PLATFORM_ADMIN_TOKEN")
            self.assertFalse(out["ready"])
            self.assertEqual("RESTORE_C7W_LOCAL_STATE",out["nextActionCode"])
            self.assertIn("lab/mcp-external-client-interop-progress.json",out["nextCommand"])


if __name__=="__main__":
    unittest.main()
