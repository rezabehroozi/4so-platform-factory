import importlib.util
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

    def test_final_evidence_handoff_precedes_missing_current_head_private_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"seed.txt").write_text("seed\n",encoding="utf-8")
            self.git(root,"add","seed.txt")
            self.git(root,"commit","-m","seed")
            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            evidence=lab/"mcp-external-client-interoperability-evidence.json"
            progress.write_text("{}\n",encoding="utf-8")
            evidence.write_text("{}\n",encoding="utf-8")
            expected={
                "nextActionCode":"RUN_C9_SEAL",
                "nextCommand":[sys.executable,"scripts/seal_final_exact_release.py","--root",".","--out","lab/final-exact-release-evidence.json"],
                "sourceCommitSHA":self.git(root,"rev-parse","HEAD"),
                "certifiedSourceCommitSHA":"a"*40,
                "detail":"ready for exact C9 seal",
            }
            with (
                mock.patch.object(mod.runner,"git_handoff",return_value=expected) as handoff,
                mock.patch.object(mod.campaign,"live_preflight",side_effect=AssertionError("network must not run after final C7W evidence")),
            ):
                out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","",None,"C7W_PLATFORM_ADMIN_TOKEN")
            handoff.assert_called_once_with(root.resolve(),evidence,progress)
            self.assertTrue(out["ready"])
            self.assertEqual("RUN_C9_SEAL",out["nextActionCode"])
            self.assertEqual(expected["nextCommand"],out["nextCommand"])
            self.assertNotEqual("RESTORE_C7W_LOCAL_STATE",out["nextActionCode"])
            self.assertEqual([],out["requiredInputs"])
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
            lab=root/"lab"; lab.mkdir()
            progress=lab/"mcp-external-client-interop-progress.json"
            progress.write_text("{}\n",encoding="utf-8")
            with mock.patch.object(mod.runner,"git_handoff",side_effect=AssertionError("final handoff must not run for progress-only state")):
                out=mod.preflight(root,ROOT/"lab/mcp-external-client-interop-matrix.json","",None,"C7W_PLATFORM_ADMIN_TOKEN")
            self.assertFalse(out["ready"])
            self.assertEqual("RESTORE_C7W_LOCAL_STATE",out["nextActionCode"])
            self.assertIn("lab/mcp-external-client-interop-progress.json",out["nextCommand"])


if __name__=="__main__":
    unittest.main()
