import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)

spec=importlib.util.spec_from_file_location("run_mcp_external_interop_complete_progress_recovery_test",ROOT/"scripts/run_mcp_external_interop.py")
runner=importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)


class C7WCompleteProgressCrashRecoveryTests(unittest.TestCase):
    def test_complete_progress_without_evidence_resumes_at_bulk_seal(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=runner.secure_state_dir(root/"state")
            (state/"campaign.json").write_text("{}",encoding="utf-8")
            progress=root/"progress.json"; progress.write_text("{}",encoding="utf-8")
            evidence=root/"evidence.json"
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=progress,evidence_out=evidence)
            complete={"certified":list(runner.core.CLIENTS),"missing":[],"complete":True,"nextClient":None,"campaignPrepared":True,"campaignId":"mcp-interop-complete","sourceCommitSHA":"a"*40,"runtimeVersion":"0.0.test"}
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",return_value=complete),
            ):
                out=runner.status(args)
        self.assertEqual("RUN_C7W_SEAL",out["nextActionCode"])
        self.assertEqual(runner.runner_command(state,"seal"),out["nextCommand"])
        self.assertTrue(out["complete"])
        self.assertFalse(out["physicalCertified"])


if __name__=="__main__":
    unittest.main()
