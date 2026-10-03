import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_seal_boundary",ROOT/"scripts"/"run_mcp_external_interop.py")
runner=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runner)


class C7WEvidenceSealBoundaryTests(unittest.TestCase):
    def test_fourth_admit_does_not_publish_final_evidence_before_bulk_seal(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state=runner.secure_state_dir(root/"state")
            p=runner.paths(state)
            client="grok"
            (p["campaign"]).write_text("{}",encoding="utf-8")
            (p["packets"]/(client+".json")).write_text("{}",encoding="utf-8")
            capture=root/"capture.json"; capture.write_text("{}",encoding="utf-8")
            progress=root/"progress.json"
            evidence=root/"evidence.json"
            args=SimpleNamespace(
                state_dir=state,
                matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
                client=client,
                capture=capture,
                token_env="TOKEN",
                attempts=1,
                interval_seconds=0.0,
                progress_out=progress,
                evidence_out=evidence,
                allow_campaign_supersede=False,
            )
            writes=[]
            def record_write(path,value,label):
                writes.append((Path(path),label))
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner.core,"load",return_value={"sourceCommitSHA":"a"*40}),
                mock.patch.object(runner,"require_active_campaign_source",return_value="a"*40),
                mock.patch.object(runner.finalizer,"finalize",return_value={"authority":runner.core.RECEIPT_AUTHORITY,"clientId":client}),
                mock.patch.object(runner.core,"write_json_once_or_identical",side_effect=record_write),
                mock.patch.object(runner.admission,"matrix_contract",return_value=({"protocol":"2026-07-28"},list(runner.core.REQUIRED_CHECKS),{})),
                mock.patch.object(runner.core,"verify_receipt",return_value={"clientId":client,"requestIds":{},"executedAt":"2026-10-01T00:00:00Z","campaignCreatedAt":"2026-10-01T00:00:00Z","campaignExpiresAt":"2026-10-02T00:00:00Z","executionAuditWindowSeconds":60}),
                mock.patch.object(runner.audit_fetch,"fetch",return_value={}),
                mock.patch.object(runner.admission,"progress_lock"),
                mock.patch.object(runner.admission,"merge",return_value={"clients":[1,2,3,4],"certifiedClientCount":4,"complete":True}),
                mock.patch.object(runner.admission,"final_evidence",return_value={"authority":"projected-only"}),
                mock.patch.object(runner.core,"write_json_atomic_replace"),
                mock.patch.object(runner,"progress_status",return_value={"certified":list(runner.core.CLIENTS),"complete":True,"nextClient":None}),
            ):
                out=runner.admit(args)
            self.assertEqual("RUN_C7W_SEAL",out["nextActionCode"])
            self.assertFalse(any(path==evidence for path,_ in writes),writes)
            self.assertFalse(evidence.exists())


if __name__=="__main__":
    unittest.main()
