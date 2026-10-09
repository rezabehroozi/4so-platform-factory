import importlib.util
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_admit_source_freeze",ROOT/"scripts"/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WAdmitSourceFreezeTests(unittest.TestCase):
    def fixture(self,root:Path):
        state=mod.secure_state_dir(root/"state")
        p=mod.paths(state)
        client="chatgpt"
        (p["packets"]/(client+".json")).write_text("{}\n",encoding="utf-8")
        capture=p["captures"]/(client+".capture.json"); capture.write_text("{}\n",encoding="utf-8")
        audit=p["audits"]/(client+".json"); audit.write_text("[]\n",encoding="utf-8")
        args=SimpleNamespace(
            state_dir=state,
            matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
            client=client,
            capture=capture,
            token_env="TOKEN",
            attempts=1,
            interval_seconds=0.0,
            progress_out=root/"progress.json",
            evidence_out=root/"evidence.json",
            allow_campaign_supersede=False,
        )
        return state,p,client,audit,args

    def run_admit(self,args,client,audit,source_checks):
        source_sha="a"*40
        normalized={
            "clientId":client,
            "requestIds":{},
            "executedAt":"2026-10-01T00:00:00Z",
            "campaignCreatedAt":"2026-10-01T00:00:00Z",
            "campaignExpiresAt":"2026-10-02T00:00:00Z",
            "executionAuditWindowSeconds":60,
        }
        atomic_write=mock.Mock()
        next_action=mock.Mock(return_value={"nextActionCode":"RUN_EXTERNAL_CLIENT","nextCommand":[]})
        with (
            mock.patch.object(mod,"require_canonical_matrix",side_effect=lambda root,path:path),
            mock.patch.object(mod.core,"load",return_value={"sourceCommitSHA":source_sha}),
            mock.patch.object(mod,"require_active_campaign_source",side_effect=source_checks),
            mock.patch.object(mod.finalizer,"finalize",return_value={"authority":mod.core.RECEIPT_AUTHORITY,"clientId":client}),
            mock.patch.object(mod.core,"write_json_once_or_identical"),
            mock.patch.object(mod.admission,"matrix_contract",return_value=({"protocol":"2026-07-28"},list(mod.core.REQUIRED_CHECKS),{"sourceCommitSHA":source_sha})),
            mock.patch.object(mod.core,"verify_receipt",return_value=normalized),
            mock.patch.object(mod.core,"verify_server_audit",return_value={}) as verify_audit,
            mock.patch.object(mod.audit_fetch,"fetch",side_effect=AssertionError("existing audit must avoid network")),
            mock.patch.object(mod.admission,"progress_lock",return_value=nullcontext()),
            mock.patch.object(mod.admission,"merge",return_value={"clients":[],"certifiedClientCount":0,"complete":False}),
            mock.patch.object(mod.core,"write_json_atomic_replace",atomic_write),
            mock.patch.object(mod,"progress_status",return_value={"certified":[],"complete":False,"nextClient":"claude"}),
            mock.patch.object(mod,"external_client_action",next_action),
        ):
            try:
                result=mod.admit(args)
                error=None
            except RuntimeError as exc:
                result=None; error=exc
        verify_audit.assert_called_once_with(audit,normalized,client)
        return result,error,atomic_write,next_action

    def test_source_drift_after_audit_blocks_progress_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); _,_,client,audit,args=self.fixture(root)
            result,error,atomic_write,next_action=self.run_admit(
                args,client,audit,["a"*40,RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")]
            )
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertRegex(str(error),"MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")
        atomic_write.assert_not_called()
        next_action.assert_not_called()

    def test_source_drift_after_progress_blocks_next_client_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); _,_,client,audit,args=self.fixture(root)
            result,error,atomic_write,next_action=self.run_admit(
                args,client,audit,["a"*40,"a"*40,RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")]
            )
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertRegex(str(error),"MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")
        atomic_write.assert_called_once()
        next_action.assert_not_called()


if __name__=="__main__":
    unittest.main()
