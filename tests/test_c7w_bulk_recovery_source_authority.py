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
SPEC=importlib.util.spec_from_file_location("c7w_bulk_recovery_source_authority",ROOT/"scripts/run_mcp_external_interop.py")
runner=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(runner)


class C7WBulkRecoverySourceAuthorityTests(unittest.TestCase):
    def state_with_bulk(self,root:Path,*,campaign:bool=True)->Path:
        state=runner.secure_state_dir(root/"state")
        p=runner.paths(state)
        if campaign:
            p["campaign"].write_text('{"campaignId":"mcp-interop-old"}',encoding="utf-8")
        for client in runner.core.CLIENTS:
            (p["receipts"]/(client+".json")).write_text("{}",encoding="utf-8")
            (p["audits"]/(client+".json")).write_text("{}",encoding="utf-8")
        return state

    def args(self,root:Path,state:Path,*,progress:bool=True):
        progress_path=root/"progress.json"
        if progress:
            progress_path.write_text("{}",encoding="utf-8")
        return SimpleNamespace(
            state_dir=state,
            matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
            progress_out=progress_path,
            evidence_out=root/"evidence.json",
        )

    def incomplete(self):
        return {
            "certified":["chatgpt","claude","gemini"],
            "missing":["grok"],
            "complete":False,
            "nextClient":"grok",
            "campaignPrepared":True,
        }

    def test_stale_source_blocks_bulk_seal_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=self.state_with_bulk(root); args=self.args(root,state)
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",return_value=self.incomplete()),
                mock.patch.object(runner.core,"load",return_value={"sourceCommitSHA":"a"*40}),
                mock.patch.object(runner,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
                mock.patch.object(runner.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout="b"*40)),
            ):
                out=runner.status(args)
        self.assertEqual("RERUN_C7W_ON_CURRENT_SOURCE",out["nextActionCode"])
        self.assertEqual("CAMPAIGN_SOURCE_DRIFT",out["recoveryReason"])
        self.assertTrue(out["replacementAdmitRequiresCampaignSupersede"])
        self.assertNotIn("RUN_C7W_SEAL",str(out))

    def test_expired_stale_source_blocks_bulk_seal_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=self.state_with_bulk(root); args=self.args(root,state)
            calls=[]
            def status(*a,**kw):
                calls.append(kw.get("require_live",True))
                if kw.get("require_live",True):
                    raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_EXPIRED")
                return self.incomplete()
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",side_effect=status),
                mock.patch.object(runner.core,"load",return_value={"campaignId":"mcp-interop-old","sourceCommitSHA":"a"*40}),
                mock.patch.object(runner,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
                mock.patch.object(runner.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout="b"*40)),
            ):
                out=runner.status(args)
        self.assertEqual([True,False],calls)
        self.assertEqual("RERUN_C7W_ON_CURRENT_SOURCE",out["nextActionCode"])
        self.assertNotIn("RUN_C7W_SEAL",str(out))

    def test_orphan_bulk_artifacts_never_route_to_seal_or_same_state_prepare(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=self.state_with_bulk(root,campaign=False); args=self.args(root,state,progress=False)
            value={"certified":[],"missing":list(runner.core.CLIENTS),"complete":False,"nextClient":"chatgpt","campaignPrepared":False}
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",return_value=value),
            ):
                out=runner.status(args)
        self.assertEqual("RESTORE_C7W_CAMPAIGN_STATE",out["nextActionCode"])
        self.assertEqual("BULK_ARTIFACT_CAMPAIGN_STATE_MISSING",out["recoveryReason"])
        self.assertEqual([],out["nextCommand"])
        self.assertEqual(str(runner.paths(state)["campaign"]),out["requiredStatePath"])
        self.assertNotIn("RUN_C7W_SEAL",str(out))
        self.assertNotIn("PREPARE_C7W_CAMPAIGN",str(out))

    def test_dirty_source_routes_to_restore_not_rerun_for_incomplete_campaign(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=self.state_with_bulk(root); args=self.args(root,state)
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",return_value=self.incomplete()),
                mock.patch.object(runner.core,"load",return_value={"sourceCommitSHA":"a"*40}),
                mock.patch.object(runner,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")),
            ):
                out=runner.status(args)
        self.assertEqual("RESTORE_C7W_SOURCE_FREEZE",out["nextActionCode"])
        self.assertEqual("SOURCE_FREEZE_REQUIRED",out["recoveryReason"])
        self.assertEqual(["git","status","--short"],out["nextCommand"])
        self.assertNotIn("RERUN_C7W_ON_CURRENT_SOURCE",str(out))
        self.assertNotIn("RUN_C7W_SEAL",str(out))

    def test_dirty_source_routes_to_restore_for_complete_progress_too(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=self.state_with_bulk(root); args=self.args(root,state)
            complete={"certified":list(runner.core.CLIENTS),"missing":[],"complete":True,"nextClient":None,"campaignPrepared":True}
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",return_value=complete),
                mock.patch.object(runner.core,"load",return_value={"sourceCommitSHA":"a"*40}),
                mock.patch.object(runner,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")),
            ):
                out=runner.status(args)
        self.assertEqual("RESTORE_C7W_SOURCE_FREEZE",out["nextActionCode"])
        self.assertEqual(["git","status","--short"],out["nextCommand"])
        self.assertNotIn("RETIRE_STALE_C7W_PROGRESS",str(out))
        self.assertNotIn("RUN_C7W_SEAL",str(out))


if __name__=="__main__":
    unittest.main()
