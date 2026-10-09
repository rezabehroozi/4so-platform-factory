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
        self.assertEqual("EXECUTION_ARTIFACT_CAMPAIGN_STATE_MISSING",out["recoveryReason"])
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

    def test_partial_orphan_execution_artifact_requires_campaign_restore(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=runner.secure_state_dir(root/"state"); p=runner.paths(state)
            (p["receipts"]/"chatgpt.json").write_text("{}",encoding="utf-8")
            args=self.args(root,state,progress=False)
            value={"certified":[],"missing":list(runner.core.CLIENTS),"complete":False,"nextClient":"chatgpt","campaignPrepared":False}
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",return_value=value),
            ):
                out=runner.status(args)
        self.assertEqual("RESTORE_C7W_CAMPAIGN_STATE",out["nextActionCode"])
        self.assertEqual("EXECUTION_ARTIFACT_CAMPAIGN_STATE_MISSING",out["recoveryReason"])
        self.assertNotIn("PREPARE_C7W_CAMPAIGN",str(out))

    def test_empty_state_requires_source_freeze_before_prepare_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=runner.secure_state_dir(root/"state"); args=self.args(root,state,progress=False)
            value={"certified":[],"missing":list(runner.core.CLIENTS),"complete":False,"nextClient":"chatgpt","campaignPrepared":False}
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",return_value=value),
                mock.patch.object(runner,"require_c7w_source_freeze",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_SOURCE_NOT_FROZEN")),
            ):
                out=runner.status(args)
        self.assertEqual("RESTORE_C7W_SOURCE_FREEZE",out["nextActionCode"])
        self.assertEqual("SOURCE_FREEZE_REQUIRED",out["recoveryReason"])
        self.assertEqual(["git","status","--short"],out["nextCommand"])
        self.assertNotIn("PREPARE_C7W_CAMPAIGN",str(out))

    def test_prepare_rejects_orphan_execution_artifacts_before_new_campaign(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=runner.secure_state_dir(root/"state"); p=runner.paths(state)
            (p["captures"]/"chatgpt.capture.json").write_text("{}",encoding="utf-8")
            args=SimpleNamespace(
                state_dir=state,
                matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
                progress_out=root/"progress.json",
                endpoint="https://mcp.example.test/mcp",
                oauth_client_map=None,
                token_env="C7W_PLATFORM_ADMIN_TOKEN",
                source_commit_sha="",
            )
            with (
                mock.patch.object(runner,"require_c7w_source_freeze"),
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
            ):
                with self.assertRaisesRegex(RuntimeError,"ORPHAN_STATE_REQUIRES_RECOVERY"):
                    runner.prepare(args)

    def test_prepare_rechecks_source_before_external_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/"state"
            args=SimpleNamespace(
                state_dir=state,
                matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",
                progress_out=root/"progress.json",
                endpoint="https://mcp.example.test/mcp",
                oauth_client_map=root/"oauth.json",
                token_env="C7W_PLATFORM_ADMIN_TOKEN",
                source_commit_sha="a"*40,
            )
            campaign={"campaignId":"mcp-interop-source-recheck","sourceCommitSHA":"a"*40,"runtimeVersion":"0.0.0"}
            with (
                mock.patch.object(runner,"require_c7w_source_freeze"),
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner.campaign_builder,"source_commit_sha",return_value="a"*40),
                mock.patch.object(runner.core,"load",return_value={}),
                mock.patch.object(runner.core,"validate_matrix_contract"),
                mock.patch.object(runner.campaign_builder,"load_oauth_bindings",return_value=({},"sha256:"+"0"*64)),
                mock.patch.object(runner.campaign_builder,"runtime_identity_readback",return_value={}),
                mock.patch.object(runner.campaign_builder,"trusted_client_readback",return_value={}),
                mock.patch.object(runner.campaign_builder,"live_preflight",return_value={}),
                mock.patch.object(runner.campaign_builder,"prepare",return_value=campaign),
                mock.patch.object(runner.core,"write_json_once_or_identical"),
                mock.patch.object(runner.packet_builder,"packet",return_value={}),
                mock.patch.object(runner,"capture_template",return_value={}),
                mock.patch.object(runner,"client_execution_handoff",return_value={}),
                mock.patch.object(runner,"external_client_action",return_value={"nextActionCode":"RUN_EXTERNAL_CLIENT"}),
                mock.patch.object(runner,"require_active_campaign_source",side_effect=RuntimeError("MCP_EXTERNAL_LOCAL_ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY")),
            ):
                with self.assertRaisesRegex(RuntimeError,"ACTIVE_CAMPAIGN_SOURCE_DELTA_NOT_EVIDENCE_ONLY"):
                    runner.prepare(args)


if __name__=="__main__":
    unittest.main()
