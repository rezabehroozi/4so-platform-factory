import importlib.util
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)


def load(name,rel):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


core=load("seal_mcp_external_interop_expired_complete_test","scripts/seal_mcp_external_interop.py")
sys.modules["seal_mcp_external_interop"]=core
admission=load("admit_mcp_external_receipt_expired_complete_test","scripts/admit_mcp_external_receipt.py")
sys.modules["admit_mcp_external_receipt"]=admission
runner=load("run_mcp_external_interop_expired_complete_test","scripts/run_mcp_external_interop.py")


class C7WExpiredCompleteRecoveryTests(unittest.TestCase):
    def test_expired_campaign_is_live_rejected_but_historically_verifiable(self):
        spec={"campaignMaxAgeSeconds":3600,"executionAuditWindowSeconds":60}
        now=datetime.now(timezone.utc)
        campaign={
            "createdAt":core.utc_timestamp(now-timedelta(hours=2)),
            "expiresAt":core.utc_timestamp(now-timedelta(hours=1)),
        }
        with self.assertRaisesRegex(RuntimeError,"CAMPAIGN_EXPIRED"):
            core.campaign_time_window(campaign,spec,now=now)
        created,expires,audit_window=core.campaign_time_window(campaign,spec,now=now,require_live=False)
        self.assertLess(expires,now)
        self.assertLess(created,expires)
        self.assertEqual(60,audit_window)

    def test_bulk_seal_uses_historical_campaign_and_receipt_validation(self):
        matrix={"spec":{"protocol":"2026-07-28","sharedRequiredChecks":list(core.REQUIRED_CHECKS)}}
        campaign={"_matrixSha256":"sha256:"+"a"*64,"campaignId":"mcp-interop-expired-complete","_campaignSha256":"sha256:"+"b"*64,"oauthClientBindingsSha256":"sha256:"+"c"*64,"sourceCommitSHA":"d"*40,"runtimeVersion":"0.0.test"}
        rows=[]
        for client in core.CLIENTS:
            rows.append({"clientId":client,"endpoint":"https://mcp.example.test/mcp","executionId":"run-"+client,"evidenceDigest":"sha256:"+(client[0]*64),"providerExecutionRef":"provider-"+client,"requestIds":{check:f"{client}-{idx}-request" for idx,check in enumerate(core.AUDITED_CHECKS)}})
        with (
            mock.patch.object(core,"load",return_value=matrix),
            mock.patch.object(core,"validate_matrix_contract",return_value=matrix["spec"]),
            mock.patch.object(core,"verify_campaign",return_value=campaign) as verify_campaign,
            mock.patch.object(core,"verify_receipt",side_effect=rows) as verify_receipt,
            mock.patch.object(core,"verify_server_audit",return_value={}),
            mock.patch.object(core,"build_interop_evidence",return_value={"authority":core.AUTHORITY}) as build,
        ):
            out=core.seal(Path("matrix.json"),Path("campaign.json"),Path("receipts"),Path("audits"))
        self.assertEqual(core.AUTHORITY,out["authority"])
        self.assertFalse(verify_campaign.call_args.kwargs["require_live"])
        self.assertEqual(len(core.CLIENTS),verify_receipt.call_count)
        self.assertTrue(all(call.kwargs.get("require_live") is False for call in verify_receipt.call_args_list))
        build.assert_called_once()

    def test_runner_seal_checks_complete_progress_historically(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=runner.secure_state_dir(root/"state")
            (state/"campaign.json").write_text("{}",encoding="utf-8")
            progress=root/"progress.json"; progress.write_text("{}",encoding="utf-8")
            evidence=root/"evidence.json"
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=progress,evidence_out=evidence)
            value={"campaignId":"mcp-interop-expired-complete","sourceCommitSHA":"a"*40,"certifiedClientCount":4,"externalCertificationPass":True}
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner.core,"load",return_value={"sourceCommitSHA":"a"*40}),
                mock.patch.object(runner,"require_active_campaign_source",return_value="a"*40),
                mock.patch.object(runner,"progress_status",return_value={"complete":True,"nextClient":None}) as status,
                mock.patch.object(runner.admission,"final_evidence",return_value=value),
                mock.patch.object(runner.core,"seal",return_value=value),
                mock.patch.object(runner.core,"write_json_once_or_identical"),
                mock.patch.object(runner,"git_handoff",return_value={"nextActionCode":"COMMIT_C7W_EVIDENCE"}),
            ):
                out=runner.seal(args)
        self.assertFalse(status.call_args.kwargs["require_live"])
        self.assertEqual("SEALED",out["action"])

    def test_expired_incomplete_status_still_requests_replacement_not_new_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=runner.secure_state_dir(root/"state")
            campaign=state/"campaign.json"; campaign.write_text('{"campaignId":"mcp-interop-expired"}',encoding="utf-8")
            progress=root/"progress.json"; progress.write_text("{}",encoding="utf-8")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=progress,evidence_out=root/"evidence.json")
            calls=[]
            def progress_status(*a,**kw):
                calls.append(kw.get("require_live",True))
                if kw.get("require_live",True):
                    raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_EXPIRED")
                return {"certified":["chatgpt"],"missing":["claude","gemini","grok"],"complete":False,"nextClient":"claude","campaignPrepared":True}
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",side_effect=progress_status),
                mock.patch.object(runner.core,"load",return_value={"campaignId":"mcp-interop-expired"}),
            ):
                out=runner.status(args)
        self.assertEqual([True,False],calls)
        self.assertEqual("PREPARE_REPLACEMENT_C7W_CAMPAIGN",out["nextActionCode"])
        self.assertNotIn("RUN_EXTERNAL_CLIENT",str(out))

    def test_expired_incomplete_progress_with_all_captured_artifacts_resumes_seal(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=runner.secure_state_dir(root/"state"); p=runner.paths(state)
            (p["campaign"]).write_text('{"campaignId":"mcp-interop-expired-captured"}',encoding="utf-8")
            for client in core.CLIENTS:
                (p["receipts"]/(client+".json")).write_text("{}",encoding="utf-8")
                (p["audits"]/(client+".json")).write_text("{}",encoding="utf-8")
            progress=root/"progress.json"; progress.write_text("{}",encoding="utf-8")
            args=SimpleNamespace(state_dir=state,matrix=ROOT/"lab/mcp-external-client-interop-matrix.json",progress_out=progress,evidence_out=root/"evidence.json")
            def progress_status(*a,**kw):
                if kw.get("require_live",True):
                    raise RuntimeError("MCP_EXTERNAL_CAMPAIGN_EXPIRED")
                return {"certified":["chatgpt","claude","gemini"],"missing":["grok"],"complete":False,"nextClient":"grok","campaignPrepared":True}
            with (
                mock.patch.object(runner,"require_canonical_matrix",side_effect=lambda root,path:path),
                mock.patch.object(runner,"progress_status",side_effect=progress_status),
            ):
                out=runner.status(args)
        self.assertEqual("RUN_C7W_SEAL",out["nextActionCode"])
        self.assertEqual(runner.runner_command(state,"seal"),out["nextCommand"])
        self.assertTrue(out["recoveryRequired"])
        self.assertEqual("CAPTURED_ARTIFACT_PROGRESS_RECONCILIATION",out["recoveryReason"])
        self.assertNotIn("RUN_EXTERNAL_CLIENT",str(out))

    def test_recovered_progress_preserves_and_matches_existing_admitted_rows(self):
        bulk_rows=[{"clientId":client,"marker":client} for client in core.CLIENTS]
        bulk={"authority":core.AUTHORITY,"clients":bulk_rows,"certifiedClientCount":4,"externalCertificationPass":True}
        campaign={"campaignId":"mcp-interop-recover","sourceCommitSHA":"a"*40,"runtimeVersion":"0.0.test"}
        expected={"clients":[],"certifiedClientCount":0,"complete":False,"externalCertificationPass":False,"serverAuditWitnessPass":False}
        with tempfile.TemporaryDirectory() as td:
            progress=Path(td)/"progress.json"; progress.write_text("{}",encoding="utf-8")
            with (
                mock.patch.object(runner.core,"load",side_effect=[{},{}]),
                mock.patch.object(runner.core,"validate_matrix_contract",return_value={}),
                mock.patch.object(runner.core,"verify_campaign",return_value=campaign),
                mock.patch.object(runner.admission,"base_progress",return_value=expected),
                mock.patch.object(runner.admission,"validate_existing",side_effect=[{"chatgpt":bulk_rows[0]}, {client:row for client,row in zip(core.CLIENTS,bulk_rows)}]),
                mock.patch.object(runner.admission,"validate_existing_campaign_rows") as validate_rows,
            ):
                recovered=runner.recover_complete_progress_from_bulk(Path("matrix.json"),Path("campaign.json"),bulk,progress)
        self.assertTrue(recovered["complete"])
        self.assertEqual(4,recovered["certifiedClientCount"])
        self.assertEqual(bulk_rows,recovered["clients"])
        self.assertTrue(recovered["externalCertificationPass"])
        self.assertTrue(recovered["serverAuditWitnessPass"])
        self.assertEqual(2,validate_rows.call_count)


if __name__=="__main__":
    unittest.main()
