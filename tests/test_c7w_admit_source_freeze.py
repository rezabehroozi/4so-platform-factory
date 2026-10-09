import importlib.util
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import c7w_execution_bindings as source_authority

SPEC=importlib.util.spec_from_file_location("admit_mcp_external_receipt_source_freeze",ROOT/"scripts"/"admit_mcp_external_receipt.py")
admission=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(admission)


def matrix_document():
    return {
        "authority":admission.core.MATRIX_AUTHORITY,
        "spec":{
            "externalCertificationStatus":"pending",
            "protocol":"2026-07-28",
            "transport":"streamable-http",
            "sharedRequiredChecks":list(admission.core.REQUIRED_CHECKS),
            "clients":[{"id":client,"displayName":admission.core.CLIENT_SURFACES[client]} for client in admission.core.CLIENTS],
        },
    }


class C7WAdmitSourceFreezeTests(unittest.TestCase):
    def test_matrix_contract_rejects_source_drift(self):
        campaign={"sourceCommitSHA":"a"*40}
        with (
            mock.patch.object(admission.core,"load",return_value=matrix_document()),
            mock.patch.object(admission.core,"verify_campaign",return_value=campaign),
            mock.patch.object(source_authority,"source_commit_sha",return_value="b"*40),
            mock.patch.object(admission.core,"validate_evidence_only_source_lineage",side_effect=RuntimeError("MCP_EXTERNAL_PROGRESS_SOURCE_DRIFT")) as lineage,
        ):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_PROGRESS_SOURCE_DRIFT"):
                admission.matrix_contract(Path("matrix.json"),Path("campaign.json"))
        lineage.assert_called_once()

    def test_merge_rechecks_source_after_receipt_and_audit_validation(self):
        campaign={"sourceCommitSHA":"a"*40}
        row={
            "executionId":"execution-1",
            "evidenceDigest":"sha256:"+"1"*64,
            "providerExecutionRef":"provider-ref-1",
            "requestIds":{},
        }
        with (
            mock.patch.object(admission,"matrix_contract",return_value=({"protocol":"2026-07-28"},[],campaign)),
            mock.patch.object(admission,"base_progress",return_value={}),
            mock.patch.object(admission.core,"verify_receipt",return_value=row),
            mock.patch.object(admission.core,"verify_server_audit",return_value={}),
            mock.patch.object(source_authority,"source_commit_sha",return_value="b"*40),
            mock.patch.object(admission.core,"validate_evidence_only_source_lineage",side_effect=RuntimeError("MCP_EXTERNAL_PROGRESS_SOURCE_DRIFT")) as lineage,
        ):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_PROGRESS_SOURCE_DRIFT"):
                admission.merge(Path("matrix.json"),Path("campaign.json"),Path("receipt.json"),Path("audit.json"),"chatgpt",None)
        lineage.assert_called_once()

    def test_campaign_row_validation_rechecks_source_before_status_handoff(self):
        now=datetime.now(timezone.utc)
        campaign={"sourceCommitSHA":"a"*40}
        with (
            mock.patch.object(admission.core,"campaign_time_window",return_value=(now,now+timedelta(hours=1),60)),
            mock.patch.object(admission.core,"endpoint",return_value="https://mcp.example.test/mcp"),
            mock.patch.object(source_authority,"source_commit_sha",return_value="b"*40),
            mock.patch.object(admission.core,"validate_evidence_only_source_lineage",side_effect=RuntimeError("MCP_EXTERNAL_PROGRESS_SOURCE_DRIFT")) as lineage,
        ):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_PROGRESS_SOURCE_DRIFT"):
                admission.validate_existing_campaign_rows({}, {"endpoint":"https://mcp.example.test/mcp"}, campaign, {})
        lineage.assert_called_once()

    def test_final_evidence_rechecks_source_before_projection(self):
        progress={
            "matrixSha256":"sha256:"+"1"*64,
            "campaignId":"mcp-interop-unit",
            "campaignSha256":"sha256:"+"2"*64,
            "oauthClientBindingsSha256":"sha256:"+"3"*64,
            "sourceCommitSHA":"a"*40,
            "runtimeVersion":"0.0.unit",
            "protocol":"2026-07-28",
            "transport":"streamable-http",
            "endpoint":"https://mcp.example.test/mcp",
            "clients":[],
            "complete":True,
        }
        ordered={client:{} for client in admission.core.CLIENTS}
        with (
            mock.patch.object(admission.core,"load",return_value=progress),
            mock.patch.object(admission,"validate_existing",return_value=ordered),
            mock.patch.object(source_authority,"source_commit_sha",return_value="b"*40),
            mock.patch.object(admission.core,"validate_evidence_only_source_lineage",side_effect=RuntimeError("MCP_EXTERNAL_PROGRESS_SOURCE_DRIFT")) as lineage,
            mock.patch.object(admission.core,"build_interop_evidence",return_value={}) as build,
        ):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_PROGRESS_SOURCE_DRIFT"):
                admission.final_evidence(progress,Path("progress.json"))
        lineage.assert_called_once()
        build.assert_not_called()


if __name__=="__main__":
    unittest.main()
