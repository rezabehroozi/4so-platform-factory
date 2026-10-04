import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("seal_mcp_external_interop_receipt_provenance",ROOT/"scripts"/"seal_mcp_external_interop.py")
core=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(core)


class C7WReceiptExecutionBindingProvenanceTests(unittest.TestCase):
    def projection(self):
        source="a"*40
        document={
            "authority":"MCP_EXTERNAL_EXECUTION_BINDINGS_V1",
            "sourceCommitSHA":source,
            "resources":{
                "foreignProjectId":"foreign-project",
                "sameProjectOperationId":"same-project-operation",
                "selfApprovalRequestId":"self-approval-request",
            },
            "credentialProfileContractAuthority":"MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1",
            "credentialProfileContractSha256":"sha256:"+"2"*64,
        }
        raw=(json.dumps(document,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8")
        projection={
            "executionBindingAuthority":document["authority"],
            "executionBindingsSha256":"sha256:"+hashlib.sha256(raw).hexdigest(),
            "executionBindings":document["resources"],
            "credentialProfileContractAuthority":document["credentialProfileContractAuthority"],
            "credentialProfileContractSha256":document["credentialProfileContractSha256"],
        }
        return source,projection

    def test_receipt_projection_matches_campaign_snapshot_and_rejects_drift(self):
        source,projection=self.projection()
        campaign={"sourceCommitSHA":source,**projection}
        receipt=dict(projection)
        self.assertEqual(projection,core.validate_receipt_execution_binding(receipt,campaign,"chatgpt"))
        drift=dict(receipt,executionBindingsSha256="sha256:"+"9"*64)
        with self.assertRaisesRegex(RuntimeError,"EXECUTION_BINDING_DRIFT"):
            core.validate_receipt_execution_binding(drift,campaign,"chatgpt")

    def test_legacy_unbound_fixture_remains_compatible_but_partial_projection_is_rejected(self):
        source,_=self.projection()
        self.assertEqual({},core.validate_receipt_execution_binding({}, {"sourceCommitSHA":source},"chatgpt"))
        with self.assertRaisesRegex(RuntimeError,"EXECUTION_BINDING_FIELDS_INVALID"):
            core.validate_receipt_execution_binding(
                {"executionBindingAuthority":"MCP_EXTERNAL_EXECUTION_BINDINGS_V1"},
                {"sourceCommitSHA":source},
                "chatgpt",
            )

    def test_finalizer_and_verifier_carry_nested_execution_binding_provenance(self):
        finalizer=(ROOT/"scripts"/"finalize_mcp_external_client_receipt.py").read_text(encoding="utf-8")
        seal=(ROOT/"scripts"/"seal_mcp_external_interop.py").read_text(encoding="utf-8")
        for marker in (
            '"executionBindingAuthority":packet["executionBindingAuthority"]',
            '"executionBindingsSha256":packet["executionBindingsSha256"]',
            '"executionBindings":resources',
            '"credentialProfileContractAuthority":packet["credentialProfileContractAuthority"]',
            '"credentialProfileContractSha256":packet["credentialProfileContractSha256"]',
        ):
            self.assertIn(marker,finalizer)
        self.assertIn("validate_receipt_execution_binding(row,campaign,client)",seal)
        self.assertIn("**execution_binding",seal)


if __name__=="__main__":
    unittest.main()
