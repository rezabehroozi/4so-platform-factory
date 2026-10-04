import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_execution_authority_gate",ROOT/"scripts"/"c7w_execution_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WExecutionAuthorityGateTests(unittest.TestCase):
    def write(self,root,rel,text):
        p=root/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(text,encoding="utf-8")

    def good(self,root):
        self.write(root,"scripts/reconcile_c7w_trusted_clients.py",'''AUTHORITY="MCP_EXTERNAL_TRUSTED_CLIENT_RECONCILIATION_V1"\ndef reconcile_plan(): pass\ndef reconcile():\n    before=fetch_rows()\n    try: create_row()\n    except RuntimeError as exc:\n        if "status=409" not in str(exc): raise\n    after=fetch_rows()\n    return preflight_command()\ndef preflight_command(): pass\n''')
        self.write(root,"scripts/c7w_preflight.py",'''DEFAULT_EXECUTION_BINDING_REL=".state/private/c7w-execution-bindings.json"\ndef trusted_client_reconcile_command(): return ["scripts/reconcile_c7w_trusted_clients.py"]\n# "RECONCILE_C7W_TRUSTED_CLIENTS"\n# PREPARE_C7W_EXECUTION_BINDINGS scripts/c7w_execution_bindings.py executionBindingsSha256\n# MCP_EXTERNAL_EXECUTION_BINDINGS_PATH_INVALID\n''')
        self.write(root,"scripts/prepare_c7w_oauth_bindings.py",'''DEFAULT_OUTPUT=".state/private/c7w-oauth-client-bindings.json"\ndef followup_preflight_command(): pass\n''')
        self.write(root,"scripts/c7w_execution_bindings.py",'''AUTHORITY="MCP_EXTERNAL_EXECUTION_BINDINGS_V1"\nDEFAULT_OUTPUT=Path(".state/private/c7w-execution-bindings.json")\ndef validate_document(): pass\ndef canonical_output_path(): pass\ndef materialize(): pass\n# credentialProfileContractSha256\n''')
        self.write(root,"scripts/c7w_credential_profiles.py",'''AUTHORITY="MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1"\ndef contract(): return {}\ndef contract_digest(): return "sha256:"+"0"*64\n''')
        self.write(root,"scripts/c7w_execution_provenance.py",'''EXECUTION_BINDING_AUTHORITY="MCP_EXTERNAL_EXECUTION_BINDINGS_V1"\nCREDENTIAL_PROFILE_CONTRACT_AUTHORITY="MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1"\ndef credential_contract_digest():\n    return credential_profiles.contract_digest()\ndef projection():\n    credential_digest=""\n    if credential_digest!=credential_contract_digest():\n        raise RuntimeError("EXECUTION_BINDING_CREDENTIAL_CONTRACT_INVALID")\ndef validate_rows():\n    # EXECUTION_BINDING_MIXED EXECUTION_BINDING_REQUIRED\n    pass\ndef validate_receipt_execution_binding(): pass\n''')
        self.write(root,"scripts/run_mcp_external_interop.py",'''AUTHORITY="MCP_EXTERNAL_LOCAL_EXECUTION_RUNNER_V1"\ndef runner_command(): pass\n''')
        self.write(root,"scripts/prepare_mcp_external_interop_campaign.py",'''AUTHORITY=core.CAMPAIGN_AUTHORITY\ndef source_commit_sha(): pass\ndef execution_binding_snapshot(): pass\ndef normalize_execution_binding_snapshot(): pass\ndef prepare(matrix_path):\n    if canonical_execution_binding_required(matrix_path): pass\n# executionBindingsSha256 MCP_EXTERNAL_CAMPAIGN_EXECUTION_BINDING_DRIFT\n''')
        self.write(root,"scripts/seal_mcp_external_interop.py",'''AUTHORITY="MCP_EXTERNAL_CLIENT_INTEROPERABILITY_EVIDENCE_V1"\ndef validate_evidence_only_source_lineage(): pass\ndef validate_receipt_execution_binding(): pass\ndef verify_receipt(row,campaign,client):\n    execution_binding=validate_receipt_execution_binding(row,campaign,client)\n    return {**execution_binding}\ndef build_interop_evidence(rows,source_commit_sha):\n    execution_provenance.validate_rows(rows,source_commit_sha,"MCP_EXTERNAL_EVIDENCE",require_bound=True)\n''')
        self.write(root,"scripts/prepare_mcp_external_client_execution.py",'''AUTHORITY="MCP_EXTERNAL_CLIENT_EXECUTION_PACKET_V1"\ndef _binding_snapshot(): pass\n# executionBindingsSha256 credentialProfileContract\n''')
        self.write(root,"scripts/finalize_mcp_external_client_receipt.py",'''def _packet_execution_bindings(): pass\n# executionBindingsSha256 credentialProfileContractSha256\n# "executionBindings":resources\n''')
        self.write(root,"scripts/admit_mcp_external_receipt.py",'''def validate_existing():\n    execution_provenance.validate_rows([],"0"*40,"MCP_EXTERNAL_PROGRESS",require_bound=False)\ndef validate_existing_campaign_rows(row,campaign,client):\n    core.validate_receipt_execution_binding(row,campaign,client)\n''')

    def test_complete_owner_graph_passes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root); self.assertEqual([],mod.validate(root))

    def test_missing_reconciler_or_wiring_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root); (root/"scripts/reconcile_c7w_trusted_clients.py").unlink(); codes=[c for c,_ in mod.validate(root)]; self.assertIn("C7W_EXECUTION_OWNER_MISSING",codes)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root); (root/"scripts/c7w_preflight.py").write_text("# disconnected\n",encoding="utf-8"); codes=[c for c,_ in mod.validate(root)]; self.assertIn("C7W_RECONCILIATION_WIRING_INVALID",codes); self.assertIn("C7W_EXECUTION_BINDINGS_WIRING_INVALID",codes)

    def test_missing_execution_binding_owner_or_packet_placeholder_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root); (root/"scripts/c7w_execution_bindings.py").unlink(); codes=[c for c,_ in mod.validate(root)]; self.assertIn("C7W_EXECUTION_OWNER_MISSING",codes); self.assertIn("C7W_EXECUTION_BINDINGS_OWNER_INVALID",codes)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root); packet=root/"scripts/prepare_mcp_external_client_execution.py"; packet.write_text(packet.read_text()+"\n# <foreign-project-id>\n",encoding="utf-8"); errors=mod.validate(root); self.assertTrue(any(code=="C7W_EXECUTION_PLACEHOLDER_FORBIDDEN" and "<foreign-project-id>" in detail for code,detail in errors))

    def test_execution_binding_multi_path_authority_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root)
            execution=root/"scripts/c7w_execution_bindings.py"
            execution.write_text(execution.read_text().replace("def canonical_output_path(): pass\n",""),encoding="utf-8")
            preflight=root/"scripts/c7w_preflight.py"
            preflight.write_text(preflight.read_text().replace("# MCP_EXTERNAL_EXECUTION_BINDINGS_PATH_INVALID\n",""),encoding="utf-8")
            codes=[c for c,_ in mod.validate(root)]
            self.assertIn("C7W_EXECUTION_BINDINGS_OWNER_INVALID",codes)
            self.assertIn("C7W_EXECUTION_BINDINGS_WIRING_INVALID",codes)

    def test_missing_provenance_anchor_or_final_evidence_binding_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root)
            provenance=root/"scripts/c7w_execution_provenance.py"
            provenance.write_text(provenance.read_text().replace("def credential_contract_digest():\n    return credential_profiles.contract_digest()\n",""),encoding="utf-8")
            codes=[c for c,_ in mod.validate(root)]
            self.assertIn("C7W_EXECUTION_PROVENANCE_OWNER_INVALID",codes)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root)
            seal=root/"scripts/seal_mcp_external_interop.py"
            seal.write_text(seal.read_text().replace('    execution_provenance.validate_rows(rows,source_commit_sha,"MCP_EXTERNAL_EVIDENCE",require_bound=True)\n',''),encoding="utf-8")
            codes=[c for c,_ in mod.validate(root)]
            self.assertIn("C7W_SEAL_OWNER_INVALID",codes)

    def test_credential_digest_owner_or_delegation_drift_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root)
            profiles=root/"scripts/c7w_credential_profiles.py"
            profiles.write_text(profiles.read_text().replace('def contract_digest(): return "sha256:"+"0"*64\n',''),encoding="utf-8")
            codes=[c for c,_ in mod.validate(root)]
            self.assertIn("C7W_CREDENTIAL_PROFILE_OWNER_INVALID",codes)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good(root)
            provenance=root/"scripts/c7w_execution_provenance.py"
            provenance.write_text(provenance.read_text().replace("credential_profiles.contract_digest()","'sha256:'+('0'*64)"),encoding="utf-8")
            codes=[c for c,_ in mod.validate(root)]
            self.assertIn("C7W_EXECUTION_PROVENANCE_OWNER_INVALID",codes)


if __name__=="__main__": unittest.main()
