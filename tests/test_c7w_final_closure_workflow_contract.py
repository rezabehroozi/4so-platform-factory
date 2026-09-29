import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class C7WFinalClosureGitContractTests(unittest.TestCase):
    def read(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_external_execution_packet_carries_server_observed_binding(self):
        packet = self.read("scripts/prepare_mcp_external_client_execution.py")
        self.assertIn("interop_binding_digest", packet)
        self.assertIn("Mcp-Interop-Binding", packet)
        self.assertIn("INTEROP_BINDING_AUTHORITY", packet)
        self.assertIn('"secretsIncluded":False', packet)

    def test_capture_finalizer_rebuilds_receipt_from_packet_authority(self):
        finalizer = self.read("scripts/finalize_mcp_external_client_receipt.py")
        self.assertIn("MCP_EXTERNAL_CLIENT_CAPTURE_V1", finalizer)
        self.assertIn("interop_binding_digest", finalizer)
        self.assertIn("MCP_EXTERNAL_CAPTURE_PACKET_SERVER_BINDING_INVALID", finalizer)
        self.assertIn("MCP_EXTERNAL_CAPTURE_PACKET_SERVER_BINDING_MISSING", finalizer)
        self.assertIn('"evidenceDigest":core.sha256(capture_path)', finalizer)

    def test_sealer_requires_exact_audit_ids_and_server_binding(self):
        seal = self.read("scripts/seal_mcp_external_interop.py")
        self.assertIn("MCP_EXTERNAL_RECEIPT_REQUEST_ID_REUSE", seal)
        self.assertIn("MCP_EXTERNAL_AUDIT_REQUEST_AMBIGUOUS", seal)
        self.assertIn("MCP_EXTERNAL_AUDIT_INTEROP_BINDING_MISSING", seal)
        self.assertIn("validate_server_audit_witness", seal)
        self.assertIn("mcpInteropBindingDigest", seal)

    def test_audit_window_fetch_is_campaign_bound_and_secret_safe(self):
        fetcher = self.read("scripts/fetch_mcp_external_audit_window.py")
        matrix = self.read("lab/mcp-external-client-interop-matrix.json")
        self.assertIn("core.verify_campaign", fetcher)
        self.assertIn("core.verify_receipt", fetcher)
        self.assertIn("core.validate_audit_export", fetcher)
        self.assertIn("AUDIT_REQUEST_IDS_PENDING", fetcher)
        self.assertIn('default="C7W_PLATFORM_ADMIN_TOKEN"', fetcher)
        self.assertNotIn("--token ", fetcher)
        self.assertIn('"auditTokenSource": "environment:C7W_PLATFORM_ADMIN_TOKEN"', matrix)
        self.assertNotIn("C7W_PLATFORM_ADMIN_TOKEN=<secret>", matrix)

    def test_incremental_progress_reuses_canonical_binding_and_witness_contract(self):
        progress = self.read("scripts/admit_mcp_external_receipt.py")
        self.assertIn("core.validate_interop_binding", progress)
        self.assertIn("core.validate_server_audit_witness", progress)
        self.assertIn("MCP_EXTERNAL_PROGRESS_REQUEST_ID_REUSE", progress)
        self.assertIn("MCP_EXTERNAL_PROGRESS_PROVIDER_EXECUTION_REUSE", progress)

    def test_final_release_reuses_same_c7w_contract(self):
        final = self.read("scripts/final_exact_release_admission.py")
        self.assertIn("seal_mcp_external_interop as mcp_contract", final)
        self.assertIn("mcp_contract.validate_interop_binding", final)
        self.assertIn("mcp_contract.validate_server_audit_witness", final)
        self.assertNotIn("gh run list", final)

    def test_matrix_names_real_external_evidence_blocker(self):
        matrix = self.read("lab/mcp-external-client-interop-matrix.json")
        self.assertIn("MCP_EXTERNAL_CLIENT_INTEROP_EVIDENCE_PENDING", matrix)
        self.assertNotIn("MCP_EXTERNAL_CLIENT_INTEROP_MATRIX_PENDING", matrix)
        self.assertIn("--audits /secure/audits", matrix)
        self.assertIn("finalReleaseSealCommand", matrix)
        self.assertIn("scripts/seal_final_exact_release.py", matrix)
        self.assertNotIn("finalReleaseAdmissionCommand", matrix)

    def test_c9_is_locally_executable_without_ci_run_identity(self):
        seal = self.read("scripts/seal_final_exact_release.py")
        self.assertIn('AUTHORITY = "FINAL_EXACT_RELEASE_SEAL_V1"', seal)
        self.assertIn('EXECUTION_AUTHORITY = "LOCAL_EXACT_RELEASE_SEAL_V1"', seal)
        self.assertIn("admission.verify(root)", seal)
        self.assertIn('"build-release"', seal)
        self.assertIn('"scripts/build_release.py"', seal)
        self.assertIn('"scripts/verify_release.py"', seal)
        self.assertIn('"--full"', seal)
        self.assertIn("git_source(root)", seal)
        self.assertIn("atomic_write_json", seal)
        self.assertNotIn("GITHUB_RUN_ID", seal)
        self.assertNotIn("gh run", seal)

    def test_roadmap_does_not_treat_github_workflows_as_c7w_or_c9_authority(self):
        program = self.read("internal/targetmodel/program.go")
        self.assertIn("MCP_EXTERNAL_CLIENT_INTEROP_EVIDENCE_PENDING", program)
        for workflow in (
            ".github/workflows/mcp-external-interop-campaign.yml",
            ".github/workflows/mcp-external-interop-seal.yml",
            ".github/workflows/mcp-external-receipt-admission.yml",
            ".github/workflows/final-exact-release-seal.yml",
        ):
            self.assertNotIn(workflow, program)


if __name__ == "__main__":
    unittest.main()
