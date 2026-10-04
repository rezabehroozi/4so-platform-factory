import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "prepare_mcp_external_interop_campaign_execution_binding_snapshot",
    ROOT / "scripts" / "prepare_mcp_external_interop_campaign.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class C7WCampaignExecutionBindingSnapshotTests(unittest.TestCase):
    def snapshot(self):
        return {
            "executionBindingAuthority": "MCP_EXTERNAL_EXECUTION_BINDINGS_V1",
            "executionBindingsSha256": "sha256:" + "1" * 64,
            "executionBindings": {
                "foreignProjectId": "foreign-project",
                "sameProjectOperationId": "same-project-operation",
                "selfApprovalRequestId": "self-approval-request",
            },
            "credentialProfileContractAuthority": "MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1",
            "credentialProfileContractSha256": "sha256:" + "2" * 64,
        }

    def trusted(self):
        return {
            client: {
                "oauthClientId": f"oauth-{client}",
                "trustedClientId": f"trusted-{client}",
                "trustedClientRevision": 1,
                "trustedClientProvider": client,
            }
            for client in mod.CLIENTS
        }

    def test_prepare_persists_supplied_execution_binding_snapshot(self):
        source_sha = "a" * 40
        snapshot = self.snapshot()
        runtime_identity = {
            "authority": "MCP_EXTERNAL_RUNTIME_SOURCE_IDENTITY_V1",
            "product": "4SO Platform Factory",
            "version": "test-runtime",
            "sourceCommitSHA": source_sha,
        }
        with tempfile.TemporaryDirectory() as td:
            matrix = Path(td) / "matrix.json"
            matrix.write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(mod.core, "load_with_sha256", return_value=({}, "sha256:" + "3" * 64)),
                mock.patch.object(
                    mod.core,
                    "validate_matrix_contract",
                    return_value={
                        "campaignMaxAgeSeconds": 3600,
                        "executionAuditWindowSeconds": 60,
                        "protocol": "2026-07-28",
                        "transport": "streamable-http",
                    },
                ),
                mock.patch.object(mod, "normalize_execution_binding_snapshot", return_value=snapshot),
            ):
                campaign = mod.prepare(
                    matrix,
                    "https://mcp.example.test/mcp",
                    {"authority": mod.PREFLIGHT_AUTHORITY},
                    "sha256:" + "4" * 64,
                    self.trusted(),
                    runtime_identity,
                    execution_binding_snapshot=snapshot,
                )
        for key, value in snapshot.items():
            self.assertEqual(value, campaign[key])

    def test_resume_rejects_execution_binding_snapshot_drift(self):
        source_sha = "a" * 40
        snapshot = self.snapshot()
        campaign = {
            "sourceCommitSHA": source_sha,
            "endpoint": "https://mcp.example.test/mcp",
            **snapshot,
        }
        with tempfile.TemporaryDirectory() as td:
            matrix = Path(td) / "matrix.json"
            out = Path(td) / "campaign.json"
            matrix.write_text("{}", encoding="utf-8")
            out.write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(mod.core, "load", return_value={"spec": {}}),
                mock.patch.object(mod.core, "verify_campaign", return_value=campaign),
                mock.patch.object(mod.core, "validate_evidence_only_source_lineage", return_value=None),
                mock.patch.object(mod, "normalize_execution_binding_snapshot", side_effect=lambda value, _source: value),
            ):
                self.assertIs(
                    campaign,
                    mod.resume_existing(
                        matrix,
                        "https://mcp.example.test/mcp",
                        out,
                        source_sha,
                        execution_binding_snapshot=snapshot,
                    ),
                )
                drift = dict(snapshot, executionBindingsSha256="sha256:" + "9" * 64)
                with self.assertRaisesRegex(RuntimeError, "EXECUTION_BINDING_DRIFT"):
                    mod.resume_existing(
                        matrix,
                        "https://mcp.example.test/mcp",
                        out,
                        source_sha,
                        execution_binding_snapshot=drift,
                    )

    def test_canonical_entrypoints_bind_campaign_before_packet_generation(self):
        campaign_source = (ROOT / "scripts" / "prepare_mcp_external_interop_campaign.py").read_text(encoding="utf-8")
        runner_source = (ROOT / "scripts" / "run_mcp_external_interop.py").read_text(encoding="utf-8")
        self.assertIn("c7w_execution_bindings", campaign_source)
        self.assertIn("execution_binding_snapshot(source_sha)", campaign_source)
        self.assertIn("execution_binding_snapshot=execution_snapshot", campaign_source)
        self.assertIn("canonical_execution_binding_required(matrix_path)", campaign_source)
        self.assertIn("require_canonical_matrix(root,args.matrix)", runner_source)


if __name__ == "__main__":
    unittest.main()
