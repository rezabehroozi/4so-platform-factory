import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class C7WFinalClosureWorkflowContractTests(unittest.TestCase):
    def read(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_incremental_receipt_admission_uses_exact_audit_ids_and_replays_with_audit(self):
        text = self.read(".github/workflows/mcp-external-receipt-admission.yml")
        self.assertNotIn("security-audit-events?limit=1000", text)
        self.assertIn('--data-urlencode "requestId=$rid"', text)
        self.assertIn("AUDIT_REQUEST_IDS_PENDING", self.read("internal/api/identity_authority.go"))
        commands = [
            line.strip()
            for line in text.splitlines()
            if "python3 scripts/admit_mcp_external_receipt.py" in line
        ]
        self.assertGreaterEqual(len(commands), 2)
        for command in commands:
            self.assertIn("--audit /tmp/mcp-external/security-audit.json", command)
        self.assertIn("supersede_incomplete_campaign:", text)
        self.assertIn("--allow-campaign-supersede", text)

    def test_campaign_is_live_discovery_gated_before_packets_are_created(self):
        text = self.read(".github/workflows/mcp-external-interop-campaign.yml")
        self.assertIn("Preflight public MCP OAuth discovery and challenge", text)
        self.assertIn("/.well-known/oauth-protected-resource", text)
        self.assertIn('.resource == $endpoint', text)
        self.assertIn('index("mcp.read")', text)
        self.assertIn('index("mcp.operate")', text)
        self.assertIn('test "$code" = "401"', text)
        self.assertIn("MCP-Protocol-Version: 2026-07-28", text)

    def test_bulk_seal_reuses_campaign_artifact_and_retries_audit_visibility(self):
        text = self.read(".github/workflows/mcp-external-interop-seal.yml")
        self.assertIn("campaign_run_id:", text)
        self.assertIn('gh run download "$CAMPAIGN_RUN_ID"', text)
        self.assertNotIn("security-audit-events?limit=1000", text)
        self.assertIn('--data-urlencode "requestId=$rid"', text)
        self.assertIn("for attempt in $(seq 1 15)", text)
        self.assertIn('test "$code" = "409"', text)

    def test_external_receipts_cannot_reuse_server_request_ids_across_clients(self):
        seal = self.read("scripts/seal_mcp_external_interop.py")
        progress = self.read("scripts/admit_mcp_external_receipt.py")
        self.assertIn("MCP_EXTERNAL_RECEIPT_REQUEST_ID_REUSE", seal)
        self.assertIn("MCP_EXTERNAL_PROGRESS_REQUEST_ID_REUSE", progress)

    def test_final_release_seals_actual_checkout_and_avoids_self_trigger_loop(self):
        text = self.read(".github/workflows/final-exact-release-seal.yml")
        self.assertIn("paths-ignore:", text)
        self.assertIn("- lab/final-exact-release-evidence.json", text)
        self.assertIn("group: final-exact-release-main", text)
        self.assertIn("cancel-in-progress: true", text)
        self.assertIn('source_sha="$(git rev-parse HEAD)"', text)
        self.assertIn('echo "SOURCE_SHA=$source_sha" >> "$GITHUB_ENV"', text)
        self.assertIn('"sourceCommitSHA":os.environ["SOURCE_SHA"]', text)
        self.assertIn('test "$(git rev-parse origin/main)" = "$SOURCE_SHA"', text)
        self.assertNotRegex(text, re.compile(r'"sourceCommitSHA":os\.environ\["GITHUB_SHA"\]'))


if __name__ == "__main__":
    unittest.main()
