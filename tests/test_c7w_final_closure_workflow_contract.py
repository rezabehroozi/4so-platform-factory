import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class C7WFinalClosureWorkflowContractTests(unittest.TestCase):
    def read(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_external_workflows_accept_captures_and_finalize_receipts_server_side(self):
        incremental = self.read(".github/workflows/mcp-external-receipt-admission.yml")
        self.assertIn("capture_b64:", incremental)
        self.assertNotIn("receipt_b64:", incremental)
        self.assertIn("finalize_mcp_external_client_receipt.py", incremental)
        self.assertIn(".capture.json", incremental)
        self.assertEqual(1, incremental.count("/tmp/mcp-external/${{ inputs.client }}.capture.json"))
        self.assertEqual(1, incremental.count("/tmp/mcp-external/${{ inputs.client }}.packet.json"))
        bulk = self.read(".github/workflows/mcp-external-interop-seal.yml")
        for client in ("chatgpt", "claude", "gemini", "grok"):
            self.assertIn(f"{client}_capture_b64:", bulk)
            self.assertNotIn(f"{client}_receipt_b64:", bulk)
        self.assertIn("finalize_mcp_external_client_receipt.py", bulk)

    def test_recovery_rebuilds_receipt_from_preserved_capture_before_merge(self):
        text = self.read(".github/workflows/mcp-external-receipt-recovery.yml")
        self.assertIn("$CLIENT.capture.json", text)
        self.assertIn("$CLIENT.packet.json", text)
        self.assertIn("$CLIENT.rebuilt.json", text)
        self.assertIn("finalize_mcp_external_client_receipt.py", text)
        self.assertIn('cmp "/tmp/mcp-external/$CLIENT.rebuilt.json" "/tmp/mcp-external/$CLIENT.json"', text)

    def test_incremental_receipt_admission_uses_exact_audit_ids_and_replays_with_audit(self):
        text = self.read(".github/workflows/mcp-external-receipt-admission.yml")
        self.assertNotIn("security-audit-events?limit=1000", text)
        self.assertIn('--data-urlencode "requestId=$rid"', text)
        api = self.read("internal/api/identity_authority.go")
        self.assertIn("AUDIT_REQUEST_IDS_PENDING", api)
        self.assertIn("securityAuditRequestIDValid", api)
        self.assertNotIn("securityAuditRequestIDPattern", api)
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

    def test_incremental_admission_preserves_verified_packet_before_git_push(self):
        text = self.read(".github/workflows/mcp-external-receipt-admission.yml")
        self.assertIn("Preserve verified admission packet before Git persistence", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("/tmp/mcp-external/campaign.json", text)
        self.assertIn("/tmp/mcp-external/${{ inputs.client }}.json", text)
        self.assertIn("/tmp/mcp-external/security-audit.json", text)
        self.assertLess(
            text.index("Preserve verified admission packet before Git persistence"),
            text.index("Reconcile onto latest main and persist progress"),
        )

    def test_verified_admission_packet_has_recovery_workflow(self):
        text = self.read(".github/workflows/mcp-external-receipt-recovery.yml")
        self.assertIn("admission_run_id:", text)
        self.assertIn('test "$(jq -r .name <<<"$run_json")" = "mcp-external-receipt-admission"', text)
        self.assertIn('gh run download "$ADMISSION_RUN_ID"', text)
        self.assertIn('mcp-external-receipt-$CLIENT-$ADMISSION_RUN_ID', text)
        self.assertIn("python3 scripts/admit_mcp_external_receipt.py", text)
        self.assertIn("git reset --hard origin/main", text)
        self.assertIn("cancel-in-progress: false", text)

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

    def test_failed_incremental_admission_auto_recovers_only_preserved_verified_packets(self):
        text = self.read(".github/workflows/mcp-external-receipt-recovery.yml")
        self.assertIn('workflows: ["mcp-external-receipt-admission"]', text)
        self.assertIn("github.event.workflow_run.conclusion == 'failure'", text)
        self.assertIn("admission failed before a verified packet was preserved; automatic recovery is a safe no-op", text)
        self.assertIn('select(test("^mcp-external-receipt-(chatgpt|claude|gemini|grok)-"+$run+"$"))', text)
        self.assertIn("expected exactly one recoverable packet artifact", text)
        self.assertIn("if: steps.packet.outputs.recoverable == 'true'", text)

    def test_final_seal_is_triggered_by_incremental_or_recovered_c7w_completion(self):
        text = self.read(".github/workflows/final-exact-release-seal.yml")
        self.assertIn('"mcp-external-receipt-admission"', text)
        self.assertIn('"mcp-external-receipt-recovery"', text)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", text)

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
