import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_prepare_guard",ROOT/"scripts/run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class C7WPrepareEvidenceGuardTests(unittest.TestCase):
    def test_prepare_rejects_existing_canonical_evidence_before_live_campaign_work(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            state=root/"state"
            state.mkdir()
            evidence=root/"evidence.json"
            evidence.write_text("{}",encoding="utf-8")
            args=SimpleNamespace(
                state_dir=state,
                matrix=root/"matrix.json",
                progress_out=root/"progress.json",
                evidence_out=evidence,
                source_commit_sha="",
                endpoint="https://example.invalid/mcp",
                oauth_client_map=None,
                token_env="C7W_PLATFORM_ADMIN_TOKEN",
            )
            with (
                mock.patch.object(mod.Path,"cwd",return_value=root),
                mock.patch.object(mod,"require_c7w_source_freeze"),
                mock.patch.object(mod,"require_canonical_matrix",return_value=args.matrix),
                mock.patch.object(mod,"secure_state_dir",return_value=state),
                mock.patch.object(mod.campaign_builder,"source_commit_sha",side_effect=AssertionError("live prepare reached")),
            ):
                with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_PREPARE_WITH_CANONICAL_EVIDENCE"):
                    mod.prepare(args)


if __name__=="__main__":
    unittest.main()
