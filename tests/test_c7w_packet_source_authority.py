import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)
SPEC=importlib.util.spec_from_file_location("c7w_packet_source_authority",ROOT/"scripts/prepare_mcp_external_client_execution.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class C7WPacketSourceAuthorityTests(unittest.TestCase):
    def test_packet_rejects_campaign_when_current_source_changed(self):
        campaign={"sourceCommitSHA":"a"*40}
        with (
            mock.patch.object(mod.core,"load",return_value={"spec":{}}),
            mock.patch.object(mod.core,"verify_campaign",return_value=campaign),
            mock.patch.object(
                mod.execution_bindings,
                "source_commit_sha",
                side_effect=RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_MISMATCH"),
            ) as source_check,
        ):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_MISMATCH"):
                mod.packet(Path("matrix.json"),Path("campaign.json"),"chatgpt")
        source_check.assert_called_once_with(mod.ROOT,campaign["sourceCommitSHA"],require_freeze=True)


if __name__=="__main__":
    unittest.main()
