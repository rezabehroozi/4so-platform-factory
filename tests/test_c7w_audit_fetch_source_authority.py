import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)
SPEC=importlib.util.spec_from_file_location("c7w_audit_fetch_source_authority",ROOT/"scripts/fetch_mcp_external_audit_window.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class Response:
    status=200
    def __init__(self,url): self.url=url
    def geturl(self): return self.url
    def read(self,_limit): return b"[{}]"
    def __enter__(self): return self
    def __exit__(self,*_args): return False


class C7WAuditFetchSourceAuthorityTests(unittest.TestCase):
    def test_source_drift_after_network_response_blocks_audit_persist(self):
        campaign={"sourceCommitSHA":"a"*40}
        matrix={"authority":mod.core.MATRIX_AUTHORITY,"spec":{"sharedRequiredChecks":list(mod.core.REQUIRED_CHECKS),"protocol":"2026-07-28"}}
        receipt={
            "endpoint":"https://mcp.example.test/mcp",
            "requestIds":{name:f"request-{idx:02d}-authority" for idx,name in enumerate(mod.core.AUDITED_CHECKS,1)},
        }
        opener=SimpleNamespace(open=lambda req,timeout: Response(req.full_url))
        with (
            mock.patch.object(mod.core,"load",return_value=matrix),
            mock.patch.object(mod.core,"verify_campaign",return_value=campaign),
            mock.patch.object(mod.core,"verify_receipt",return_value=receipt),
            mock.patch.object(mod,"exact_https_opener",return_value=opener),
            mock.patch.object(mod,"atomic_write") as persist,
            mock.patch.dict(mod.os.environ,{"C7W_PLATFORM_ADMIN_TOKEN":"token-value"},clear=False),
            mock.patch.object(
                mod.execution_bindings,
                "source_commit_sha",
                side_effect=["a"*40,RuntimeError("MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_MISMATCH")],
            ) as source_check,
        ):
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_EXECUTION_BINDINGS_SOURCE_MISMATCH"):
                mod.fetch(Path("matrix.json"),Path("campaign.json"),Path("receipt.json"),"chatgpt","C7W_PLATFORM_ADMIN_TOKEN",Path("audit.json"),1,0)
        self.assertEqual(2,source_check.call_count)
        persist.assert_not_called()


if __name__=="__main__":
    unittest.main()
