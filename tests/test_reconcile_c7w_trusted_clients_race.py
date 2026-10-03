import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("reconcile_c7w_trusted_clients",ROOT/"scripts"/"reconcile_c7w_trusted_clients.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ReconcileC7WTrustedClientsRaceTests(unittest.TestCase):
    def bindings(self):
        return {client:f"oauth-{client}" for client in mod.CLIENTS}

    def active(self,client):
        return {
            "id":f"trusted-{client}",
            "revision":1,
            "clientId":f"oauth-{client}",
            "displayName":f"C7W {client}",
            "provider":client,
            "state":"ACTIVE",
        }

    def test_concurrent_409_is_recovered_only_by_final_active_readback(self):
        before=[self.active("chatgpt"),self.active("claude"),self.active("gemini")]
        after=before+[self.active("grok")]
        with (
            mock.patch.object(mod,"fetch_rows",side_effect=[before,after]) as fetch,
            mock.patch.object(mod,"create_row",side_effect=RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_CREATE_HTTP_INVALID status=409")) as create,
        ):
            out=mod.reconcile("https://mcp.example.test/mcp",self.bindings(),"TOKEN_ENV")
        self.assertEqual(2,fetch.call_count)
        create.assert_called_once()
        self.assertEqual(4,out["trustedClientCount"])
        self.assertEqual([],out["createdProviders"])
        self.assertEqual("RUN_C7W_PREFLIGHT",out["nextActionCode"])

    def test_non_conflict_create_failure_remains_fatal(self):
        before=[self.active("chatgpt"),self.active("claude"),self.active("gemini")]
        with (
            mock.patch.object(mod,"fetch_rows",return_value=before),
            mock.patch.object(mod,"create_row",side_effect=RuntimeError("MCP_EXTERNAL_TRUSTED_CLIENT_CREATE_HTTP_INVALID status=500")),
        ):
            with self.assertRaisesRegex(RuntimeError,"status=500"):
                mod.reconcile("https://mcp.example.test/mcp",self.bindings(),"TOKEN_ENV")


if __name__=="__main__":
    unittest.main()
