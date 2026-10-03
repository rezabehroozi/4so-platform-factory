import importlib.util, json, sys, unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("reconcile_c7w_trusted_clients",ROOT/"scripts"/"reconcile_c7w_trusted_clients.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ReconcileC7WTrustedClientsTests(unittest.TestCase):
    def bindings(self):
        return {client:f"oauth-{client}" for client in mod.CLIENTS}

    def active(self,client,client_id=None):
        return {
            "id":f"trusted-{client}","revision":1,
            "clientId":client_id or f"oauth-{client}",
            "displayName":f"C7W {client}","provider":client,"state":"ACTIVE",
        }

    def test_plan_is_idempotent_when_all_expected_active_rows_exist(self):
        rows=[self.active(client) for client in mod.CLIENTS]
        plan=mod.reconcile_plan(rows,self.bindings())
        self.assertEqual([],plan["create"])
        self.assertEqual(list(mod.CLIENTS),plan["ready"])

    def test_plan_creates_only_missing_or_revoked_only_binding(self):
        rows=[self.active("chatgpt"),self.active("claude"),self.active("gemini")]
        rows.append({"id":"old-grok","revision":2,"clientId":"oauth-grok","provider":"grok","state":"REVOKED"})
        plan=mod.reconcile_plan(rows,self.bindings())
        self.assertEqual(["grok"],[row["provider"] for row in plan["create"]])
        self.assertEqual("oauth-grok",plan["create"][0]["clientId"])
        self.assertEqual([],plan["create"][0]["redirectUris"])

    def test_plan_rejects_wrong_provider_active_binding(self):
        rows=[self.active(client) for client in mod.CLIENTS]
        rows[-1]["provider"]="claude"
        with self.assertRaisesRegex(RuntimeError,"TRUSTED_CLIENT_CONFLICT grok"):
            mod.reconcile_plan(rows,self.bindings())

    def test_plan_rejects_multiple_active_rows_for_same_client_id(self):
        rows=[self.active(client) for client in mod.CLIENTS]
        duplicate=dict(rows[0]); duplicate["id"]="trusted-chatgpt-duplicate"
        rows.append(duplicate)
        with self.assertRaisesRegex(RuntimeError,"TRUSTED_CLIENT_CONFLICT chatgpt"):
            mod.reconcile_plan(rows,self.bindings())

    def test_reconcile_creates_missing_rows_and_proves_final_readback_without_token_leak(self):
        bindings=self.bindings()
        before=[self.active("chatgpt"),self.active("claude"),self.active("gemini")]
        after=before+[self.active("grok")]
        with (
            mock.patch.object(mod,"fetch_rows",side_effect=[before,after]) as fetch,
            mock.patch.object(mod,"create_row",return_value=self.active("grok")) as create,
        ):
            out=mod.reconcile("https://mcp.example.test/mcp",bindings,"TOKEN_ENV")
        self.assertEqual(2,fetch.call_count)
        create.assert_called_once()
        self.assertEqual(4,out["trustedClientCount"])
        self.assertEqual("RUN_C7W_PREFLIGHT",out["nextActionCode"])
        self.assertNotIn("secret",json.dumps(out).lower())
        self.assertNotIn("oauth-grok",json.dumps(out))


if __name__=="__main__":
    unittest.main()
