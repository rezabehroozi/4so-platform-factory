import importlib.util, sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("prepare_mcp_external_interop_campaign",ROOT/"scripts"/"prepare_mcp_external_interop_campaign.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WTrustedClientReadbackTests(unittest.TestCase):
    def bindings(self):
        return {client:f"oauth-{client}" for client in mod.CLIENTS}

    def active(self,client,suffix="new"):
        return {
            "id":f"trusted-{client}-{suffix}",
            "revision":2,
            "clientId":f"oauth-{client}",
            "provider":client,
            "state":"ACTIVE",
        }

    def test_revoked_history_does_not_block_one_active_registration(self):
        rows=[]
        for client in mod.CLIENTS:
            rows.append({
                "id":f"trusted-{client}-old","revision":1,"clientId":f"oauth-{client}",
                "provider":client,"state":"REVOKED",
            })
            rows.append(self.active(client))
        out=mod.resolve_trusted_client_rows(rows,self.bindings())
        self.assertEqual(set(mod.CLIENTS),set(out))
        for client in mod.CLIENTS:
            self.assertEqual(f"trusted-{client}-new",out[client]["trustedClientId"])
            self.assertEqual(2,out[client]["trustedClientRevision"])

    def test_multiple_active_rows_for_same_client_fail_closed(self):
        rows=[]
        for client in mod.CLIENTS:
            rows.append(self.active(client,"one"))
        rows.append(self.active("chatgpt","two"))
        with self.assertRaisesRegex(RuntimeError,"IDENTITY_INVALID chatgpt"):
            mod.resolve_trusted_client_rows(rows,self.bindings())

    def test_active_row_with_wrong_provider_fails_closed(self):
        rows=[self.active(client) for client in mod.CLIENTS]
        rows[0]["provider"]="claude"
        with self.assertRaisesRegex(RuntimeError,"IDENTITY_INVALID chatgpt"):
            mod.resolve_trusted_client_rows(rows,self.bindings())

    def test_revoked_only_registration_fails_closed(self):
        rows=[]
        for client in mod.CLIENTS:
            row=self.active(client); row["state"]="REVOKED"; rows.append(row)
        with self.assertRaisesRegex(RuntimeError,"IDENTITY_INVALID chatgpt"):
            mod.resolve_trusted_client_rows(rows,self.bindings())


if __name__=="__main__":
    unittest.main()
