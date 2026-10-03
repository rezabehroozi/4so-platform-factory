import importlib.util
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("reconcile_c7w_trusted_clients",ROOT/"scripts"/"reconcile_c7w_trusted_clients.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ReconcileC7WTrustedClientsHandoffTests(unittest.TestCase):
    def test_preflight_command_preserves_endpoint_oauth_map_and_token_env(self):
        oauth=Path(".state/private/c7w-oauth-client-bindings.json")
        command=mod.preflight_command("https://mcp.example.test/mcp",oauth,"TOKEN_ENV")
        self.assertEqual(sys.executable,command[0])
        self.assertIn("scripts/c7w_preflight.py",command)
        self.assertIn("--endpoint",command)
        self.assertIn("https://mcp.example.test/mcp",command)
        self.assertIn("--oauth-client-map",command)
        self.assertIn(str(oauth),command)
        self.assertIn("--token-env",command)
        self.assertIn("TOKEN_ENV",command)


if __name__=="__main__":
    unittest.main()
