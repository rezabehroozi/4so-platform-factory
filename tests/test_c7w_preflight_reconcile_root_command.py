import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("c7w_preflight",ROOT/"scripts"/"c7w_preflight.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WPreflightReconcileRootCommandTests(unittest.TestCase):
    def test_reconcile_command_is_explicitly_root_bound(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            oauth=root/".state/private/c7w-oauth-client-bindings.json"
            command=mod.trusted_client_reconcile_command(root,"https://mcp.example.test/mcp",oauth,"TOKEN_ENV")
        self.assertEqual(sys.executable,command[0])
        self.assertIn("scripts/reconcile_c7w_trusted_clients.py",command)
        self.assertIn("--root",command)
        self.assertIn(str(root),command)
        self.assertIn("--endpoint",command)
        self.assertIn(str(oauth),command)
        self.assertIn("TOKEN_ENV",command)


if __name__=="__main__": unittest.main()
