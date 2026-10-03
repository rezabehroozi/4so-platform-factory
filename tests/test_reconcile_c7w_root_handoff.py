import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("reconcile_c7w_trusted_clients",ROOT/"scripts"/"reconcile_c7w_trusted_clients.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ReconcileC7WRootHandoffTests(unittest.TestCase):
    def test_followup_preflight_is_root_bound(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            oauth=root/".state/private/c7w-oauth-client-bindings.json"
            command=mod.preflight_command(root,"https://mcp.example.test/mcp",oauth,"TOKEN_ENV")
        self.assertEqual(sys.executable,command[0])
        self.assertIn("--root",command)
        self.assertIn(str(root),command)
        self.assertIn(str(oauth),command)


if __name__=="__main__": unittest.main()
