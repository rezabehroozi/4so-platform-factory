import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("validate_repository",ROOT/"scripts"/"validate_repository.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WReconciliationRepositoryGateTests(unittest.TestCase):
    def write(self,root:Path,rel:str,text:str)->None:
        path=root/rel; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(text,encoding="utf-8")

    def good_tree(self,root:Path)->None:
        self.write(root,"scripts/reconcile_c7w_trusted_clients.py",'''AUTHORITY="MCP_EXTERNAL_TRUSTED_CLIENT_RECONCILIATION_V1"\ndef reconcile_plan(): pass\ndef reconcile():\n    before=fetch_rows()\n    create_row()\n    after=fetch_rows()\n    return preflight_command()\ndef preflight_command(): pass\n''')
        self.write(root,"scripts/c7w_preflight.py",'''def trusted_client_reconcile_command():\n    return ["scripts/reconcile_c7w_trusted_clients.py"]\n# RECONCILE_C7W_TRUSTED_CLIENTS\n''')

    def test_gate_accepts_complete_reconciliation_owner_and_wiring(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good_tree(root); errors=[]
            mod.validate_c7w_reconciliation_authority(root,errors)
            self.assertEqual([],errors)

    def test_gate_rejects_missing_or_unwired_reconciliation_owner(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good_tree(root)
            (root/"scripts/reconcile_c7w_trusted_clients.py").unlink(); errors=[]
            mod.validate_c7w_reconciliation_authority(root,errors)
            self.assertIn("C7W_TRUSTED_CLIENT_RECONCILER_MISSING",[code for code,_ in errors])
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.good_tree(root)
            (root/"scripts/c7w_preflight.py").write_text("# no reconciliation handoff\n",encoding="utf-8"); errors=[]
            mod.validate_c7w_reconciliation_authority(root,errors)
            self.assertIn("C7W_TRUSTED_CLIENT_RECONCILER_UNWIRED",[code for code,_ in errors])


if __name__=="__main__":
    unittest.main()
