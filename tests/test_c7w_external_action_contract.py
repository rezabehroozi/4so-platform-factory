import ast
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import run_mcp_external_interop as mod


class C7WExternalActionContractTests(unittest.TestCase):
    def test_external_client_action_is_not_a_local_admit_command(self):
        with tempfile.TemporaryDirectory() as td:
            state=mod.secure_state_dir(Path(td)/"state")
            out=mod.external_client_action(state,"chatgpt")
        self.assertEqual("RUN_EXTERNAL_CLIENT",out["nextActionCode"])
        self.assertEqual([],out["nextCommand"])
        self.assertEqual("chatgpt",out["nextClientHandoff"]["clientId"])
        self.assertEqual(
            out["nextClientHandoff"]["admitCommand"],
            out["postExternalExecutionCommand"],
        )

    def test_prepare_admit_and_status_share_external_action_owner(self):
        source=(ROOT/"scripts"/"run_mcp_external_interop.py").read_text(encoding="utf-8")
        tree=ast.parse(source)
        for name in ("prepare","admit","status"):
            fn=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name)
            calls=[
                node
                for node in ast.walk(fn)
                if isinstance(node,ast.Call)
                and isinstance(node.func,ast.Name)
                and node.func.id=="external_client_action"
            ]
            self.assertTrue(calls,f"{name} must use external_client_action for RUN_EXTERNAL_CLIENT handoff")


if __name__=="__main__":
    unittest.main()
