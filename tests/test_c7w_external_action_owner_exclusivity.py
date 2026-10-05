import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location(
    "c7w_execution_authority_gate_external_owner",
    ROOT/"scripts"/"c7w_execution_authority_gate.py",
)
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class C7WExternalActionOwnerExclusivityTests(unittest.TestCase):
    def test_prepare_cannot_emit_external_action_outside_canonical_helper(self):
        source='''\ndef external_client_action():\n    return {"nextActionCode":"RUN_EXTERNAL_CLIENT","nextCommand":[],"nextClientHandoff":{},"postExternalExecutionCommand":[]}\ndef prepare(flag):\n    if flag:\n        return external_client_action()\n    return {"nextActionCode":"RUN_EXTERNAL_CLIENT","nextCommand":["python","admit.py"],"nextClientHandoff":{},"postExternalExecutionCommand":[]}\ndef admit(): return external_client_action()\ndef status(): return external_client_action()\n'''
        errors=mod.external_client_action_contract_errors(source)
        self.assertIn("PREPARE_EXTERNAL_ACTION_DIRECT_EMISSION_INVALID",errors)


if __name__=="__main__":
    unittest.main()
