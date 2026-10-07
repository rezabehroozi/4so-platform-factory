import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("validate_repository_windows_scope",ROOT/"scripts/validate_repository.py")
VALIDATE=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VALIDATE)


class WindowsLocalExecutionContractScopeTests(unittest.TestCase):
    def test_c7w_runner_is_owned_by_dedicated_authority_gate_not_windows_marker_gate(self):
        self.assertNotIn("scripts/run_mcp_external_interop.py",VALIDATE.WINDOWS_LOCAL_EXECUTION_CONTRACTS)
        makefile=(ROOT/"Makefile").read_text(encoding="utf-8")
        self.assertIn("scripts/release_tool_authority_gate.py --root .",makefile)

    def test_windows_contract_fixture_does_not_require_c7w_runner(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for rel,required in VALIDATE.WINDOWS_LOCAL_EXECUTION_CONTRACTS.items():
                if rel=="scripts/run_mcp_external_interop.py":
                    continue
                path=root/rel
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text("\n".join(required)+"\n",encoding="utf-8")
            errors=[]
            VALIDATE.validate_windows_local_execution_contract(root,errors)
            c7w=[detail for code,detail in errors if "run_mcp_external_interop.py" in detail]
            self.assertEqual([],c7w)


if __name__=="__main__":
    unittest.main()
