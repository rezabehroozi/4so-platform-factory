import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("c7w_execution_authority_gate_workdir",ROOT/"scripts/c7w_execution_authority_gate.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WRunnerWorkingDirectoryGateTests(unittest.TestCase):
    def test_rejects_runner_without_canonical_working_directory_projection(self):
        source='''\nfrom pathlib import Path\ndef main():\n    root=Path.cwd().resolve()\n    result={}\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(source))

    def test_accepts_runner_with_reachable_root_bound_projection(self):
        source='''\nfrom pathlib import Path\ndef main():\n    root=Path.cwd().resolve()\n    result={}\n    result["workingDirectory"]=str(root)\n    return result\n'''
        self.assertEqual([],mod.runner_working_directory_contract_errors(source))

    def test_rejects_nested_or_dead_projection(self):
        source='''\nfrom pathlib import Path\ndef main():\n    root=Path.cwd().resolve()\n    result={}\n    if False:\n        result["workingDirectory"]=str(root)\n    def dead():\n        result["workingDirectory"]=str(root)\n    return result\n'''
        self.assertIn("RUNNER_WORKING_DIRECTORY_WIRING_INVALID",mod.runner_working_directory_contract_errors(source))


if __name__=="__main__":
    unittest.main()
