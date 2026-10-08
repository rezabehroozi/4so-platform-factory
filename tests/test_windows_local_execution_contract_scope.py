import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("validate_repository_windows_scope",ROOT/"scripts/validate_repository.py")
mod=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mod)


class WindowsLocalExecutionContractScopeTests(unittest.TestCase):
    def test_c7w_runner_is_not_owned_by_windows_marker_gate(self):
        self.assertNotIn("scripts/run_mcp_external_interop.py",mod.WINDOWS_LOCAL_EXECUTION_CONTRACTS)

    def test_windows_specific_owners_remain_covered(self):
        for path in (
            "scripts/project_runtime.py",
            "scripts/admit_mcp_external_receipt.py",
            "scripts/run_go_package_shard.py",
            "scripts/run_smoke_shard.py",
            "scripts/verify_release.py",
            "scripts/postgresql_runtime_certify.py",
        ):
            self.assertIn(path,mod.WINDOWS_LOCAL_EXECUTION_CONTRACTS)


if __name__=="__main__":
    unittest.main()
