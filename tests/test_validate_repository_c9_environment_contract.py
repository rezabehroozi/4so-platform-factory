import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("validate_repository",ROOT/"scripts"/"validate_repository.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


GOOD='''
def exact_source_toolchain_lock(root, source_sha):
    return {}

def require_exact_release_environment(root, toolchain_lock=None):
    return {}

def resume_existing_evidence(root, out):
    source_sha="a"*40
    toolchain_lock,_=exact_source_toolchain_lock(root, source_sha)
    require_exact_release_environment(
        root,
        toolchain_lock=toolchain_lock,
    )

def execute(root, out):
    source_sha="b"*40
    toolchain_lock,_=exact_source_toolchain_lock(root,source_sha)
    require_exact_release_environment(root, toolchain_lock = toolchain_lock)
'''


class C9EnvironmentContractTests(unittest.TestCase):
    def test_semantic_contract_accepts_format_independent_source_bound_toolchain(self):
        self.assertEqual([],mod.final_exact_release_environment_contract_errors(GOOD))

    def test_semantic_contract_rejects_unbound_environment_call(self):
        broken=GOOD.replace(
            'require_exact_release_environment(root, toolchain_lock = toolchain_lock)',
            'require_exact_release_environment(root)',
        )
        errors=mod.final_exact_release_environment_contract_errors(broken)
        self.assertIn('EXECUTE_ENVIRONMENT_TOOLCHAIN_LOCK_MISSING',errors)

    def test_semantic_contract_rejects_missing_exact_source_toolchain_lock(self):
        broken=GOOD.replace(
            'toolchain_lock,_=exact_source_toolchain_lock(root, source_sha)',
            'toolchain_lock={}',
            1,
        )
        errors=mod.final_exact_release_environment_contract_errors(broken)
        self.assertIn('RESUME_SOURCE_TOOLCHAIN_LOCK_MISSING',errors)


if __name__=="__main__":
    unittest.main()
