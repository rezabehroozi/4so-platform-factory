import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class ReleaseToolAuthorityGateContractTests(unittest.TestCase):
    def test_gate_locks_verifier_environment_and_exact_host_architecture(self):
        gate=(ROOT/"scripts"/"release_tool_authority_gate.py").read_text(encoding="utf-8")
        for code in (
            "RELEASE_TOOLCHAIN_VERIFIER_ENVIRONMENT_INVALID",
            "RELEASE_HOST_ARCHITECTURE_GUARD_INVALID",
        ):
            self.assertIn(code,gate)
        for marker in (
            "verification_environment",
            "release_binary_builder.release_build_environment",
            "require_release_build_host",
            "normalized_machine",
            "observedArchitecture",
            "requiredArchitecture",
        ):
            self.assertIn(marker,gate)


if __name__=="__main__":
    unittest.main()
