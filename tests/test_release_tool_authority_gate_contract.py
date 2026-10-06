import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class ReleaseToolAuthorityGateContractTests(unittest.TestCase):
    def test_gate_locks_verifier_environment_and_exact_host_architecture(self):
        gate=(ROOT/"scripts"/"release_tool_authority_gate.py").read_text(encoding="utf-8")
        for code in (
            "RELEASE_TOOLCHAIN_VERIFIER_ENVIRONMENT_INVALID",
            "RELEASE_HOST_ARCHITECTURE_GUARD_INVALID",
            "RELEASE_BINARY_TARGET_SET_INVALID",
            "RELEASE_PACKAGER_BINARY_SET_INVALID",
            "RELEASE_VERIFIER_BINARY_SET_INVALID",
            "FINAL_EXACT_RELEASE_PREFLIGHT_HANDOFF_INVALID",
        ):
            self.assertIn(code,gate)
        for marker in (
            "verification_environment",
            "release_binary_builder.release_build_environment",
            "require_release_build_host",
            "normalized_machine",
            "observedArchitecture",
            "requiredArchitecture",
            "TARGETS",
            "BINARIES",
            "RELEASE_BINARIES",
            "dapr-runtime",
            "validate_existing_evidence",
            "INSPECT_C9_EXISTING_EVIDENCE",
            "exact_source_admission",
            "MCP_EXTERNAL_INTEROP_PENDING",
            "RUN_C7W_PREFLIGHT",
            "admissionReady",
            "bind_execution_context",
            "requiredWorkingDirectory",
            "<exact-source-checkout-root>",
        ):
            self.assertIn(marker,gate)

    def test_gate_includes_build_release_git_authority_owner(self):
        gate=(ROOT/"scripts"/"release_tool_authority_gate.py").read_text(encoding="utf-8")
        compact="".join(gate.split())
        self.assertIn('("scripts/build_release.py",packager)',compact)


if __name__=="__main__":
    unittest.main()