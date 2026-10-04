import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SEAL_SPEC = importlib.util.spec_from_file_location(
    "seal_final_exact_release", ROOT / "scripts" / "seal_final_exact_release.py"
)
sealer = importlib.util.module_from_spec(SEAL_SPEC)
SEAL_SPEC.loader.exec_module(sealer)
PRE_SPEC = importlib.util.spec_from_file_location(
    "c9_preflight", ROOT / "scripts" / "c9_preflight.py"
)
mod = importlib.util.module_from_spec(PRE_SPEC)
PRE_SPEC.loader.exec_module(mod)


class C9AdmissionPreflightTests(unittest.TestCase):
    def test_c7w_pending_blocks_before_environment_and_hands_back_to_c7w_preflight(self):
        source_sha = "a" * 40
        progress = {
            "authority": "MCP_EXTERNAL_CLIENT_INTEROP_PROGRESS_V1",
            "certifiedClientCount": 2,
            "certifiedClients": ["chatgpt", "claude"],
            "missingClients": ["gemini", "grok"],
            "nextClient": "gemini",
            "complete": False,
            "evidenceSealPending": False,
        }
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(sealer, "git_source", return_value=source_sha), \
             mock.patch.object(sealer, "exact_source_admission", side_effect=sealer.admission.Pending("MCP_EXTERNAL_INTEROP_PENDING")), \
             mock.patch.object(sealer.admission, "external_client_progress", return_value=progress), \
             mock.patch.object(sealer, "exact_release_environment_preflight", side_effect=AssertionError("environment must not run before final admission")):
            root=Path(td).resolve()
            result = mod.preflight(root)
        self.assertFalse(result["ready"])
        self.assertEqual(["MCP_EXTERNAL_INTEROP_PENDING"], result["blockers"])
        self.assertEqual("RUN_C7W_PREFLIGHT", result["nextActionCode"])
        self.assertEqual([mod.sys.executable, "scripts/c7w_preflight.py", "--root", "."], result["nextCommand"])
        self.assertEqual(str(root),result["workingDirectory"])
        self.assertEqual(progress, result["externalClientProgress"])
        self.assertEqual(source_sha, result["sourceCommitSHA"])
        self.assertFalse(result["physicalCertified"])

    def test_ready_admission_allows_environment_preflight(self):
        source_sha = "b" * 40
        admitted = {
            "authority": sealer.admission.AUTHORITY,
            "admitted": True,
            "physicalCertified": False,
        }
        env = {
            "authority": sealer.ENVIRONMENT_PREFLIGHT_AUTHORITY,
            "ready": True,
            "requiredHost": "linux-amd64-exact-toolchain",
            "missingHostTools": [],
            "blockers": [],
            "physicalCertified": False,
        }
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(sealer, "git_source", return_value=source_sha), \
             mock.patch.object(sealer, "exact_source_admission", return_value=admitted) as admission_call, \
             mock.patch.object(sealer, "exact_release_environment_preflight", return_value=env) as environment_call:
            root=Path(td).resolve()
            result = mod.preflight(root)
        admission_call.assert_called_once_with(root, source_sha)
        environment_call.assert_called_once_with(root)
        self.assertTrue(result["ready"])
        self.assertEqual("RUN_C9_SEAL", result["nextActionCode"])
        self.assertEqual([mod.sys.executable,"scripts/seal_final_exact_release.py","--root",".","--out","lab/final-exact-release-evidence.json"],result["nextCommand"])
        self.assertEqual(str(root),result["workingDirectory"])
        self.assertEqual(source_sha, result["sourceCommitSHA"])
        self.assertEqual(sealer.admission.AUTHORITY, result["admissionAuthority"])
        self.assertTrue(result["admissionReady"])
        self.assertFalse(result["physicalCertified"])


if __name__ == "__main__":
    unittest.main()
