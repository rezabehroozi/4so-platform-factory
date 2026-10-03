import importlib.util
import os
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


class C9PreflightHandoffTests(unittest.TestCase):
    def ready_context(self):
        fake_lock = {
            "authority": sealer.TOOLCHAIN_AUTHORITY,
            "spec": {"admissionStatus": "admitted", "exactCompiler": {}},
        }
        browser_doc = {"version": "unit-browser"}
        stack = (
            mock.patch.object(sealer.sys, "platform", "linux"),
            mock.patch.object(sealer, "normalized_machine", return_value="amd64"),
            mock.patch.object(sealer.json, "loads", return_value=fake_lock),
            mock.patch.object(sealer, "safe_toolchain_archive", return_value=(Path("/tmp/go.tgz"), {})),
            mock.patch.object(
                sealer.browser_authority,
                "validate_ui_browser_authority",
                return_value=(Path("/tmp/chrome"), browser_doc),
            ),
            mock.patch.dict(
                os.environ,
                {sealer.browser_authority.ENV_AUTHORITY: "/tmp/authority.json"},
                clear=False,
            ),
            mock.patch.object(sealer.shutil, "which", return_value="/usr/bin/tool"),
        )
        return stack

    def test_ready_preflight_emits_direct_native_c9_command(self):
        with tempfile.TemporaryDirectory() as td:
            stack = self.ready_context()
            with stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6]:
                result = mod.enrich(sealer.exact_release_environment_preflight(Path(td)))
        self.assertTrue(result["ready"])
        self.assertEqual(mod.AUTHORITY, result["handoffAuthority"])
        self.assertEqual("RUN_C9_SEAL", result["nextActionCode"])
        self.assertEqual([], result["requiredInputs"])
        self.assertEqual("linux-amd64-exact-toolchain", result["requiredHost"])
        self.assertEqual(mod.C9_COMMAND, result["nextCommand"])
        self.assertFalse(result["physicalCertified"])

    def test_missing_browser_and_host_tools_emit_exact_remediation_inputs(self):
        fake_lock = {
            "authority": sealer.TOOLCHAIN_AUTHORITY,
            "spec": {"admissionStatus": "admitted", "exactCompiler": {}},
        }
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(sealer.sys, "platform", "linux"), \
             mock.patch.object(sealer, "normalized_machine", return_value="amd64"), \
             mock.patch.object(sealer.json, "loads", return_value=fake_lock), \
             mock.patch.object(sealer, "safe_toolchain_archive", return_value=(Path(td) / "go.tgz", {})), \
             mock.patch.dict(os.environ, {sealer.browser_authority.ENV_AUTHORITY: ""}, clear=False), \
             mock.patch.object(sealer.shutil, "which", return_value=None):
            result = mod.enrich(sealer.exact_release_environment_preflight(Path(td)))
        self.assertFalse(result["ready"])
        self.assertEqual("PROVIDE_C9_ENVIRONMENT_INPUTS", result["nextActionCode"])
        self.assertIn(sealer.browser_authority.ENV_AUTHORITY, result["requiredInputs"])
        self.assertEqual(["gcc", "ld", "ldd", "readelf"], result["missingHostTools"])
        self.assertEqual(["gcc", "ld", "ldd", "readelf"], result["requiredHostTools"])
        self.assertEqual([], result["nextCommand"])
        self.assertIn("UI_BROWSER_AUTHORITY_MISSING", result["blockers"])

    def test_non_linux_amd64_preflight_hands_off_to_exact_linux_host(self):
        fake_lock = {
            "authority": sealer.TOOLCHAIN_AUTHORITY,
            "spec": {"admissionStatus": "admitted", "exactCompiler": {}},
        }
        browser_doc = {"version": "unit-browser"}
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(sealer.sys, "platform", "win32"), \
             mock.patch.object(sealer, "normalized_machine", return_value="amd64"), \
             mock.patch.object(sealer.json, "loads", return_value=fake_lock), \
             mock.patch.object(sealer, "safe_toolchain_archive", return_value=(Path(td) / "go.tgz", {})), \
             mock.patch.object(sealer.browser_authority, "validate_ui_browser_authority", return_value=(Path(td) / "chrome", browser_doc)), \
             mock.patch.dict(os.environ, {sealer.browser_authority.ENV_AUTHORITY: str(Path(td) / "authority.json")}, clear=False), \
             mock.patch.object(sealer.shutil, "which", return_value="C:/tool.exe"):
            result = mod.enrich(sealer.exact_release_environment_preflight(Path(td)))
        self.assertFalse(result["ready"])
        self.assertEqual("RUN_C9_ON_EXACT_LINUX_HOST", result["nextActionCode"])
        self.assertEqual("linux-amd64-exact-toolchain", result["requiredHost"])
        self.assertEqual([], result["nextCommand"])
        self.assertEqual(mod.C9_COMMAND_TEMPLATE, result["nextCommandTemplate"])

    def test_toolchain_archive_blocker_requests_admitted_archive(self):
        for code in (
            "FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISSING",
            "FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISMATCH",
        ):
            with self.subTest(code=code):
                result = mod.enrich(
                    {
                        "ready": False,
                        "requiredHost": "linux-amd64-exact-toolchain",
                        "blockers": [code],
                        "physicalCertified": False,
                    }
                )
                self.assertEqual("PROVIDE_C9_ENVIRONMENT_INPUTS", result["nextActionCode"])
                self.assertIn("vendor/toolchains/<admitted-go-archive>", result["requiredInputs"])

    def test_toolchain_lock_authority_blocker_is_source_defect_not_archive_input(self):
        for code in (
            "FINAL_EXACT_RELEASE_TOOLCHAIN_AUTHORITY_INVALID",
            "FINAL_EXACT_RELEASE_TOOLCHAIN_NOT_ADMITTED",
            "FINAL_EXACT_RELEASE_TOOLCHAIN_PATH_INVALID",
            "FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK_INVALID",
        ):
            with self.subTest(code=code):
                result = mod.enrich(
                    {
                        "ready": False,
                        "requiredHost": "linux-amd64-exact-toolchain",
                        "blockers": [code],
                        "physicalCertified": False,
                    }
                )
                self.assertEqual("INSPECT_C9_SOURCE_AUTHORITY", result["nextActionCode"])
                self.assertEqual([], result["requiredInputs"])
                self.assertEqual(
                    ["git", "status", "--short", "--", "lab/release-build-toolchain-lock.json"],
                    result["nextCommand"],
                )


if __name__ == "__main__":
    unittest.main()
