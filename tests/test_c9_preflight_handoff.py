import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "seal_final_exact_release", ROOT / "scripts" / "seal_final_exact_release.py"
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class C9PreflightHandoffTests(unittest.TestCase):
    def ready_context(self):
        fake_lock = {
            "authority": mod.TOOLCHAIN_AUTHORITY,
            "spec": {"admissionStatus": "admitted", "exactCompiler": {}},
        }
        browser_doc = {"version": "unit-browser"}
        stack = (
            mock.patch.object(mod.sys, "platform", "linux"),
            mock.patch.object(mod, "normalized_machine", return_value="amd64"),
            mock.patch.object(mod.json, "loads", return_value=fake_lock),
            mock.patch.object(mod, "safe_toolchain_archive", return_value=(Path("/tmp/go.tgz"), {})),
            mock.patch.object(
                mod.browser_authority,
                "validate_ui_browser_authority",
                return_value=(Path("/tmp/chrome"), browser_doc),
            ),
            mock.patch.dict(
                os.environ,
                {mod.browser_authority.ENV_AUTHORITY: "/tmp/authority.json"},
                clear=False,
            ),
            mock.patch.object(mod.shutil, "which", return_value="/usr/bin/tool"),
        )
        return stack

    def test_ready_preflight_emits_direct_native_c9_command(self):
        with tempfile.TemporaryDirectory() as td:
            stack = self.ready_context()
            with stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6]:
                result = mod.exact_release_environment_preflight(Path(td))
        self.assertTrue(result["ready"])
        self.assertEqual("RUN_C9_SEAL", result["nextActionCode"])
        self.assertEqual([], result["requiredInputs"])
        self.assertEqual("linux-amd64-exact-toolchain", result["requiredHost"])
        self.assertEqual(
            [
                mod.sys.executable,
                "scripts/seal_final_exact_release.py",
                "--root",
                ".",
                "--out",
                "lab/final-exact-release-evidence.json",
            ],
            result["nextCommand"],
        )
        self.assertFalse(result["physicalCertified"])

    def test_missing_browser_and_host_tools_emit_exact_remediation_inputs(self):
        fake_lock = {
            "authority": mod.TOOLCHAIN_AUTHORITY,
            "spec": {"admissionStatus": "admitted", "exactCompiler": {}},
        }
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(mod.sys, "platform", "linux"), \
             mock.patch.object(mod, "normalized_machine", return_value="amd64"), \
             mock.patch.object(mod.json, "loads", return_value=fake_lock), \
             mock.patch.object(mod, "safe_toolchain_archive", return_value=(Path(td) / "go.tgz", {})), \
             mock.patch.dict(os.environ, {mod.browser_authority.ENV_AUTHORITY: ""}, clear=False), \
             mock.patch.object(mod.shutil, "which", return_value=None):
            result = mod.exact_release_environment_preflight(Path(td))
        self.assertFalse(result["ready"])
        self.assertEqual("PROVIDE_C9_ENVIRONMENT_INPUTS", result["nextActionCode"])
        self.assertIn(mod.browser_authority.ENV_AUTHORITY, result["requiredInputs"])
        self.assertEqual(["gcc", "ld", "ldd", "readelf"], result["missingHostTools"])
        self.assertEqual([], result["nextCommand"])
        self.assertIn("UI_BROWSER_AUTHORITY_MISSING", result["blockers"])

    def test_non_linux_amd64_preflight_hands_off_exact_source_to_linux_host(self):
        fake_lock = {
            "authority": mod.TOOLCHAIN_AUTHORITY,
            "spec": {"admissionStatus": "admitted", "exactCompiler": {}},
        }
        browser_doc = {"version": "unit-browser"}
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(mod.sys, "platform", "win32"), \
             mock.patch.object(mod, "normalized_machine", return_value="amd64"), \
             mock.patch.object(mod.json, "loads", return_value=fake_lock), \
             mock.patch.object(mod, "safe_toolchain_archive", return_value=(Path(td) / "go.tgz", {})), \
             mock.patch.object(mod.browser_authority, "validate_ui_browser_authority", return_value=(Path(td) / "chrome", browser_doc)), \
             mock.patch.dict(os.environ, {mod.browser_authority.ENV_AUTHORITY: str(Path(td) / "authority.json")}, clear=False), \
             mock.patch.object(mod.shutil, "which", return_value="C:/tool.exe"):
            result = mod.exact_release_environment_preflight(Path(td))
        self.assertFalse(result["ready"])
        self.assertEqual("RUN_C9_ON_EXACT_LINUX_HOST", result["nextActionCode"])
        self.assertEqual("linux-amd64-exact-toolchain", result["requiredHost"])
        self.assertEqual([], result["nextCommand"])
        self.assertEqual(
            [
                "<python>",
                "scripts/seal_final_exact_release.py",
                "--root",
                ".",
                "--out",
                "lab/final-exact-release-evidence.json",
            ],
            result["nextCommandTemplate"],
        )


if __name__ == "__main__":
    unittest.main()
