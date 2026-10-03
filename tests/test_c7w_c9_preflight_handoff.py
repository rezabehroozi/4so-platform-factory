import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop",ROOT/"scripts"/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class C7WToC9PreflightHandoffTests(unittest.TestCase):
    def test_linux_handoff_uses_machine_actionable_c9_preflight_owner(self):
        with mock.patch.object(mod.sys,"platform","linux"):
            out=mod.c9_handoff("a"*40)
        self.assertEqual("RUN_C9_SEAL",out["nextActionCode"])
        self.assertEqual([sys.executable,"scripts/c9_preflight.py","--root",".","--preflight"],out["preflightCommand"])
        self.assertEqual("--preflight",out["preflightCommand"][-1])
        self.assertEqual(mod.c9_seal_command(),out["nextCommand"])

    def test_windows_handoff_templates_machine_actionable_c9_preflight_owner(self):
        with mock.patch.object(mod.sys,"platform","win32"):
            out=mod.c9_handoff("b"*40)
        self.assertEqual("RUN_C9_ON_EXACT_LINUX_HOST",out["nextActionCode"])
        self.assertEqual(["<python>","scripts/c9_preflight.py","--root",".","--preflight"],out["preflightCommandTemplate"])
        self.assertEqual("--preflight",out["preflightCommandTemplate"][-1])
        self.assertEqual("b"*40,out["requiredSourceCommitSHA"])


if __name__=="__main__":
    unittest.main()
