import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop",ROOT/"scripts"/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class C7WToC9PreflightHandoffTests(unittest.TestCase):
    def test_linux_handoff_uses_machine_actionable_c9_preflight_owner(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(mod.sys,"platform","linux"):
            root=Path(td).resolve()
            out=mod.c9_handoff("a"*40,root)
        self.assertEqual("RUN_C9_SEAL",out["nextActionCode"])
        self.assertEqual([sys.executable,"scripts/c9_preflight.py","--root",str(root),"--preflight"],out["preflightCommand"])
        self.assertEqual("--preflight",out["preflightCommand"][-1])
        self.assertEqual([sys.executable,"scripts/seal_final_exact_release.py","--root",str(root),"--out","lab/final-exact-release-evidence.json"],out["nextCommand"])
        self.assertEqual(str(root),out["workingDirectory"])

    def test_windows_handoff_templates_machine_actionable_c9_preflight_owner(self):
        with mock.patch.object(mod.sys,"platform","win32"):
            out=mod.c9_handoff("b"*40)
        self.assertEqual("RUN_C9_ON_EXACT_LINUX_HOST",out["nextActionCode"])
        self.assertEqual(["<python>","scripts/c9_preflight.py","--root","<exact-source-checkout-root>","--preflight"],out["preflightCommandTemplate"])
        self.assertEqual(["<python>","scripts/seal_final_exact_release.py","--root","<exact-source-checkout-root>","--out","lab/final-exact-release-evidence.json"],out["nextCommandTemplate"])
        self.assertEqual("--preflight",out["preflightCommandTemplate"][-1])
        self.assertEqual("<exact-source-checkout-root>",out["requiredWorkingDirectory"])
        self.assertEqual("b"*40,out["requiredSourceCommitSHA"])


if __name__=="__main__":
    unittest.main()
