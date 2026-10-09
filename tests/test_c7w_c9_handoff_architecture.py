import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)
import run_mcp_external_interop as runner


class C7WC9HandoffArchitectureTests(unittest.TestCase):
    def test_linux_arm64_routes_to_exact_amd64_host(self):
        with (
            mock.patch.object(runner.sys,"platform","linux"),
            mock.patch.object(runner.os,"uname",return_value=SimpleNamespace(machine="aarch64")),
        ):
            out=runner.c9_handoff("a"*40)
        self.assertEqual("RUN_C9_ON_EXACT_LINUX_HOST",out["nextActionCode"])
        self.assertEqual([],out["nextCommand"])
        self.assertEqual("linux-amd64-exact-toolchain",out["requiredHost"])
        self.assertEqual("a"*40,out["requiredSourceCommitSHA"])

    def test_linux_x86_64_keeps_direct_c9_handoff(self):
        with (
            mock.patch.object(runner.sys,"platform","linux"),
            mock.patch.object(runner.os,"uname",return_value=SimpleNamespace(machine="x86_64")),
        ):
            out=runner.c9_handoff("b"*40)
        self.assertEqual("RUN_C9_SEAL",out["nextActionCode"])
        self.assertEqual(runner.c9_seal_command(),out["nextCommand"])
        self.assertEqual(runner.c9_preflight_command(),out["preflightCommand"])


if __name__=="__main__":
    unittest.main()
