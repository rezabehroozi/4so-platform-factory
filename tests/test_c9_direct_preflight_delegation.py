import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_direct_preflight",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9DirectPreflightDelegationTests(unittest.TestCase):
    def test_direct_preflight_delegates_to_canonical_c9_preflight(self):
        root=Path("/repo")
        delegated=subprocess.CompletedProcess(args=[],returncode=2)
        with (
            mock.patch.object(sys,"argv",["seal_final_exact_release.py","--root",str(root),"--preflight"]),
            mock.patch.object(mod,"exact_release_environment_preflight",side_effect=AssertionError("direct environment preflight bypassed final admission")),
            mock.patch.object(mod.subprocess,"run",return_value=delegated) as run,
        ):
            rc=mod.main()
        self.assertEqual(2,rc)
        run.assert_called_once()
        command=run.call_args.args[0]
        canonical=Path(mod.__file__).resolve().with_name("c9_preflight.py")
        self.assertEqual([sys.executable,str(canonical),"--root",str(root.resolve()),"--preflight"],command)
        self.assertEqual(root.resolve(),run.call_args.kwargs["cwd"])
        self.assertEqual(mod.clean_git_env(),run.call_args.kwargs["env"])
        self.assertIsNone(run.call_args.kwargs["stdout"])
        self.assertIsNone(run.call_args.kwargs["stderr"])


if __name__=="__main__":
    unittest.main()
