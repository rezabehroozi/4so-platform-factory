import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "package_release_exact.py"


def load_wrapper():
    if not WRAPPER.is_file():
        raise AssertionError("exact release packager wrapper is missing")
    spec = importlib.util.spec_from_file_location("package_release_exact", WRAPPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ReleasePackagerEnvironmentTests(unittest.TestCase):
    def test_packager_tool_authority_reuses_native_builder_environment(self):
        mod = load_wrapper()
        root = Path("/repo")
        clean_env = {"PATH": "/safe", "GOWORK": "off", "GOFLAGS": ""}
        toolchain_spec={"exactCompiler":{},"exactCGOToolchain":{}}
        with (
            mock.patch.dict(os.environ, {"GO": "/opt/exact-go/bin/go"}, clear=True),
            mock.patch.object(mod.release_binary_builder, "require_release_build_host") as host_gate,
            mock.patch.object(mod.release_binary_builder, "release_build_environment", return_value=clean_env.copy()) as build_env,
            mock.patch.object(mod.release_binary_builder, "admitted_toolchain_spec", return_value=toolchain_spec) as admitted,
            mock.patch.object(mod.release_binary_builder, "require_go_binary_identity") as go_identity,
            mock.patch.object(mod.release_binary_builder, "require_cgo_toolchain_identity") as cgo_identity,
        ):
            go_binary, env = mod.release_tool_authority(root)

        self.assertEqual("/opt/exact-go/bin/go", go_binary)
        self.assertEqual("/safe", env["PATH"])
        self.assertEqual("/opt/exact-go/bin/go", env["GO"])
        host_gate.assert_called_once_with()
        build_env.assert_called_once_with()
        admitted.assert_called_once_with(root)
        go_identity.assert_called_once_with(root, "/opt/exact-go/bin/go", mock.ANY, toolchain_spec)
        cgo_identity.assert_called_once_with(root, mock.ANY, toolchain_spec)
        self.assertIs(go_identity.call_args.args[2], cgo_identity.call_args.args[1])
        self.assertIs(go_identity.call_args.args[3], cgo_identity.call_args.args[2])

    def test_packager_runs_legacy_packager_only_inside_exact_environment(self):
        mod = load_wrapper()
        root = Path("/repo")
        env = {"PATH": "/safe", "GO": "/opt/exact-go/bin/go", "PYTHONNOUSERSITE": "1"}
        completed = mock.Mock(returncode=0, stdout="RELEASE_BUILD_PASS archive sha count\n", stderr="")
        with (
            mock.patch.object(mod, "release_tool_authority", return_value=(env["GO"], env)) as authority,
            mock.patch.object(mod.subprocess, "run", return_value=completed) as run,
        ):
            result = mod.run_packager(root)
        self.assertEqual(0, result)
        authority.assert_called_once_with(root.resolve())
        run.assert_called_once_with(
            [sys.executable, "scripts/build_release.py", "."],
            cwd=root.resolve(),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_make_and_c9_use_exact_packager_wrapper(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        sealer = (ROOT / "scripts" / "seal_final_exact_release.py").read_text(encoding="utf-8")
        self.assertIn(
            'GO="$(GO)" $(PYTHON) scripts/package_release_exact.py --root .',
            makefile,
        )
        self.assertIn('"scripts/package_release_exact.py"', sealer)
        self.assertNotIn('[sys.executable, "scripts/build_release.py", "."]', sealer)


if __name__ == "__main__":
    unittest.main()
