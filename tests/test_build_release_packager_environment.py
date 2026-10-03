import importlib.util
import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_release", ROOT / "scripts" / "build_release.py"
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ReleasePackagerEnvironmentTests(unittest.TestCase):
    def test_packager_tool_authority_reuses_native_builder_environment(self):
        root = Path("/repo")
        clean_env = {"PATH": "/safe", "GOWORK": "off", "GOFLAGS": ""}
        with (
            mock.patch.dict(os.environ, {"GO": "/opt/exact-go/bin/go"}, clear=True),
            mock.patch.object(mod.release_binary_builder, "release_build_environment", return_value=clean_env.copy()) as build_env,
            mock.patch.object(mod.release_binary_builder, "require_go_binary_identity") as go_identity,
            mock.patch.object(mod.release_binary_builder, "require_cgo_toolchain_identity") as cgo_identity,
        ):
            go_binary, env = mod.release_tool_authority(root)

        self.assertEqual("/opt/exact-go/bin/go", go_binary)
        self.assertEqual(clean_env, env)
        build_env.assert_called_once_with()
        go_identity.assert_called_once_with(root, "/opt/exact-go/bin/go", clean_env)
        cgo_identity.assert_called_once_with(root, clean_env)

    def test_packager_tool_probes_use_explicit_sanitized_environment(self):
        env = {"PATH": "/safe"}
        go_binary = "/opt/exact-go/bin/go"

        go_version = mock.Mock(returncode=0, stdout="go version go1.27.1 linux/amd64\n", stderr="")
        with mock.patch.object(mod.subprocess, "run", return_value=go_version) as run:
            self.assertEqual(
                "go version go1.27.1 linux/amd64",
                mod.go_toolchain_version(go_binary, env),
            )
        run.assert_called_once_with(
            [go_binary, "version"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )

        identity = mock.Mock(
            returncode=0,
            stdout=(
                "platform.4so.io/factory/internal/buildinfo.Version=0.0.363\n"
                + "platform.4so.io/factory/internal/buildinfo.SourceCommit=" + "a" * 40 + "\n"
            ),
            stderr="",
        )
        with mock.patch.object(mod.subprocess, "run", return_value=identity) as run:
            mod.verify_binary_build_identity(
                Path("binary"), "0.0.363", "a" * 40, go_binary, env
            )
        run.assert_called_once_with(
            [go_binary, "version", "-m", "binary"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        first_line = mock.Mock(returncode=0, stdout="gcc exact\nextra\n", stderr="")
        with mock.patch.object(mod.subprocess, "run", return_value=first_line) as run:
            self.assertEqual("gcc exact", mod.command_first_line(["gcc", "--version"], env))
        run.assert_called_once_with(
            ["gcc", "--version"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )

    def test_elf_metadata_uses_explicit_sanitized_environment(self):
        env = {"PATH": "/safe"}
        notes = mock.Mock(returncode=0, stdout="Build ID: abcdef\n", stderr="")
        dynamic = mock.Mock(returncode=0, stdout="Shared library: [libpq.so.5]\n", stderr="")
        with mock.patch.object(mod.subprocess, "run", side_effect=[notes, dynamic]) as run:
            out = mod.elf_metadata(Path("binary"), env)
        self.assertEqual("abcdef", out["gnuBuildID"])
        self.assertEqual(["libpq.so.5"], out["runtimeNeeded"])
        self.assertEqual(2, run.call_count)
        for call in run.call_args_list:
            self.assertIs(env, call.kwargs["env"])


if __name__ == "__main__":
    unittest.main()
