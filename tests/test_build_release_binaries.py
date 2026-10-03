import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_release_binaries", ROOT / "scripts" / "build_release_binaries.py"
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class NativeReleaseBinaryBuilderTests(unittest.TestCase):
    def test_release_build_environment_strips_semantic_overrides(self):
        injected = {
            "PATH": "/tmp/evil-bin:/usr/bin",
            "GOFLAGS": "-overlay=/tmp/evil.json",
            "GOWORK": "/tmp/evil.work",
            "GOENV": "/tmp/evil.goenv",
            "GOROOT": "/tmp/fake-go",
            "GOTOOLDIR": "/tmp/fake-tools",
            "CGO_CFLAGS": "-include /tmp/evil.h",
            "CGO_LDFLAGS": "-Wl,--dynamic-linker=/tmp/evil",
            "CC": "/tmp/fake-gcc",
            "CXX": "/tmp/fake-g++",
            "LD_PRELOAD": "/tmp/evil.so",
            "LD_LIBRARY_PATH": "/tmp/evil-lib",
            "GIT_DIR": "/tmp/other.git",
            "GIT_WORK_TREE": "/tmp/other-tree",
            "SOURCE_COMMIT": "f" * 40,
        }
        with mock.patch.dict(os.environ, injected, clear=True):
            env = mod.release_build_environment()

        self.assertEqual(
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            env["PATH"],
        )
        self.assertEqual("C", env["LANG"])
        self.assertEqual("C", env["LC_ALL"])
        self.assertEqual("UTC", env["TZ"])
        self.assertEqual("local", env["GOTOOLCHAIN"])
        self.assertEqual("off", env["GOENV"])
        self.assertEqual("off", env["GOWORK"])
        self.assertEqual("", env["GOFLAGS"])
        self.assertEqual("off", env["GOPROXY"])
        self.assertEqual("off", env["GOSUMDB"])
        for key in (
            "GOROOT", "GOTOOLDIR", "CGO_CFLAGS", "CGO_LDFLAGS", "CC", "CXX",
            "LD_PRELOAD", "LD_LIBRARY_PATH", "GIT_DIR", "GIT_WORK_TREE", "SOURCE_COMMIT",
        ):
            self.assertNotIn(key, env)

    def test_build_uses_sanitized_environment_for_every_go_invocation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bin" / "linux-amd64").mkdir(parents=True)
            clean_env = {"PATH": "/safe", "GOWORK": "off", "GOFLAGS": ""}
            calls = []

            def fake_run(argv, **kwargs):
                calls.append((list(argv), dict(kwargs.get("env") or {})))
                target = Path(argv[argv.index("-o") + 1])
                target.write_bytes(b"binary")
                return mock.Mock(returncode=0, stdout="")

            with (
                mock.patch.object(mod.sys, "platform", "linux"),
                mock.patch.object(mod, "release_identity", return_value=("a" * 40, "0.0.363")),
                mock.patch.object(mod, "release_build_environment", return_value=clean_env.copy()) as build_env,
                mock.patch.object(mod.subprocess, "run", side_effect=fake_run),
            ):
                mod.build(root, "/opt/exact-go/bin/go")

            build_env.assert_called_once_with()
            self.assertEqual(len(mod.TARGETS), len(calls))
            for (_, _, cgo), (_, env) in zip(mod.TARGETS, calls, strict=True):
                self.assertEqual("/safe", env["PATH"])
                self.assertEqual("off", env["GOWORK"])
                self.assertEqual("", env["GOFLAGS"])
                self.assertEqual("linux", env["GOOS"])
                self.assertEqual("amd64", env["GOARCH"])
                self.assertEqual(cgo, env["CGO_ENABLED"])


if __name__ == "__main__":
    unittest.main()
