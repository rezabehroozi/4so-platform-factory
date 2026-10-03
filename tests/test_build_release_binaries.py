import hashlib
import importlib.util
import os
import subprocess
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
            "PYTHONHOME": "/tmp/evil-python-home",
            "PYTHONPATH": "/tmp/evil-python-path",
            "PYTHONSTARTUP": "/tmp/evil-python-startup.py",
            "PYTHONINSPECT": "1",
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
        self.assertEqual("1", env["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual("1", env["PYTHONNOUSERSITE"])
        for key in (
            "GOROOT", "GOTOOLDIR", "CGO_CFLAGS", "CGO_LDFLAGS", "CC", "CXX",
            "LD_PRELOAD", "LD_LIBRARY_PATH", "GIT_DIR", "GIT_WORK_TREE",
            "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT", "SOURCE_COMMIT",
        ):
            self.assertNotIn(key, env)

    def test_make_toolchain_verifier_and_builder_use_same_go_selector(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            'GO="$(GO)" $(PYTHON) scripts/verify_release_build_toolchain.py --require-admitted',
            makefile,
        )
        self.assertIn(
            'scripts/build_release_binaries.py --root . --go "$(GO)"',
            makefile,
        )

    def test_go_binary_identity_is_bound_to_exact_lock(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec = {
                "exactCompiler": {
                    "version": "go1.27.1",
                    "goos": "linux",
                    "goarch": "amd64",
                }
            }
            env = {"PATH": "/safe"}
            good = mock.Mock(returncode=0, stdout="go version go1.27.1 linux/amd64\n", stderr="")
            with mock.patch.object(mod.subprocess, "run", return_value=good) as run:
                mod.require_go_binary_identity(root, "/opt/exact-go/bin/go", env, spec)
            run.assert_called_once_with(
                ["/opt/exact-go/bin/go", "version"],
                cwd=root,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            bad = mock.Mock(returncode=0, stdout="go version go1.26.0 linux/amd64\n", stderr="")
            with mock.patch.object(mod.subprocess, "run", return_value=bad):
                with self.assertRaisesRegex(RuntimeError, "GO_IDENTITY_MISMATCH"):
                    mod.require_go_binary_identity(root, "/opt/exact-go/bin/go", env, spec)

    def test_cgo_identity_is_bound_to_same_sanitized_environment_as_build(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            header = root / "libpq-fe.h"
            library = root / "libpq.so.5.18"
            header.write_bytes(b"header")
            library.write_bytes(b"library")
            expected = {
                "ccVersion": "gcc exact 1.0",
                "ldVersion": "GNU ld exact 1.0",
                "libcVersion": "ldd exact 1.0",
                "libpqHeaderPath": str(header),
                "libpqHeaderSha256": hashlib.sha256(header.read_bytes()).hexdigest(),
                "libpqLibraryPath": str(library),
                "libpqLibrarySha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            }
            spec = {"exactCGOToolchain": expected}
            env = {"PATH": "/safe"}
            outputs = {
                "gcc": "gcc exact 1.0\n",
                "ld": "GNU ld exact 1.0\n",
                "ldd": "ldd exact 1.0\n",
            }
            calls = []

            def fake_run(argv, **kwargs):
                calls.append((list(argv), kwargs.get("env")))
                return mock.Mock(returncode=0, stdout=outputs[argv[0]], stderr="")

            with mock.patch.object(mod.subprocess, "run", side_effect=fake_run):
                mod.require_cgo_toolchain_identity(root, env, spec)
            self.assertEqual(["gcc", "ld", "ldd"], [argv[0] for argv, _ in calls])
            self.assertTrue(all(call_env is env for _, call_env in calls))

            outputs["gcc"] = "gcc drifted\n"
            with mock.patch.object(mod.subprocess, "run", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "CGO_IDENTITY_MISMATCH"):
                    mod.require_cgo_toolchain_identity(root, env, spec)

    def test_build_uses_one_admitted_snapshot_and_sanitized_environment_for_every_go_invocation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bin" / "linux-amd64").mkdir(parents=True)
            clean_env = {"PATH": "/safe", "GOWORK": "off", "GOFLAGS": ""}
            toolchain_spec={"exactCompiler":{},"exactCGOToolchain":{}}
            calls = []

            def fake_run(argv, **kwargs):
                calls.append((list(argv), dict(kwargs.get("env") or {})))
                target = Path(argv[argv.index("-o") + 1])
                target.write_bytes(b"binary")
                return mock.Mock(returncode=0, stdout="")

            with (
                mock.patch.object(mod.sys, "platform", "linux"),
                mock.patch.object(mod.platform,"machine",return_value="x86_64"),
                mock.patch.object(mod, "release_identity", return_value=("a" * 40, "0.0.363")),
                mock.patch.object(mod, "release_build_environment", return_value=clean_env.copy()) as build_env,
                mock.patch.object(mod, "admitted_toolchain_spec", return_value=toolchain_spec) as admitted,
                mock.patch.object(mod, "require_go_binary_identity") as go_identity,
                mock.patch.object(mod, "require_cgo_toolchain_identity") as cgo_identity,
                mock.patch.object(mod.subprocess, "run", side_effect=fake_run),
            ):
                mod.build(root, "/opt/exact-go/bin/go")

            build_env.assert_called_once_with()
            admitted.assert_called_once_with(root.resolve())
            go_identity.assert_called_once_with(root.resolve(), "/opt/exact-go/bin/go", clean_env, toolchain_spec)
            cgo_identity.assert_called_once_with(root.resolve(), clean_env, toolchain_spec)
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
