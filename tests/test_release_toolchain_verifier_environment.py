import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=str(ROOT/"scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0,SCRIPTS)
SPEC=importlib.util.spec_from_file_location(
    "verify_release_build_toolchain_env_test",ROOT/"scripts"/"verify_release_build_toolchain.py"
)
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ReleaseToolchainVerifierEnvironmentTests(unittest.TestCase):
    def test_verification_environment_reuses_release_builder_sanitizer_and_selected_go(self):
        clean={"PATH":"/safe","GOWORK":"off","GOFLAGS":""}
        with (
            mock.patch.dict(os.environ,{"GO":"/opt/exact-go/bin/go","PATH":"/tmp/shadow"},clear=True),
            mock.patch.object(mod.release_binary_builder,"release_build_environment",return_value=clean.copy()) as sanitizer,
        ):
            go_binary,env=mod.verification_environment()
        self.assertEqual("/opt/exact-go/bin/go",go_binary)
        self.assertEqual("/opt/exact-go/bin/go",env["GO"])
        self.assertEqual("/safe",env["PATH"])
        sanitizer.assert_called_once_with()

    def test_go_and_cgo_probes_use_same_explicit_environment(self):
        env={"PATH":"/safe","GO":"/opt/exact-go/bin/go"}
        go=mock.Mock(returncode=0,stdout="go version go1.27.1 linux/amd64\n",stderr="")
        with mock.patch.object(mod.subprocess,"run",return_value=go) as run:
            rc,actual=mod.current_go(env)
        self.assertEqual(0,rc)
        self.assertEqual("go version go1.27.1 linux/amd64",actual)
        run.assert_called_once_with(
            ["/opt/exact-go/bin/go","version"],env=env,text=True,capture_output=True
        )

        tool=mock.Mock(returncode=0,stdout="gcc exact\nextra\n",stderr="")
        with mock.patch.object(mod.subprocess,"run",return_value=tool) as run:
            rc,actual=mod.command_first_line(["gcc","--version"],env)
        self.assertEqual(0,rc)
        self.assertEqual("gcc exact",actual)
        run.assert_called_once_with(
            ["gcc","--version"],env=env,text=True,capture_output=True
        )

    def test_active_cgo_validation_uses_sanitized_environment_for_all_tools(self):
        lock={
            "spec":{
                "admissionStatus":"admitted",
                "exactCGOToolchain":{
                    "ccVersion":"gcc exact",
                    "ldVersion":"ld exact",
                    "libcVersion":"ldd exact",
                    "libpqHeaderPath":"/header",
                    "libpqHeaderSha256":"a"*64,
                    "libpqLibraryPath":"/library",
                    "libpqLibrarySha256":"b"*64,
                },
            }
        }
        env={"PATH":"/safe"}
        observed=[]
        versions={"gcc":"gcc exact","ld":"ld exact","ldd":"ldd exact"}
        def first(command,probe_env):
            observed.append(probe_env)
            return 0,versions[command[0]]
        digests={"/header":"a"*64,"/library":"b"*64}
        with (
            mock.patch.object(mod,"command_first_line",side_effect=first),
            mock.patch.object(mod,"file_sha256",side_effect=lambda path:digests[str(path)]),
        ):
            self.assertEqual([],mod.validate_active_cgo(lock,env))
        self.assertEqual([env,env,env],observed)


if __name__=="__main__":
    unittest.main()
