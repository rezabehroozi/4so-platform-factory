import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]


def load(name,rel):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ExactReleaseHostArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scripts=str(ROOT/"scripts")
        if scripts not in sys.path:
            sys.path.insert(0,scripts)
        cls.builder=load("build_release_binaries_host_test","scripts/build_release_binaries.py")
        cls.sealer=load("seal_final_exact_release_host_test","scripts/seal_final_exact_release.py")

    def test_native_builder_rejects_linux_arm64_before_build(self):
        with (
            mock.patch.object(self.builder.sys,"platform","linux"),
            mock.patch.object(self.builder.platform,"machine",return_value="aarch64"),
        ):
            with self.assertRaisesRegex(RuntimeError,"LINUX_AMD64_HOST_REQUIRED"):
                self.builder.require_release_build_host()

    def test_native_builder_accepts_linux_x86_64(self):
        with (
            mock.patch.object(self.builder.sys,"platform","linux"),
            mock.patch.object(self.builder.platform,"machine",return_value="x86_64"),
        ):
            self.builder.require_release_build_host()

    def test_c9_rejects_linux_arm64_before_exact_toolchain_execution(self):
        with (
            mock.patch.object(self.sealer.sys,"platform","linux"),
            mock.patch.object(self.sealer.platform,"machine",return_value="aarch64"),
        ):
            with self.assertRaisesRegex(RuntimeError,"LINUX_AMD64_HOST_REQUIRED"):
                self.sealer.require_exact_release_host()

    def test_c9_preflight_reports_architecture_blocker(self):
        with (
            mock.patch.object(self.sealer.sys,"platform","linux"),
            mock.patch.object(self.sealer.platform,"machine",return_value="aarch64"),
            mock.patch.object(self.sealer,"safe_toolchain_archive",side_effect=RuntimeError("FINAL_EXACT_RELEASE_TOOLCHAIN_ARCHIVE_MISSING")),
            mock.patch.object(self.sealer.shutil,"which",return_value="/usr/bin/tool"),
            mock.patch.dict(self.sealer.os.environ,{self.sealer.browser_authority.ENV_AUTHORITY:""},clear=False),
        ):
            out=self.sealer.exact_release_environment_preflight(ROOT)
        self.assertFalse(out["ready"])
        self.assertIn("FINAL_EXACT_RELEASE_LINUX_AMD64_HOST_REQUIRED",out["blockers"])
        self.assertEqual("aarch64",out["observedArchitecture"])
        self.assertEqual("amd64",out["requiredArchitecture"])


if __name__=="__main__":
    unittest.main()
