import importlib.util
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]

PKG_SPEC=importlib.util.spec_from_file_location("package_release_exact_git_env",ROOT/"scripts"/"package_release_exact.py")
pkg=importlib.util.module_from_spec(PKG_SPEC); PKG_SPEC.loader.exec_module(pkg)

BUILDER_SPEC=importlib.util.spec_from_file_location("build_release_binaries_git_env",ROOT/"scripts"/"build_release_binaries.py")
builder=importlib.util.module_from_spec(BUILDER_SPEC); BUILDER_SPEC.loader.exec_module(builder)


class ExactReleasePackagerGitEnvironmentTests(unittest.TestCase):
    def test_packager_source_sha_ignores_inherited_git_authority(self):
        seen=[]
        def fake_run(command,**kwargs):
            seen.append(kwargs)
            return SimpleNamespace(returncode=0,stdout="a"*40+"\n")
        injected={"GIT_DIR":"/tmp/evil.git","GIT_WORK_TREE":"/tmp/evil-tree","GIT_INDEX_FILE":"/tmp/evil-index"}
        with mock.patch.dict(os.environ,injected,clear=False), mock.patch.object(pkg.subprocess,"run",side_effect=fake_run):
            self.assertEqual("a"*40,pkg.exact_source_sha(Path("/repo")))
        self.assertEqual(1,len(seen))
        self.assertIn("env",seen[0])
        self.assertFalse(any(key.startswith("GIT_") for key in seen[0]["env"]))

    def test_toolchain_lock_head_probe_ignores_inherited_git_authority(self):
        lock={"authority":builder.TOOLCHAIN_AUTHORITY,"spec":{"admissionStatus":"admitted"}}
        snapshot=b"locked-toolchain-snapshot"
        seen=[]
        def fake_run(command,**kwargs):
            seen.append(kwargs)
            return SimpleNamespace(returncode=0,stdout=snapshot,stderr=b"")
        injected={"GIT_DIR":"/tmp/evil.git","GIT_OBJECT_DIRECTORY":"/tmp/evil-objects","GIT_INDEX_FILE":"/tmp/evil-index"}
        with (
            mock.patch.dict(os.environ,injected,clear=False),
            mock.patch.object(builder,"load_json_snapshot_bytes",return_value=(lock,snapshot)),
            mock.patch.object(builder.subprocess,"run",side_effect=fake_run),
        ):
            self.assertEqual(lock["spec"],builder.admitted_toolchain_spec(Path("/repo")))
        self.assertEqual(1,len(seen))
        self.assertIn("env",seen[0])
        self.assertFalse(any(key.startswith("GIT_") for key in seen[0]["env"]))

    def test_binary_builder_source_head_ignores_inherited_git_authority(self):
        seen=[]
        def fake_run(command,**kwargs):
            seen.append(kwargs)
            return SimpleNamespace(returncode=0,stdout="c"*40+"\n")
        injected={"GIT_DIR":"/tmp/evil.git","GIT_WORK_TREE":"/tmp/evil-tree","GIT_INDEX_FILE":"/tmp/evil-index"}
        with mock.patch.dict(os.environ,injected,clear=False), mock.patch.object(builder.subprocess,"run",side_effect=fake_run):
            self.assertEqual("c"*40,builder.git_head(Path("/repo")))
        self.assertEqual(1,len(seen))
        self.assertIn("env",seen[0])
        self.assertFalse(any(key.startswith("GIT_") for key in seen[0]["env"]))


if __name__=="__main__":
    unittest.main()
