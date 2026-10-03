import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release_exact_lock_test",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9ExactToolchainLockSourceTests(unittest.TestCase):
    def git(self,root:Path,*args:str)->str:
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def repo_with_lock(self,root:Path)->tuple[str,dict,bytes]:
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        lock={
            "authority":mod.TOOLCHAIN_AUTHORITY,
            "spec":{
                "admissionStatus":"admitted",
                "exactCompiler":{
                    "localArchivePath":"vendor/toolchains/go.tgz",
                    "archiveSize":1234,
                    "archiveSha256":"a"*64,
                },
            },
        }
        path=root/"lab"/"release-build-toolchain-lock.json"
        path.parent.mkdir(parents=True)
        raw=(json.dumps(lock,indent=2,sort_keys=True)+"\n").encode("utf-8")
        path.write_bytes(raw)
        self.git(root,"add","lab/release-build-toolchain-lock.json")
        self.git(root,"commit","-m","lock")
        return self.git(root,"rev-parse","HEAD"),lock,raw

    def test_exact_toolchain_lock_comes_from_committed_source_not_mutable_worktree(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source_sha,expected,raw=self.repo_with_lock(root)
            mutable={"authority":"MUTATED","spec":{"admissionStatus":"admitted"}}
            (root/"lab"/"release-build-toolchain-lock.json").write_text(json.dumps(mutable),encoding="utf-8")
            lock,digest=mod.exact_source_toolchain_lock(root.resolve(),source_sha)
            self.assertEqual(expected,lock)
            self.assertEqual("sha256:"+hashlib.sha256(raw).hexdigest(),digest)
            self.assertNotEqual(mutable,lock)

    def test_exact_toolchain_lock_rejects_missing_or_invalid_source_object(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source_sha,_,_=self.repo_with_lock(root)
            with self.assertRaisesRegex(RuntimeError,"TOOLCHAIN_LOCK_SOURCE_OBJECT"):
                mod.exact_source_json(root.resolve(),source_sha,"lab/missing.json","FINAL_EXACT_RELEASE_TOOLCHAIN_LOCK")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_SHA_INVALID"):
                mod.exact_source_toolchain_lock(root.resolve(),"bad")

    def test_environment_gate_can_be_bound_to_exact_toolchain_lock(self):
        exact_lock={"authority":mod.TOOLCHAIN_AUTHORITY,"spec":{"admissionStatus":"admitted","exactCompiler":{}}}
        browser_doc={"version":"unit-browser"}
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(mod.sys,"platform","linux"), \
             mock.patch.object(mod,"safe_toolchain_archive",return_value=(Path(td)/"go.tgz",{})) as safe, \
             mock.patch.object(mod.browser_authority,"validate_ui_browser_authority",return_value=(Path(td)/"chrome",browser_doc)), \
             mock.patch.dict(mod.os.environ,{mod.browser_authority.ENV_AUTHORITY:str(Path(td)/"authority.json")},clear=False), \
             mock.patch.object(mod.shutil,"which",return_value="/usr/bin/tool"):
            out=mod.exact_release_environment_preflight(Path(td),toolchain_lock=exact_lock)
        self.assertTrue(out["ready"])
        safe.assert_called_once_with(Path(td).resolve(),exact_lock)


if __name__=="__main__":
    unittest.main()
