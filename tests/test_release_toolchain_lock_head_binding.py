import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("build_release_binaries",ROOT/"scripts"/"build_release_binaries.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ReleaseToolchainLockHeadBindingTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def fixture(self,root):
        self.git(root,"init","-b","main")
        self.git(root,"config","user.email","test@example.invalid")
        self.git(root,"config","user.name","Test")
        lab=root/"lab"; lab.mkdir()
        lock={"authority":mod.TOOLCHAIN_AUTHORITY,"spec":{"admissionStatus":"admitted","exactCompiler":{},"exactCGOToolchain":{}}}
        path=lab/"release-build-toolchain-lock.json"
        path.write_text(json.dumps(lock,sort_keys=True)+"\n",encoding="utf-8")
        self.git(root,"add","lab/release-build-toolchain-lock.json")
        self.git(root,"commit","-m","lock")
        return path,lock

    def test_admitted_lock_must_match_exact_head_blob(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); path,lock=self.fixture(root)
            self.assertEqual(lock["spec"],mod.admitted_toolchain_spec(root))
            tampered=dict(lock)
            tampered["spec"]=dict(lock["spec"])
            tampered["spec"]["transientInjection"]="must-not-be-admitted"
            path.write_text(json.dumps(tampered,sort_keys=True)+"\n",encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"TOOLCHAIN_LOCK_INVALID"):
                mod.admitted_toolchain_spec(root)

    def test_lock_loader_uses_git_head_blob_binding(self):
        source=(ROOT/"scripts"/"build_release_binaries.py").read_text(encoding="utf-8")
        start=source.index("def admitted_toolchain_spec")
        end=source.index("\ndef require_go_binary_identity",start)
        block=source[start:end]
        self.assertIn("HEAD:lab/release-build-toolchain-lock.json",block)
        self.assertIn("snapshot_bytes",block)
        self.assertIn("head_blob",block)


if __name__=="__main__":
    unittest.main()
