import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("build_release_binaries",ROOT/"scripts"/"build_release_binaries.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ReleaseBinaryBuilderStableLockTests(unittest.TestCase):
    def test_snapshot_loader_reads_one_regular_json_file(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"lock.json"
            expected={"authority":"unit","spec":{}}
            path.write_text(json.dumps(expected)+"\n",encoding="utf-8")
            self.assertEqual(expected,mod.load_json_snapshot(path,"RELEASE_BINARY_BUILD_TOOLCHAIN_LOCK",1024*1024))

    def test_admitted_toolchain_spec_does_not_reopen_lock_path(self):
        source=(ROOT/"scripts"/"build_release_binaries.py").read_text(encoding="utf-8")
        start=source.index("def admitted_toolchain_spec")
        end=source.index("\ndef require_go_binary_identity",start)
        block=source[start:end]
        self.assertIn("load_json_snapshot(lock_path",block)
        self.assertNotIn("lock_path.read_text",block)
        self.assertNotIn("lock_path.stat()",block)

    def test_snapshot_loader_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            target=root/"target.json"; target.write_text("{}\n",encoding="utf-8")
            link=root/"lock.json"
            try:
                link.symlink_to(target.name)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"FILE_INVALID"):
                mod.load_json_snapshot(link,"RELEASE_BINARY_BUILD_TOOLCHAIN_LOCK",1024*1024)


if __name__=="__main__":
    unittest.main()
