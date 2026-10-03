import importlib.util
import hashlib
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("build_release_binaries",ROOT/"scripts"/"build_release_binaries.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class ReleaseBinaryBuilderStableCGOHashTests(unittest.TestCase):
    def test_file_sha256_hashes_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"libpq.so"
            payload=b"exact-cgo-bytes\n"
            path.write_bytes(payload)
            self.assertEqual(hashlib.sha256(payload).hexdigest(),mod.file_sha256(path))

    def test_file_sha256_does_not_use_check_then_path_open(self):
        source=(ROOT/"scripts"/"build_release_binaries.py").read_text(encoding="utf-8")
        start=source.index("def file_sha256")
        end=source.index("\ndef command_first_line",start)
        block=source[start:end]
        self.assertIn("os.open",block)
        self.assertIn("os.fstat",block)
        self.assertIn("os.path.samestat",block)
        self.assertNotIn("path.open",block)
        self.assertNotIn("path.lstat",block)

    def test_file_sha256_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            target=root/"real"; target.write_bytes(b"real")
            link=root/"link"
            try:
                link.symlink_to(target.name)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"CGO_FILE_INVALID"):
                mod.file_sha256(link)


if __name__=="__main__":
    unittest.main()
