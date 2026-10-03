import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("final_exact_release_admission_snapshot_test",ROOT/"scripts/final_exact_release_admission.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class FinalExactReleaseAdmissionSnapshotTests(unittest.TestCase):
    def test_snapshot_loader_uses_stable_bytes_and_returns_matching_digest(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"authority.json"
            path.write_text('{"ok":true}\n',encoding="utf-8")
            expected={"ok":True}; digest="sha256:"+"a"*64
            with mock.patch.object(mod.mcp_contract,"load_with_sha256",return_value=(expected,digest)) as stable:
                value,observed=mod.load_snapshot(path,"AUTHORITY")
            stable.assert_called_once_with(path,"AUTHORITY",max_bytes=2*1024*1024)
            self.assertIs(value,expected)
            self.assertEqual(digest,observed)

    def test_snapshot_loader_preserves_pending_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"missing.json"
            with self.assertRaisesRegex(mod.Pending,"AUTHORITY_PENDING"):
                mod.load_snapshot(path,"AUTHORITY")

    def test_snapshot_loader_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"authority.json"
            path.write_text('[]\n',encoding="utf-8")
            with mock.patch.object(mod.mcp_contract,"load_with_sha256",return_value=([],"sha256:"+"b"*64)):
                with self.assertRaisesRegex(RuntimeError,"AUTHORITY_NOT_OBJECT"):
                    mod.load_snapshot(path,"AUTHORITY")

    def test_verify_has_no_second_digest_read_for_admission_json(self):
        source=(ROOT/"scripts/final_exact_release_admission.py").read_text(encoding="utf-8")
        start=source.index("def verify(")
        end=source.index("\ndef main",start)
        verify_source=source[start:end]
        self.assertNotIn("digest(lock_path)",verify_source)
        self.assertNotIn("digest(matrix_path)",verify_source)
        self.assertNotIn("digest(mcp_path)",verify_source)
        self.assertIn("lock,lock_sha256=load_snapshot",verify_source)
        self.assertIn("matrix,matrix_sha256=load_snapshot",verify_source)
        self.assertIn("mcp,mcp_sha256=load_snapshot",verify_source)


if __name__=="__main__":
    unittest.main()
