import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C9EvidenceSnapshotTests(unittest.TestCase):
    def test_existing_evidence_snapshot_reads_one_regular_json_file(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"evidence.json"
            expected={"authority":"unit","sourceCommitSHA":"a"*40}
            path.write_text(json.dumps(expected)+"\n",encoding="utf-8")
            self.assertEqual(expected,mod.load_existing_evidence_snapshot(path))

    def test_existing_evidence_snapshot_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            target=root/"target.json"; target.write_text("{}\n",encoding="utf-8")
            link=root/"evidence.json"
            try:
                link.symlink_to(target.name)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError,"EXISTING_EVIDENCE_INVALID"):
                mod.load_existing_evidence_snapshot(link)

    def test_resume_source_uses_snapshot_loader_not_path_read_text(self):
        source=(ROOT/"scripts"/"seal_final_exact_release.py").read_text(encoding="utf-8")
        start=source.index("def resume_existing_evidence")
        end=source.index("\ndef execute",start)
        block=source[start:end]
        self.assertIn("load_existing_evidence_snapshot(out)",block)
        self.assertNotIn("out.read_text",block)


if __name__=="__main__":
    unittest.main()
